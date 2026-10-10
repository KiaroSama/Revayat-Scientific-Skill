"""Trusted stdlib-only Windows CI owner; never imports production/test modules."""
import argparse
import ctypes
import ctypes.wintypes as w
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import uuid

P = ctypes.c_void_p
SIZE = ctypes.c_size_t


class Startup(ctypes.Structure):
    _fields_ = [('cb', w.DWORD), ('reserved', P), ('desktop', P), ('title', P),
                ('x', w.DWORD), ('y', w.DWORD), ('width', w.DWORD), ('height', w.DWORD),
                ('chars_x', w.DWORD), ('chars_y', w.DWORD), ('fill', w.DWORD), ('flags', w.DWORD),
                ('show', w.WORD), ('reserved_size', w.WORD), ('reserved_bytes', P),
                ('stdin', P), ('stdout', P), ('stderr', P)]


class StartupEx(ctypes.Structure):
    _fields_ = [('startup', Startup), ('attributes', P)]


class ProcessInfo(ctypes.Structure):
    _fields_ = [('process', P), ('thread', P), ('pid', w.DWORD), ('tid', w.DWORD)]


class Basic(ctypes.Structure):
    _fields_ = [('process_time', ctypes.c_longlong), ('job_time', ctypes.c_longlong),
                ('flags', w.DWORD), ('min_ws', SIZE), ('max_ws', SIZE), ('pids', w.DWORD),
                ('affinity', SIZE), ('priority', w.DWORD), ('scheduling', w.DWORD)]


class Extended(ctypes.Structure):
    _fields_ = [('basic', Basic), ('io', ctypes.c_ulonglong * 6), ('process_mem', SIZE),
                ('job_mem', SIZE), ('peak_process', SIZE), ('peak_job', SIZE)]


class Accounting(ctypes.Structure):
    _fields_ = [('times', ctypes.c_longlong * 4), ('faults', w.DWORD), ('total', w.DWORD),
                ('active', w.DWORD), ('terminated', w.DWORD)]


class SecurityAttributes(ctypes.Structure):
    _fields_ = [('size', w.DWORD), ('descriptor', P), ('inherit', w.BOOL)]


def bind():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    signatures = {
        'CreateJobObjectW': ([P, w.LPCWSTR], P),
        'SetInformationJobObject': ([P, ctypes.c_int, P, w.DWORD], w.BOOL),
        'QueryInformationJobObject': ([P, ctypes.c_int, P, w.DWORD, P], w.BOOL),
        'CreatePipe': ([ctypes.POINTER(P), ctypes.POINTER(P), ctypes.POINTER(SecurityAttributes), w.DWORD], w.BOOL),
        'SetHandleInformation': ([P, w.DWORD, w.DWORD], w.BOOL),
        'CreateFileW': ([w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(SecurityAttributes), w.DWORD, w.DWORD, P], P),
        'InitializeProcThreadAttributeList': ([P, w.DWORD, w.DWORD, ctypes.POINTER(SIZE)], w.BOOL),
        'UpdateProcThreadAttribute': ([P, w.DWORD, SIZE, P, SIZE, P, P], w.BOOL),
        'DeleteProcThreadAttributeList': ([P], None),
        'CreateProcessW': ([w.LPCWSTR, w.LPWSTR, P, P, w.BOOL, w.DWORD, P, w.LPCWSTR,
                            ctypes.POINTER(StartupEx), ctypes.POINTER(ProcessInfo)], w.BOOL),
        'AssignProcessToJobObject': ([P, P], w.BOOL), 'ResumeThread': ([P], w.DWORD),
        'WaitForSingleObject': ([P, w.DWORD], w.DWORD),
        'GetExitCodeProcess': ([P, ctypes.POINTER(w.DWORD)], w.BOOL),
        'TerminateProcess': ([P, w.DWORD], w.BOOL), 'TerminateJobObject': ([P, w.DWORD], w.BOOL),
        'ReadFile': ([P, P, w.DWORD, ctypes.POINTER(w.DWORD), P], w.BOOL),
        'CancelIoEx': ([P, P], w.BOOL), 'CloseHandle': ([P], w.BOOL),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = arguments, result
    return kernel


def check(value, operation):
    if not value:
        raise ctypes.WinError(ctypes.get_last_error(), operation)


def run_owned(kernel, pwsh, entry, python, root, run_id, cleanup=False):
    arguments = [pwsh, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(entry),
                 '-Python', str(python), '-Root', str(root), '-RunId', run_id]
    if cleanup:
        arguments.append('-CleanupOnly')
    child, job, attributes = ProcessInfo(), None, None
    handles, readers, threads = [], [], []
    chunks, errors = [bytearray(), bytearray()], []
    lock = threading.Lock()
    last_progress = [time.monotonic()]
    started = resumed = False
    sa = SecurityAttributes(ctypes.sizeof(SecurityAttributes), None, True)

    def drain(handle, index):
        buffer = ctypes.create_string_buffer(4096)
        try:
            while True:
                count = w.DWORD()
                if not kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None):
                    code = ctypes.get_last_error()
                    if code == 109:
                        break
                    raise ctypes.WinError(code, 'outer pipe capture')
                if not count.value:
                    break
                with lock:
                    if sum(map(len, chunks)) + count.value > 1048576:
                        raise RuntimeError('outer combined output exceeded 1 MiB')
                    chunks[index].extend(buffer.raw[:count.value])
                    last_progress[0] = time.monotonic()
        except Exception as error:
            with lock:
                errors.append(error)

    def reap():
        if job:
            check(kernel.TerminateJobObject(job, 125), 'terminate outer owned job')
            deadline = time.monotonic() + 5
            accounting = Accounting()
            while True:
                check(kernel.QueryInformationJobObject(job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None), 'observe outer active processes')
                if not accounting.active:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError('outer owned job did not reap')
                time.sleep(0.02)

    try:
        job = kernel.CreateJobObjectW(None, None)
        check(job, 'create compiler-independent owner job')
        limits = Extended()
        limits.basic.flags, limits.basic.pids = 0x2000 | 8, 64
        check(kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)), 'set outer kill-on-close/PID bounds')
        writers = []
        for index in range(2):
            reader, writer = P(), P()
            check(kernel.CreatePipe(ctypes.byref(reader), ctypes.byref(writer), ctypes.byref(sa), 4096), 'create outer capture pipe')
            handles.extend((reader.value, writer.value)); readers.append(reader.value); writers.append(writer.value)
            check(kernel.SetHandleInformation(reader, 1, 0), 'exclude outer reader inheritance')
            thread = threading.Thread(target=drain, args=(reader.value, index), daemon=False)
            thread.start(); threads.append(thread)
        stdin = kernel.CreateFileW('NUL', 0x80000000, 3, ctypes.byref(sa), 3, 0x80, None)
        check(stdin != ctypes.c_void_p(-1).value, 'open outer detached stdin'); handles.append(stdin)
        needed = SIZE()
        kernel.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(needed))
        check(needed.value, 'outer attribute size')
        attributes = ctypes.create_string_buffer(needed.value)
        check(kernel.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(needed)), 'initialize outer attributes')
        inherited = (P * 3)(stdin, *writers)
        check(kernel.UpdateProcThreadAttribute(attributes, 0, 0x20002, inherited, ctypes.sizeof(inherited), None, None), 'outer handle allowlist')
        startup = StartupEx()
        startup.startup.cb, startup.startup.flags = ctypes.sizeof(StartupEx), 0x100
        startup.startup.stdin = stdin
        startup.startup.stdout, startup.startup.stderr = writers
        startup.attributes = ctypes.cast(attributes, P)
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(arguments))
        check(kernel.CreateProcessW(pwsh, command, None, None, True, 0x80000 | 4 | 0x8000000,
                                    None, str(root), ctypes.byref(startup), ctypes.byref(child)), 'create suspended trusted PowerShell bootstrap')
        started = True
        check(kernel.AssignProcessToJobObject(job, child.process), 'own bootstrap before resume')
        check(kernel.ResumeThread(child.thread) != 0xFFFFFFFF, 'resume owned bootstrap'); resumed = True
        for handle in [stdin, *writers]:
            kernel.CloseHandle(handle); handles.remove(handle)
        start = time.monotonic()
        while True:
            state = kernel.WaitForSingleObject(child.process, 100)
            if state == 0:
                break
            check(state == 258, 'wait owned bootstrap')
            with lock:
                if errors:
                    raise errors[0]
                idle = time.monotonic() - last_progress[0]
            if time.monotonic() - start > (30 if cleanup else 300) or idle > (15 if cleanup else 45):
                raise TimeoutError('outer bootstrap wall/idle ceiling exceeded')
        exit_code = w.DWORD()
        check(kernel.GetExitCodeProcess(child.process, ctypes.byref(exit_code)), 'read bootstrap exit code')
        reap()
        for thread in threads:
            thread.join(5)
            if thread.is_alive():
                raise TimeoutError('outer pipe reader survived process-tree reaping')
        with lock:
            if errors:
                raise errors[0]
            stdout, stderr = (bytes(data).decode('utf-8', errors='strict') for data in chunks)
        if stdout:
            print(stdout, end='', flush=True)
        if stderr:
            print(stderr, end='', file=sys.stderr, flush=True)
        return exit_code.value
    finally:
        try:
            if started and not resumed:
                check(kernel.TerminateProcess(child.process, 125), 'terminate suspended bootstrap')
            reap()
        finally:
            if attributes is not None:
                kernel.DeleteProcThreadAttributeList(attributes)
            for handle in handles:
                if handle in readers:
                    kernel.CancelIoEx(handle, None)
                kernel.CloseHandle(handle)
            try:
                for thread in threads:
                    thread.join(5)
                    if thread.is_alive():
                        raise TimeoutError('outer capture thread cleanup failed')
            finally:
                if child.thread:
                    kernel.CloseHandle(child.thread)
                if child.process:
                    kernel.CloseHandle(child.process)
                if job:
                    kernel.CloseHandle(job)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--python', required=True)
    parser.add_argument('--root', required=True)
    args = parser.parse_args()
    if os.name != 'nt':
        raise RuntimeError('Windows bootstrap requires native Windows')
    root, python = Path(args.root).resolve(strict=True), Path(args.python).resolve(strict=True)
    entry = Path(__file__).with_name('Run-WindowsSecurity.ps1').resolve(strict=True)
    if entry.parent != root / 'tests/security/windows':
        raise RuntimeError('outer entry must be the fixed owning repository script')
    pwsh = shutil.which('pwsh')
    if not pwsh:
        raise RuntimeError('existing PowerShell 7 prerequisite unavailable')
    kernel, run_id = bind(), uuid.uuid4().hex
    try:
        status = run_owned(kernel, pwsh, entry, python, root, run_id)
    finally:
        cleanup = run_owned(kernel, pwsh, entry, python, root, run_id, cleanup=True)
        if cleanup:
            raise RuntimeError('outer owned virtual-disk cleanup failed exit=' + str(cleanup))
    return status


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'phase': 'windows-bootstrap', 'status': 'failed', 'error': str(error)}, sort_keys=True),
              file=sys.stderr, flush=True)
        raise SystemExit(1)
