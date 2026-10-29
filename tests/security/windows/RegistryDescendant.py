"""Fixed primary-only authority descendant with bounded LOCAL pipe capture."""
import ctypes
import ctypes.wintypes as w
import os
from pathlib import Path
import subprocess
import sys
import time

P = ctypes.c_void_p
U32 = ctypes.c_uint32


class CaptureFailure(Exception):
    def __init__(self, original, cleanup, code, stderr):
        super().__init__('fixed descendant transport failed')
        self.original, self.cleanup = original, tuple(cleanup)
        self.code, self.stderr = code, bytearray(stderr)


def require(value):
    if not value:
        raise RuntimeError('fixed descendant transport is inconclusive')


class Security(ctypes.Structure):
    _fields_ = [('length', U32), ('descriptor', P), ('inherit', ctypes.c_int32)]


class Native:
    def __init__(self):
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        self.b = ctypes.WinDLL('bcrypt')
        declarations = (
            ('CreateNamedPipeW', [w.LPCWSTR, U32, U32, U32, U32, U32, U32, ctypes.POINTER(Security)], P),
            ('CreateFileW', [w.LPCWSTR, U32, U32, ctypes.POINTER(Security), U32, U32, P], P),
            ('ConnectNamedPipe', [P, P], ctypes.c_int32),
            ('GetNamedPipeClientProcessId', [P, ctypes.POINTER(U32)], ctypes.c_int32),
            ('GetCurrentProcessId', [], U32), ('GetCurrentProcess', [], P),
            ('GetStdHandle', [U32], P), ('GetFileType', [P], U32),
            ('SetHandleInformation', [P, U32, U32], ctypes.c_int32),
            ('GetHandleInformation', [P, ctypes.POINTER(U32)], ctypes.c_int32),
            ('DuplicateHandle', [P, P, P, ctypes.POINTER(P), U32, ctypes.c_int32, U32], ctypes.c_int32),
            ('PeekNamedPipe', [P, P, U32, P, ctypes.POINTER(U32), P], ctypes.c_int32),
            ('ReadFile', [P, P, U32, ctypes.POINTER(U32), P], ctypes.c_int32),
            ('WaitForSingleObject', [P, U32], U32),
            ('GetExitCodeProcess', [P, ctypes.POINTER(U32)], ctypes.c_int32),
            ('TerminateProcess', [P, U32], ctypes.c_int32), ('CloseHandle', [P], ctypes.c_int32),
        )
        for name, arguments, result in declarations:
            function = getattr(self.k, name)
            function.argtypes, function.restype = arguments, result
        self.b.BCryptGenRandom.argtypes = [P, P, U32, U32]
        self.b.BCryptGenRandom.restype = ctypes.c_int32
        require(ctypes.sizeof(P) == 8 and ctypes.sizeof(Security) == 24)

    def checked(self, success):
        if not success:
            # Capture only a failed call's immediate error; callers never emit it.
            raise ctypes.WinError(ctypes.get_last_error())

    @staticmethod
    def valid(handle):
        return type(handle) is int and 0 < handle < 0x7FFFFFFFFFFFFFFF

    def pair(self, role, own, check):
        require(role in ('output', 'error'))
        check()
        nonce = (ctypes.c_ubyte * 16)()
        path = None
        try:
            require(self.b.BCryptGenRandom(None, nonce, 16, 2) == 0)
            path = ctypes.create_unicode_buffer('\\\\.\\pipe\\LOCAL\\RegistryAuthority-' +
                                                ''.join(format(byte, '02X') for byte in nonce) + '-' + role)
            security = Security(ctypes.sizeof(Security), None, 0)
            raw = self.k.CreateNamedPipeW(path, 0x80001, 9, 1, 4096, 4096, 0, ctypes.byref(security))
            error = ctypes.get_last_error() if raw == P(-1).value else None
            server = own(raw)
            if error is not None:
                raise ctypes.WinError(error)
            require(self.valid(server))
            check()
            security.inherit = 1
            raw = self.k.CreateFileW(path, 0x40000000, 0, ctypes.byref(security), 3, 0x100000, None)
            error = ctypes.get_last_error() if raw == P(-1).value else None
            client = own(raw)
            if error is not None:
                raise ctypes.WinError(error)
            require(self.valid(client))
            connected = self.k.ConnectNamedPipe(server, None)
            error = ctypes.get_last_error() if not connected else None
            require(not connected and error == 535)
            pid = U32()
            self.checked(self.k.GetNamedPipeClientProcessId(server, ctypes.byref(pid)))
            require(pid.value == self.k.GetCurrentProcessId())
            self.checked(self.k.SetHandleInformation(server, 1, 0))
            check()
            return server, client
        finally:
            ctypes.memset(nonce, 0, ctypes.sizeof(nonce))
            if path is not None:
                ctypes.memset(path, 0, ctypes.sizeof(path))

    def input(self, own, check):
        check()
        borrowed = self.k.GetStdHandle(0xFFFFFFF6)
        require(self.valid(borrowed) and self.k.GetFileType(borrowed) == 2)
        current, duplicate = self.k.GetCurrentProcess(), P()
        success = self.k.DuplicateHandle(current, borrowed, current, ctypes.byref(duplicate), 0, True, 2)
        error = ctypes.get_last_error() if not success else None
        handle = own(duplicate.value)
        if not success:
            raise ctypes.WinError(error)
        require(self.valid(handle) and self.k.GetFileType(handle) == 2)
        check()
        return handle

    def standards(self, handles):
        require(len(handles) == 3 and len(set(handles)) == 3)
        for handle, kind in zip(handles, (2, 3, 3)):
            require(self.valid(handle) and handle & 3 != 3 and self.k.GetFileType(handle) == kind)
            flags = U32()
            self.checked(self.k.GetHandleInformation(handle, ctypes.byref(flags)))
            require(flags.value & 1 == 1)

    def peek(self, handle):
        available = U32()
        success = self.k.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None)
        if success:
            return available.value
        error = ctypes.get_last_error()
        if error != 109:
            raise ctypes.WinError(error)
        return None

    def read(self, handle, capacity):
        require(0 < capacity <= 1024)
        buffer, count = ctypes.create_string_buffer(capacity), U32()
        try:
            self.checked(self.k.ReadFile(handle, buffer, capacity, ctypes.byref(count), None))
            require(0 < count.value <= capacity)
            return buffer.raw[:count.value]
        finally:
            ctypes.memset(buffer, 0, capacity)

    def wait(self, handle, milliseconds):
        result = self.k.WaitForSingleObject(handle, milliseconds)
        if result == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        require(result in (0, 0x102))
        return result == 0

    def exit(self, handle):
        code = U32()
        self.checked(self.k.GetExitCodeProcess(handle, ctypes.byref(code)))
        return code.value

    def kill(self, handle):
        self.checked(self.k.TerminateProcess(handle, 125))

    def close(self, handle):
        self.checked(self.k.CloseHandle(handle))


def _spawn(handles):
    startup = subprocess.STARTUPINFO(
        dwFlags=subprocess.STARTF_USESTDHANDLES, hStdInput=handles[0],
        hStdOutput=handles[1], hStdError=handles[2], lpAttributeList={'handle_list': list(handles)})
    arguments = [sys.executable, '-I', '-B', '-X', 'utf8',
                 str(Path(__file__).with_name('RegistryAuthorityProbe.py').resolve()), '--descendant']
    return subprocess.Popen(arguments, stdin=None, stdout=None, stderr=None, startupinfo=startup,
                            close_fds=True, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
                            env=dict(os.environ), cwd=str(Path(sys.executable).parent))


def _run(api, spawn, clock):
    end = clock() + 5
    handles, output, errors = [], bytearray(), bytearray()
    child, original, code = None, None, None
    signaled = False
    cleanup = []

    def check():
        if clock() >= end:
            raise TimeoutError('fixed descendant deadline exceeded')

    def own(handle):
        if type(handle) is int and 0 < handle < 0x7FFFFFFFFFFFFFFF:
            require(handle not in handles)
            handles.append(handle)
        return handle

    def close(handle):
        # Remove before the single close attempt; never retry a possibly recycled handle.
        handles.remove(handle)
        api.close(handle)

    def drain(handle, buffer, limit, final):
        check()
        available = api.peek(handle)
        if available is None:
            return True
        require(type(available) is int and 0 <= available <= limit - len(buffer))
        if available:
            block = api.read(handle, min(available, 1024))
            require(type(block) is bytes and 0 < len(block) <= min(available, 1024))
            buffer.extend(block)
        elif final:
            raise RuntimeError('fixed descendant EOF is incomplete')
        return False

    try:
        stdout, stdout_write = api.pair('output', own, check)
        stderr, stderr_write = api.pair('error', own, check)
        stdin = api.input(own, check)
        standard = [stdin, stdout_write, stderr_write]
        api.standards(standard)
        check()
        child = spawn(standard)
        require(child is not None)
        # Popen is now the process-handle owner; no later failure can abandon it.
        for handle in (stdout_write, stderr_write, stdin):
            close(handle)
        ended = [False, False]
        while not signaled:
            for index, (handle, buffer, limit) in enumerate(((stdout, output, 1024), (stderr, errors, 512))):
                if not ended[index]:
                    ended[index] = drain(handle, buffer, limit, False)
            check()
            signaled = api.wait(child._handle, max(1, min(25, int((end - clock()) * 1000))))
        code = api.exit(child._handle)
        require(type(code) is int and 0 <= code <= 0xFFFFFFFF)
        child.returncode = code
        check()
        # Each fair round consumes bytes or observes EOF; empty final Peek is fatal.
        for _ in range(1024 + 512 + 2):
            for index, (handle, buffer, limit) in enumerate(((stdout, output, 1024), (stderr, errors, 512))):
                if not ended[index]:
                    ended[index] = drain(handle, buffer, limit, True)
            if all(ended):
                break
        require(all(ended))
        text, error_text = output.decode('ascii', errors='strict'), errors.decode('ascii', errors='strict')
    except Exception as error:
        original = error
    finally:
        cleanup_end = clock() + 2

        def attempt(operation):
            try:
                operation()
            except Exception as error:
                cleanup.append(error)

        if child is not None:
            if not signaled:
                attempt(lambda: api.kill(child._handle))
                def reap():
                    remaining = max(0, int((cleanup_end - clock()) * 1000))
                    require(api.wait(child._handle, remaining))
                attempt(reap)
            for handle in tuple(handles):
                attempt(lambda handle=handle: close(handle))
            try:
                attempt(child._handle.Close)
            finally:
                child._child_created = False
        else:
            for handle in tuple(handles):
                attempt(lambda handle=handle: close(handle))
        if clock() >= cleanup_end:
            cleanup.append(TimeoutError('fixed descendant cleanup deadline exceeded'))
    try:
        if original is not None or cleanup:
            raise CaptureFailure(original, cleanup, code, errors)
        return subprocess.CompletedProcess([], code, text, error_text)
    finally:
        output[:] = b'\0' * len(output)
        errors[:] = b'\0' * len(errors)


def run():
    require(os.name == 'nt' and sys.version_info[:2] == (3, 11) and sys.argv[-1:] != ['--descendant'])
    return _run(Native(), _spawn, time.monotonic)
