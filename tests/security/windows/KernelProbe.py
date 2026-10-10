"""Trusted finite kernel observations. Does not import reviewed project modules."""
import ctypes
import ctypes.wintypes as w
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

K = ctypes.WinDLL('kernel32', use_last_error=True)
A = ctypes.WinDLL('advapi32', use_last_error=True)
P = ctypes.c_void_p
K.GetCurrentProcess.restype = P
K.VirtualAlloc.argtypes = [P, ctypes.c_size_t, w.DWORD, w.DWORD]
K.VirtualAlloc.restype = P
K.VirtualFree.argtypes = [P, ctypes.c_size_t, w.DWORD]
A.OpenProcessToken.argtypes = [P, w.DWORD, ctypes.POINTER(P)]
A.GetTokenInformation.argtypes = [P, ctypes.c_int, P, w.DWORD, ctypes.POINTER(w.DWORD)]
K.CloseHandle.argtypes = [P]
K.QueryInformationJobObject.argtypes = [P, ctypes.c_int, P, w.DWORD, P]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Basic(ctypes.Structure):
    _fields_ = [('process_time', ctypes.c_longlong), ('job_time', ctypes.c_longlong),
                ('flags', w.DWORD), ('min_ws', ctypes.c_size_t), ('max_ws', ctypes.c_size_t),
                ('pids', w.DWORD), ('affinity', ctypes.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]


class Extended(ctypes.Structure):
    _fields_ = [('basic', Basic), ('io', ctypes.c_ulonglong * 6), ('process_mem', ctypes.c_size_t),
                ('job_mem', ctypes.c_size_t), ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]


def denied_write(path):
    try:
        with open(path, 'wb') as stream:
            stream.write(b'containment must reject this write')
    except PermissionError:
        return
    raise AssertionError('protected write was not kernel-denied: ' + str(path))


def token_controls():
    token = P()
    require(A.OpenProcessToken(K.GetCurrentProcess(), 8, ctypes.byref(token)), 'cannot query worker token')
    try:
        for kind, name in ((29, 'AppContainer'), (46, 'LPAC')):
            value, returned = w.DWORD(), w.DWORD()
            require(A.GetTokenInformation(token, kind, ctypes.byref(value), 4, ctypes.byref(returned)),
                    'cannot query ' + name)
            require(value.value == 1, 'worker is not ' + name)
        returned = w.DWORD()
        A.GetTokenInformation(token, 30, None, 0, ctypes.byref(returned))
        data = ctypes.create_string_buffer(returned.value)
        require(A.GetTokenInformation(token, 30, data, len(data), ctypes.byref(returned)),
                'cannot query capabilities')
        require(w.DWORD.from_buffer(data).value == 0, 'worker has unexpected capabilities')
    finally:
        K.CloseHandle(token)


def authority_controls(root, scratch):
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [('length', w.DWORD), ('descriptor', P), ('inherit', w.BOOL)]
    K.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(SecurityAttributes), w.DWORD, w.DWORD, P]
    K.CreateFileW.restype = P
    A.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(P), ctypes.POINTER(w.DWORD)]
    A.SetNamedSecurityInfoW.argtypes = [w.LPWSTR, ctypes.c_int, w.DWORD, P, P, P, P]
    A.SetSecurityInfo.argtypes = [P, ctypes.c_int, w.DWORD, P, P, P, P]
    A.GetSecurityDescriptorDacl.argtypes = [P, ctypes.POINTER(w.BOOL), ctypes.POINTER(P), ctypes.POINTER(w.BOOL)]
    K.LocalFree.argtypes = [P]
    invalid = ctypes.c_void_p(-1).value
    token, returned = P(), w.DWORD()
    require(A.OpenProcessToken(K.GetCurrentProcess(), 8, ctypes.byref(token)), 'cannot query authority token')
    package_data = None
    try:
        A.GetTokenInformation(token, 31, None, 0, ctypes.byref(returned))
        package_data = ctypes.create_string_buffer(returned.value)
        require(A.GetTokenInformation(token, 31, package_data, len(package_data), ctypes.byref(returned)),
                'cannot query package SID')
        package_sid = P.from_buffer(package_data)
        text = w.LPWSTR()
        A.ConvertSidToStringSidW.argtypes = [P, ctypes.POINTER(w.LPWSTR)]
        require(A.ConvertSidToStringSidW(package_sid, ctypes.byref(text)), 'cannot stringify package SID')
        try:
            sid = text.value
        finally:
            K.LocalFree(ctypes.cast(text, P))
        # Ordinary scratch ACL/owner changes must be denied by the kernel, not by a helper.
        path = scratch / 'authority-normal'
        path.write_bytes(b'bounded authority probe')
        descriptor, size = P(), w.DWORD()
        require(A.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;;GA;;;' + sid + ')', 1,
                ctypes.byref(descriptor), ctypes.byref(size)), 'cannot prepare protected DACL probe')
        try:
            present, defaulted, dacl = w.BOOL(), w.BOOL(), P()
            require(A.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                                                ctypes.byref(defaulted)), 'cannot inspect test DACL')
            for info, owner, acl in ((4 | 0x80000000, None, dacl), (1, package_sid, None)):
                result = A.SetNamedSecurityInfoW(str(path), 1, info, owner, None, acl, None)
                require(result == 5, 'child can change scratch DACL/owner; mandatory authority denial unavailable')
            path.unlink()
            # Explicit protected creator DACL must not evade owner/ACL policy or logical quota.
            protected = scratch / 'authority-protected'
            sa = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            handle = K.CreateFileW(str(protected), 0xC0000000, 3, ctypes.byref(sa), 1, 0x80, None)
            if handle == invalid:
                require(ctypes.get_last_error() == 5, 'protected creator rejected without authority denial')
            else:
                try:
                    for access in (0x40000, 0x80000):
                        control = K.CreateFileW(str(protected), access, 3, None, 3, 0x80, None)
                        if control != invalid:
                            K.CloseHandle(control)
                            raise AssertionError('protected creator bypassed mandatory DACL/owner authority denial')
                        require(ctypes.get_last_error() == 5, 'protected object authority failed without kernel denial')
                finally:
                    K.CloseHandle(handle)
                    protected.unlink(missing_ok=True)
        finally:
            K.LocalFree(descriptor)
            path.unlink(missing_ok=True)
        # Raw volume write/quota authority must not be inherited from the elevated setup process.
        raw = '\\\\.\\' + scratch.drive
        handle = K.CreateFileW(raw, 0xC0000000, 3, None, 3, 0, None)
        if handle != invalid:
            K.CloseHandle(handle)
            raise AssertionError('child can open raw volume with write/quota authority')
        require(ctypes.get_last_error() == 5, 'raw-volume authority failed without access denial')
    finally:
        K.CloseHandle(token)


def run():
    require(os.name == 'nt' and sys.version_info[:2] == (3, 11), 'native Windows 3.11 required')
    root, scratch, powershell = map(Path, sys.argv[1:4])
    token_controls()
    if sys.argv[-1] == 'wall-tree':
        subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(30)'],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NO_WINDOW)
        print('trusted wall-tree negative control started', flush=True)
        time.sleep(30)
        raise AssertionError('wall-tree was not terminated')
    keys = {'SYSTEMROOT', 'WINDIR', 'PATH', 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA',
            'TEMP', 'TMP', 'PYTHONIOENCODING', 'REVAYAT_CHROMIUM', 'DOTNET_CLI_HOME', 'XDG_CACHE_HOME'}
    require(set(os.environ) == keys, 'worker inherited or lost an environment variable')
    require('SCIENTIFIC_AMBIENT_CANARY' not in os.environ, 'ambient environment canary leaked')
    for name in ('HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP', 'DOTNET_CLI_HOME', 'XDG_CACHE_HOME'):
        require(Path(os.environ[name]).is_relative_to(scratch), name + ' is not scratch-local')
    require(Path.cwd() == scratch, 'worker CWD is not scratch')
    writable = scratch / 'positive-write'
    writable.write_bytes(b'bounded control')
    require(writable.read_bytes() == b'bounded control', 'scratch write failed')
    A.GetNamedSecurityInfoW.argtypes = [w.LPCWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(P), P, P, P, ctypes.POINTER(P)]
    A.EqualSid.argtypes = [P, P]
    K.LocalFree.argtypes = [P]
    owner, descriptor, token = P(), P(), P()
    user_data = None
    try:
        require(A.GetNamedSecurityInfoW(str(writable), 1, 1, ctypes.byref(owner), None, None, None,
                                       ctypes.byref(descriptor)) == 0, 'cannot inspect scratch file owner')
        require(A.OpenProcessToken(K.GetCurrentProcess(), 8, ctypes.byref(token)), 'cannot query quota user')
        returned = w.DWORD()
        A.GetTokenInformation(token, 1, None, 0, ctypes.byref(returned))
        user_data = ctypes.create_string_buffer(returned.value)
        require(A.GetTokenInformation(token, 1, user_data, len(user_data), ctypes.byref(returned)), 'cannot inspect quota user SID')
        require(A.EqualSid(owner, P.from_buffer(user_data)), 'new child file owner does not match quota user SID')
    finally:
        if descriptor:
            K.LocalFree(descriptor)
        if token:
            K.CloseHandle(token)
    writable.unlink()
    authority_controls(root, scratch)
    for path in (root / 'forbidden-write', Path(sys.executable).parent / 'forbidden-write',
                 powershell.parent / 'forbidden-write', root.parent / 'forbidden-write'):
        denied_write(path)
    try:
        (root.parent / 'host-canary').read_bytes()
    except PermissionError:
        pass
    else:
        raise AssertionError('off-scratch host canary was accessible')
    # Profileless identity must not gain a writable per-app profile via known folders.
    require(not (root.parent / 'profile').exists(), 'unexpected profile storage')
    # Probe own HKCU creation: no registry capability means a kernel denial, not a writable profile.
    import winreg
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, 'Software\\ScientificSandboxProbe')
    except PermissionError:
        pass
    else:
        winreg.CloseKey(key)
        raise AssertionError('LPAC registry write was permitted')

    for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
        for kind, port in ((socket.SOCK_STREAM, int(sys.argv[4])), (socket.SOCK_DGRAM, int(sys.argv[5]))):
            with socket.socket(family, kind) as client:
                client.settimeout(1)
                try:
                    if kind == socket.SOCK_STREAM:
                        client.connect((address, port))
                    else:
                        client.sendto(b'bounded dummy probe', (address, port))
                except OSError as error:
                    require(error.winerror == 10013, 'network failed without kernel access denial: ' + str(error.winerror))
                else:
                    raise AssertionError('LPAC network operation was permitted')

    limits = Extended()
    require(K.QueryInformationJobObject(None, 9, ctypes.byref(limits), ctypes.sizeof(limits), None),
            'cannot query effective child job')
    require(limits.basic.flags & (0x2000 | 0x200 | 0x100 | 8 | 4) == (0x2000 | 0x200 | 0x100 | 8 | 4),
            'effective mandatory job flags missing')
    require(not limits.basic.flags & (0x800 | 0x1000), 'job permits breakaway')
    require(limits.basic.pids == 8 and limits.process_mem == 384 * 1024**2 and limits.job_mem == 512 * 1024**2,
            'effective PID/memory bounds differ')
    cpu = (w.DWORD * 2)()
    require(K.QueryInformationJobObject(None, 15, cpu, ctypes.sizeof(cpu), None), 'cannot query CPU limit')
    require(tuple(cpu) == (5, 1000), 'effective hard CPU cap differs')
    allocation = K.VirtualAlloc(None, 385 * 1024**2, 0x3000, 4)
    if allocation:
        K.VirtualFree(allocation, 0, 0x8000)
        raise AssertionError('kernel committed-memory ceiling did not reject allocation')
    require(ctypes.get_last_error() in (8, 1455, 1816), 'allocation failed for unrecognized reason')
    children = []
    try:
        for _ in range(7):
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            children.append(child)
        try:
            extra = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'raise SystemExit(0)'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
        except OSError as error:
            require(error.winerror in (1816, 5, 8), 'PID limit failed for unrecognized reason')
        else:
            children.append(extra)
            require(extra.wait(timeout=3) != 0, 'kernel active-PID ceiling permitted extra child')
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)

    # Same hard quota bounds both aggregate streams and individual sparse logical lengths.
    K.DeviceIoControl.argtypes = [P, w.DWORD, P, w.DWORD, P, w.DWORD, ctypes.POINTER(w.DWORD), P]
    import msvcrt
    for sparse in (False, True):
        path = scratch / ('quota-sparse' if sparse else 'quota-ordinary')
        try:
            with path.open('w+b') as stream:
                if sparse:
                    returned = w.DWORD()
                    require(K.DeviceIoControl(msvcrt.get_osfhandle(stream.fileno()), 0x900C4, None, 0,
                                              None, 0, ctypes.byref(returned), None), 'cannot mark sparse quota probe')
                try:
                    stream.truncate(16 * 1024**2 + 1)
                except OSError as error:
                    require(error.winerror in (112, 39, 1816), 'quota denial was not a space/quota error')
                else:
                    raise AssertionError('NTFS hard quota failed to bound logical file length')
        finally:
            path.unlink(missing_ok=True)
    aggregate = []
    try:
        for index in range(2):
            path = scratch / ('quota-aggregate-' + str(index))
            aggregate.append(path)
            with path.open('w+b') as stream:
                returned = w.DWORD()
                require(K.DeviceIoControl(msvcrt.get_osfhandle(stream.fileno()), 0x900C4, None, 0,
                                          None, 0, ctypes.byref(returned), None), 'cannot mark aggregate sparse probe')
                try:
                    stream.truncate(9 * 1024**2)
                except OSError as error:
                    require(index == 1 and error.winerror in (112, 39, 1816), 'aggregate quota failed before expected bound')
                else:
                    require(index == 0, 'two individually permitted files exceeded aggregate quota')
    finally:
        for path in aggregate:
            path.unlink(missing_ok=True)
    print(json.dumps({'phase': 'preflight', 'status': 'passed', 'lpac': True, 'capabilities': 0,
                      'cpu_rate': 1000, 'pids': 8, 'process_memory_mib': 384, 'job_memory_mib': 512,
                      'quota_bytes': 16 * 1024**2, 'python': sys.version.split()[0]}, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        run()
    except Exception as error:
        print(json.dumps({'phase': 'preflight', 'status': 'failed', 'error': str(error)}, sort_keys=True),
              file=sys.stderr, flush=True)
        raise SystemExit(1)
