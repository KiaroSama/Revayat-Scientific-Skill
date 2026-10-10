"""Trusted finite kernel observations. Does not import reviewed project modules."""
import ctypes
import ctypes.wintypes as w
import errno
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


class SidAttributes(ctypes.Structure):
    _fields_ = [('sid', P), ('attributes', w.DWORD)]


class Groups(ctypes.Structure):
    _fields_ = [('count', w.DWORD), ('first', SidAttributes)]


class Luid(ctypes.Structure):
    _fields_ = [('low', w.DWORD), ('high', w.LONG)]


class Privilege(ctypes.Structure):
    _fields_ = [('luid', Luid), ('attributes', w.DWORD)]


def token_data(token, kind):
    returned = w.DWORD()
    A.GetTokenInformation(token, kind, None, 0, ctypes.byref(returned))
    require(0 < returned.value <= 65536, 'unexpected token information size')
    data = ctypes.create_string_buffer(returned.value)
    require(A.GetTokenInformation(token, kind, data, len(data), ctypes.byref(returned)), 'token information unavailable')
    return data


def sid_text(sid):
    A.ConvertSidToStringSidW.argtypes = [P, ctypes.POINTER(w.LPWSTR)]
    K.LocalFree.argtypes = [P]
    text = w.LPWSTR()
    require(A.ConvertSidToStringSidW(sid, ctypes.byref(text)), 'cannot stringify token SID')
    try:
        return text.value
    finally:
        K.LocalFree(ctypes.cast(text, P))


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
        A.LookupPrivilegeValueW.argtypes = [w.LPCWSTR, w.LPCWSTR, ctypes.POINTER(Luid)]
        traverse = Luid()
        require(A.LookupPrivilegeValueW(None, 'SeChangeNotifyPrivilege', ctypes.byref(traverse)), 'cannot identify traversal privilege')
        privileges = token_data(token, 3)
        count = w.DWORD.from_buffer(privileges).value
        require(count <= 128 and 4 + count * ctypes.sizeof(Privilege) <= len(privileges), 'invalid token privilege buffer')
        for index in range(count):
            item = Privilege.from_buffer(privileges, 4 + index * ctypes.sizeof(Privilege))
            require((item.luid.low, item.luid.high) == (traverse.low, traverse.high),
                    'dangerous privilege remains present in worker token')
        user_data = token_data(token, 1)
        package_data = token_data(token, 31)
        require(len(user_data) >= ctypes.sizeof(P) and len(package_data) >= ctypes.sizeof(P), 'truncated token SID pointers')
        owners = {sid_text(P.from_buffer(user_data)), sid_text(P.from_buffer(package_data))}
        groups = token_data(token, 2)
        count = w.DWORD.from_buffer(groups).value
        require(count <= 256 and Groups.first.offset + count * ctypes.sizeof(SidAttributes) <= len(groups),
                'invalid token groups buffer')
        for index in range(count):
            item = SidAttributes.from_buffer(groups, Groups.first.offset + index * ctypes.sizeof(SidAttributes))
            if item.attributes & 8:
                owners.add(sid_text(item.sid))
        require(len(owners) <= 16, 'unbounded assignable owner set')
        return sorted(owners)
    finally:
        K.CloseHandle(token)


def native_eof_quota(handle, sparse):
    K.DeviceIoControl.argtypes = [P, w.DWORD, P, w.DWORD, P, w.DWORD, ctypes.POINTER(w.DWORD), P]
    K.SetFilePointerEx.argtypes = [P, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), w.DWORD]
    K.SetEndOfFile.argtypes = [P]
    if sparse:
        returned = w.DWORD()
        require(K.DeviceIoControl(handle, 0x900C4, None, 0, None, 0, ctypes.byref(returned), None),
                'native sparse control failed')
    position = ctypes.c_longlong()
    require(K.SetFilePointerEx(handle, 1024, ctypes.byref(position), 0), 'native small EOF seek failed')
    require(K.SetEndOfFile(handle), 'native permitted EOF control failed')
    require(K.SetFilePointerEx(handle, 16 * 1024**2 + 1, ctypes.byref(position), 0), 'native excessive EOF seek failed')
    require(not K.SetEndOfFile(handle), 'native logical EOF limit was not enforced')
    require(ctypes.get_last_error() in (112, 39, 1816), 'native EOF rejection was not a quota/space denial')
    require(K.SetFilePointerEx(handle, 0, ctypes.byref(position), 0) and K.SetEndOfFile(handle),
            'native quota fixture could not be reset')


def authority_controls(root, scratch, owners):
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
            # Private creator DACL may change its own scratch file, never protected roots or quotas.
            for protected_root in (root, Path(sys.executable).parent, Path(sys.executable),
                                   Path(sys.argv[3]).parent, root.parent / 'host-canary', scratch):
                for info, owner, acl in ((4 | 0x80000000, None, dacl), (1, package_sid, None)):
                    require(A.SetNamedSecurityInfoW(str(protected_root), 1, info, owner, None, acl, None) == 5,
                            'protected root DACL/owner authority was not denied')
            protected = scratch / 'authority-protected'
            sa = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            handle = K.CreateFileW(str(protected), 0xC00C0000, 3, ctypes.byref(sa), 1, 0x80, None)
            require(handle != invalid, 'private protected creator positive control failed')
            try:
                require(A.SetSecurityInfo(handle, 1, 4 | 0x80000000, None, None, dacl, None) == 0,
                        'private scratch DACL control failed')
                native_eof_quota(handle, sparse=False)
                native_eof_quota(handle, sparse=True)
                A.ConvertStringSidToSidW.argtypes = [w.LPCWSTR, ctypes.POINTER(P)]
                for owner_name in owners:
                    owner_sid = P()
                    require(A.ConvertStringSidToSidW(owner_name, ctypes.byref(owner_sid)), 'cannot prepare finite owner SID')
                    try:
                        assigned = A.SetSecurityInfo(handle, 1, 1, owner_sid, None, None, None)
                        if assigned == 0:
                            native_eof_quota(handle, sparse=True)
                        else:
                            require(assigned in (5, 1307), 'finite owner assignment failed unexpectedly')
                    finally:
                        K.LocalFree(owner_sid)
                # Outside identity must not be assignable even with WRITE_OWNER on an own file.
                outsider = P()
                require(A.ConvertStringSidToSidW('S-1-5-21-101-202-303-404', ctypes.byref(outsider)), 'outside-owner probe SID invalid')
                try:
                    require(A.SetSecurityInfo(handle, 1, 1, outsider, None, None, None) in (5, 1307),
                            'private creator escaped finite quota owner identities')
                finally:
                    K.LocalFree(outsider)
                denied_write(root / 'protected-creator-escape')
            finally:
                K.CloseHandle(handle)
                protected.unlink(missing_ok=True)
        finally:
            K.LocalFree(descriptor)
            path.unlink(missing_ok=True)
        # Raw volume write/quota authority must not be inherited from the elevated setup process.
        raw = '\\\\.\\' + scratch.drive
        for access in (0xC0000000, 0x40000000, 2):
            handle = K.CreateFileW(raw, access, 3, None, 3, 0, None)
            if handle != invalid:
                K.CloseHandle(handle)
                raise AssertionError('child can open raw volume with write/quota authority')
            require(ctypes.get_last_error() == 5, 'raw-volume authority failed without access denial')
    finally:
        K.CloseHandle(token)


def run():
    require(os.name == 'nt' and sys.version_info[:2] == (3, 11), 'native Windows 3.11 required')
    root, scratch, powershell = map(Path, sys.argv[1:4])
    owners = token_controls()
    if sys.argv[-1] == 'token-child':
        print(json.dumps({'phase': 'token-child', 'owners': owners}, sort_keys=True), flush=True)
        return
    if sys.argv[-1] == 'wall-tree':
        subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(30)'],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NO_WINDOW)
        print('trusted wall-tree negative control started', flush=True)
        time.sleep(30)
        raise AssertionError('wall-tree was not terminated')
    keys = {'SYSTEMROOT', 'WINDIR', 'PATH', 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA',
            'TEMP', 'TMP', 'PYTHONIOENCODING', 'REVAYAT_CHROMIUM', 'DOTNET_CLI_HOME', 'XDG_CACHE_HOME'}
    K.GetDiskFreeSpaceExW.argtypes = [w.LPCWSTR, ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong)]
    available, total, free = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
    require(K.GetDiskFreeSpaceExW(str(scratch), ctypes.byref(available), ctypes.byref(total), ctypes.byref(free)),
            'cannot observe fixed scratch filesystem capacity')
    require(0 < total.value <= 128 * 1024**2, 'scratch caller-visible space exceeds assigned ceiling')
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
    child_token = subprocess.run([sys.executable, '-I', '-B', '-X', 'utf8', str(Path(__file__)),
                                  str(root), str(scratch), str(powershell), sys.argv[4], sys.argv[5], 'token-child'],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8',
                                 timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
    require(child_token.returncode == 0 and len(child_token.stdout) < 65536, 'descendant token verification failed')
    require(json.loads(child_token.stdout)['owners'] == owners, 'descendant assignable owners/privileges changed')
    authority_controls(root, scratch, owners)
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
                native_eof_quota(msvcrt.get_osfhandle(stream.fileno()), sparse=sparse)
                if sparse:
                    returned = w.DWORD()
                    require(K.DeviceIoControl(msvcrt.get_osfhandle(stream.fileno()), 0x900C4, None, 0,
                                              None, 0, ctypes.byref(returned), None), 'cannot mark sparse quota probe')
                try:
                    stream.truncate(16 * 1024**2 + 1)
                except OSError as error:
                    require(error.errno == errno.ENOSPC, 'quota denial was not a space/quota error')
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
                    require(index == 1 and error.errno == errno.ENOSPC, 'aggregate quota failed before expected bound')
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
