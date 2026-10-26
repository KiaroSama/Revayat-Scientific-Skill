"""Fixed trusted registry authority inventory; never imports reviewed modules."""
import sys

try:
    phase = 'import-ctypes'
    import ctypes
    phase = 'import-ctypes-wintypes'
    import ctypes.wintypes as w
    phase = 'import-json'
    import json
    phase = 'import-os'
    import os
    phase = 'import-pathlib'
    from pathlib import Path
    phase = 'import-runpy'
    import runpy
    phase = 'import-subprocess'
    import subprocess
    phase = 'import-time'
    import time
except Exception as error:
    category = 'import' if isinstance(error, ImportError) else 'native' if isinstance(error, OSError) else 'other'
    role = 'descendant' if sys.argv[1:] == ['--descendant'] else 'primary'
    try:
        sys.stderr.write('REGISTRY_AUTHORITY_FAILURE role=' + role + ' child_exit=none errors=' + phase + ':' + category + '\n')
        sys.stderr.flush()
    except Exception:
        pass
    raise SystemExit(1) from None

P = ctypes.c_void_p
KEY = r'\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide'
DENIED = 0xC0000022
PHASE = 'start'
PHASES = ('start', 'token', 'root', 'mutation', 'inventory', 'identity', 'close', 'descendant', 'report',
          'import-ctypes', 'import-ctypes-wintypes', 'import-json', 'import-os', 'import-pathlib',
          'import-runpy', 'import-subprocess', 'import-time')
KINDS = ('control', 'timeout', 'decode', 'encode', 'native', 'transport', 'other', 'cleanup', 'import')


class Failure(Exception):
    def __init__(self, events, child_exit=None, original=None):
        super().__init__('fixed registry authority failure')
        self.events, self.child_exit, self.original = tuple(events), child_exit, original


def failure(error, phase):
    if isinstance(error, Failure):
        return error
    if isinstance(error, ExceptionGroup):
        parts = [failure(item, phase) for item in error.exceptions]
        return Failure(tuple(event for part in parts for event in part.events)[:8],
                       next((part.child_exit for part in parts if part.child_exit is not None), None), error)
    kind = ('timeout' if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else
            'decode' if isinstance(error, UnicodeDecodeError) else 'encode' if isinstance(error, UnicodeEncodeError) else
            'native' if isinstance(error, OSError) else 'control' if isinstance(error, RuntimeError) else 'other')
    return Failure(((phase, kind),), original=error)


def failure_wire(error, role):
    error = failure(error, PHASE)
    require(role in ('primary', 'descendant') and 1 <= len(error.events) <= 8)
    require(all(phase in PHASES and kind in KINDS for phase, kind in error.events))
    code = 'none' if error.child_exit is None else format(error.child_exit & 0xFFFFFFFF, '08X')
    return ('REGISTRY_AUTHORITY_FAILURE role=' + role + ' child_exit=' + code + ' errors=' +
            ','.join(phase + ':' + kind for phase, kind in error.events) + '\n')


def descendant_result(child):
    if child.returncode != 0:
        import re
        pattern = r'REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=([a-z:,\-]+)\n'
        match = re.fullmatch(pattern, child.stderr) if len(child.stderr) <= 512 else None
        events = [('descendant', 'transport')]
        if match:
            candidate = tuple(tuple(item.split(':')) for item in match[1].split(','))
            if 1 <= len(candidate) <= 7 and all(len(item) == 2 and item[0] in PHASES and item[1] in KINDS for item in candidate):
                events.extend(candidate)
        raise Failure(events, child.returncode)
    if child.stderr or len(child.stdout) > 1024:
        raise Failure((('descendant', 'transport'),), child.returncode)
    return child.stdout


class Unicode(ctypes.Structure):
    _fields_ = [('length', w.USHORT), ('maximum', w.USHORT), ('buffer', P)]


class Attributes(ctypes.Structure):
    _fields_ = [('length', w.ULONG), ('root', P), ('name', P), ('flags', w.ULONG),
                ('descriptor', P), ('qos', P)]


def require(value):
    if not value:
        raise Failure(((PHASE, 'control'),))


def finish(primary, actions):
    errors = [] if primary is None else [failure(primary, PHASE)]
    for action in actions:
        try:
            action()
        except Exception as error:
            errors.append(Failure((('close', 'cleanup'),), original=error))
    if errors:
        raise failure(ExceptionGroup('fixed registry authority operation/cleanup failed', errors), PHASE)


def require_token_fields(kind, elevated, filtered):
    require(kind == 1 and elevated == 0 and filtered == 1)


def require_denied(status, handle):
    require(status == DENIED and not handle)


def require_basic(status, returned, attributes, granted):
    require(status == 0 and returned == 56 and attributes == 0 and granted == 0x20019)


def read_identity(status, returned, data, expected_bytes):
    require(status == 0 and 4 <= returned <= 4096 and returned <= len(data))
    count = int.from_bytes(data[:4], 'little')
    require(count == expected_bytes and count % 2 == 0 and count <= returned - 4)
    value = data[4:4 + count].decode('utf-16-le', errors='strict')
    require('\x00' not in value)
    return value


def token_controls(trusted):
    token = P()
    a, k = trusted['A'], trusted['K']
    require(a.OpenProcessToken(k.GetCurrentProcess(), 8, ctypes.byref(token)))
    primary = None
    try:
        values = []
        for kind in (8, 20, 21):
            value, returned = w.DWORD(), w.DWORD()
            require(a.GetTokenInformation(token, kind, ctypes.byref(value), 4, ctypes.byref(returned)))
            require(returned.value == 4)
            values.append(value.value)
        require_token_fields(*values)
        require(trusted['lpac_enabled'](token))
        data = trusted['token_data'](token, 29)
        require(len(data) == 4 and w.DWORD.from_buffer(data).value == 1)
        data = trusted['token_data'](token, 30)
        require(w.DWORD.from_buffer(data).value == 0)
        a.LookupPrivilegeValueW.argtypes = [w.LPCWSTR, w.LPCWSTR, ctypes.POINTER(trusted['Luid'])]
        traverse = trusted['Luid']()
        require(a.LookupPrivilegeValueW(None, 'SeChangeNotifyPrivilege', ctypes.byref(traverse)))
        data = trusted['token_data'](token, 3)
        count, stride = w.DWORD.from_buffer(data).value, ctypes.sizeof(trusted['Privilege'])
        require(count <= 128 and 4 + count * stride <= len(data))
        for index in range(count):
            item = trusted['Privilege'].from_buffer(data, 4 + index * stride)
            require((item.luid.low, item.luid.high) == (traverse.low, traverse.high))
        data = trusted['token_data'](token, 2)
        count, offset = w.DWORD.from_buffer(data).value, trusted['Groups'].first.offset
        stride = ctypes.sizeof(trusted['SidAttributes'])
        require(count <= 256 and offset + count * stride <= len(data))
        for index in range(count):
            item = trusted['SidAttributes'].from_buffer(data, offset + index * stride)
            if trusted['sid_text'](item.sid) == 'S-1-5-32-544':
                require(not item.attributes & (8 | 4 | 2) and item.attributes & 16)
    except Exception as failure:
        primary = failure
    finally:
        finish(primary, [lambda: require(k.CloseHandle(token))])


def controls():
    global PHASE
    PHASE = 'token'
    require(os.name == 'nt' and ctypes.sizeof(P) == 8 and sys.version_info[:2] == (3, 11))
    require(ctypes.sizeof(Unicode) == 16 and ctypes.sizeof(Attributes) == 48)
    trusted = runpy.run_path(str(Path(__file__).with_name('KernelProbe.py')))
    trusted['require_detached_stdio']()
    token_controls(trusted)
    n = ctypes.WinDLL('ntdll')
    a = ctypes.WinDLL('advapi32', use_last_error=True)
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    n.NtOpenKeyEx.argtypes = [ctypes.POINTER(P), w.ULONG, ctypes.POINTER(Attributes), w.ULONG]
    n.NtOpenKeyEx.restype = w.LONG
    n.NtClose.argtypes = [P]
    n.NtClose.restype = w.LONG
    n.NtQueryObject.argtypes = [P, ctypes.c_int, P, w.ULONG, ctypes.POINTER(w.ULONG)]
    n.NtQueryObject.restype = w.LONG
    n.NtQueryKey.argtypes = [P, ctypes.c_int, P, w.ULONG, ctypes.POINTER(w.ULONG)]
    n.NtQueryKey.restype = w.LONG
    a.RegEnumKeyExW.argtypes = [P, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD), P, P, P, P]
    a.RegQueryInfoKeyW.argtypes = [P, P, P, P, ctypes.POINTER(w.DWORD), P, P,
                                 ctypes.POINTER(w.DWORD), P, P, P, ctypes.POINTER(ctypes.c_longlong)]
    k.IsProcessInJob.argtypes = [P, P, ctypes.POINTER(w.BOOL)]
    k.CompareStringOrdinal.argtypes = [w.LPCWSTR, ctypes.c_int, w.LPCWSTR, ctypes.c_int, w.BOOL]
    k.GetCurrentProcess.restype = P

    def same_name(first, second):
        result = k.CompareStringOrdinal(first, -1, second, -1, True)
        require(result in (1, 2, 3))
        return result == 2
    in_job = w.BOOL()
    require(k.IsProcessInJob(k.GetCurrentProcess(), None, ctypes.byref(in_job)) and in_job.value)
    started = time.monotonic()

    def deadline():
        require(time.monotonic() - started < 8)

    def open_key(name, access, root=None):
        deadline()
        encoded = name.encode('utf-16-le', errors='strict')
        require(0 < len(encoded) <= 1024 and '\x00' not in name)
        buffer = ctypes.create_string_buffer(encoded + b'\0\0')
        text = Unicode(len(encoded), len(encoded) + 2, ctypes.addressof(buffer))
        attrs = Attributes(ctypes.sizeof(Attributes), root, ctypes.addressof(text), 0x1040, None, None)
        handle = P()
        status = n.NtOpenKeyEx(ctypes.byref(handle), access, ctypes.byref(attrs), 0) & 0xFFFFFFFF
        return status, handle

    def valid(handle):
        return handle.value and 0 < handle.value < 0x7FFFFFFFFFFFFFFF and not 0x80000000 <= handle.value <= 0x800000FF

    def close(handle):
        if valid(handle):
            require(n.NtClose(handle) == 0)

    def qualify(handle, identity):
        global PHASE
        PHASE = 'identity'
        require(valid(handle))
        basic, returned = ctypes.create_string_buffer(56), w.ULONG()
        status = n.NtQueryObject(handle, 0, basic, 56, ctypes.byref(returned))
        require_basic(status, returned.value, w.ULONG.from_buffer(basic, 0).value, w.ULONG.from_buffer(basic, 4).value)
        data = ctypes.create_string_buffer(4096)
        status = n.NtQueryKey(handle, 3, data, 4096, ctypes.byref(returned))
        actual = read_identity(status, returned.value, data.raw, len(identity.encode('utf-16-le', errors='strict')))
        require(same_name(actual, identity))

    def counts(handle):
        keys, values, modified = w.DWORD(), w.DWORD(), ctypes.c_longlong()
        require(a.RegQueryInfoKeyW(handle, None, None, None, ctypes.byref(keys), None, None,
                                  ctypes.byref(values), None, None, None, ctypes.byref(modified)) == 0)
        require(keys.value <= 256 and values.value <= 32)
        return keys.value, values.value, modified.value

    PHASE = 'root'
    status, root = open_key(KEY, 0x20019)
    primary = None
    try:
        require(status == 0)
        qualify(root, KEY)
        PHASE = 'mutation'
        for access in (2, 4, 0x10000, 0x40000, 0x80000):
            status, denied = open_key(KEY, access)
            error = None
            try:
                require_denied(status, denied.value)
            except Exception as failure:
                error = failure
            finish(error, [lambda: close(denied)])
        before = counts(root)
        names, accessible = [], 0
        for index in range(257):
            PHASE = 'inventory'
            deadline()
            name, length = ctypes.create_unicode_buffer(512), w.DWORD(512)
            status = a.RegEnumKeyExW(root, index, name, ctypes.byref(length), None, None, None, None)
            if status == 259:
                require(index == before[0])
                break
            require(status == 0 and index < 256 and 0 < length.value < 512 and length.value == len(name.value))
            require('\\' not in name.value and '/' not in name.value and all(not same_name(name.value, prior) for prior in names))
            names.append(name.value)
            status, child = open_key(name.value, 0x20019, root)
            error = None
            try:
                require(status == 0 or status == DENIED)
                if status == 0:
                    qualify(child, KEY + '\\' + name.value)
                    accessible += 1
                else:
                    require(not child.value)
            except Exception as failure:
                error = failure
            finish(error, [lambda: close(child)])
        PHASE = 'inventory'
        require(counts(root) == before and len(names) == before[0])
        PHASE = 'token'
        token_controls(trusted)
        deadline()
        return {'accessible': accessible, 'capabilities': 0, 'granted_access': 0x20019,
                'lpac': True, 'mutation_denied': True, 'no_reparse': True, 'read': True,
                'read_surface_approved': False, 'restricted': True, 'subkeys': len(names), 'version': 1, 'x64': True}
    except Exception as failure:
        primary = failure
    finally:
        finish(primary, [lambda: close(root)])


def main():
    global PHASE
    require(sys.argv[1:] in ([], ['--descendant']))
    result = controls()
    result['role'] = 'descendant' if sys.argv[1:] else 'primary'
    own = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
    if sys.argv[1:]:
        PHASE = 'report'
        sys.stdout.write(own)
        sys.stdout.flush()
        return
    PHASE = 'descendant'
    child = subprocess.run([sys.executable, '-I', '-B', '-X', 'utf8', str(Path(__file__).resolve()), '--descendant'],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8', errors='strict',
                           timeout=5, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,
                           close_fds=True, env=dict(os.environ), cwd=str(Path(sys.executable).parent))
    complete_descendant(child, result, sys.stdout)


def complete_descendant(child, result, output_stream):
    global PHASE
    PHASE = 'descendant'
    try:
        descendant = descendant_result(child)
        record = json.loads(descendant)
        require(type(record) is dict and record.get('role') == 'descendant' and record.keys() == result.keys())
        own = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
        output = own + descendant
        require(len(output.encode('utf-8')) <= 2048 and output.isascii())
        PHASE = 'report'
        output_stream.write(output)
        output_stream.flush()
    except Exception as error:
        safe = failure(error, PHASE)
        raise Failure(safe.events, child.returncode, safe) from None


def entry(operation, report, role):
    try:
        operation()
        return 0
    except Exception as error:
        safe = failure(error, PHASE)
        try:
            report(failure_wire(safe, role))
        except Exception as reporting:
            # Reporting cannot recover a broken stream; preserve both privately and fail.
            raise Failure(safe.events + (('report', 'other'),), safe.child_exit, (safe, reporting)) from None
        return 1


if __name__ == '__main__':
    def report_failure(text):
        sys.stderr.write(text)
        sys.stderr.flush()
    try:
        code = entry(main, report_failure, 'descendant' if sys.argv[1:] == ['--descendant'] else 'primary')
    except Exception:
        code = 1
    raise SystemExit(code)
