"""Fixed private-file policy, handle-bound authority acquisition and identity-bound cleanup."""
import contextlib
import ctypes
import ctypes.wintypes as w
import sys

P = ctypes.c_void_p


class SecurityAttributes(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('descriptor', P), ('inherit', ctypes.c_int32)]


class FileIdentity(ctypes.Structure):
    _fields_ = [('volume', ctypes.c_uint64), ('identifier', ctypes.c_ubyte * 16)]


class FileAttributes(ctypes.Structure):
    _fields_ = [('attributes', ctypes.c_uint32), ('tag', ctypes.c_uint32)]


def prepare():
    require(ctypes.sizeof(P) == 8 and ctypes.sizeof(FileIdentity) == 24 and
            ctypes.sizeof(FileAttributes) == 8, 'private creator requires Windows x64 ABI')
    K.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, P, w.DWORD, w.DWORD, P]
    K.CreateFileW.restype = P
    K.ReOpenFile.argtypes = [P, w.DWORD, w.DWORD, w.DWORD]
    K.ReOpenFile.restype = P
    K.GetFileInformationByHandleEx.argtypes = [P, ctypes.c_int, P, w.DWORD]
    K.GetFinalPathNameByHandleW.argtypes = [P, w.LPWSTR, w.DWORD, w.DWORD]
    K.GetFinalPathNameByHandleW.restype = w.DWORD
    K.GetFileType.argtypes = [P]
    K.GetFileType.restype = w.DWORD
    K.GetFileAttributesW.argtypes = [w.LPCWSTR]
    K.GetFileAttributesW.restype = w.DWORD
    K.SetFileInformationByHandle.argtypes = [P, ctypes.c_int, P, w.DWORD]
    native = ctypes.WinDLL('ntdll')
    native.NtQueryObject.argtypes = [P, ctypes.c_int, P, w.ULONG, ctypes.POINTER(w.ULONG)]
    native.NtQueryObject.restype = w.LONG
    return native


def native_error():
    code = ctypes.get_last_error()
    error = OSError('private protected creator operation failed')
    error.winerror = code
    return error


def acquired(handle):
    if handle in (None, P(-1).value):
        raise native_error()
    return handle


def private_creator(path, security):
    return acquired(K.CreateFileW(str(path), 0xC0000000, 3, security, 1, 0x80, None))


@contextlib.contextmanager
def private_policy(token, package):
    user_data = token_data(token, 1)
    require(len(user_data) >= ctypes.sizeof(P), 'private creator user SID is truncated')
    user = P.from_buffer(user_data)
    require(user.value, 'private creator user SID is absent')
    text = 'D:P(A;;GA;;;' + sid_text(user) + ')(A;;GA;;;' + package + ')'
    descriptor, size = P(), w.DWORD()
    try:
        require(A.ConvertStringSecurityDescriptorToSecurityDescriptorW(text, 1, ctypes.byref(descriptor),
                ctypes.byref(size)), 'cannot prepare private creator policy')
        present, defaulted, dacl = w.BOOL(), w.BOOL(), P()
        require(A.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                ctypes.byref(defaulted)) and present.value and dacl.value, 'private creator DACL is absent')
        yield descriptor, dacl
    finally:
        primary = sys.exception()
        try:
            if descriptor:
                require(not K.LocalFree(descriptor), 'private creator policy did not release')
        except Exception as cleanup:
            if primary:
                raise ExceptionGroup('private creator operation and policy cleanup failed', [primary, cleanup])
            raise


class PrivateFile:
    def __init__(self, scratch, security):
        self.scratch = scratch
        self.parent = scratch / 'private-creator'
        self.path, self.security = self.parent / 'authority-protected', security
        self.root = self.directory = self.original = self.control = self.pin = None
        self.identity = self.expected_name = None
        self.native = prepare()
        self.ready = False

    def _identity(self, handle, directory=False):
        require(K.GetFileType(handle) == 1, 'private creator object is not a disk file')
        attributes, identity = FileAttributes(), FileIdentity()
        if not K.GetFileInformationByHandleEx(handle, 9, ctypes.byref(attributes), 8):
            raise native_error()
        require(attributes.attributes & 0x410 == (0x10 if directory else 0) and attributes.tag == 0,
                'private creator object is not plain')
        if not K.GetFileInformationByHandleEx(handle, 18, ctypes.byref(identity), 24):
            raise native_error()
        return identity.volume, bytes(identity.identifier)

    def _name(self, handle):
        output = ctypes.create_unicode_buffer(512)
        count = K.GetFinalPathNameByHandleW(handle, output, 512, 2)
        if count == 0:
            raise native_error()
        require(0 < count < 512 and len(output.value) == count, 'private creator name exceeds fixed bounds')
        return output.value

    def _bind(self, handle):
        require(self._identity(handle) == self.identity and self._name(handle) == self.expected_name,
                'private creator file binding changed')

    def _grant(self, handle, expected):
        information = (ctypes.c_uint32 * 14)()
        returned = w.ULONG()
        status = self.native.NtQueryObject(handle, 0, information, 56, ctypes.byref(returned))
        require(status == 0 and returned.value == 56 and information[0] & 2 == 0 and
                information[1] == expected, 'private creator actual handle authority differs')

    def _absent(self):
        attributes = K.GetFileAttributesW(str(self.path))
        code = ctypes.get_last_error() if attributes == 0xFFFFFFFF else None
        require(attributes == 0xFFFFFFFF and code == 2, 'private creator fixed leaf is not absent')

    def __enter__(self):
        try:
            self._absent()
            self.root = acquired(K.CreateFileW(str(self.scratch), 0x80, 7, None, 3, 0x02200000, None))
            self.root_identity = self._identity(self.root, directory=True)
            root_name = self._name(self.root)
            prefix = '\\Device\\HarddiskVolume'
            digits = root_name[len(prefix):-1]
            require(root_name.startswith(prefix) and root_name.endswith('\\') and
                    1 <= len(digits) <= 20 and all('0' <= c <= '9' for c in digits),
                    'private creator scratch name differs')
            self.directory = acquired(K.CreateFileW(str(self.parent), 0x80, 3, None, 3, 0x02200000, None))
            parent_identity = self._identity(self.directory, directory=True)
            require(parent_identity[0] == self.root_identity[0] and
                    self._name(self.directory) == root_name + 'private-creator',
                    'private creator parent binding differs')
            self.expected_name = root_name + 'private-creator\\authority-protected'
            self.ready = True
            return self
        except Exception as error:
            self.__exit__(type(error), error, error.__traceback__)
            raise

    def create(self):
        require(self.ready and self.original is None, 'private creator creation is not available')
        self.original = private_creator(self.path, self.security)

    def bind_original(self):
        require(self.ready and self.original is not None and self.pin is None,
                'private creator original binding is not available')
        self.identity = self._identity(self.original)
        require(self.identity[0] == self.root_identity[0] and self._name(self.original) == self.expected_name,
                'private creator original identity differs')
        self._grant(self.original, 0x12019F)
        self.pin = acquired(K.CreateFileW(str(self.path), 0x80, 7, None, 3, 0x00200000, None))
        self._bind(self.pin)

    def reopen(self):
        require(self.original is not None and self.pin is not None and self.control is None,
                'private creator reopen is not available')
        self.control = acquired(K.ReOpenFile(self.original, 0xC00C0000, 3, 0))

    def qualify(self):
        require(self.control is not None, 'private creator control handle is absent')
        self._bind(self.original)
        self._bind(self.control)
        self._bind(self.pin)
        self._grant(self.control, 0x1E019F)
        return self.control

    def __exit__(self, kind, original, trace):
        failures = []
        def attempt(action):
            try:
                action()
                return True
            except Exception as error:
                failures.append(error)
                return False
        def close(handle):
            if not K.CloseHandle(handle):
                raise native_error()
        bound = self.pin is not None and self.identity is not None
        if bound:
            bound = attempt(lambda: self._bind(self.pin))
        closed = True
        for name in ('original', 'control'):
            handle = getattr(self, name)
            setattr(self, name, None)
            if handle is not None:
                closed = attempt(lambda: close(handle)) and closed
        removed = False
        if bound and closed:
            deletion = None
            try:
                deletion = acquired(K.CreateFileW(str(self.path), 0x10080, 3, None, 3, 0x00200000, None))
                self._bind(deletion)
                self._bind(self.pin)
                flag = ctypes.c_ubyte(1)
                if not K.SetFileInformationByHandle(deletion, 4, ctypes.byref(flag), 1):
                    raise native_error()
                removed = True
            except Exception as error:
                failures.append(error)
            finally:
                if deletion is not None:
                    attempt(lambda: close(deletion))
        for name in ('pin', 'directory', 'root'):
            handle = getattr(self, name)
            setattr(self, name, None)
            if handle is not None:
                attempt(lambda: close(handle))
        if removed:
            attempt(self._absent)
        self.ready = False
        if failures:
            raise ExceptionGroup('private creator operation and cleanup failed',
                                 ([original] if original is not None else []) + failures)
        return False
