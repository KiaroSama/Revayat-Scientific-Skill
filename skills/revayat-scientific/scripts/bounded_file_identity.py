"""Counted exact-byte identity with stable path and opened-descriptor observations."""
import hashlib
import os
from pathlib import Path
import stat

CHUNK_BYTES = 1024 * 1024


def _observation(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def file_identity(path, *, max_bytes=None):
    """Return dev/inode/size/mtime/SHA-256, refusing ordinary mutation while reading.

    The initial size bounds every read, including one extra byte to detect growth.
    max_bytes optionally imposes a caller's existing admission limit; without it
    this is a snapshot-size bound, not a universal artifact-admission policy.
    """
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 0):
        raise ValueError('file identity byte limit must be a nonnegative integer')
    path = Path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('file identity requires a regular file')
    if max_bytes is not None and before.st_size > max_bytes:
        raise ValueError('file exceeds the caller byte limit')
    expected = _observation(before)
    digest, consumed = hashlib.sha256(), 0
    with path.open('rb') as handle:
        opened = _observation(os.fstat(handle.fileno()))
        # Windows stat/fstat can report different ctime values after copy2. Compare
        # shared identity fields, then check each observation's own change time.
        if opened[:4] != expected[:4]:
            raise ValueError('file changed before fingerprint reading')
        while True:
            chunk = handle.read(min(CHUNK_BYTES, before.st_size - consumed + 1))
            consumed += len(chunk)
            if consumed > before.st_size:
                raise ValueError('file grew beyond its fingerprint snapshot byte limit')
            if not chunk:
                break
            digest.update(chunk)
        if consumed != before.st_size or _observation(os.fstat(handle.fileno())) != opened:
            raise ValueError('file changed during fingerprint reading')
        if _observation(path.stat()) != expected:
            raise ValueError('file path changed during fingerprint reading')
    if _observation(path.stat()) != expected:
        raise ValueError('file changed after fingerprint reading')
    return expected[:4] + (digest.hexdigest(),)
