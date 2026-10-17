"""Preflight and recoverable publication of an explicitly staged file set."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from bounded_file_identity import file_identity


def _linked(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def validate_destination(destination, sources=()):
    destination = Path(destination).absolute()
    if any(_linked(part) for part in (destination, *destination.parents)):
        raise ValueError('output path must not contain links or junctions')
    if destination.exists() and not destination.is_file():
        raise ValueError('output destination must be a regular file')
    if destination.parent.is_dir():
        for sibling in destination.parent.iterdir():
            if sibling.name.casefold() == destination.name.casefold() and sibling.name != destination.name:
                raise ValueError('output collides with an existing case-variant filename')
    for source in sources:
        source = Path(source)
        if (destination.resolve() == source.resolve()
                or (destination.exists() and source.exists()
                    and os.path.samefile(destination, source))):
            raise ValueError('output destination aliases a protected source')
    return destination


def _fingerprint(path, max_bytes=None):
    if not path.exists():
        return None
    return file_identity(path, max_bytes=max_bytes)


def _identity(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    return info.st_dev, info.st_ino


def _inherited_copy(source, destination, parent, max_bytes):
    """Create bytes with destination-parent inheritance, never grant an ACL."""
    original = _fingerprint(source, max_bytes)
    if original is None:
        raise ValueError('publication stage disappeared before inherited access preparation')
    descriptor, name = tempfile.mkstemp(prefix='.revayat-publish-', dir=parent)
    temporary = Path(name)
    opened = os.fstat(descriptor)
    identity = opened.st_dev, opened.st_ino
    os.close(descriptor)
    try:
        if _linked(temporary) or _identity(temporary) != identity:
            raise ValueError('publication temporary file ownership changed')
        shutil.copyfile(source, temporary)
        if _linked(temporary) or _identity(temporary) != identity:
            raise ValueError('publication temporary file ownership changed')
        os.utime(temporary, ns=(source.stat().st_atime_ns, original[3]))
        if (_fingerprint(source, max_bytes) != original
                or _fingerprint(temporary, max_bytes)[2:] != original[2:]):
            raise ValueError('publication source changed while preparing inherited access')
        validate_destination(destination)
        if _fingerprint(source, max_bytes) != original:
            raise ValueError('publication source changed before inherited access replacement')
        if _linked(temporary) or _identity(temporary) != identity:
            raise ValueError('publication temporary file ownership changed')
        os.replace(temporary, destination)
    finally:
        if _identity(temporary) == identity and not _linked(temporary):
            temporary.unlink()


def publish_files(entries, protected_sources=(), *, max_file_bytes=None):
    """Publish staged files; retain accountable backups/locks on incomplete recovery.

    Callers validate staged formats before this operation. Cancellation propagates
    with a recovery-location note if reconciliation is interrupted. This is
    recoverable batch publication, not a filesystem-wide atomic transaction.
    Hash reads are bounded by each initial size; max_file_bytes optionally applies
    an existing caller limit without imposing a new universal admission policy.
    """
    entries = [(Path(stage).absolute(), Path(dest).absolute()) for stage, dest in entries]
    protected_sources = tuple(map(Path, protected_sources))
    destinations = set()
    all_stages = [stage for stage, _ in entries]
    for stage, dest in entries:
        validate_destination(dest, (*protected_sources, *all_stages))
        key = str(dest.resolve()).casefold()
        if key in destinations:
            raise ValueError('duplicate output destination in publication plan')
        destinations.add(key)
        if _linked(stage) or not stage.is_file():
            raise ValueError('staged output must be a regular non-linked file')
        if not dest.parent.is_dir() or stage.stat().st_dev != dest.parent.stat().st_dev:
            raise ValueError('stage and destination must be on the same filesystem')
    for index, (_, dest) in enumerate(entries):
        for _, other in entries[:index]:
            if dest.exists() and other.exists() and os.path.samefile(dest, other):
                raise ValueError('output destinations alias each other')

    backups, committed, recovery_dirs, locks = [], [], [], {}
    keep_recovery = False
    try:
        for _, dest in sorted(entries, key=lambda item: str(item[1]).casefold()):
            name = hashlib.sha256(str(dest).casefold().encode('utf-8')).hexdigest()[:24]
            lock = dest.parent / ('.revayat-publish-' + name + '.lock')
            handle = lock.open('x', encoding='utf-8')
            locks[dest] = (lock, handle, _identity(lock))
        for stage, dest in entries:
            validate_destination(dest, protected_sources)
            if os.name == 'nt':
                _inherited_copy(stage, stage, dest.parent, max_file_bytes)
            original = _fingerprint(dest, max_file_bytes)
            directory = Path(tempfile.mkdtemp(prefix='.revayat-publish-', dir=dest.parent))
            recovery_dirs.append((directory, _identity(directory)))
            backup = directory / 'previous'
            if original is not None:
                if os.name == 'nt':
                    descriptor, name = tempfile.mkstemp(prefix='.revayat-publish-', dir=dest.parent)
                    opened = os.fstat(descriptor)
                    identity = opened.st_dev, opened.st_ino
                    os.close(descriptor)
                    inherited = Path(name)
                    try:
                        if _linked(inherited) or _identity(inherited) != identity:
                            raise ValueError('publication backup temporary ownership changed')
                        if _linked(directory) or _identity(directory) != recovery_dirs[-1][1] or backup.exists():
                            raise ValueError('publication recovery directory ownership changed')
                        os.replace(inherited, backup)
                    finally:
                        if _identity(inherited) == identity and not _linked(inherited):
                            inherited.unlink()
                shutil.copy2(dest, backup)
                if _fingerprint(dest, max_file_bytes) != original or _fingerprint(backup, max_file_bytes)[2:] != original[2:]:
                    raise RuntimeError('destination changed or copied backup differs')
            journal = directory / 'recovery.json'
            lock, handle, identity = locks[dest]
            journal.write_text(json.dumps({
                'destination': str(dest), 'previous_exists': original is not None,
                'previous_fingerprint': original, 'backup': str(backup), 'stage': str(stage),
                'recovery': str(journal), 'lock': str(lock), 'lock_identity': identity,
            }, ensure_ascii=False, indent=2), encoding='utf-8')
            handle.write(str(journal) + '\n')
            handle.flush()
            backups.append((stage, dest, backup, original))
        for stage, dest, backup, original in backups:
            validate_destination(dest, protected_sources)
            if _fingerprint(dest, max_file_bytes) != original:
                raise RuntimeError('destination changed before publication')
            published = _fingerprint(stage, max_file_bytes)
            committed.append((dest, backup, original, published))
            os.replace(stage, dest)
    except BaseException:
        # Retention precedes restoration: a second cancellation cannot erase intent.
        keep_recovery = True
        failures = []
        try:
            for dest, backup, original, published in reversed(committed):
                retained = None
                try:
                    validate_destination(dest, protected_sources)
                    current = _fingerprint(dest, max_file_bytes)
                    if current == original:
                        continue
                    if current != published:
                        raise ValueError('published destination changed before rollback')
                    if original is None:
                        dest.unlink()
                    else:
                        retained = _fingerprint(backup, max_file_bytes)
                        if _linked(backup) or retained is None or retained[2:] != original[2:]:
                            raise ValueError('previous backup changed before rollback')
                        os.replace(backup, dest)
                    if _fingerprint(dest, max_file_bytes) != retained:
                        raise ValueError('restored destination changed during rollback')
                except (OSError, ValueError):
                    # An OS call may have completed before raising. Only the exact
                    # recorded backup object (or absence) proves restoration here.
                    try:
                        validate_destination(dest, protected_sources)
                        restored = (_fingerprint(dest, max_file_bytes) == retained and
                                    (original is None or (retained is not None and not backup.exists())))
                    except (OSError, ValueError):
                        restored = False
                    if not restored:
                        failures.append(str(backup.parent / 'recovery.json'))
        except BaseException as error:
            error.add_note('publication rollback needs recovery: ' + ', '.join(
                str(directory / 'recovery.json') for directory, _ in recovery_dirs))
            raise
        if failures:
            raise RuntimeError('publication rollback needs recovery: ' + ', '.join(failures))
        keep_recovery = False
        raise
    finally:
        for _, handle, _ in locks.values():
            handle.close()
        if not keep_recovery:
            try:
                for directory, identity in recovery_dirs:
                    if _linked(directory) or _identity(directory) != identity:
                        raise ValueError('publication recovery directory ownership changed')
                for lock, _, identity in locks.values():
                    if _linked(lock) or _identity(lock) != identity:
                        raise ValueError('publication lock ownership changed')
                # Keep journals until backup disposal and lock release both finish.
                for directory, _ in recovery_dirs:
                    (directory / 'previous').unlink(missing_ok=True)
                for lock, _, _ in reversed(list(locks.values())):
                    lock.unlink()
                for directory, _ in recovery_dirs:
                    shutil.rmtree(directory)
            except (OSError, ValueError) as error:
                raise RuntimeError('publication cleanup needs recovery: ' + ', '.join(
                    str(directory / 'recovery.json') for directory, _ in recovery_dirs)) from error
