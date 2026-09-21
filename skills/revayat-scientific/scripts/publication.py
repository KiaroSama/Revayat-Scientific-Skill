"""Preflight and recoverable publication of an explicitly staged file set."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile


def _linked(path):
    return path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())


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


def _fingerprint(path):
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, digest.hexdigest()


def publish_files(entries, protected_sources=()):
    """Publish staged files; roll back failure or retain backups if rollback fails.

    Callers validate staged formats before this operation. A failed rollback raises
    a RuntimeError naming the retained recovery manifest; it is never cleaned away.
    This is recoverable batch publication, not a filesystem-wide atomic transaction.
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

    backups = []
    committed = []
    recovery_dirs = []
    keep_recovery = False
    with ExitStack() as locks:
        try:
            for _, dest in sorted(entries, key=lambda item: str(item[1]).casefold()):
                name = hashlib.sha256(str(dest).casefold().encode('utf-8')).hexdigest()[:24]
                lock = dest.parent / ('.revayat-publish-' + name + '.lock')
                handle = lock.open('x', encoding='utf-8')
                locks.callback(lock.unlink, missing_ok=True)
                locks.callback(handle.close)
            for stage, dest in entries:
                validate_destination(dest, protected_sources)
                original = _fingerprint(dest)
                directory = Path(tempfile.mkdtemp(prefix='.revayat-publish-', dir=dest.parent))
                recovery_dirs.append(directory)
                backup = directory / 'previous'
                if original is not None:
                    shutil.copy2(dest, backup)
                    if _fingerprint(dest) != original:
                        raise RuntimeError('destination changed during backup')
                (directory / 'recovery.json').write_text(json.dumps({
                    'destination': str(dest), 'previous_exists': original is not None,
                    'backup': str(backup), 'stage': str(stage),
                }, ensure_ascii=False, indent=2), encoding='utf-8')
                backups.append((stage, dest, backup, original))
            for stage, dest, backup, original in backups:
                validate_destination(dest, protected_sources)
                if _fingerprint(dest) != original:
                    raise RuntimeError('destination changed before publication')
                published = _fingerprint(stage)
                os.replace(stage, dest)
                committed.append((dest, backup, original, published))
        except BaseException:
            failures = []
            for dest, backup, original, published in reversed(committed):
                try:
                    validate_destination(dest, protected_sources)
                    if _fingerprint(dest) != published:
                        raise ValueError('published destination changed before rollback')
                    if original is None:
                        dest.unlink()
                    else:
                        os.replace(backup, dest)
                except OSError:
                    failures.append(str(backup.parent / 'recovery.json'))
                except ValueError:
                    failures.append(str(backup.parent / 'recovery.json'))
            if failures:
                keep_recovery = True
                raise RuntimeError('publication rollback needs recovery: ' + ', '.join(failures))
            raise
        finally:
            if not keep_recovery:
                for directory in recovery_dirs:
                    shutil.rmtree(directory)
