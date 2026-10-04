"""Bounded, recoverable installation of a complete directory target set.

Cooperative locks and snapshots detect concurrent changes; this is not a security
sandbox or a globally atomic filesystem transaction. A failed recovery retains
its journal, backups, stages and locks for deliberate operator recovery.
"""
from dataclasses import dataclass
import hashlib
import json
import logging
from itertools import islice
import os
from pathlib import Path
import re
import shutil
import stat
import uuid

from install_paths import directory_path, linked, overlaps, validate_location

MAX_FILES = 100000
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024


def _identity(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    return info.st_dev, info.st_ino


def _digest(path):
    digest = hashlib.sha256()
    consumed = 0
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            consumed += len(chunk)
            if consumed > MAX_TREE_BYTES:
                raise ValueError('file grew beyond the installation snapshot limit')
            digest.update(chunk)
    return digest.hexdigest()


def snapshot(path):
    """Capture a bounded tree without following linked entries or special files."""
    directory_path(path)
    if not path.exists():
        return None
    records, pending, total = [], [path], 0
    while pending:
        current = pending.pop()
        children = list(islice(current.iterdir(), MAX_FILES - len(records) + 1))
        if len(children) + len(records) > MAX_FILES:
            raise ValueError('installation tree exceeds 100000-entry limit')
        for child in sorted(children):
            if linked(child):
                raise ValueError('installation tree contains a link, junction or reparse point')
            info = child.lstat()
            if stat.S_ISDIR(info.st_mode):
                if child.name.casefold() == '.git':
                    raise ValueError('installation tree contains Git administration')
                pending.append(child)
                value = None
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if total > MAX_TREE_BYTES:
                    raise ValueError('installation tree exceeds 512 MiB snapshot limit')
                value = _digest(child)
                if child.stat().st_mtime_ns != info.st_mtime_ns or child.stat().st_size != info.st_size:
                    raise ValueError('installation tree changed during inspection')
            else:
                raise ValueError('installation tree contains a nonregular entry')
            records.append((str(child.relative_to(path)), info.st_mode, info.st_size if value else 0,
                            info.st_mtime_ns, value))
            if len(records) > MAX_FILES:
                raise ValueError('installation tree exceeds 100000-entry limit')
    return _identity(path), tuple(sorted(records))


def _existing_skill(path, old):
    if old is None or not old[1]:
        return
    marker = path / 'SKILL.md'
    if not marker.is_file() or marker.stat().st_size > 128 * 1024:
        raise ValueError('--force can replace only an identified revayat-scientific installation or empty directory')
    text = marker.read_text(encoding='utf-8-sig')
    front = re.match(r'\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)', text, re.S)
    lines = front[1].splitlines() if front else []
    continuation = False
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if line[0].isspace():
            if not continuation:
                raise ValueError('installation identity has an unexpected indented continuation')
            continue
        key = re.fullmatch(r'([A-Za-z][A-Za-z0-9_-]*)[ \t]*:(.*)', line)
        if key is None:
            raise ValueError('installation identity requires simple unambiguous frontmatter keys')
        continuation = key[1] != 'name' and key[2].strip() in {'', '|', '>', '|-', '>-', '|+', '>+'}
    names = re.findall(r'^name[ \t]*:(.*)$', front[1], re.M) if front else []
    if (len(names) != 1 or names[0].strip() not in
            {'revayat-scientific', "'revayat-scientific'", '"revayat-scientific"'}):
        raise ValueError('--force destination does not identify the revayat-scientific skill')


def _payload(source, factory):
    directory_path(source)
    _existing_skill(source, (None, ('source',)))
    rows, names, total = [], set(), 0
    for path, relative in factory():
        path, relative = Path(path).absolute(), Path(relative)
        if relative.is_absolute() or '..' in relative.parts or not relative.parts:
            raise ValueError('invalid distributable payload address')
        if (not path.resolve().is_relative_to(source.resolve())
                or path.relative_to(source) != relative
                or any(linked(p) for p in (path, *path.parents))):
            raise ValueError('payload file leaves source or traverses a linked component')
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('payload entry must be a regular file')
        key = str(relative).casefold()
        if key in names:
            raise ValueError('duplicate or case-colliding payload address')
        names.add(key)
        total += info.st_size
        if total > MAX_PAYLOAD_BYTES or len(names) > 10000:
            raise ValueError('payload exceeds 64 MiB or 10000-file limit')
        rows.append((path, relative, info.st_size, _digest(path)))
    if 'skill.md' not in names:
        raise ValueError('source SKILL.md is missing')
    return tuple(rows)


def _verify_payload(rows):
    for path, _, size, digest in rows:
        if any(linked(p) for p in (path, *path.parents)) or path.stat().st_size != size or _digest(path) != digest:
            raise ValueError('source payload changed during installation')


def _mkdirs(path, created):
    directory_path(path)
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for item in reversed(missing):
        directory_path(item)
        item.mkdir()
        created.append((item, _identity(item)))


@dataclass
class Target:
    destination: Path
    old: object
    stage: Path
    backup: Path
    prepared: object = None
    lock: Path | None = None
    lock_identity: object = None


def _journal(path, targets):
    data = {'version': 1, 'operation': 'recoverable-skill-install',
            'instruction': 'Stop other installers. Compare each destination, stage and backup before restoring. Do not delete backups or locks without resolving every target.',
            'targets': [{'destination': str(t.destination), 'stage': str(t.stage),
                         'backup': str(t.backup), 'previous_exists': t.old is not None,
                         'previous_identity': t.old[0] if t.old else None,
                         'staged_identity': t.prepared[0] if t.prepared else None,
                         'lock': str(t.lock) if t.lock else None,
                         'lock_identity': t.lock_identity}
                        for t in targets]}
    with path.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())


def _rollback(targets, logger):
    failures = []
    for item in reversed(targets):
        dest, stage, backup = item.destination, item.stage, item.backup
        try:
            directory_path(dest)
            directory_path(stage)
            directory_path(backup)
            if item.prepared is not None and _identity(dest) == item.prepared[0]:
                if snapshot(dest) != item.prepared or stage.exists():
                    raise ValueError('published installation changed before rollback')
                dest.rename(stage)
            if item.old is None:
                if dest.exists():
                    raise ValueError('another directory now occupies a new installation target')
            elif _identity(dest) != item.old[0]:
                if dest.exists() or snapshot(backup) != item.old:
                    raise ValueError('previous installation cannot be safely restored')
                backup.rename(dest)
            if item.old is not None and snapshot(dest) != item.old:
                raise ValueError('previous installation changed before rollback')
        except (OSError, ValueError, RuntimeError):
            failures.append(str(dest))
    logger.log(logging.ERROR if failures else logging.WARNING, 'rollback_targets=%d unresolved=%d', len(targets), len(failures))
    return failures


def install_targets(destinations, force, logger, *, source, repository, payload_factory):
    """Validate/stage every target first; publish and roll back as one operation."""
    source, repository = Path(source).absolute(), Path(repository).absolute()
    rows = _payload(source, payload_factory)
    run_id, targets, keys = uuid.uuid4().hex, [], set()
    for position, destination in enumerate(destinations):
        dest = validate_location(destination, source, repository)
        if any(part.casefold() == 'skill-backups' or part.startswith(
                ('.revayat-install-', '.revayat-scientific-stage-')) for part in dest.parts):
            raise ValueError('installation target overlaps reserved backup, stage or recovery storage')
        key = str(dest.resolve()).casefold()
        if key in keys or any(overlaps(dest, t.destination) for t in targets):
            raise ValueError('duplicate, case-colliding or nested installation targets')
        keys.add(key)
        old = snapshot(dest)
        if old is not None and not force:
            raise FileExistsError('skill already exists; use --force to retain a backup and replace it')
        _existing_skill(dest, old)
        # Preserve normal host backup paths; custom roots remain outside the named target.
        parent = dest.parent.parent if dest.parent.name.casefold() == 'skills' else dest.parent
        backup_root = validate_location(parent / 'skill-backups', source, repository)
        stage = dest.parent / ('.revayat-scientific-stage-' + run_id + '-' + str(position))
        backup = backup_root / ('revayat-scientific-' + run_id + '-' + str(position))
        targets.append(Target(dest, old, stage, backup))
    if not targets:
        raise ValueError('installation has no targets')
    for item in targets:
        for other in targets:
            if overlaps(item.backup.parent, other.destination) or overlaps(item.stage, other.destination):
                raise ValueError('backup or staging location overlaps an installation target')
    logger.info('installation_plan targets=%d files=%d', len(targets), len(rows))
    created, locks = [], []
    journal_dir = targets[0].destination.parent / ('.revayat-install-recovery-' + run_id)
    journal_path = journal_dir / 'recovery.json'
    keep, publishing, complete = False, False, False
    journal_identity = None
    try:
        for item in sorted(targets, key=lambda t: str(t.destination).casefold()):
            _mkdirs(item.destination.parent, created)
            name = hashlib.sha256(str(item.destination).casefold().encode('utf-8')).hexdigest()[:24]
            lock = item.destination.parent / ('.revayat-install-' + name + '.lock')
            handle = lock.open('x', encoding='utf-8')
            item.lock, item.lock_identity = lock, _identity(lock)
            locks.append((lock, handle, item.lock_identity))
            handle.write(str(journal_path) + '\n')
            handle.flush()
        directory_path(journal_dir)
        journal_dir.mkdir(mode=0o700)
        journal_identity = _identity(journal_dir)
        for item in targets:
            # Final stages keep normal Windows ACL inheritance, unlike the private journal.
            item.stage.mkdir()
            item.prepared = snapshot(item.stage)
        _journal(journal_path, targets)
        for item in targets:
            validate_location(item.destination, source, repository)
            if snapshot(item.destination) != item.old:
                raise ValueError('destination changed after installation preflight')
            if item.old is not None:
                _mkdirs(item.backup.parent, created)
                if item.backup.parent.stat().st_dev != item.destination.parent.stat().st_dev:
                    raise ValueError('backup and installation must be on the same filesystem')
            ready = journal_dir / 'prepared.json'
            _journal(ready, targets)
            os.replace(ready, journal_path)
            for path, relative, size, digest in rows:
                target = item.stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
                if target.stat().st_size != size or _digest(target) != digest:
                    raise ValueError('staged payload differs from the source snapshot')
            _verify_payload(rows)
            item.prepared = snapshot(item.stage)
            logger.debug('staged_target files=%d', len(rows))
        for item in targets:
            validate_location(item.destination, source, repository)
            validate_location(item.backup.parent, source, repository)
            if snapshot(item.destination) != item.old or snapshot(item.stage) != item.prepared or item.backup.exists():
                raise ValueError('installation plan changed before publication')
        _verify_payload(rows)
        directory_path(journal_dir)
        if _identity(journal_dir) != journal_identity:
            raise ValueError('recovery directory ownership changed before publication')
        ready = journal_dir / 'prepared.json'
        _journal(ready, targets)
        os.replace(ready, journal_path)
        publishing = True
        for item in targets:
            # Repeat path/content checks immediately before the destructive boundary.
            validate_location(item.destination, source, repository)
            validate_location(item.backup.parent, source, repository)
            if snapshot(item.destination) != item.old or snapshot(item.stage) != item.prepared or item.backup.exists():
                raise ValueError('installation target changed during publication')
            if item.old is not None:
                item.destination.rename(item.backup)
            item.stage.rename(item.destination)
        complete = True
    except BaseException:
        if publishing and _rollback(targets, logger):
            keep = True
            raise RuntimeError('installation rollback needs recovery: ' + str(journal_path)) from None
        raise
    finally:
        cleanup = []
        if not keep:
            for item in targets:
                if item.stage.exists():
                    try:
                        directory_path(item.stage)
                        if item.prepared is None or _identity(item.stage) != item.prepared[0]:
                            raise ValueError('staging directory ownership changed')
                        shutil.rmtree(item.stage)
                    except (OSError, ValueError):
                        cleanup.append(str(item.stage))
            if cleanup:
                for _, handle, _ in locks:
                    handle.close()
                logger.error('installation_cleanup_unresolved count=%d', len(cleanup))
                raise RuntimeError('installation cleanup needs recovery: ' + str(journal_path))
            for lock, handle, identity in reversed(locks):
                handle.close()
                try:
                    if _identity(lock) != identity or linked(lock):
                        raise ValueError('installation lock ownership changed')
                    lock.unlink()
                except (OSError, ValueError):
                    cleanup.append(str(lock))
            if cleanup:
                logger.error('installation_cleanup_unresolved count=%d', len(cleanup))
                raise RuntimeError('installation cleanup needs recovery: ' + str(journal_path))
            if journal_identity is not None:
                try:
                    directory_path(journal_dir)
                    if _identity(journal_dir) != journal_identity:
                        raise ValueError('recovery directory ownership changed')
                    shutil.rmtree(journal_dir)
                except (OSError, ValueError):
                    raise RuntimeError('installation journal needs recovery: ' + str(journal_path)) from None
            if not complete:
                for directory, identity in reversed(created):
                    if _identity(directory) == identity and not linked(directory):
                        try:
                            directory.rmdir()
                        except OSError:
                            pass  # Never remove a directory that acquired other contents.
        else:
            for _, handle, _ in locks:
                handle.close()
    logger.info('installation_completed targets=%d backups=%d', len(targets), sum(t.old is not None for t in targets))
    for item in targets:
        print('Installed revayat-scientific: ' + str(item.destination))
        if item.old is not None:
            print('Previous installation retained: ' + str(item.backup))
