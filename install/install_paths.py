"""Directory admission for skill installation; never normalize away a link."""
import os
from pathlib import Path
import shutil
import stat
import subprocess


def linked(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


def directory_path(path):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('installation paths must not contain parent traversal')
    for part in (path, *path.parents):
        if linked(part):
            raise ValueError('installation path must not contain links, junctions or reparse points')
        if part.exists() and not part.is_dir():
            raise ValueError('installation destination and its parents must be real directories')
        if part.parent != part and part.parent.is_dir():
            for sibling in part.parent.iterdir():
                if sibling.name.casefold() == part.name.casefold() and sibling.name != part.name:
                    raise ValueError('installation path collides with an existing case-variant name')
    return path


def overlaps(first, second):
    # Treat case-only aliases conservatively even on case-sensitive filesystems.
    left, right = str(Path(first).resolve()).casefold(), str(Path(second).resolve()).casefold()
    return left == right or left.startswith(right.rstrip(os.sep) + os.sep) or right.startswith(left.rstrip(os.sep) + os.sep)


def _git_paths(anchor):
    anchor = Path(anchor).absolute()
    while not anchor.is_dir() and anchor.parent != anchor:
        anchor = anchor.parent
    marker = next((p / '.git' for p in (anchor, *anchor.parents)
                   if (p / '.git').exists() or (p / '.git').is_symlink()), None)
    bare = any((p / 'HEAD').is_file() and (p / 'objects').is_dir()
               for p in (anchor, *anchor.parents))
    if marker is None and not bare and not os.environ.get('GIT_DIR'):
        return ()
    if not shutil.which('git'):
        raise ValueError('Git is required to protect detected repository administration')
    result = subprocess.run(['git', 'rev-parse', '--path-format=absolute',
                             '--git-dir', '--git-common-dir', '--git-path', 'objects',
                             '--git-path', 'hooks', '--git-path', 'index'],
                            cwd=anchor, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    if result.returncode:
        raise ValueError('cannot resolve Git administration before installation')
    values = result.stdout.decode('utf-8').splitlines()
    if len(values) != 5 or any(not value or not Path(value).is_absolute() for value in values):
        raise ValueError('Git administration paths are ambiguous or unsupported')
    return tuple(map(Path, values)) + ((marker,) if marker else ())


def validate_location(destination, source, repository):
    destination = directory_path(destination)
    if any(part.casefold() == '.git' for part in destination.parts):
        raise ValueError('installation must not replace Git administrative data')
    if destination == Path(destination.anchor):
        raise ValueError('filesystem root is not an installation destination')
    protected = (source, Path(repository) / 'install', Path(repository) / 'tools')
    if any(overlaps(destination, root) for root in protected):
        raise ValueError('installation destination overlaps implementation or source files')
    # Resolve both the source checkout and a possible separate target repository.
    for anchor in dict.fromkeys((Path(repository), destination)):
        if any(overlaps(destination, root) for root in _git_paths(anchor)):
            raise ValueError('installation overlaps Git administrative data')
    return destination
