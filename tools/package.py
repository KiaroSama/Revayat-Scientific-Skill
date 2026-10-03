#!/usr/bin/env python3
"""Create an installable .skill ZIP without replacing any package input."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('revayat_installer', ROOT / 'install/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
from publication import publish_files, validate_destination


def repository_marker():
    for directory in (ROOT, *ROOT.parents):
        marker = directory / '.git'
        if marker.exists() or marker.is_symlink():
            return marker
    return None


def protected_inputs(payload):
    """Protect checkout sources and the known build inputs in exported archives."""
    sources = [path for path, _ in payload]
    sources.extend((Path(__file__), Path(installer.__file__)))
    if repository_marker() is not None or os.environ.get('GIT_DIR'):
        # This also protects tracked documentation/configuration outside the payload.
        result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('cannot verify repository inputs before package publication')
        sources.extend(ROOT / name for name in result.stdout.decode('utf-8').split('\0') if name)
    return sources


def git_administration():
    """Resolve administrative paths without modifying or trusting their contents."""
    marker = repository_marker()
    if marker is None and not os.environ.get('GIT_DIR'):
        return (), ()
    result = subprocess.run([
        'git', 'rev-parse', '--path-format=absolute', '--git-dir', '--git-common-dir',
        '--git-path', 'index', '--git-path', 'objects', '--git-path', 'hooks'], cwd=ROOT, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('cannot resolve Git administrative paths before publication')
    values = result.stdout.decode('utf-8').splitlines()
    if len(values) != 5 or any(not value or not Path(value).is_absolute() for value in values):
        raise ValueError('Git administrative paths were ambiguous or unsupported')
    private, common, index, objects, hooks = map(Path, values)
    roots = tuple(path.resolve() for path in (private, common, objects, hooks))
    if any(not root.is_dir() for root in roots[:2]):
        raise ValueError('Git administrative directory is unavailable')
    protected = [index] + ([marker] if marker is not None else [])
    shared = subprocess.run(['git', 'rev-parse', '--path-format=absolute', '--shared-index-path'],
                            cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    if shared.returncode:
        raise ValueError('cannot resolve Git shared index before publication')
    shared_paths = shared.stdout.decode('utf-8').splitlines()
    if len(shared_paths) > 1 or any(not value or not Path(value).is_absolute() for value in shared_paths):
        raise ValueError('Git shared-index path was ambiguous or unsupported')
    protected.extend(Path(value) for value in shared_paths)
    for root in roots:
        protected.extend(root / name for name in ('HEAD', 'index', 'config', 'packed-refs',
                                                   'commondir', 'gitdir'))
    return roots, tuple(protected)


def package_destination(destination, sources):
    """Protect Git metadata as well as payload and tracked worktree files."""
    output = validate_destination(destination, sources)
    if any(part.casefold() == '.git' for part in output.parts):
        raise ValueError('package output must not replace Git administrative data')
    admin_roots, admin_files = git_administration()
    resolved = output.resolve()
    for root in (installer.SOURCE.resolve(), ROOT / 'tools', ROOT / 'install', *admin_roots):
        if resolved == root or resolved.is_relative_to(root):
            raise ValueError('package output must not be inside a source or Git administrative directory')
    protected = (*sources, *admin_files)
    validate_destination(output, protected)
    return output, protected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/revayat-scientific.skill')
    args = parser.parse_args()
    with installer.operation_log('package', ROOT / 'logs') as logger:
        payload = list(installer.payload_files())
        sources = protected_inputs(payload)
        output, sources = package_destination(args.output, sources)
        logger.debug('planned_payload_files=%d protected_inputs=%d', len(payload), len(sources))
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.revayat-package-', dir=output.parent) as directory:
            temporary = Path(directory) / 'package.skill'
            with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
                for source, relative in payload:
                    archive.write(source, (Path('revayat-scientific') / relative).as_posix())
            with zipfile.ZipFile(temporary) as archive:
                if archive.testzip() is not None:
                    raise ValueError('package CRC verification failed')
                if 'revayat-scientific/SKILL.md' not in archive.namelist():
                    raise ValueError('package is missing SKILL.md')
            # Re-resolve worktree/common/index paths before publication as well.
            output, sources = package_destination(output, sources)
            publish_files([(temporary, output)], protected_sources=sources)
        logger.info('package_completed')
        print(output.resolve())
    return 0


if __name__ == '__main__':
    sys.exit(main())
