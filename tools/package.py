#!/usr/bin/env python3
"""Create an installable .skill ZIP without replacing any package input."""
import argparse
import importlib.util
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


def protected_inputs(payload):
    """Protect checkout sources and the known build inputs in exported archives."""
    sources = [path for path, _ in payload]
    sources.extend((Path(__file__), Path(installer.__file__)))
    if (ROOT / '.git').exists():
        # This also protects tracked documentation/configuration outside the payload.
        result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('cannot verify repository inputs before package publication')
        sources.extend(ROOT / name for name in result.stdout.decode('utf-8').split('\0') if name)
    return sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/revayat-scientific.skill')
    args = parser.parse_args()
    with installer.operation_log('package', ROOT / 'logs') as logger:
        payload = list(installer.payload_files())
        sources = protected_inputs(payload)
        output = validate_destination(args.output, sources)
        resolved = output.resolve()
        for source_root in (installer.SOURCE.resolve(), ROOT / 'tools', ROOT / 'install'):
            if resolved == source_root or resolved.is_relative_to(source_root):
                raise ValueError('package output must not be inside an implementation or skill source directory')
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
            publish_files([(temporary, output)], protected_sources=sources)
        logger.info('package_completed')
        print(output.resolve())
    return 0


if __name__ == '__main__':
    sys.exit(main())
