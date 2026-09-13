#!/usr/bin/env python3
"""Create an installable .skill ZIP using the installer's payload allowlist."""
import argparse
import importlib.util
from pathlib import Path
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('revayat_installer', ROOT / 'install/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/revayat-scientific.skill')
    args = parser.parse_args()
    with installer.operation_log('package', ROOT / 'logs') as logger:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=args.output.parent, suffix='.skill', delete=False) as handle:
                temporary = Path(handle.name)
            with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
                for source, relative in installer.payload_files():
                    archive.write(source, (Path('revayat-scientific') / relative).as_posix())
            with zipfile.ZipFile(temporary) as archive:
                if archive.testzip() is not None:
                    raise ValueError('package CRC verification failed')
                if 'revayat-scientific/SKILL.md' not in archive.namelist():
                    raise ValueError('package is missing SKILL.md')
            temporary.replace(args.output)
            logger.info('package_completed')
            print(args.output.resolve())
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
