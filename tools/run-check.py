#!/usr/bin/env python3
"""Run one CI check with wall/idle bounds and an owned process tree."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from runtime import operation_log, run_command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--idle-timeout', type=int, default=90)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or not 1 <= args.timeout <= 1800 or not 1 <= args.idle_timeout <= args.timeout:
        parser.error('provide a command and positive idle/wall bounds up to 1800 seconds')
    scratch = ROOT / '.scratch'
    scratch.mkdir(exist_ok=True)
    with operation_log('run-check', ROOT / 'logs') as logger:
        with tempfile.TemporaryDirectory(prefix='check-', dir=scratch) as directory:
            environment = {'TMP': directory, 'TEMP': directory, 'TMPDIR': directory,
                           'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUTF8': '1'}
            try:
                return run_command(command, args.timeout, logger, cwd=ROOT,
                                   env=environment, idle_timeout=args.idle_timeout)
            except subprocess.TimeoutExpired:
                print('check exceeded its wall or idle deadline; owned processes terminated', file=sys.stderr)
                return 124
            except KeyboardInterrupt:
                return 130


if __name__ == '__main__':
    raise SystemExit(main())
