#!/usr/bin/env python3
"""Portable entry point for the scientific translation helpers."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from runtime import operation_log, run_command

HERE = Path(__file__).resolve().parent
PYTHON_COMMANDS = {
    'lint': 'check-fa.py', 'text-order': 'check-pdf-text-order.py',
    'figures': 'prepare-figures.py', 'crop': 'crop-source-figures.py',
    'pages': 'extract-pdf-pages.py',
}
SHELL_COMMANDS = {'doctor': 'preflight', 'build': 'build-pdf', 'fonts': 'fetch-vazirmatn'}
POWERSHELL_OPTIONS = {
    '--verify': '-Verify', '--level': '-Level', '--terms': '-Terms',
    '--manifest': '-Manifest', '--engine': '-Engine',
    '--output-dir': '-OutputDirectory', '--require-tex': '-RequireTex',
}
HELP = {
    'build': 'build SOURCE [SLUG] [--verify] [--level journal|system-docs] '
             '[--terms TSV] [--manifest TXT] [--engine tex|chromium|weasyprint] [--output-dir DIR]',
    'doctor': 'doctor [--require-tex] -- report Python, fonts, image helpers and PDF engines',
    'fonts': 'fonts [DIRECTORY] -- fetch Vazirmatn and its license; default: fonts/',
}


def command_line(name, arguments):
    if name in PYTHON_COMMANDS:
        return [sys.executable, str(HERE / PYTHON_COMMANDS[name]), *arguments]
    if os.name == 'nt':
        shell = shutil.which('pwsh') or shutil.which('powershell')
        if not shell:
            raise RuntimeError('PowerShell 5.1+ is required on Windows')
        converted = [POWERSHELL_OPTIONS.get(arg, arg) for arg in arguments]
        return [shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
                str(HERE / (SHELL_COMMANDS[name] + '.ps1')), *converted]
    shell = shutil.which('bash')
    if not shell:
        raise RuntimeError('Bash is required for PDF tools on Linux/macOS')
    return [shell, str(HERE / (SHELL_COMMANDS[name] + '.sh')), *arguments]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=int, default=300,
                        help='subprocess wall limit in seconds, 1-1800 (default: 300)')
    parser.add_argument('command', choices=[*PYTHON_COMMANDS, *SHELL_COMMANDS])
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 1800:
        parser.error('--timeout must be between 1 and 1800 seconds')
    with operation_log('revayat-scientific', HERE.parent / 'logs') as logger:
        logger.info('command=%s', args.command)
        if args.command in HELP and any(arg in ('-h', '--help') for arg in args.arguments):
            print(HELP[args.command])
            return 0
        try:
            return run_command(command_line(args.command, args.arguments), args.timeout, logger)
        except (OSError, RuntimeError) as error:
            logger.error('command_unavailable type=%s', type(error).__name__)
            print(f'revayat-scientific: {error}', file=sys.stderr)
            return 1
        except subprocess.TimeoutExpired:
            print('revayat-scientific: command timed out; owned process tree terminated', file=sys.stderr)
            return 124
        except KeyboardInterrupt:
            print('revayat-scientific: cancelled', file=sys.stderr)
            return 130


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    sys.exit(main())
