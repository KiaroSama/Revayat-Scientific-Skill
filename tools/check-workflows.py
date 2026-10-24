#!/usr/bin/env python3
"""Adapt three literal same-commit calls for actionlint 1.7.12; never filter diagnostics."""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from runtime import operation_log

CALLS = {'security': 'security-ci', 'codeql': 'codeql', 'dependency-review': 'dependency-review'}


def actionlint_source(filename, source):
    if '$/' not in source:
        return source
    if filename != '.github/workflows/ci.yml':
        raise ValueError('self-repository compatibility is limited to the three reviewed CI jobs')
    result, seen = [], set()
    job, in_jobs = None, False
    for line in source.splitlines(keepends=True):
        if line.rstrip('\r\n') == 'jobs:':
            in_jobs = True
        match = re.fullmatch(r'  ([a-zA-Z0-9_-]+):\r?\n?', line) if in_jobs else None
        if match:
            job = match.group(1)
        if '$/' in line:
            expected = '    uses: $/.github/workflows/' + CALLS.get(job, '') + '.yml'
            if line.rstrip('\r\n') != expected or job not in CALLS or job in seen:
                raise ValueError('unsupported or duplicate self-repository workflow reference')
            seen.add(job)
            line = line[:10] + '.' + line[11:]
        result.append(line)
    if seen != set(CALLS):
        raise ValueError('self-repository compatibility requires all three reviewed workflow calls')
    return ''.join(result)


def lint_one(filename):
    path = ROOT / filename
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1048576:
        raise ValueError('workflow must be a plain file of at most 1 MiB')
    source = actionlint_source(filename, path.read_bytes().decode('utf-8'))
    # Original identity preserves local callee input/secret/output checking. Equal-width
    # substitutions preserve every other byte and diagnostic line/column in stdin.
    result = subprocess.run(['actionlint', '-stdin-filename', filename, '-'],
                            input=source, text=True, encoding='utf-8', cwd=ROOT,
                            timeout=30, check=False)
    return result.returncode


def main():
    with operation_log('check-workflows', ROOT / 'logs') as logger:
        try:
            paths = sorted(path for path in (ROOT / '.github/workflows').iterdir()
                           if path.suffix in ('.yml', '.yaml'))
            if not paths:
                raise ValueError('no workflows found for required validation')
            failed = False
            for path in paths:
                filename = path.relative_to(ROOT).as_posix()
                code = lint_one(filename)
                logger.info('workflow_checked file=%s exit_code=%d', filename, code)
                failed |= code != 0
            return int(failed)
        except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
            logger.exception('workflow validation failed')
            print('Workflow validation failed; inspect the check-workflows log.', file=sys.stderr)
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
