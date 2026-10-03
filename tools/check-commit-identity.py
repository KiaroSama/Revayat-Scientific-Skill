#!/usr/bin/env python3
"""Check raw commit identities; use a base only for introduced-commit CI checks."""
import argparse
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from runtime import operation_log

APPROVED_EMAIL = 'Kiaro.Sama.Dev@gmail.com'


def _git(repository, arguments):
    result = subprocess.run(['git', '--no-replace-objects', *arguments], cwd=repository, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, encoding='utf-8', timeout=30)
    if result.returncode:
        raise ValueError('Git identity inspection failed; check repository and revision availability')
    return result.stdout


def _resolve(repository, revision):
    value = _git(repository, ['rev-parse', '--verify', '--end-of-options', revision + '^{commit}']).strip()
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value):
        raise ValueError('revision did not resolve to one commit')
    return value


def inspect_identities(repository, head='HEAD', base=None):
    if _git(repository, ['rev-parse', '--is-shallow-repository']).strip() != 'false':
        raise ValueError('shallow repository cannot establish complete commit identities; fetch full history first')
    grafts = Path(_git(repository, ['rev-parse', '--git-path', 'info/grafts']).strip())
    if not grafts.is_absolute():
        grafts = Path(repository) / grafts
    if grafts.exists() and grafts.stat().st_size:
        raise ValueError('legacy grafts can hide ancestry; inspect an ungrafted complete history')
    head = _resolve(repository, head)
    revision = _resolve(repository, base) + '..' + head if base is not None else head
    # Lowercase %ae/%ce expose stored emails, not mailmap-normalized display names.
    rows = _git(repository, ['log', '--format=%H%x00%ae%x00%ce', revision, '--']).splitlines()
    failures = []
    for row in rows:
        fields = row.split('\0')
        if len(fields) != 3 or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', fields[0]):
            raise ValueError('malformed raw commit identity record')
        roles = [role for role, value in zip(('author', 'committer'), fields[1:])
                 if value != APPROVED_EMAIL]
        if roles:
            failures.append((fields[0], tuple(roles)))
    return len(rows), failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--head', default='HEAD', help='head revision; all reachable history by default')
    parser.add_argument('--base', help='exclude commits reachable from this base, for PR checks only')
    args = parser.parse_args(argv)
    try:
        with operation_log('check-commit-identity', ROOT / 'logs') as logger:
            logger.debug('scope=%s', 'introduced-commits' if args.base else 'complete-head-history')
            count, failures = inspect_identities(ROOT, args.head, args.base)
            if args.base:
                logger.warning('range check does not certify excluded historical identities')
            for sha, roles in failures:
                logger.error('unapproved_identity commit=%s roles=%s', sha, ','.join(roles))
                print(f'Unapproved commit identity: {sha} ({", ".join(roles)})', file=sys.stderr)
            logger.info('checked_commits=%d failing_commits=%d', count, len(failures))
            print(f'Identity check: {count} commits, {len(failures)} mismatches; required email={APPROVED_EMAIL}')
            return int(bool(failures))
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print('Identity check unavailable: ' + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
