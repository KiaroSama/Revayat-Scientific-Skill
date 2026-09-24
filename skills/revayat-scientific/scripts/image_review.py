"""Validate explicit, asset-bound review of a legitimate dark original."""
import hashlib
import json
from pathlib import Path
import re

MAX_REVIEW_BYTES = 16 * 1024


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate dark-image review key')
        result[key] = value
    return result


def _sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def reviewed_dark_original(source):
    """Only discharge the darkness heuristic; never waive image validation."""
    source = Path(source)
    review = source.with_name(source.name + '.review.json')
    linked = lambda path: path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())
    if any(linked(path) for path in (review, *review.parents)):
        raise ValueError('dark-image review must not traverse a link or junction')
    if not review.exists():
        return False
    if not review.is_file():
        raise ValueError('dark-image review must be a regular JSON file')
    with review.open('rb') as handle:
        raw = handle.read(MAX_REVIEW_BYTES + 1)
    if len(raw) > MAX_REVIEW_BYTES:
        raise ValueError('dark-image review exceeds 16 KiB')
    try:
        record = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('invalid dark-image review encoding or JSON') from error
    if (not isinstance(record, dict)
            or set(record) != {'version', 'sha256', 'decision', 'note'}
            or type(record['version']) is not int or record['version'] != 1
            or record['decision'] != 'preserve-dark-original'
            or not isinstance(record['sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', record['sha256'])
            or not isinstance(record['note'], str)
            or not 1 <= len(record['note'].strip()) <= 4096):
        raise ValueError('invalid dark-image review schema or decision')
    if record['sha256'] != _sha256(source):
        raise ValueError('dark-image review is stale; compare the current original again')
    return True
