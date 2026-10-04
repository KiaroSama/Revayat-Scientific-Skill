"""Bind a build's checked inputs, reserved outputs and rendered bytes across stages.

This private per-run record is a coordination aid, not authentication or a lock
against hostile filesystem writers. Renderer resource admission stays separate.
"""
import hashlib
import json
import os
from pathlib import Path
import re

from document_context import DocumentContext
from publication import validate_destination
from source_model import Source

MAX_FILES = 8192
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}\Z')


def file_hash(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('build input or artifact is missing or exceeds 512 MiB')
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise ValueError('build input or artifact grew beyond 512 MiB')
            digest.update(chunk)
    return digest.hexdigest()


def document_inputs(source, sidecars=(), requested=None):
    source = Path(source).resolve()
    model = Source(source)
    context = DocumentContext(source, source.parent, [], None)
    paths = list(model.closure.sources) if model.closure else [source]
    paths.extend(context.asset(reference) for _, reference in model.image_references())
    paths.extend(Path(path).resolve() for path in sidecars)
    if requested is not None:
        paths.append(Path(requested).resolve())
    paths = list(dict.fromkeys(paths))
    if len(paths) > MAX_FILES:
        raise ValueError('build input count exceeds 8192')
    return paths


def _paths(records):
    if not isinstance(records, dict) or len(records) > MAX_FILES:
        raise ValueError('invalid bounded build fingerprint map')
    for name, digest in records.items():
        if (not isinstance(name, str) or not Path(name).is_absolute()
                or not isinstance(digest, str) or not HASH.fullmatch(digest)):
            raise ValueError('invalid build path or fingerprint')
    return records


def _destinations(outputs, sources):
    names = [Path(name).name.casefold() for name in outputs[2:] if isinstance(name, str)]
    if len(names) != len(set(names)):
        raise ValueError('build preview basenames must be unique')
    planned = []
    seen = set()
    for name in outputs:
        if not isinstance(name, str) or not Path(name).is_absolute():
            raise ValueError('build output paths must be absolute')
        path = validate_destination(name, sources)
        key = str(path.resolve()).casefold()
        if key in seen or any(path.exists() and other.exists() and os.path.samefile(path, other)
                              for other in planned):
            raise ValueError('build output paths collide or alias each other')
        seen.add(key)
        planned.append(path)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate build record key')
        result[key] = value
    return result


def load_guard(path):
    path = validate_destination(path)
    if not path.is_file() or path.stat().st_size > MAX_RECORD_BYTES:
        raise ValueError('build record is unavailable or exceeds 4 MiB')
    with path.open('rb') as handle:
        raw = handle.read(MAX_RECORD_BYTES + 1)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError('build record grew beyond 4 MiB')
    record = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
    if (not isinstance(record, dict) or set(record) != {'schema', 'inputs', 'outputs', 'rendered'}
            or type(record['schema']) is not int or record['schema'] != 1
            or not isinstance(record['outputs'], list) or not 2 <= len(record['outputs']) <= 5):
        raise ValueError('invalid build record schema')
    _paths(record['inputs'])
    _paths(record['rendered'])
    _destinations(record['outputs'], [path, *map(Path, record['inputs'])])
    if not record['inputs'] or set(record['rendered']) - {record['outputs'][0]}:
        raise ValueError('invalid build input or rendered-artifact identity')
    return record


def _save(path, record, *, new=False):
    path = validate_destination(path)
    raw = (json.dumps(record, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError('build record exceeds 4 MiB')
    if new:
        with path.open('xb') as handle:
            handle.write(raw)
    else:
        temporary = path.with_name(path.name + '.pending')
        created = False
        try:
            with temporary.open('xb') as handle:
                created = True
                handle.write(raw)
            os.replace(temporary, path)
        finally:
            if created:
                temporary.unlink(missing_ok=True)


def create_guard(path, source, working, output, *, terms, manifest, requested=None, samples=()):
    inputs = document_inputs(source, (terms, manifest), requested)
    outputs = [str(Path(name).absolute()) for name in (working, output, *samples)]
    if not 2 <= len(outputs) <= 5:
        raise ValueError('build needs two PDF outputs and at most three preview outputs')
    _destinations(outputs, [Path(path), *inputs])
    record = {'schema': 1, 'inputs': {str(name): file_hash(name) for name in inputs},
              'outputs': outputs, 'rendered': {}}
    _save(path, record, new=True)
    check_guard(path)
    return record


def check_guard(path, resources=None):
    """Check the pre-lint snapshot, then admit actual renderer resources, if any."""
    record = load_guard(path)
    added = {} if resources is None else dict(_paths(resources))
    merged = dict(record['inputs'])
    for name, digest in added.items():
        if name in merged and merged[name] != digest:
            raise ValueError('renderer consumed a different checked input revision')
        merged[name] = digest
    if len(merged) > MAX_FILES:
        raise ValueError('build resource count exceeds 8192')
    _destinations(record['outputs'], [Path(path), *map(Path, merged)])
    for name, digest in {**merged, **record['rendered']}.items():
        if file_hash(name) != digest:
            raise ValueError('checked build input or rendered artifact changed; rerun all build checks')
    if merged != record['inputs']:
        record['inputs'] = merged
        _save(path, record)
    return record


def seal_rendered(path, output, digest):
    record = check_guard(path)
    if str(Path(output).absolute()) != record['outputs'][0] or not HASH.fullmatch(digest):
        raise ValueError('renderer output differs from the planned working PDF')
    if file_hash(output) != digest:
        raise ValueError('working PDF changed during renderer publication')
    record['rendered'] = {record['outputs'][0]: digest}
    _save(path, record)
    check_guard(path)
