"""Host-only receipts let a surviving process owner reap its TeX containers."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid

DIRECTORY_ENV = 'REVAYAT_TEX_OWNER_DIR'
TOKEN_ENV = 'REVAYAT_TEX_OWNER_TOKEN'
TOKEN = re.compile(r'[a-f0-9]{32}\Z')


def regular_path(path):
    path = Path(path).absolute()
    if any(part.is_symlink() or (hasattr(part, 'is_junction') and part.is_junction())
           for part in (path, *path.parents)):
        raise ValueError('container ownership paths must not contain links')
    return path


def read_json(path, limit=65536):
    path = regular_path(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError('invalid bounded container ownership record')
    return json.loads(path.read_text(encoding='utf-8'))


def validate_scope(directory, token):
    directory = regular_path(directory)
    if (not TOKEN.fullmatch(token or '') or directory.name != '.revayat-tex-owner-' + token
            or not directory.is_dir() or read_json(directory / 'scope.json', 4096) != {'token': token}):
        raise ValueError('container ownership scope identity mismatch')
    return directory


def register(config, staging, run_id):
    directory, token = os.environ.get(DIRECTORY_ENV), os.environ.get(TOKEN_ENV)
    if not directory and not token:
        return None
    owner = validate_scope(directory, token)
    if not TOKEN.fullmatch(run_id):
        raise ValueError('invalid container run identity')
    staging = regular_path(staging)
    if not staging.name.startswith('.revayat-tex-') or not staging.is_dir():
        raise ValueError('invalid owned staging directory')
    record = {'token': token, 'run_id': run_id, 'staging': str(staging), 'config': config}
    (staging / 'owner.json').write_text(json.dumps({'token': token, 'run_id': run_id}), encoding='utf-8')
    path = owner / ('container-' + run_id + '.json')
    temporary = path.with_suffix('.pending')
    with temporary.open('x', encoding='utf-8') as handle:
        json.dump(record, handle)
    os.replace(temporary, path)
    return path


def acknowledge(receipt):
    if receipt is not None:
        regular_path(receipt).unlink()


def records(directory, token):
    root = validate_scope(directory, token)
    paths = sorted(root.rglob('container-*.json'))
    if len(paths) > 256:
        raise ValueError('container ownership receipt limit exceeded')
    for path in paths:
        owner = regular_path(path.parent)
        if not owner.is_relative_to(root):
            raise ValueError('container receipt leaves its owner scope')
        item = read_json(path)
        if set(item) != {'token', 'run_id', 'staging', 'config'}:
            raise ValueError('unexpected container receipt fields')
        validate_scope(owner, item['token'])
        if not TOKEN.fullmatch(item['run_id']) or path.name != 'container-' + item['run_id'] + '.json':
            raise ValueError('container receipt run identity mismatch')
        staging = regular_path(item['staging'])
        if (not staging.name.startswith('.revayat-tex-') or not staging.is_dir()
                or read_json(staging / 'owner.json', 4096) != {'token': item['token'], 'run_id': item['run_id']}):
            raise ValueError('container staging ownership mismatch')
        yield path, item, staging


def sweep(directory, token, logger):
    if not list(records(directory, token)):
        return
    from runtime import run_command
    command = [sys.executable, str(Path(__file__).with_name('tex-container.py')),
               '--cleanup-receipts', str(directory), '--owner-token', token]
    code = run_command(command, 90, logger)
    if code:
        raise RuntimeError('owned container cleanup did not complete')
    if list(records(directory, token)):
        raise RuntimeError('owned container receipts remain after cleanup')


@contextmanager
def container_scope(logger, environment, cwd=None):
    parent, token = environment.get(DIRECTORY_ENV), environment.get(TOKEN_ENV)
    base = validate_scope(parent, token) if parent or token else regular_path(cwd or Path.cwd())
    identity = uuid.uuid4().hex
    directory = base / ('.revayat-tex-owner-' + identity)
    directory.mkdir(mode=0o700)
    (directory / 'scope.json').write_text(json.dumps({'token': identity}), encoding='utf-8')
    try:
        yield {**environment, DIRECTORY_ENV: str(directory), TOKEN_ENV: identity}
    finally:
        try:
            sweep(directory, identity, logger)
        except BaseException as error:
            # Ancestor scopes can still discover nested receipts after this owner
            # is killed. Failed recovery evidence must never be deleted here.
            logger.error('container_cleanup_unverified recovery=%s', directory)
            raise RuntimeError('container cleanup unverified; retained ownership evidence: ' + str(directory)) from error
        else:
            shutil.rmtree(validate_scope(directory, identity))
