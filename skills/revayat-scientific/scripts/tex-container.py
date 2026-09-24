#!/usr/bin/env python3
"""Compile approved TeX inputs using a preinstalled, isolated local container."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import csv
import io
import json
import logging
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.parse import urlsplit
import uuid

from document_context import DocumentContext
from publication import publish_files, validate_destination
from runtime import operation_log, run_command
from tex_source import masked_tex, source_closure
from tex_supervisor import acknowledge, records, register

DEFAULT_IMAGE = 'revayat-scientific-tex:1'
IMAGE_LABEL = 'org.revayat.tex.toolchain'
RUN_LABEL = 'org.revayat.tex.run'
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_INPUT_FILES = 512
INNER_TIMEOUT = 120


def call(arguments, logger, timeout=15):
    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = run_command(arguments, timeout, logger, env={
            'DOCKER_CONTEXT': '', 'DOCKER_HOST': '', 'CONTAINER_HOST': '', 'CONTAINER_CONNECTION': ''})
    text = output.getvalue()
    if len(text) > 2 * 1024 * 1024 or '\ufffd' in text:
        raise ValueError('container runtime returned invalid structured output')
    return code, text


def read_json(arguments, logger):
    code, output = call(arguments, logger)
    if code:
        raise RuntimeError('local container runtime query failed')
    return json.loads(output)


def validate_endpoint(endpoint, kind):
    parsed = urlsplit(endpoint)
    if parsed.scheme == 'unix' and not parsed.netloc and parsed.path.startswith('/'):
        return
    if kind == 'docker' and re.fullmatch(r'npipe:////\./pipe/[A-Za-z0-9_.-]+', endpoint):
        return
    if kind == 'podman' and parsed.scheme == 'ssh' and parsed.hostname in ('127.0.0.1', '::1', 'localhost') and parsed.path.startswith('/'):
        return
    raise ValueError('only a local container endpoint is allowed; remote jobs are forbidden')


def runtime_config(logger):
    requested = os.environ.get('REVAYAT_CONTAINER_RUNTIME')
    executable = shutil.which(requested) if requested else (shutil.which('docker') or shutil.which('podman'))
    if not executable:
        raise RuntimeError('Docker or Podman is not available on PATH')
    executable = str(Path(executable).resolve())
    kind = Path(executable).stem.lower()
    if kind not in ('docker', 'podman'):
        raise ValueError('runtime must be Docker or Podman')
    if kind == 'docker':
        context = os.environ.get('DOCKER_CONTEXT')
        endpoint = os.environ.get('DOCKER_HOST') if not context else None
        if not endpoint:
            rows = read_json([executable, 'context', 'inspect', *([context] if context else [])], logger)
            endpoint = rows[0]['Endpoints']['docker']['Host']
        validate_endpoint(endpoint, kind)
        base = [executable, '--host', endpoint]
    elif sys.platform.startswith('linux') and not os.environ.get('CONTAINER_HOST') and not os.environ.get('CONTAINER_CONNECTION'):
        base = [executable, '--remote=false']
    else:
        rows = read_json([executable, 'system', 'connection', 'list', '--format=json'], logger)
        selected = os.environ.get('CONTAINER_CONNECTION')
        endpoint = os.environ.get('CONTAINER_HOST')
        choices = [row for row in rows if row.get('Name') == selected] if selected else [row for row in rows if row.get('Default')]
        if endpoint:
            choices = [row for row in rows if row.get('URI') == endpoint]
        if len(choices) != 1:
            raise ValueError('a single configured local Podman connection is required')
        connection = choices[0]
        endpoint = connection['URI']
        validate_endpoint(endpoint, kind)
        base = [executable, '--url', endpoint]
        if connection.get('Identity'):
            base += ['--identity', connection['Identity']]
    information = read_json([*base, 'info', '--format=json'], logger)
    operating_system = information.get('OSType') if kind == 'docker' else information.get('host', {}).get('os')
    if operating_system != 'linux':
        raise ValueError('the container runtime must use Linux containers')
    image = os.environ.get('REVAYAT_TEX_IMAGE', DEFAULT_IMAGE)
    if not image or image.startswith('-') or any(c.isspace() for c in image):
        raise ValueError('invalid preinstalled TeX image reference')
    images = read_json([*base, 'image', 'inspect', image], logger)
    if len(images) != 1 or (images[0].get('Config', {}).get('Labels') or {}).get(IMAGE_LABEL) != '1':
        raise ValueError('preinstalled TeX image does not declare the supported toolchain')
    # Use immutable identity after inspecting the trusted configured tag.
    image_id = images[0].get('Id') or images[0].get('ID')
    if not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', image_id or ''):
        raise ValueError('container image identity is invalid')
    return {'base': base, 'kind': kind, 'image': image_id}


def approved_files(source):
    source = Path(source).resolve()
    if source.suffix.lower() != '.tex':
        raise ValueError('isolated TeX requires a .tex source')
    root = source.parent
    closure = source_closure(source)
    approved = set(closure.sources)
    context = DocumentContext(source, root, [], None)
    for path in closure.sources:
        text = masked_tex(path.read_text(encoding='utf-8'))
        commands = list(re.finditer(r'\\includegraphics\b\*?', text))
        for command in commands:
            argument = re.match(r'\s*(?:\[[^\]]*\]\s*)?\{([^{}]+)\}', text[command.end():])
            if argument is None or any(c in argument[1] for c in '\\#$%~^&'):
                raise ValueError('graphics require a literal reviewed asset path')
            asset = context.asset(argument[1].strip())
            if asset.suffix.lower() not in ('.pdf', '.png', '.jpg', '.jpeg'):
                raise ValueError('container graphics must be PDF, PNG or JPEG')
            approved.add(asset)
    # Only the dedicated local font directory is approved, never the whole job.
    fonts = root / 'fonts'
    if fonts.exists():
        if fonts.is_symlink() or not fonts.is_dir():
            raise ValueError('local font directory must not be linked')
        for path in fonts.iterdir():
            if path.suffix.lower() in ('.ttf', '.otf'):
                approved.add(path)
    result, size = [], 0
    for path in sorted(approved):
        resolved = path.resolve()
        if not resolved.is_relative_to(root) or not path.is_file():
            raise ValueError('approved asset leaves the document root')
        if any(p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction())
               for p in (path, *path.parents) if p == root or root in p.parents):
            raise ValueError('approved input paths must not contain links')
        relative = resolved.relative_to(root)
        if any(char in str(relative) for char in '\r\n\x00'):
            raise ValueError('invalid document path')
        size += path.stat().st_size
        if size > MAX_INPUT_BYTES or len(result) >= MAX_INPUT_FILES:
            raise ValueError('approved TeX input set exceeds its size limit')
        result.append((resolved, relative))
    return result


def mount_argument(source, target, readonly=False):
    buffer = io.StringIO()
    values = ['type=bind', 'src=' + str(Path(source).resolve()), 'dst=' + target]
    if readonly:
        values.append('readonly')
    csv.writer(buffer, lineterminator='').writerow(values)
    return buffer.getvalue()


def run_arguments(config, directory, source_name, run_id):
    command = [*config['base'], 'run', '--rm', '--pull=never', '--name', 'revayat-tex-' + run_id,
               '--label', RUN_LABEL + '=' + run_id, '--cidfile', str(directory / 'container.cid'),
               '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
               '--pids-limit=64', '--memory=1g', '--memory-swap=1g', '--cpus=2',
               '--ulimit', 'fsize=268435456:268435456', '--ulimit', 'nofile=128:128',
               '--log-driver=none',
               '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=268435456', '--workdir=/input',
               '--mount', mount_argument(directory / 'input', '/input', True),
               '--mount', mount_argument(directory / 'output', '/output'),
               '--env', 'HOME=/tmp/tex-home', '--env', 'TEXMFVAR=/tmp/tex-var',
               '--env', 'TEXMFCONFIG=/tmp/tex-config', '--env', 'TEXMFOUTPUT=/output',
               '--entrypoint=/usr/bin/timeout']
    uid = os.getuid() if sys.platform.startswith('linux') else 65532
    gid = os.getgid() if sys.platform.startswith('linux') else 65532
    if config['kind'] == 'podman' and sys.platform.startswith('linux') and uid:
        command += ['--userns=keep-id']
    command += ['--user', f'{uid or 65532}:{gid or 65532}', config['image'], '--signal=TERM',
                '--kill-after=5s', f'{INNER_TIMEOUT}s', '/usr/local/bin/revayat-tex-entry', '/input/' + source_name]
    return command


def cleanup(config, directory, run_id, logger, require_receipt=False):
    base = config['base']
    listing = [*base, 'ps', '-a', '--filter', 'label=' + RUN_LABEL + '=' + run_id,
               '--no-trunc', '--format', '{{.ID}}']
    code, text = call(listing, logger)
    if code:
        raise RuntimeError('cannot verify owned container cleanup')
    identifiers = text.split()
    cid = directory / 'container.cid'
    expected = cid.read_text(encoding='utf-8').strip() if cid.exists() else None
    if require_receipt and expected is None and not identifiers:
        raise RuntimeError('container launch outcome is unknown; ownership evidence retained')
    if expected is not None and not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise RuntimeError('invalid owned-container receipt; cleanup evidence retained')
    if expected and expected not in identifiers:
        code, all_ids = call([*base, 'ps', '-a', '--no-trunc', '--format', '{{.ID}}'], logger)
        if code or expected in all_ids.split():
            raise RuntimeError('CID container cannot be verified through its ownership label')
    for identifier in identifiers:
        if not re.fullmatch(r'[0-9a-f]{64}', identifier) or (expected and identifier != expected):
            raise RuntimeError('owned-container identity mismatch')
        records = read_json([*base, 'inspect', identifier], logger)
        record = records[0]
        if ((record.get('Config', {}).get('Labels') or {}).get(RUN_LABEL) != run_id
                or record.get('Name', '').lstrip('/') != 'revayat-tex-' + run_id
                or (record.get('Id') or record.get('ID')) != identifier):
            raise RuntimeError('refusing to remove a container without matching ownership')
        code, _ = call([*base, 'rm', '--force', identifier], logger)
        if code:
            raise RuntimeError('owned container removal failed')
    code, remaining = call(listing, logger)
    if code or remaining.strip():
        raise RuntimeError('owned container cleanup could not be confirmed')


def cleanup_receipts(directory, token, logger):
    planned = list(records(directory, token))
    for receipt, item, staging in planned:
        config = item['config']
        if not isinstance(config, dict) or set(config) != {'base', 'kind', 'image'}:
            raise ValueError('invalid container recovery configuration')
        base, kind = config['base'], config['kind']
        if (not isinstance(base, list) or not all(isinstance(value, str) for value in base)
                or not base or not Path(base[0]).is_absolute() or not Path(base[0]).is_file()
                or kind not in ('docker', 'podman') or Path(base[0]).stem.lower() != kind):
            raise ValueError('invalid recovery runtime identity')
        if kind == 'docker':
            if len(base) != 3 or base[1] != '--host':
                raise ValueError('invalid Docker recovery endpoint')
            validate_endpoint(base[2], kind)
        elif base[1:] != ['--remote=false']:
            if len(base) not in (3, 5) or base[1] != '--url' or (len(base) == 5 and base[3] != '--identity'):
                raise ValueError('invalid Podman recovery endpoint')
            validate_endpoint(base[2], kind)
        if not re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', config['image']):
            raise ValueError('invalid recovery image identity')
    for receipt, item, staging in planned:
        cleanup(item['config'], staging, item['run_id'], logger, require_receipt=True)
        shutil.rmtree(staging)
        acknowledge(receipt)
    logger.info('supervised_container_cleanup receipts=%d', len(planned))


def compile_document(source, output, logger):
    # Endpoint/image readiness precedes even reading the document.
    config = runtime_config(logger)
    logger.info('container_runtime=%s image=%s', config['kind'], config['image'])
    source, output = Path(source).resolve(), Path(output).absolute()
    inputs = approved_files(source)
    validate_destination(output, [path for path, _ in inputs])
    output.parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='.revayat-tex-', dir=output.parent))
    run_id = uuid.uuid4().hex
    keep = False
    receipt = None
    try:
        incoming, outgoing = directory / 'input', directory / 'output'
        incoming.mkdir(mode=0o755)
        outgoing.mkdir(mode=0o777)
        outgoing.chmod(0o777)
        for original, relative in inputs:
            target = incoming / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
            # The mount enforces RO. Windows read-only attributes prevent cleanup.
            target.chmod(0o644)
        try:
            receipt = register(config, directory, run_id)
            code, _ = call(run_arguments(config, directory, source.name, run_id), logger, timeout=INNER_TIMEOUT + 30)
            if code:
                raise RuntimeError(f'isolated XeLaTeX failed or exceeded its deadline (exit_code={code})')
        finally:
            try:
                cleanup(config, directory, run_id, logger)
                acknowledge(receipt)
            except BaseException:
                keep = True
                (directory / 'recovery.json').write_text(json.dumps({'run_id': run_id,
                    'container_name': 'revayat-tex-' + run_id,
                    'status': 'cleanup_not_verified'}, indent=2) + '\n', encoding='utf-8')
                raise RuntimeError('container cleanup failed; retained evidence: ' + str(directory))
        pdf = outgoing / 'document.pdf'
        if pdf.is_symlink() or not pdf.is_file() or pdf.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError('container did not produce a safe bounded PDF')
        import pymupdf
        with pymupdf.open(pdf) as document:
            if not document.is_pdf or document.needs_pass or document.page_count < 1 or document.is_repaired:
                raise ValueError('isolated renderer produced an invalid or repaired PDF')
            for page in document:
                if page.rect.is_empty or page.rect.is_infinite:
                    raise ValueError('isolated renderer produced invalid page geometry')
        publish_files([(pdf, output)], protected_sources=[path for path, _ in inputs])
        logger.info('isolated_tex_published input_files=%d', len(inputs))
    finally:
        if not keep:
            shutil.rmtree(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', action='store_true')
    parser.add_argument('--cleanup-receipts', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--owner-token', help=argparse.SUPPRESS)
    parser.add_argument('source', nargs='?', type=Path)
    parser.add_argument('output', nargs='?', type=Path)
    args = parser.parse_args(argv)
    with operation_log('tex-container', Path(__file__).resolve().parent / 'logs') as logger:
        if args.cleanup_receipts is not None:
            cleanup_receipts(args.cleanup_receipts, args.owner_token, logger)
            return 0
        if args.probe:
            try:
                config = runtime_config(logger)
                print(json.dumps({'available': True, 'runtime': config['kind'], 'image': config['image']}))
                return 0
            except Exception as error:
                print(json.dumps({'available': False, 'reason': str(error)}))
                return 2
        if args.source is None or args.output is None:
            parser.error('SOURCE and OUTPUT are required')
        compile_document(args.source, args.output, logger)
    print(args.output)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'tex-container: {type(error).__name__}: {error}', file=sys.stderr)
        raise SystemExit(2)
