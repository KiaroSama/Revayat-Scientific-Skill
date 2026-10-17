#!/usr/bin/env python3
"""Run the finite Linux security tier through a prepared local Docker image."""
import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
LABEL = 'org.revayat.security.run'
MAX_OUTPUT = 1024 * 1024


def command(arguments, logger, timeout=15, idle_timeout=20):
    chunks, overflow = [], threading.Event()
    started = time.monotonic()
    progress = [started]
    safe = {key: value for key, value in os.environ.items()
            if key in ('PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'HOME')}
    safe.update(DOCKER_HOST='', DOCKER_CONTEXT='', PYTHONUTF8='1')
    child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=safe)

    def drain():
        total = 0
        while data := child.stdout.read1(8192):
            total += len(data)
            if total > MAX_OUTPUT:
                overflow.set()
                child.kill()
                break
            chunks.append(data)
            progress[0] = time.monotonic()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        while child.poll() is None:
            now = time.monotonic()
            if now - started > timeout or now - progress[0] > idle_timeout:
                raise RuntimeError('security controller wall/idle deadline exceeded')
            time.sleep(0.05)
        child.wait(timeout=5)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        reader.join(timeout=5)
        child.stdout.close()
    if reader.is_alive() or overflow.is_set():
        raise RuntimeError('security controller diagnostic bound exceeded')
    text = b''.join(chunks).decode('utf-8', errors='strict')
    logger.info('command_completed exit_code=%d', child.returncode)
    return child.returncode, text


def checked(arguments, logger, timeout=15):
    code, output = command(arguments, logger, timeout)
    if code:
        raise RuntimeError('security controller command failed: ' + output[-2048:])
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='revayat-scientific-security:1')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,150}', args.image):
        raise ValueError('invalid prepared image name')
    docker = shutil.which('docker')
    if not docker or os.name == 'nt':
        raise RuntimeError('security tier requires local Linux Docker')
    logs = ROOT / 'logs'
    logs.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')
    log_path = logs / ('security-ci_' + stamp + '_UTC.log')
    if log_path.exists():
        log_path = logs / ('security-ci_' + stamp + '_UTC_' + uuid.uuid4().hex[:8] + '.log')
    logger = logging.Logger('security-ci', logging.INFO)
    try:
        handler = logging.FileHandler(log_path, mode='x', encoding='utf-8')
    except OSError:
        handler = logging.StreamHandler()
        print('security-ci: file logging unavailable; using stderr')
    formatter = logging.Formatter('[%(asctime)s UTC] [%(levelname)s] [%(name)s] %(message)s', '%Y-%m-%d %H:%M:%S')
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    run_id = uuid.uuid4().hex
    name = 'revayat-security-' + run_id
    started = time.monotonic()
    base = [docker, '--context', 'default']
    launched = False
    scratch = ROOT / '.scratch'
    scratch.mkdir(exist_ok=True)
    view = tempfile.TemporaryDirectory(prefix='security public view ', dir=scratch)
    try:
        logger.info('started run_id=%s', run_id)
        context = json.loads(checked(base + ['context', 'inspect', 'default'], logger))[0]
        endpoint = context.get('Endpoints', {}).get('docker', {}).get('Host', '')
        if not endpoint.startswith('unix:///'):
            raise RuntimeError('security tier refuses a non-local Docker endpoint')
        info = json.loads(checked(base + ['info', '--format', '{{json .}}'], logger))
        if info.get('OSType') != 'linux' or info.get('CgroupVersion') != '2':
            raise RuntimeError('security tier requires Linux cgroup v2')
        image = json.loads(checked(base + ['image', 'inspect', args.image], logger))[0]
        image_id = image.get('Id', '')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
            raise RuntimeError('security image has no immutable identity')
        public = Path(view.name)
        # Runtime bind mounts do not use .dockerignore. Copy only the public
        # source/fixture roots; never expose assistant state, VCS or private jobs.
        tracked = checked(['git', '-C', str(ROOT), 'ls-files', '-z'], logger).split('\0')
        # Newly authored files are explicit, not an untracked directory scan.
        harness = ('README.md', 'coverage.json', 'Dockerfile', 'linux_probe.py',
                   'linux_entry.sh', 'linux_worker.py', 'admissions.py', 'tex_output.py')
        names = set(tracked) | {'tests/security/' + name for name in harness}
        for relative in sorted(names):
            if not relative.startswith(('skills/revayat-scientific/', 'tests/security/')):
                continue
            parts = Path(relative).parts
            if (Path(relative).is_absolute() or '..' in parts
                    or any(part.startswith('.') or part in ('logs', '__pycache__', 'secrets.md',
                                                            'explain-AI.md') for part in parts)):
                raise ValueError('private source cannot enter security view')
            source = ROOT / relative
            for item in (source, *source.parents):
                if item == ROOT.parent:
                    break
                info = item.lstat()
                if item.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                    raise ValueError('linked source cannot enter security view')
            if not source.is_file():
                raise ValueError('security source must be a regular file')
            destination = public / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o444)
        for directory in public.rglob('*'):
            if directory.is_dir():
                directory.chmod(0o555)
        empty = public / 'empty-device-directory'
        empty.mkdir(mode=0o555)
        public.chmod(0o555)
        mount = 'type=bind,src=' + str(public) + ',dst=/target,readonly'
        if ',' in str(public):
            raise ValueError('security checkout path cannot contain a comma')
        run = base + ['run', '--pull=never', '--name', name, '--label', LABEL + '=' + run_id,
                      '--network=none', '--read-only', '--cap-drop=ALL',
                      '--security-opt=no-new-privileges', '--user=65532:65532',
                      '--cpus=2', '--memory=1g', '--memory-swap=1g', '--pids-limit=64',
                      '--ulimit=fsize=67108864:67108864', '--ulimit=nofile=128:128',
                      '--log-driver=none', '--tmpfs=/scratch:rw,nosuid,nodev,noexec,size=134217728,mode=1777',
                      '--mount', mount,
                      '--mount', 'type=bind,src=' + str(empty) + ',dst=/dev/shm,readonly',
                      '--mount', 'type=bind,src=' + str(empty) + ',dst=/dev/mqueue,readonly',
                      image_id]
        launched = True
        code, output = command(run, logger, timeout=110)
        print(output, end='')
        if code:
            raise RuntimeError('isolated security scenarios failed exit_code=' + str(code))
        if '"phase": "preflight", "status": "passed"' not in output:
            raise RuntimeError('missing native isolation preflight evidence')
        if '"phase": "scenarios", "status": "passed"' not in output:
            raise RuntimeError('missing security scenario evidence')
        logger.info('security_tier_completed image_id=%s', image_id)
    finally:
        try:
            if launched:
                receipt = json.loads(checked(base + ['inspect', name], logger))[0]
                if (receipt.get('Config', {}).get('Labels', {}).get(LABEL) != run_id
                        or receipt.get('Name') != '/' + name
                        or not re.fullmatch(r'[0-9a-f]{64}', receipt.get('Id', ''))):
                    raise RuntimeError('security container ownership is ambiguous')
                checked(base + ['rm', '--force', receipt['Id']], logger)
                remaining = checked(base + ['ps', '--all', '--quiet', '--filter', 'label=' + LABEL + '=' + run_id], logger)
                if remaining.strip():
                    raise RuntimeError('owned security container survived cleanup')
                logger.info('owned_cleanup_completed')
        finally:
            logger.info('finished duration_seconds=%.3f', time.monotonic() - started)
            handler.close()
            logger.removeHandler(handler)
            for directory in Path(view.name).rglob('*'):
                if directory.is_dir():
                    directory.chmod(0o700)
            Path(view.name).chmod(0o700)
            view.cleanup()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print('security-ci: ' + str(error))
        raise SystemExit(1)
