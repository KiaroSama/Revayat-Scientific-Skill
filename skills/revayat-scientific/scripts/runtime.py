"""Bounded subprocess execution and content-free UTC operation logs."""
from contextlib import contextmanager
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid


@contextmanager
def operation_log(name: str, directory: Path):
    logger = logging.Logger(name, logging.INFO)
    formatter = logging.Formatter('[%(asctime)s UTC] [%(levelname)s] [%(name)s] %(message)s',
                                  '%Y-%m-%d %H:%M:%S')
    formatter.converter = time.gmtime
    handler = None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H-%M-%S')
        path = directory / f'{name}_{stamp}_UTC.log'
        if path.exists():
            path = directory / f'{name}_{stamp}_UTC_{uuid.uuid4().hex[:8]}.log'
        handler = logging.FileHandler(path, mode='x', encoding='utf-8')
    except OSError:
        print(f'{name}: file logging unavailable; using stderr', file=sys.stderr)
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info('started python=%s platform=%s', sys.version.split()[0], sys.platform)
    started = time.monotonic()
    try:
        yield logger
    except BaseException as error:
        # Exception messages and process output can contain private document text.
        logger.error('failed type=%s', type(error).__name__)
        raise
    finally:
        logger.info('finished duration_seconds=%.3f', time.monotonic() - started)
        handler.flush()
        handler.close()
        logger.removeHandler(handler)


def run_command(command: list[str], timeout: int, logger: logging.Logger, *, cwd=None, env=None) -> int:
    environment = {**os.environ, **(env or {}), 'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1',
                   'PATH': str(Path(sys.executable).parent) + os.pathsep + os.environ.get('PATH', '')}
    job = None
    process = None
    if os.name == 'nt':
        from windows_job import WindowsJob
        job = WindowsJob()
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8',
            env=environment, cwd=cwd, start_new_session=os.name != 'nt',
            creationflags=0x00000004 if job else 0)
        if job:
            job.attach_and_resume(process)
        logger.info('process_started pid=%d', process.pid)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            if job:
                job.close()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.communicate(timeout=15)
            logger.error('process_tree_terminated pid=%d', process.pid)
            raise
        sys.stdout.write(stdout)
        sys.stderr.write(stderr)
        logger.log(logging.INFO if process.returncode == 0 else logging.ERROR,
                   'process_finished pid=%d exit_code=%d', process.pid, process.returncode)
        return process.returncode
    finally:
        if job:
            job.close()
        if process is not None:
            if os.name != 'nt':
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=15)
