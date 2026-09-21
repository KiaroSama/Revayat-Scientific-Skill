"""Bounded subprocess execution and content-free UTC operation logs."""
from contextlib import contextmanager
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time
import uuid


@contextmanager
def operation_log(name: str, directory: Path, *, level=None):
    selected = (level or os.environ.get('REVAYAT_LOG_LEVEL', 'INFO')).upper()
    if selected not in ('DEBUG', 'INFO', 'WARNING', 'ERROR'):
        raise ValueError('REVAYAT_LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR')
    logger = logging.Logger(name, getattr(logging, selected))
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


def run_command(command: list[str], timeout: int, logger: logging.Logger, *, cwd=None,
                env=None, idle_timeout=None) -> int:
    if timeout <= 0 or (idle_timeout is not None and idle_timeout <= 0):
        raise ValueError('process time limits must be positive')
    environment = {**os.environ, **(env or {}), 'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1'}
    environment['PATH'] = str(Path(sys.executable).parent) + os.pathsep + environment.get('PATH', '')
    job = None
    process = None
    readers = []
    if os.name == 'nt':
        from windows_job import WindowsJob
        job = WindowsJob()
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, cwd=cwd, start_new_session=os.name != 'nt',
            creationflags=0x00000004 if job else 0)
        if job:
            job.attach_and_resume(process)
        logger.info('process_started pid=%d', process.pid)
        try:
            events = queue.SimpleQueue()
            budget_lock = threading.Lock()
            captured = 0

            def read_pipe(index, pipe):
                nonlocal captured
                try:
                    while chunk := pipe.read1(8192):
                        with budget_lock:
                            captured += len(chunk)
                            if captured > 32 * 1024 * 1024:
                                raise RuntimeError('tool diagnostics exceeded the 32 MiB limit')
                        events.put((index, chunk))
                except Exception as error:
                    events.put((index, error))
                finally:
                    events.put((index, None))

            for index, pipe in enumerate((process.stdout, process.stderr)):
                reader = threading.Thread(target=read_pipe, args=(index, pipe), daemon=True)
                reader.start()
                readers.append(reader)
            buffers = [[], []]
            finished = 0
            started = progress = time.monotonic()
            while finished < 2 or process.poll() is None:
                now = time.monotonic()
                wall_left = timeout - (now - started)
                if wall_left <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                idle_left = idle_timeout - (now - progress) if idle_timeout is not None else wall_left
                if idle_left <= 0:
                    raise subprocess.TimeoutExpired(command, idle_timeout)
                try:
                    index, chunk = events.get(timeout=min(0.5, wall_left, idle_left))
                except queue.Empty:
                    continue
                if isinstance(chunk, Exception):
                    raise chunk
                if chunk is None:
                    finished += 1
                else:
                    progress = time.monotonic()
                    buffers[index].append(chunk)
            stdout, stderr = (b''.join(chunks) for chunks in buffers)
        except BaseException:
            if job:
                job.close()
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=15)
            logger.error('process_tree_terminated pid=%d', process.pid)
            raise
        # Tool diagnostics may use a legacy codepage; document files and structured
        # results are decoded strictly by their format-specific readers instead.
        sys.stdout.write(stdout.decode('utf-8', errors='replace'))
        sys.stderr.write(stderr.decode('utf-8', errors='replace'))
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
                process.wait(timeout=15)
            for reader in readers:
                reader.join(timeout=5)
            for pipe in (process.stdout, process.stderr):
                if pipe:
                    pipe.close()
