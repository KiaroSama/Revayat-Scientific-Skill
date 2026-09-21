"""Use the production process owner for tests that start native helpers."""
from contextlib import redirect_stderr, redirect_stdout
import io
import logging
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/revayat-scientific/scripts'))
from runtime import run_command


def run(command, *, timeout=30, **options):
    # Callers use explicit paths. Retain subprocess.run's small result contract.
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = run_command(list(command), timeout, logging.Logger('test-process'),
                           cwd=options.get('cwd'), env=options.get('env'),
                           idle_timeout=options.get('idle_timeout', min(timeout, 90)))
    return subprocess.CompletedProcess(command, code, stdout.getvalue(), stderr.getvalue())
