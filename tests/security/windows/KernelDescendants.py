"""Fixed ordinary-token and resource-control children using confined standard handles."""
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

transport = runpy.run_path(str(Path(__file__).with_name('RegistryDescendant.py')))
require = transport['require']


def _options(handles):
    startup = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESTDHANDLES,
        hStdInput=handles[0], hStdOutput=handles[1], hStdError=handles[2],
        lpAttributeList={'handle_list': list(handles)})
    return dict(stdin=None, stdout=None, stderr=None, startupinfo=startup,
                close_fds=True, creationflags=subprocess.DETACHED_PROCESS,
                env=dict(os.environ), cwd=os.getcwd())


def _spawn_token(handles):
    arguments = [sys.executable, '-I', '-B', '-X', 'utf8',
                 str(Path(__file__).with_name('KernelProbe.py')), *sys.argv[1:7], 'token-child']
    return subprocess.Popen(arguments, **_options(handles))


def token_child():
    require(len(sys.argv) == 7)
    try:
        return transport['_run'](transport['Native'](), _spawn_token, time.monotonic, 65535)
    except transport['CaptureFailure'] as failure:
        failure.stderr[:] = b'\0' * len(failure.stderr)
        raise


class Standards:
    """Duplicate only the inherited NUL/pipe standards; never own their originals."""
    def __init__(self):
        self.api = transport['Native']()
        self.handles = []
        self.end = time.monotonic() + 5
        self.ready = False

    def _check(self):
        if time.monotonic() >= self.end:
            raise TimeoutError('fixed standard-handle preparation deadline exceeded')

    def _own(self, handle):
        if type(handle) is int and 0 < handle < 0x7FFFFFFFFFFFFFFF:
            require(handle not in self.handles)
            self.handles.append(handle)
        return handle

    def _close(self, original):
        failures = []
        for handle in tuple(self.handles):
            self.handles.remove(handle)
            try:
                self.api.close(handle)
            except Exception as error:
                failures.append(error)
        self.ready = False
        if failures:
            raise transport['CaptureFailure'](original, failures, None, b'')

    def __enter__(self):
        try:
            for identifier, kind in ((0xFFFFFFF6, 2), (0xFFFFFFF5, 3), (0xFFFFFFF4, 3)):
                self.api.standard(identifier, kind, self._own, self._check)
            self.api.standards(self.handles)
            self.ready = True
            return self
        except Exception as error:
            self._close(error)
            raise

    def __exit__(self, kind, error, trace):
        self._close(error)
        return False

    def prepare(self, role):
        require(self.ready and role in ('wall', 'pid-hold', 'pid-extra'))
        self._check()
        code = {'wall': 'import time; time.sleep(30)', 'pid-hold': 'import time; time.sleep(10)',
                'pid-extra': 'raise SystemExit(0)'}[role]
        return ([sys.executable, '-I', '-B', '-c', code],), _options(self.handles)
