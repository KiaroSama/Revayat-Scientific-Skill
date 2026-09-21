"""A dead launcher must not leave a live descendant holding its output pipes."""
import ctypes
from contextlib import redirect_stdout, redirect_stderr
import io
from ctypes import wintypes
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/revayat-scientific/scripts'))
from runtime import operation_log, run_command


class ProcessOwnershipTest(unittest.TestCase):
    def test_idle_deadline_is_distinct_from_wall_deadline(self):
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            run_command([sys.executable, '-c', 'import threading; threading.Event().wait()'],
                        5, logging.Logger('idle-test'), idle_timeout=0.2)
        self.assertEqual(caught.exception.timeout, 0.2)

    def test_environment_and_diagnostic_bytes_preserve_exit_code(self):
        output, errors = io.StringIO(), io.StringIO()
        program = ('import os,sys; '
                   'print(os.environ["PATH"], flush=True); '
                   'sys.stdout.buffer.write(bytes([255])); '
                   'sys.stderr.buffer.write(bytes([254])); sys.exit(7)')
        with redirect_stdout(output), redirect_stderr(errors):
            result = run_command([sys.executable, '-c', program], 5,
                                 logging.Logger('diagnostic-test'), env={'PATH': 'caller-path'})
        self.assertEqual(result, 7)
        self.assertIn(os.pathsep + 'caller-path', output.getvalue())
        self.assertIn('\ufffd', output.getvalue())
        self.assertIn('\ufffd', errors.getvalue())

    def test_debug_file_logging_is_explicit_utf8(self):
        root = Path(__file__).resolve().parents[1] / '.scratch'
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as directory:
            with operation_log('probe', Path(directory), level='DEBUG') as logger:
                logger.debug('phase=prepare')
                logger.warning('count=0')
            text = next(Path(directory).glob('*.log')).read_text(encoding='utf-8')
            self.assertIn('[DEBUG] [probe] phase=prepare', text)
            self.assertIn('[WARNING] [probe] count=0', text)

    def test_timeout_terminates_descendant_after_launcher_exits(self):
        with tempfile.TemporaryDirectory(prefix='revayat process ') as directory:
            pid_file = Path(directory) / 'child.txt'
            program = (
                'import subprocess,sys; from pathlib import Path; '
                'child=subprocess.Popen([sys.executable,"-c","import threading; threading.Event().wait()"],'
                'stdout=sys.stdout,stderr=sys.stderr); '
                'Path(sys.argv[1]).write_text(str(child.pid),encoding="utf-8")'
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                run_command([sys.executable, '-c', program, str(pid_file)], 1,
                            logging.Logger('ownership-test'))
            child = int(pid_file.read_text(encoding='utf-8'))
            if os.name == 'nt':
                api = ctypes.WinDLL('kernel32', use_last_error=True)
                api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
                api.OpenProcess.restype = wintypes.HANDLE
                api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
                api.CloseHandle.argtypes = [wintypes.HANDLE]
                handle = api.OpenProcess(0x00100000, False, child)
                if handle:
                    try:
                        self.assertEqual(api.WaitForSingleObject(handle, 5000), 0)
                    finally:
                        api.CloseHandle(handle)
            else:
                result = subprocess.run(['ps', '-o', 'stat=', '-p', str(child)],
                    capture_output=True, text=True, encoding='utf-8', timeout=5)
                self.assertTrue(not result.stdout.strip() or result.stdout.strip().startswith('Z'), result.stdout)


if __name__ == '__main__':
    unittest.main()
