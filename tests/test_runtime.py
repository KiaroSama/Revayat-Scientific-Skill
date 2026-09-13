"""A dead launcher must not leave a live descendant holding its output pipes."""
import ctypes
from ctypes import wintypes
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/revayat-scientific/scripts'))
from runtime import run_command


class ProcessOwnershipTest(unittest.TestCase):
    def test_timeout_terminates_descendant_after_launcher_exits(self):
        with tempfile.TemporaryDirectory(prefix='revayat process ') as directory:
            pid_file = Path(directory) / 'child.txt'
            program = (
                'import subprocess,sys; from pathlib import Path; '
                'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"],'
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
