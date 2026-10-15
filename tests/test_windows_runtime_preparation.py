"""Exercise trusted preparation functions, not the native security entry point."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from processes import run as owned_run

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell preparation functions')
class RuntimePreparationTest(unittest.TestCase):
    def test_streaming_validation_copy_progress_and_refusal(self):
        shell = shutil.which('pwsh')
        self.assertIsNotNone(shell, 'PowerShell 7 is required on Windows')
        (ROOT / '.scratch').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='runtime preparation ', dir=ROOT / '.scratch') as directory:
            result = owned_run([
                shell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                str(ROOT / 'tests/security/windows/Check-RuntimePreparation.ps1'),
                '-Root', str(ROOT), '-Work', directory,
            ], timeout=15, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RUNTIME_PREPARATION_FUNCTIONS_OK native_methods_invoked=false', result.stdout)


if __name__ == '__main__':
    unittest.main()
