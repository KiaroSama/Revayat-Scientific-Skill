"""Real Windows renderer plus strict-gate and extraction compatibility checks."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from processes import run as owned_run

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/revayat-scientific'
FIXTURES = ROOT / 'tests/fixtures'


class NativeBuildTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'win32', 'PowerShell font verification')
    def test_unicode_font_flag_is_not_embedding(self):
        shell = shutil.which('pwsh') or shutil.which('powershell')
        with tempfile.TemporaryDirectory(prefix='font verification ') as directory:
            script = Path(directory) / 'check.ps1'
            script.write_text('''param([string]$Verifier)
. $Verifier
function Test-PdfStructure { return $true }
function Get-Tool { param($Name) return $Name }
function Write-Log { param($Message) [Console]::Error.WriteLine($Message) }
function Invoke-Tool {
    param($Exe, $Arguments)
    if ($Exe -eq 'pdfinfo') { return [pscustomobject]@{ExitCode=0;Output=@('Pages: 3')} }
    if ($Exe -eq 'pdffonts') {
        return [pscustomobject]@{ExitCode=0;Output=@(
            'name type encoding emb sub uni object ID', '--------------------------------',
            'Example CID TrueType Identity-H no no yes 4 0')}
    }
    throw 'Unembedded fonts must be refused before rasterization'
}
if (Test-OutputPdf 'unused.pdf' $PSScriptRoot 'unused') { exit 1 }
exit 0
''', encoding='utf-8')
            result = owned_run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
                'Bypass', '-File', str(script), str(SKILL / 'scripts/verify-pdf.ps1')], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('no embedded font', result.stderr)

    def test_extraction_uses_utf8(self):
        result = owned_run(
            [sys.executable, str(SKILL / 'scripts/check-pdf-text-order.py'),
             '--source', str(FIXTURES / 'good.tex'), '--extracted',
             str(FIXTURES / 'pdf-text-logical.txt')],
            capture_output=True, text=True, encoding='utf-8', timeout=10,
            env={**os.environ, 'PYTHONIOENCODING': 'utf-8'},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('check-pdf-text-order: logical', result.stderr)

    @unittest.skipUnless(sys.platform == 'win32', 'native Windows build; Linux covers POSIX')
    def test_windows_build_preserves_destination_on_failure(self):
        shell = shutil.which('pwsh') or shutil.which('powershell')
        self.assertIsNotNone(shell, 'PowerShell is required on the Windows runner')
        with tempfile.TemporaryDirectory(prefix='scientific build ') as directory:
            work = Path(directory)
            for source, name in [('build-smoke.html', 'doc.html'),
                                 ('terms-empty.tsv', 'terms.tsv'),
                                 ('manifest-empty.txt', 'manifest.txt')]:
                shutil.copyfile(FIXTURES / source, work / name)
            output = work / 'delivered'
            output.mkdir()
            destination = output / 'article.pdf'
            destination.write_bytes(b'previous approved edition')
            command = [sys.executable, str(SKILL / 'scripts/revayat-scientific.py'),
                       '--timeout', '60', 'build', str(work / 'doc.html'),
                       'article', '--level', 'journal', '--output-dir', str(output)]
            (work / 'terms.tsv').unlink()
            refused = owned_run(command, capture_output=True, text=True,
                                     encoding='utf-8', timeout=20)
            self.assertNotEqual(refused.returncode, 0, refused.stdout)
            self.assertIn('terms.tsv', refused.stderr)
            self.assertEqual(destination.read_bytes(), b'previous approved edition')
            shutil.copyfile(FIXTURES / 'terms-empty.tsv', work / 'terms.tsv')
            built = owned_run(command, capture_output=True, text=True,
                                   encoding='utf-8', timeout=90)
            self.assertEqual(built.returncode, 0, built.stderr)
            self.assertTrue(destination.read_bytes().startswith(b'%PDF-'))
            self.assertIn(b'%%EOF', destination.read_bytes()[-2048:])
            self.assertIsNotNone(shutil.which('pdftoppm'), 'Windows CI must install Poppler')
            verified = owned_run(command + ['--verify'], capture_output=True, text=True,
                                      encoding='utf-8', timeout=90)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            for sample in ['first', 'mid', 'last']:
                self.assertTrue((work / f'verify-article-{sample}.png').is_file(), sample)
            # This probes the actual PDF, not an ASCII stand-in for extraction.
            if shutil.which('pdftotext'):
                ordered = owned_run(
                    [sys.executable, str(SKILL / 'scripts/check-pdf-text-order.py'),
                     str(destination), '--source', str(work / 'doc.html')],
                    capture_output=True, text=True, encoding='utf-8', timeout=20)
                self.assertIn(ordered.returncode, (0, 2), ordered.stderr)
                self.assertNotIn('UnicodeDecodeError', ordered.stderr)


if __name__ == '__main__':
    unittest.main()
