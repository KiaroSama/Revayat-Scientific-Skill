"""Real Windows renderer plus strict-gate and extraction compatibility checks."""
import os
import json
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
    @classmethod
    def setUpClass(cls):
        (ROOT / '.scratch').mkdir(exist_ok=True)

    def test_presentation_forms_preserve_logical_order(self):
        # Captured from the real Vazirmatn/XeLaTeX fixture, not reversed to fit the check.
        result = owned_run([sys.executable, str(SKILL / 'scripts/check-pdf-text-order.py'),
            '--source', str(FIXTURES / 'build-smoke-body.tex'), '--extracted',
            str(FIXTURES / 'pdf-text-presentation.txt')], timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('check-pdf-text-order: logical', result.stderr)

    @unittest.skipUnless(sys.platform == 'win32', 'PowerShell font verification')
    def test_unicode_font_flag_is_not_embedding(self):
        with tempfile.TemporaryDirectory(prefix='font verification ', dir=ROOT / '.scratch') as directory:
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
            for name in ('pwsh', 'powershell'):
                with self.subTest(shell=name):
                    shell = shutil.which(name)
                    self.assertIsNotNone(shell, f'{name} is required by the Windows compatibility matrix')
                    result = owned_run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
                        'Bypass', '-File', str(script), str(SKILL / 'scripts/verify-pdf.ps1')], timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('no embedded font', result.stderr)

    @unittest.skipUnless(sys.platform == 'win32', 'native Windows PowerShell compatibility')
    def test_windows_shells_refuse_missing_container_without_changing_delivery(self):
        with tempfile.TemporaryDirectory(prefix='shell compatibility فارسی ', dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            source = work / 'document.tex'
            shutil.copyfile(SKILL / 'assets/rtl-document.tex', source)
            shutil.copyfile(FIXTURES / 'terms-empty.tsv', work / 'terms.tsv')
            shutil.copyfile(FIXTURES / 'manifest-empty.txt', work / 'manifest.txt')
            delivery = work / 'delivery'
            delivery.mkdir()
            output = delivery / 'article.pdf'
            output.write_bytes(b'previous approved delivery')
            for name in ('pwsh', 'powershell'):
                with self.subTest(shell=name):
                    shell = shutil.which(name)
                    self.assertIsNotNone(shell, f'{name} is required by the Windows compatibility matrix')
                    result = owned_run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
                        'Bypass', '-File', str(SKILL / 'scripts/build-pdf.ps1'), str(source),
                        'article', '-Engine', 'tex', '-Level', 'journal',
                        '-OutputDirectory', str(delivery)], timeout=20,
                        env={'REVAYAT_CONTAINER_RUNTIME': str(work / 'missing-container.exe')})
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn('explicit PDF engine is unavailable: tex', result.stderr)
                    self.assertEqual(output.read_bytes(), b'previous approved delivery')
                    self.assertFalse((work / 'document.pdf').exists())

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
        self.assertIsNotNone(shutil.which('pwsh'), 'PowerShell 7 is required for the real Windows render')
        with tempfile.TemporaryDirectory(prefix='scientific build فارسی ', dir=ROOT / '.scratch') as directory:
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
            import pymupdf
            with pymupdf.open(destination) as document:
                self.assertFalse(document.is_repaired)
                self.assertEqual(document.page_count, 3)
            previous = destination.read_bytes()
            ordered = owned_run([sys.executable, str(SKILL / 'scripts/check-pdf-text-order.py'),
                str(destination), '--source', str(work / 'doc.html'), '--json'], timeout=20)
            self.assertIn(ordered.returncode, (0, 2, 3), ordered.stderr)
            order = json.loads(ordered.stdout)
            self.assertIsNotNone(shutil.which('pdftoppm'), 'Windows CI must install Poppler')
            verified = owned_run(command + ['--verify'], capture_output=True, text=True,
                                      encoding='utf-8', timeout=90)
            if order['status'] == 'passed':
                self.assertEqual(verified.returncode, 0, verified.stderr)
            else:
                self.assertNotEqual(verified.returncode, 0, verified.stderr)
                self.assertIn('text extraction order', verified.stderr)
                self.assertEqual(destination.read_bytes(), previous)
            for sample in ['first', 'mid', 'last']:
                self.assertTrue((work / f'verify-article-{sample}.png').is_file(), sample)
            self.assertNotIn('UnicodeDecodeError', ordered.stderr)


if __name__ == '__main__':
    unittest.main()
