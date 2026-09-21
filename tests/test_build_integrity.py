"""Real browser rendering must reject denied resources without replacing delivery."""
import os
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from processes import run

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'


def browser_path():
    explicit = os.environ.get('REVAYAT_CHROMIUM')
    if explicit:
        return explicit
    for name in ('msedge', 'chrome', 'google-chrome', 'chromium'):
        if shutil.which(name):
            return shutil.which(name)
    for base in ('ProgramFiles', 'ProgramFiles(x86)', 'LOCALAPPDATA'):
        for relative in ('Microsoft/Edge/Application/msedge.exe', 'Google/Chrome/Application/chrome.exe'):
            candidate = Path(os.environ.get(base, '')) / relative
            if candidate.is_file():
                return str(candidate)
    return None


class BuildIntegrityTest(unittest.TestCase):
    def test_failed_or_invalid_renderer_cannot_replace_delivery(self):
        import pymupdf
        spec = importlib.util.spec_from_file_location('render_contract', SCRIPTS / 'render-html.py')
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        (ROOT / '.scratch').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            source, output = work / 'document.html', work / 'approved.pdf'
            source.write_text('<html lang="fa" dir="rtl"><p>متن علمی</p></html>', encoding='utf-8')
            output.write_bytes(b'previous approved delivery')
            original = output.read_bytes()
            for outcome in ('nonzero-valid', 'zero-missing', 'zero-truncated', 'changed-source'):
                def worker(command, *unused):
                    stage = Path(command[3])
                    if outcome != 'zero-missing':
                        with pymupdf.open() as document:
                            document.new_page()
                            document.save(stage)
                        if outcome == 'zero-truncated':
                            stage.write_bytes(b'%PDF-1.7\ntruncated')
                    stage.with_suffix('.resources.json').write_text(json.dumps({str(source):
                        hashlib.sha256(source.read_bytes()).hexdigest()}), encoding='utf-8')
                    if outcome == 'changed-source':
                        source.write_text('<html>changed</html>', encoding='utf-8')
                    return 1 if outcome == 'nonzero-valid' else 0
                with self.subTest(outcome=outcome), patch.object(renderer, 'run_command', side_effect=worker):
                    if outcome == 'nonzero-valid':
                        self.assertEqual(renderer.main([str(source), str(output), '--engine', 'weasyprint']), 1)
                    else:
                        with self.assertRaises((OSError, ValueError, RuntimeError)):
                            renderer.main([str(source), str(output), '--engine', 'weasyprint'])
                    self.assertEqual(output.read_bytes(), original)
                    self.assertFalse(list(work.glob('.revayat-render-*')))

    def test_real_chromium_resource_denial_preserves_previous_delivery(self):
        browser = browser_path()
        if not browser:
            if os.environ.get('SCIENTIFIC_REQUIRE_BROWSER') == '1':
                self.fail('CI requires a configured Chromium executable')
            self.skipTest('no configured Chromium executable available')
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch, prefix='render فارسی ') as directory:
            root = Path(directory)
            job = root / 'job'
            job.mkdir()
            source = job / 'document.html'
            source.write_text('<html lang="fa" dir="rtl"><style>@page{size:180mm 240mm}'
                              '</style><p>این متن فارسی برای بررسی خروجی است.</p></html>', encoding='utf-8')
            output = job / 'output.pdf'
            command = [sys.executable, str(SCRIPTS / 'render-html.py'), str(source), str(output),
                       '--engine', 'chromium', '--browser', browser]
            result = run(command, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr)
            import pymupdf
            with pymupdf.open(output) as document:
                self.assertEqual(document.page_count, 1)
                self.assertAlmostEqual(document[0].rect.width, 180 * 72 / 25.4, delta=1)
                self.assertAlmostEqual(document[0].rect.height, 240 * 72 / 25.4, delta=1)
            approved = output.read_bytes()
            outside = root / 'outside.css'
            outside.write_text('body { color: red }', encoding='utf-8')
            source.write_text('<html><link rel="stylesheet" href="' + outside.as_uri()
                              + '"><p>متن علمی</p></html>', encoding='utf-8')
            result = run(command, timeout=90)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), approved)
            self.assertFalse(list(job.glob('.revayat-render-*')))


if __name__ == '__main__':
    unittest.main()
