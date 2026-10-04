"""Native builds must preserve inputs, previous delivery and coherent previews."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from PIL import Image
import pymupdf
from processes import run

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log


class DeliveryFixture(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch, prefix='native delivery فارسی ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'doc.html'
        self.html = (ROOT / 'tests/fixtures/build-smoke.html').read_text(encoding='utf-8')
        self.source.write_bytes(self.html.encode('utf-8'))
        self.terms, self.manifest = self.root / 'terms.tsv', self.root / 'manifest.txt'
        self.terms.write_bytes((ROOT / 'tests/fixtures/terms-empty.tsv').read_bytes())
        self.manifest.write_bytes(b'')
        self.delivery = self.root / 'delivered'
        self.delivery.mkdir()
        self.output = self.delivery / 'article.pdf'
        self.output.write_bytes(b'previous approved delivery')
        self.samples = [self.root / f'verify-article-{role}.png' for role in ('first', 'last', 'mid')]
        self.scope = operation_log('test-build-delivery', self.root / 'logs')
        self.log = self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)

    def asset(self, name, css=False):
        target = self.root / name
        Image.new('RGB', (80, 80), (220, 240, 250)).save(target)
        if css:
            style = self.root / 'local.css'
            style.write_bytes(('body { background-image: url("' + name + '"); }').encode())
            html = self.html.replace('</head>', '<link rel="stylesheet" href="local.css"></head>')
        else:
            html = self.html.replace('<body>', '<body><img dir="ltr" src="' + name + '" alt="شکل پژوهش">')
            self.manifest.write_bytes((name + '\n').encode())
        self.source.write_bytes(html.encode('utf-8'))
        return target

    def invoke(self, *extra, verify=True, env=None):
        command = [sys.executable, str(SCRIPTS / 'revayat-scientific.py'), '--timeout', '60',
                   'build', str(self.source), 'article', '--engine', 'weasyprint',
                   '--output-dir', str(self.delivery)]
        if verify:
            command.append('--verify')
        result = run([*command, *extra], timeout=75, env=env)
        self.log.debug('native build exited code=%d', result.returncode)
        return result

    def unchanged(self, files):
        for path, data in files.items():
            self.assertEqual(path.read_bytes(), data, path.name)
        self.assertFalse(list(self.root.glob('.revayat-build-*')))
        self.assertFalse(list(self.root.glob('.revayat-render-*')))
        self.assertFalse(list(self.delivery.glob('.revayat-delivery-*')))


class NativeBuildDeliveryTest(DeliveryFixture):
    def setUp(self):
        if os.environ.get('SCIENTIFIC_REQUIRE_BUILD_GUARD') != '1':
            self.skipTest('native build-input preservation tier')
        super().setUp()
        for executable in ('bash', 'pdfinfo', 'pdffonts', 'pdftoppm', 'pdftotext'):
            self.assertIsNotNone(shutil.which(executable), 'required native tool: ' + executable)
        try:
            from weasyprint import HTML
            from weasyprint.urls import URLFetcher
        except ImportError:
            self.fail('required native build tier needs the supported WeasyPrint API')

    def test_each_source_preview_collision_is_rejected_before_any_output_changes(self):
        for role in ('first', 'last', 'mid'):
            with self.subTest(role=role):
                asset = self.asset(f'verify-article-{role}.png')
                retained = {path: path.read_bytes() for path in (self.source, self.terms, self.manifest, asset, self.output)}
                result = self.invoke()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('protected source', result.stderr)
                self.unchanged(retained)
                self.assertFalse(self.source.with_suffix('.pdf').exists())

    def test_terms_and_manifest_with_pdf_suffix_are_never_delivery_targets(self):
        self.output.unlink()
        self.delivery = self.root
        for field in ('terms', 'manifest'):
            with self.subTest(field=field):
                target = self.root / 'article.pdf'
                target.write_bytes(getattr(self, field).read_bytes())
                retained = {path: path.read_bytes() for path in (self.source, self.terms, self.manifest, target)}
                result = self.invoke('--' + field, str(target), verify=False)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('protected source', result.stderr)
                self.unchanged(retained)
                self.assertFalse(self.source.with_suffix('.pdf').exists())

    def test_css_only_preview_resource_is_preserved_and_cannot_replace_working_pdf(self):
        asset = self.asset('verify-article-first.png', css=True)
        working = self.source.with_suffix('.pdf')
        working.write_bytes(b'previous working PDF')
        retained = {path: path.read_bytes() for path in (
            self.source, self.terms, self.manifest, asset, self.output, working, self.root / 'local.css')}
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('protected source', result.stderr)
        self.unchanged(retained)

    def test_noverify_does_not_reserve_unused_preview_paths(self):
        asset = self.asset('verify-article-first.png')
        retained = {path: path.read_bytes() for path in (self.source, self.terms, self.manifest, asset)}
        result = self.invoke(verify=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.unchanged(retained)
        self.assertEqual(self.output.read_bytes(), self.source.with_suffix('.pdf').read_bytes())
        self.assertFalse(self.samples[1].exists())

    def test_successful_three_to_one_page_rebuild_refreshes_every_preview_role(self):
        asset = self.asset('figure.png')
        retained = {path: path.read_bytes() for path in (self.source, self.terms, self.manifest, asset)}
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.unchanged(retained)
        with pymupdf.open(self.output) as document:
            self.assertEqual(document.page_count, 3)
        for path in self.samples:
            with Image.open(path) as image:
                image.verify()
        self.assertEqual(self.output.read_bytes(), self.source.with_suffix('.pdf').read_bytes())
        evidence = os.environ.get('SCIENTIFIC_EVIDENCE_DIR')
        if evidence:
            target = Path(evidence)
            target.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.output, target / 'guarded-build.pdf')
            for path in self.samples:
                shutil.copyfile(path, target / ('guarded-' + path.name))
        # All content still fits on one page after removing explicit page breaks.
        shorter = self.source.read_text(encoding='utf-8').replace('class="page"', 'class="continuous"')
        self.source.write_bytes(shorter.encode('utf-8'))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        with pymupdf.open(self.output) as document:
            self.assertEqual(document.page_count, 1)
        pixels = []
        for path in self.samples:
            with Image.open(path) as image:
                pixels.append((image.size, image.tobytes()))
        self.assertEqual(pixels[0], pixels[1])
        self.assertEqual(pixels[0], pixels[2])
        self.assertEqual(self.output.read_bytes(), self.source.with_suffix('.pdf').read_bytes())
        self.unchanged({self.source: shorter.encode('utf-8'), asset: retained[asset]})

    def test_late_raster_failure_preserves_entire_previous_preview_batch(self):
        for path in self.samples:
            path.write_bytes(b'previous approved preview')
        retained = {path: path.read_bytes() for path in [self.output, self.source, self.terms, self.manifest, *self.samples]}
        wrapper = self.root / 'tools'
        wrapper.mkdir()
        real = shutil.which('pdftoppm')
        script = wrapper / 'pdftoppm'
        script.write_text('#!' + sys.executable + '\n' + '''import logging, subprocess, sys, time
logging.Formatter.converter = time.gmtime
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s UTC [%(levelname)s] %(message)s')
if sys.argv[-1].endswith('-last'):
    logging.error('Synthetic late raster failure')
    raise SystemExit(31)
logging.info('Running the real initial raster operation')
raise SystemExit(subprocess.call([''' + repr(real) + ''', *sys.argv[1:]]))
''', encoding='utf-8')
        script.chmod(0o755)
        result = self.invoke(env={'PATH': str(wrapper) + os.pathsep + os.environ['PATH']})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('Synthetic late raster failure', result.stderr)
        self.unchanged(retained)


@unittest.skipUnless(sys.platform == 'win32', 'native PowerShell 5.1 and 7 input admission')
class WindowsBuildDeliveryTest(DeliveryFixture):
    def test_both_native_shells_preserve_colliding_source_inputs(self):
        asset = self.asset('verify-article-first.png')
        for name in ('powershell', 'pwsh'):
            with self.subTest(shell=name):
                shell = shutil.which(name)
                self.assertIsNotNone(shell, 'both supported Windows shells are required')
                retained = {path: path.read_bytes() for path in (asset, self.output, self.source)}
                result = run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', str(SCRIPTS / 'build-pdf.ps1'), str(self.source), 'article',
                    '-Engine', 'chromium', '-Verify', '-OutputDirectory', str(self.delivery)],
                    timeout=30, env={'REVAYAT_CHROMIUM': sys.executable})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('protected source', result.stderr)
                self.unchanged(retained)
                self.assertFalse(self.source.with_suffix('.pdf').exists())


if __name__ == '__main__':
    unittest.main()
