"""Public regressions for journal terms, original quotes and source image sampling."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

from processes import run

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/revayat-scientific'
CLI = SKILL / 'scripts/revayat-scientific.py'
SCRATCH = ROOT / '.scratch'


class FidelityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SCRATCH.mkdir(exist_ok=True)

    def test_journal_terms_and_scoped_original_quote(self):
        with tempfile.TemporaryDirectory(prefix='scientific fidelity ', dir=SCRATCH) as directory:
            work = Path(directory)
            source = work / 'journal.tex'
            source.write_text('\\begin{document}\nپیاده‌سازی مرجع ارائه می‌شود.\n'
                              '% fa-lint: allow arabic-letters\nكتاب علمي\n'
                              '\nاین متن فارسی است.\n\\end{document}\n', encoding='utf-8')
            checker = SKILL / 'scripts/check-fa.py'
            journal = run([sys.executable, str(checker), str(source), '--level', 'journal'], timeout=20)
            self.assertEqual(journal.returncode, 0, journal.stderr + journal.stdout)
            operational = run([sys.executable, str(checker), str(source), '--level', 'system-docs'], timeout=20)
            self.assertEqual(operational.returncode, 1)
            self.assertIn('forbidden-fa', operational.stdout)
            source.write_text(source.read_text(encoding='utf-8').replace(
                'این متن فارسی است.', 'اين متن فارسی است.\n\\begin{LTR}\n'
                '\\includegraphics{missing.png}\n\\end{LTR}'), encoding='utf-8')
            broken = run([sys.executable, str(checker), str(source), '--level', 'journal'], timeout=20)
            self.assertEqual(broken.returncode, 1)
            self.assertIn('arabic-letters', broken.stdout)
            self.assertIn('missing-image', broken.stdout)

    def test_crop_preserves_source_sampling_and_rotation(self):
        import pymupdf
        from PIL import Image

        with tempfile.TemporaryDirectory(prefix='scientific density ', dir=SCRATCH) as directory:
            work = Path(directory)
            asset = work / 'original.png'
            Image.new('RGB', (720, 360), (100, 150, 200)).save(asset)
            source = work / 'source.pdf'
            with pymupdf.open() as document:
                for rotation in (0, 90):
                    page = document.new_page(width=400, height=400)
                    page.insert_image(pymupdf.Rect(80, 90, 224, 162), filename=str(asset))
                    page.set_rotation(rotation)
                document.save(source)
            original = hashlib.sha256(source.read_bytes()).hexdigest()
            mapping = work / 'map.tsv'
            mapping.write_text('figure_id\tpdf_page\nnormal\t1\nrotated\t2\n', encoding='utf-8')
            output = work / 'figures'
            result = run([sys.executable, str(CLI), 'crop', str(source), '--out', str(output),
                          '--map', str(mapping), '--dpi', '300'], timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ('normal', 'rotated'):
                with self.subTest(name=name), Image.open(output / f'fig-{name}.png') as image:
                    self.assertGreaterEqual(min(image.info['dpi']), 359)
                    self.assertGreaterEqual(max(image.size), 720)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)

    def test_crop_rejects_oversized_allocation_and_invalid_density(self):
        import pymupdf

        with tempfile.TemporaryDirectory(prefix='scientific crop limit ', dir=SCRATCH) as directory:
            work = Path(directory)
            source = work / 'source.pdf'
            with pymupdf.open() as document:
                page = document.new_page(width=1000, height=1000)
                page.draw_rect(pymupdf.Rect(60, 60, 900, 900), color=(0, 0, 0))
                document.save(source)
            mapping = work / 'map.tsv'
            mapping.write_text('figure_id\tpdf_page\nlarge\t1\n', encoding='utf-8')
            output = work / 'figures'
            output.mkdir()
            previous = output / 'fig-large.png'
            previous.write_bytes(b'previous output must survive')
            base = [sys.executable, str(CLI), 'crop', str(source), '--out', str(output), '--map', str(mapping)]
            for density, message in [('2400', '50 million pixels'), ('0', '--dpi must be')]:
                with self.subTest(density=density):
                    result = run([*base, '--dpi', density], timeout=20)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertEqual(previous.read_bytes(), b'previous output must survive')
            self.assertEqual([path.name for path in output.iterdir()], ['fig-large.png'])


if __name__ == '__main__':
    unittest.main()
