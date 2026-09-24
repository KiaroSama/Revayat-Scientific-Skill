"""Crop geometry and complete-map validation protect scientific artwork."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('crop_images', SCRIPTS / 'crop-source-figures.py')
CROP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CROP)


class CropIntegrityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / '.scratch').mkdir(exist_ok=True)

    def test_invalid_late_map_preserves_previous_output(self):
        import pymupdf
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            source, mapping, output = work / 'source.pdf', work / 'map.tsv', work / 'figures'
            with pymupdf.open() as document:
                page = document.new_page(width=200, height=200)
                page.draw_rect(pymupdf.Rect(40, 60, 140, 130), fill=(1, 0, 0))
                document.save(source)
            output.mkdir()
            previous = output / 'fig-first.png'
            previous.write_bytes(b'previous approved figure')
            mapping.write_text('figure_id\tpdf_page\nfirst\t1\ninvalid\t-1\n', encoding='utf-8')
            with self.assertRaises((ValueError, OSError)):
                CROP.main([str(source), '--map', str(mapping), '--out', str(output)])
            self.assertEqual(previous.read_bytes(), b'previous approved figure')
            self.assertEqual(sorted(p.name for p in output.iterdir()), ['fig-first.png'])

    def test_transitive_components_edges_and_ambiguity(self):
        import pymupdf
        rectangles = [pymupdf.Rect(0, 50, 40, 80), pymupdf.Rect(90, 50, 130, 80),
                      pymupdf.Rect(40, 70, 90, 100)]
        groups = CROP.cluster(rectangles, pymupdf, gap=1)
        self.assertEqual(len(groups), 1)
        self.assertEqual(tuple(groups[0]), (0, 50, 130, 100))
        with pymupdf.open() as doc:
            page = doc.new_page(width=612, height=792)
            for rectangle in ((598, 30, 608, 100), (0, 0, 60, 60), (10, 740, 100, 792)):
                with self.subTest(rectangle=rectangle):
                    self.assertTrue(CROP.pad_clip(page, pymupdf.Rect(rectangle), pymupdf).contains(pymupdf.Rect(rectangle)))
        with self.assertRaisesRegex(ValueError, 'reviewed'):
            CROP.pick_clusters([pymupdf.Rect(0, 0, 50, 50), pymupdf.Rect(100, 100, 150, 150)], 1)

    def test_map_rejects_malformed_rows_duplicates_and_nonfinite_rectangles(self):
        cases = ['', 'figure_id\tpdf_page\n', 'wrong\theader\n', 'x\t0\n', 'x\t1.5\n',
                 'x\t1\nx\t2\n', 'X\t1\nx\t2\n', 'x\t1\ninvalid\n', '../x\t1\n',
                 'figure_id\tpdf_page\tx0\ty0\tx1\ty1\nx\t1\t0\t0\tnan\t40\n']
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            mapping = Path(directory) / 'map.tsv'
            for text in cases:
                mapping.write_text(text, encoding='utf-8')
                with self.subTest(text=text), self.assertRaises((ValueError, CROP.csv.Error)):
                    CROP.load_map(mapping)
            mapping.write_text('figure_id,pdf_page\nx,1\ny,2\n', encoding='utf-8')
            self.assertEqual(set(CROP.load_map(mapping)), {1, 2})

    def test_explicit_edge_crop_and_late_failures_preserve_batch(self):
        import pymupdf
        import publication
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            source, mapping, output = work / 'source.pdf', work / 'map.tsv', work / 'output'
            with pymupdf.open() as doc:
                page = doc.new_page(width=612, height=792)
                page.draw_rect(pymupdf.Rect(598, 20, 608, 80), fill=(1, 0, 0), color=(1, 0, 0))
                doc.save(source)
            original = hashlib.sha256(source.read_bytes()).hexdigest()
            mapping.write_text('figure_id\tpdf_page\tx0\ty0\tx1\ty1\n'
                               'first\t1\t590\t10\t612\t90\nsecond\t1\t580\t10\t612\t90\n', encoding='utf-8')
            output.mkdir()
            previous = output / 'fig-first.png'
            previous.write_bytes(b'old approved crop')
            argv = [str(source), '--map', str(mapping), '--out', str(output), '--dpi', '72']
            original_render = CROP.render_clip
            def fail_render(page, clip, dest, module, dpi):
                if dest.name == 'fig-second.png':
                    raise OSError('injected render failure')
                return original_render(page, clip, dest, module, dpi)
            with patch.object(CROP, 'render_clip', side_effect=fail_render), self.assertRaises(OSError):
                CROP.main(argv)
            self.assertEqual(previous.read_bytes(), b'old approved crop')
            original_replace = publication.os.replace
            def fail_publish(stage, dest):
                if Path(dest).name == 'fig-second.png':
                    raise OSError('injected publication failure')
                return original_replace(stage, dest)
            with patch.object(publication.os, 'replace', side_effect=fail_publish), self.assertRaises(OSError):
                CROP.main(argv)
            self.assertEqual(previous.read_bytes(), b'old approved crop')
            self.assertEqual([p.name for p in output.iterdir()], ['fig-first.png'])
            self.assertEqual(CROP.main(argv), 0)
            pix = pymupdf.Pixmap(previous)
            self.assertIn(bytes((255, 0, 0)), pix.samples)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)


if __name__ == '__main__':
    unittest.main()
