"""Raster derivatives share bounded read-only PDF admission, not transform policy."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest.mock

import pymupdf

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
import pdf_input

SPEC = importlib.util.spec_from_file_location('crop_admission', SCRIPTS / 'crop-source-figures.py')
CROP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CROP)


class CropAdmissionTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch' / 'improvement-pdf'
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix='crop admission ', dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.source, self.mapping = self.work / 'source.pdf', self.work / 'map.tsv'
        self.output = self.work / 'crops'
        self.output.mkdir()
        self.crop = self.output / 'fig-sample.png'
        self.previous = b'previous approved crop'
        self.crop.write_bytes(self.previous)
        self.mapping.write_text('figure_id\tpdf_page\tx0\ty0\tx1\ty1\n'
                                'sample\t1\t20\t30\t80\t90\n', encoding='utf-8')
        self.argv = [str(self.source), '--out', str(self.output), '--map', str(self.mapping), '--dpi', '72']

    def fixture(self, kind='ordinary'):
        self.source.unlink(missing_ok=True)
        with pymupdf.open() as document:
            page = document.new_page(width=100, height=120)
            page.draw_rect(pymupdf.Rect(20, 30, 80, 90), fill=(1, 0, 0), color=(1, 0, 0))
            if kind == 'signature':
                signature = document.get_new_xref()
                document.update_object(signature, '<< /Type /Sig /ByteRange [0 10 20 30] >>')
                document.xref_set_key(document.pdf_catalog(), 'Perms', f'<< /DocMDP {signature} 0 R >>')
            encryption = ({'encryption': pymupdf.PDF_ENCRYPT_AES_256,
                           'owner_pw': 'authored-owner', 'user_pw': ''} if kind == 'encrypted' else {})
            document.save(self.source, **encryption)
        if kind == 'repaired':
            self.source.write_bytes(self.source.read_bytes().split(b'\nxref\n', 1)[0] + b'\n%%EOF\n')
        return self.source.read_bytes()

    def test_selected_crop_admission_preserves_source(self):
        original = self.fixture()
        for limit, maximum in (('MAX_PDF_BYTES', 1), ('MAX_PDF_PAGES', 0), ('MAX_PDF_OBJECTS', 1)):
            with self.subTest(limit=limit), unittest.mock.patch.object(pdf_input, limit, maximum):
                with self.assertRaisesRegex(ValueError, '512 MiB|page/object'):
                    CROP.main(self.argv)
            self.assertEqual(self.crop.read_bytes(), self.previous)
            self.assertEqual(self.source.read_bytes(), original)
            self.assertEqual([path.name for path in self.output.iterdir()], ['fig-sample.png'])
        for kind in ('encrypted', 'repaired'):
            with self.subTest(kind=kind):
                original = self.fixture(kind)
                with pymupdf.open(self.source) as document:
                    if kind == 'encrypted':
                        self.assertTrue(document.metadata.get('encryption'))
                    else:
                        self.assertTrue(document.is_repaired)
                with self.assertRaisesRegex(ValueError, 'encrypt|repair'):
                    CROP.main(self.argv)
                self.assertEqual(self.crop.read_bytes(), self.previous)
                self.assertEqual(self.source.read_bytes(), original)
                self.assertEqual([path.name for path in self.output.iterdir()], ['fig-sample.png'])
        original = self.fixture('signature')
        with pymupdf.open(self.source) as document:
            signature = int(document.xref_get_key(document.pdf_catalog(), 'Perms/DocMDP')[1].split()[0])
            self.assertEqual(document.xref_get_key(signature, 'Type'), ('name', '/Sig'))
        self.assertEqual(CROP.main(self.argv), 0)
        pixels = pymupdf.Pixmap(self.crop)
        self.assertEqual((pixels.width, pixels.height), (60, 60))
        self.assertIn(bytes((255, 0, 0)), pixels.samples)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual([path.name for path in self.output.iterdir()], ['fig-sample.png'])


if __name__ == '__main__':
    unittest.main()
