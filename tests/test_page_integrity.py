"""Contiguous page extraction never overwrites or aliases its source."""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('page_extract', SCRIPTS / 'extract-pdf-pages.py')
PAGES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PAGES)


class PageIntegrityTest(unittest.TestCase):
    def test_same_path_keeps_complete_source(self):
        import pymupdf
        (ROOT / '.scratch').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            source = Path(directory) / 'source.pdf'
            with pymupdf.open() as doc:
                for _ in range(3):
                    doc.new_page()
                doc.save(source)
            before = source.read_bytes()
            opened, rejection = [], None
            real_open = pymupdf.open
            def record_open(*args, **kwargs):
                doc = real_open(*args, **kwargs)
                opened.append(doc)
                return doc
            with patch.object(sys, 'argv', ['pages', str(source), str(source), '1']), patch.object(pymupdf, 'open', side_effect=record_open):
                try:
                    PAGES.main()
                except Exception as error:
                    rejection = error
                finally:
                    for doc in opened:
                        if not doc.is_closed:
                            doc.close()
            self.assertIsInstance(rejection, ValueError)
            self.assertEqual(source.read_bytes(), before)
            with pymupdf.open(source) as reopened:
                self.assertEqual(reopened.page_count, 3)

    def test_range_validation_aliases_and_rollback(self):
        import pymupdf
        import publication
        (ROOT / '.scratch').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            source, output = work / 'source.pdf', work / 'result.pdf'
            with pymupdf.open() as doc:
                for number in range(3):
                    page = doc.new_page(width=250 + number * 10, height=400)
                    page.insert_text((20, 30), f'page {number + 1}')
                doc.save(source)
            original = hashlib.sha256(source.read_bytes()).hexdigest()
            output.write_bytes(b'previous approved PDF')
            for page_range in ('0', '-1', '1.5', '2-1', '1-4', 'nan'):
                with self.subTest(page_range=page_range), self.assertRaises((ValueError, SystemExit)):
                    PAGES.main([str(source), str(output), page_range])
                self.assertEqual(output.read_bytes(), b'previous approved PDF')
            alias = work / 'hardlink.pdf'
            os.link(source, alias)
            with self.assertRaises(ValueError):
                PAGES.main([str(source), str(alias), '1'])
            with patch.object(publication.os, 'replace', side_effect=OSError('injected failure')):
                with self.assertRaises(OSError):
                    PAGES.main([str(source), str(output), '1-2'])
            self.assertEqual(output.read_bytes(), b'previous approved PDF')
            self.assertEqual(PAGES.main([str(source), str(output), '2-3']), 0)
            with pymupdf.open(output) as doc:
                self.assertEqual(doc.page_count, 2)
                self.assertEqual([page.rect.width for page in doc], [260, 270])
                self.assertEqual([page.get_text().strip() for page in doc], ['page 2', 'page 3'])
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), original)
            self.assertFalse(any(p.is_dir() for p in work.iterdir()))

    def test_encrypted_and_malformed_inputs_leave_output_unchanged(self):
        import pymupdf
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            encrypted, bad, output = work / 'locked.pdf', work / 'bad.pdf', work / 'out.pdf'
            with pymupdf.open() as doc:
                doc.new_page()
                doc.save(encrypted, encryption=pymupdf.PDF_ENCRYPT_AES_256,
                         owner_pw='fixture-owner', user_pw='fixture-user')
            bad.write_bytes(b'not a PDF')
            output.write_bytes(b'old approved PDF')
            for source in (encrypted, bad):
                with self.subTest(source=source.name), self.assertRaises(Exception):
                    PAGES.main([str(source), str(output), '1'])
                self.assertEqual(output.read_bytes(), b'old approved PDF')
            self.assertFalse(any(p.is_dir() for p in work.iterdir()))


if __name__ == '__main__':
    unittest.main()
