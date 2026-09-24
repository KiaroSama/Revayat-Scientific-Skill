"""Real PDF outline preservation and publication-failure regressions."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import pymupdf

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log

SPEC = importlib.util.spec_from_file_location('pdf_outline_tests', SCRIPTS / 'document-pdf.py')
PDF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PDF)


class PdfOutlinePreservationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='scientific outlines ')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.log = operation_log('test-pdf-outlines', self.root / 'logs')
        self.logger = self.log.__enter__()
        self.addCleanup(self.log.__exit__, None, None, None)
        self.logger.info('running test=%s', self._testMethodName)
        self.first = self.root / 'first.pdf'
        self.source = self.root / 'source.pdf'
        self.output = self.root / 'output.pdf'
        with pymupdf.open() as doc:
            doc.new_page(width=400, height=500).insert_text((40, 60), 'First document')
            doc.save(self.first)

    def create_source(self, rotation=0, crop=False, toc=True):
        with pymupdf.open() as doc:
            for index in range(2):
                page = doc.new_page(width=500, height=600)
                page.insert_text((60, 150), f'Untouched source {index}')
                if crop:
                    page.set_cropbox(pymupdf.Rect(30, 40, 470, 560))
                page.set_rotation(rotation)
            if toc:
                doc.set_toc([
                    [1, 'عنوان علمی', 2, {'kind': 1, 'page': 1,
                     'to': pymupdf.Point(90, 210), 'zoom': 1.25,
                     'bold': True, 'italic': True, 'color': (0.2, 0.4, 0.6)}],
                    [2, 'Reference', -1, {'kind': 2, 'uri': 'https://example.org/paper?q=1&v=2'}],
                ], collapse=0)
                refs = doc.get_outline_xrefs()
                doc.xref_set_key(refs[0], 'Count', '-1')
                doc.xref_set_key(refs[1], 'A/IsMap', 'true')
            doc.save(self.source)

    def test_destinations_styles_and_uri_actions_survive(self):
        self.create_source()
        PDF.merge_pdfs([self.first, self.source], self.output)
        with pymupdf.open(self.source) as before, pymupdf.open(self.output) as after:
            source_toc, result_toc = before.get_toc(False), after.get_toc(False)
            self.assertEqual(len(source_toc), len(result_toc))
            self.assertEqual(result_toc[0][:3], [1, 'عنوان علمی', 3])
            for key in ('to', 'zoom', 'italic', 'bold', 'collapse', 'color'):
                self.assertEqual(source_toc[0][3][key], result_toc[0][3][key], key)
            self.assertEqual(result_toc[0][3]['page'], 2)
            self.assertEqual(result_toc[1][3]['kind'], pymupdf.LINK_URI)
            self.assertEqual(result_toc[1][3]['uri'], source_toc[1][3]['uri'])
            self.assertEqual(after.xref_get_key(result_toc[1][3]['xref'], 'A/IsMap'),
                             ('bool', 'true'))

    def test_rotations_crop_offsets_and_page_pixels_are_unchanged(self):
        for rotation in (0, 90, 180, 270):
            with self.subTest(rotation=rotation):
                self.create_source(rotation, crop=True)
                PDF.merge_pdfs([self.first, self.source], self.output)
                with pymupdf.open(self.source) as before, pymupdf.open(self.output) as after:
                    original = before.get_toc(False)[0][3]
                    merged = after.get_toc(False)[0][3]
                    self.assertEqual(original['to'], merged['to'])
                    self.assertEqual(original['zoom'], merged['zoom'])
                    for index in range(2):
                        self.assertEqual(before[index].get_pixmap().samples,
                                         after[index + 1].get_pixmap().samples)

    def test_standard_fit_destinations_and_null_coordinates_are_preserved(self):
        for tail in ('/XYZ null 220 null', '/Fit', '/FitH 240', '/FitV null',
                     '/FitR 20 30 220 330', '/FitB', '/FitBH null', '/FitBV 30'):
            with self.subTest(tail=tail):
                self.create_source()
                with pymupdf.open(self.source) as doc:
                    xref = doc.get_outline_xrefs()[0]
                    doc.xref_set_key(xref, 'A', 'null')
                    doc.xref_set_key(xref, 'Dest', f'[{doc.page_xref(1)} 0 R {tail}]')
                    data = doc.tobytes()
                self.source.write_bytes(data)
                PDF.merge_pdfs([self.first, self.source], self.output)
                with pymupdf.open(self.output) as doc:
                    value = doc.xref_get_key(doc.get_outline_xrefs()[0], 'Dest')
                    self.assertEqual(value[0], 'array')
                    self.assertEqual(value[1].split('R', 1)[1].strip(),
                                     tail + ']')

    def test_repeated_source_remaps_each_copy_and_preserves_inputs(self):
        self.create_source()
        before = self.source.read_bytes()
        PDF.merge_pdfs([self.source, self.source], self.output)
        self.assertEqual(self.source.read_bytes(), before)
        with pymupdf.open(self.output) as doc:
            toc = doc.get_toc(False)
            self.assertEqual([toc[0][2], toc[2][2]], [2, 4])
            self.assertEqual([toc[0][3]['page'], toc[2][3]['page']], [1, 3])
            self.assertEqual(toc[0][3]['to'], toc[2][3]['to'])

    def test_no_outline_is_not_fabricated(self):
        self.create_source(toc=False)
        PDF.merge_pdfs([self.first, self.source], self.output)
        with pymupdf.open(self.output) as doc:
            self.assertEqual(doc.get_toc(), [])
            self.assertEqual(doc.page_count, 3)

    def test_advanced_or_chained_actions_refuse_before_publication(self):
        self.output.write_bytes(b'previous approved edition')
        for action in ('<< /S /Named /N /FirstPage >>',
                       '<< /S /URI /URI (https://example.org) /Next << /S /Named /N /FirstPage >> >>'):
            with self.subTest(action=action):
                self.create_source()
                with pymupdf.open(self.source) as doc:
                    xref = doc.get_outline_xrefs()[0]
                    doc.xref_set_key(xref, 'A', action)
                    data = doc.tobytes()
                self.source.write_bytes(data)
                with self.assertRaises(ValueError):
                    PDF.merge_pdfs([self.first, self.source], self.output)
                self.assertEqual(self.output.read_bytes(), b'previous approved edition')
                self.assertEqual(self.source.read_bytes(), data)

    def test_failed_staged_outline_verification_preserves_destination(self):
        self.create_source()
        self.output.write_bytes(b'previous approved edition')
        with mock.patch.object(PDF, 'verify_outlines', side_effect=ValueError('injected lost destination')):
            with self.assertRaises(ValueError):
                PDF.merge_pdfs([self.first, self.source], self.output)
        self.assertEqual(self.output.read_bytes(), b'previous approved edition')
        self.assertFalse(list(self.root.glob('.revayat-*')))


if __name__ == '__main__':
    unittest.main()
