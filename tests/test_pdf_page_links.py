"""Page navigation is admitted before copying and verified before publication."""
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


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PDF = load('page_links_pdf', 'document-pdf.py')
PAGES = load('page_links_extract', 'extract-pdf-pages.py')


class PdfPageLinksTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch' / 'improvement-pdf'
        scratch.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix='page links ', dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.source = self.work / 'source.pdf'
        self.output = self.work / 'output.pdf'
        self.previous = b'previous approved PDF'
        self.output.write_bytes(self.previous)

    def test_named_link_boundary_is_explicit(self):
        with pymupdf.open() as document:
            document.new_page(width=200, height=300)
            document.new_page(width=200, height=300)
            document.xref_set_key(document.pdf_catalog(), 'Dests',
                                  f'<< /XYZDest [{document.page_xref(1)} 0 R /XYZ 10 250 1.5] >>')
            page = document[0]
            page.insert_link({'kind': pymupdf.LINK_NAMED, 'name': 'XYZDest',
                              'from': pymupdf.Rect(10, 20, 80, 40)})
            document.save(self.source)
        original = self.source.read_bytes()
        with pymupdf.open(self.source) as source:
            named = source.resolve_names()['XYZDest']
            self.assertEqual((named['page'], named['to'], named['zoom']), (1, (10, 250), 1.5))
            links = source[0].get_links()
            self.assertEqual(len(links), 1)
            self.assertEqual(links[0]['kind'], pymupdf.LINK_NAMED)
            self.assertEqual(links[0]['nameddest'], 'XYZDest')
            self.assertEqual(links[0]['from'], pymupdf.Rect(10, 20, 80, 40))
        for operation in ('merge', 'extract'):
            with self.subTest(operation=operation):
                self.output.write_bytes(self.previous)
                with self.assertRaisesRegex(ValueError, 'named.*link|link.*named'):
                    if operation == 'merge':
                        PDF.merge_pdfs([self.source], self.output)
                    else:
                        PAGES.main([str(self.source), str(self.output), '1-2'])
                self.assertEqual(self.output.read_bytes(), self.previous)
                self.assertEqual(self.source.read_bytes(), original)
                self.assertFalse(list(self.work.glob('.revayat-*')))

    def test_links_to_omitted_pages_fail_before_output(self):
        with pymupdf.open() as document:
            for _ in range(3):
                document.new_page(width=200, height=300)
            document[1].insert_link({'kind': pymupdf.LINK_GOTO, 'page': 0,
                                     'to': pymupdf.Point(20, 50), 'zoom': 1.25,
                                     'from': pymupdf.Rect(10, 20, 80, 40)})
            document.save(self.source)
        original = self.source.read_bytes()
        with pymupdf.open(self.source) as source:
            links = source[1].get_links()
            self.assertEqual(len(links), 1)
            self.assertEqual((links[0]['kind'], links[0]['page']), (pymupdf.LINK_GOTO, 0))
        with self.assertRaisesRegex(ValueError, 'outside.*range|omitted'):
            PAGES.main([str(self.source), str(self.output), '2-3'])
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertFalse(list(self.work.glob('.revayat-*')))

    def test_supported_navigation_is_verified_before_publication(self):
        uri = 'https://example.invalid/paper?q=1&v=2'
        with pymupdf.open() as document:
            for _ in range(3):
                document.new_page(width=240, height=360)
            document[1].insert_link({'kind': pymupdf.LINK_GOTO, 'page': 2,
                                     'to': pymupdf.Point(30, 70), 'zoom': 1.25,
                                     'from': pymupdf.Rect(10, 20, 80, 40)})
            document[1].insert_link({'kind': pymupdf.LINK_URI, 'uri': uri,
                                     'from': pymupdf.Rect(10, 50, 100, 70)})
            document.save(self.source)
        original = self.source.read_bytes()
        with pymupdf.open(self.source) as source:
            local = source[1].get_links()[0]
            kind, destination = source.xref_get_key(local['xref'], 'A/D')
            self.assertEqual(kind, 'array')
            self.assertEqual(destination.split('R', 1)[1].strip(), '/XYZ 30 290 1.25]')
            source_zoom = local['zoom']
        first = self.work / 'prefix.pdf'
        with pymupdf.open() as document:
            document.new_page(width=100, height=150)
            document.save(first)
        prefix = first.read_bytes()
        real_save = pymupdf.Document.save

        def lose_navigation(document, filename, *args, **kwargs):
            for page in document:
                for link in page.get_links():
                    page.delete_link(link)
            return real_save(document, filename, *args, **kwargs)

        for operation in ('merge', 'extract'):
            def invoke():
                if operation == 'merge':
                    PDF.merge_pdfs([first, self.source], self.output)
                else:
                    self.assertEqual(PAGES.main([str(self.source), str(self.output), '2-3']), 0)

            with self.subTest(operation=operation):
                self.output.write_bytes(self.previous)
                with mock.patch.object(pymupdf.Document, 'save', lose_navigation):
                    with self.assertRaisesRegex(ValueError, 'link|navigation'):
                        invoke()
                self.assertEqual(self.output.read_bytes(), self.previous)
                invoke()
                with pymupdf.open(self.output) as result:
                    page_number, target = (2, 3) if operation == 'merge' else (0, 1)
                    self.assertEqual(result.page_count, 4 if operation == 'merge' else 2)
                    links = result[page_number].get_links()
                    self.assertEqual(len(links), 2)
                    local = next(link for link in links if link['kind'] == pymupdf.LINK_GOTO)
                    external = next(link for link in links if link['kind'] == pymupdf.LINK_URI)
                    self.assertEqual(local['page'], target)
                    self.assertEqual(local['from'], pymupdf.Rect(10, 20, 80, 40))
                    self.assertEqual(local['to'], pymupdf.Point(30, 70))
                    self.assertEqual(local['zoom'], source_zoom)
                    kind, destination = result.xref_get_key(local['xref'], 'A/D')
                    self.assertEqual(kind, 'array')
                    self.assertEqual(destination.split('R', 1)[0].lstrip('[').split(),
                                     [str(result.page_xref(target)), '0'])
                    self.assertEqual(destination.split('R', 1)[1].strip(), '/XYZ 30 290 1.25]')
                    self.assertEqual(external['uri'], uri)
                    self.assertEqual(external['from'], pymupdf.Rect(10, 50, 100, 70))
                    self.assertEqual(tuple(result[page_number].rect), (0, 0, 240, 360))
                self.assertEqual(self.source.read_bytes(), original)
                self.assertEqual(first.read_bytes(), prefix)
                self.assertFalse(list(self.work.glob('.revayat-*')))

    def test_raw_unresolved_annotations_are_not_silently_omitted(self):
        for destination in ('(MissingDestination)', '/MissingDestination'):
            with self.subTest(destination=destination):
                self.source.unlink(missing_ok=True)
                with pymupdf.open() as document:
                    page = document.new_page(width=200, height=300)
                    xref = document.get_new_xref()
                    document.update_object(xref, '<< /Type /Annot /Subtype /Link '
                                           '/Rect [10 260 80 280] /Dest ' + destination + ' >>')
                    document.xref_set_key(page.xref, 'Annots', f'[{xref} 0 R]')
                    document.save(self.source)
                original = self.source.read_bytes()
                with pymupdf.open(self.source) as source:
                    annotations = source[0].annot_xrefs()
                    self.assertEqual(len(annotations), 1)
                    self.assertEqual(annotations[0][1], pymupdf.PDF_ANNOT_LINK)
                    self.assertIn(source.xref_get_key(annotations[0][0], 'Dest')[0], ('name', 'string'))
                for operation in ('merge', 'extract'):
                    self.output.write_bytes(self.previous)
                    with self.assertRaisesRegex(ValueError, 'link'):
                        if operation == 'merge':
                            PDF.merge_pdfs([self.source], self.output)
                        else:
                            PAGES.main([str(self.source), str(self.output), '1'])
                    self.assertEqual(self.output.read_bytes(), self.previous)
                    self.assertEqual(self.source.read_bytes(), original)
                self.assertFalse(list(self.work.glob('.revayat-*')))

    def test_remote_raw_navigation_is_refused_before_output(self):
        with pymupdf.open() as document:
            page = document.new_page(width=200, height=300)
            xref = document.get_new_xref()
            document.update_object(xref, '<< /Type /Annot /Subtype /Link '
                                   '/Rect [10 260 80 280] /A << /S /GoToR '
                                   '/F (other.pdf) /D [1 /XYZ 30 290 1.25] >> >>')
            document.xref_set_key(page.xref, 'Annots', f'[{xref} 0 R]')
            document.save(self.source)
        original = self.source.read_bytes()
        with pymupdf.open(self.source) as source:
            links = source[0].get_links()
            self.assertEqual(len(links), 1)
            self.assertEqual((links[0]['kind'], links[0]['page'], links[0]['file']),
                             (pymupdf.LINK_GOTOR, 1, 'other.pdf'))
            kind, destination = source.xref_get_key(links[0]['xref'], 'A/D')
            self.assertEqual(kind, 'array')
            self.assertEqual(destination.split(), ['[1/XYZ', '30', '290', '1.25]'])
        for operation in ('merge', 'extract'):
            with self.subTest(operation=operation):
                self.output.write_bytes(self.previous)
                with self.assertRaisesRegex(ValueError, 'remote.*link|link.*remote'):
                    if operation == 'merge':
                        PDF.merge_pdfs([self.source], self.output)
                    else:
                        PAGES.main([str(self.source), str(self.output), '1'])
                self.assertEqual(self.output.read_bytes(), self.previous)
                self.assertEqual(self.source.read_bytes(), original)
                self.assertFalse(list(self.work.glob('.revayat-*')))
                self.assertFalse((self.work / 'other.pdf').exists())

    def test_chained_page_actions_fail_before_output(self):
        with pymupdf.open() as document:
            page = document.new_page(width=200, height=300)
            page.insert_link({'kind': pymupdf.LINK_GOTO, 'page': 0,
                              'to': pymupdf.Point(30, 70),
                              'from': pymupdf.Rect(10, 20, 80, 40)})
            page = document.reload_page(page)
            xref = page.get_links()[0]['xref']
            document.xref_set_key(xref, 'A/Next',
                                  '<< /S /URI /URI (https://example.invalid/next) >>')
            document.save(self.source)
        original = self.source.read_bytes()
        with pymupdf.open(self.source) as source:
            links = source[0].get_links()
            self.assertEqual(len(links), 1)
            self.assertEqual(links[0]['kind'], pymupdf.LINK_GOTO)
            self.assertEqual(source.xref_get_key(links[0]['xref'], 'A/Next/S'), ('name', '/URI'))
            self.assertEqual(source.xref_get_key(links[0]['xref'], 'A/Next/URI'),
                             ('string', 'https://example.invalid/next'))
        for operation in ('merge', 'extract'):
            with self.subTest(operation=operation):
                self.output.write_bytes(self.previous)
                with self.assertRaisesRegex(ValueError, 'chained.*link|link.*chain'):
                    if operation == 'merge':
                        PDF.merge_pdfs([self.source], self.output)
                    else:
                        PAGES.main([str(self.source), str(self.output), '1'])
                self.assertEqual(self.output.read_bytes(), self.previous)
                self.assertEqual(self.source.read_bytes(), original)
                self.assertFalse(list(self.work.glob('.revayat-*')))


if __name__ == '__main__':
    unittest.main()
