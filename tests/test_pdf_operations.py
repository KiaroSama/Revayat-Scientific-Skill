"""Native PDF preservation, form typing and extraction provenance controls."""
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
SCRATCH = ROOT / '.scratch'
sys.path.insert(0, str(SCRIPTS))


def helper():
    spec = importlib.util.spec_from_file_location('document_pdf', SCRIPTS / 'document-pdf.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def form_fixture(path):
    import pymupdf
    with pymupdf.open() as document:
        page = document.new_page(width=420, height=600)
        page.insert_text((30, 40), 'Scientific form: sample count and consent')
        for name, kind, rect, value in (
            ('count', pymupdf.PDF_WIDGET_TYPE_TEXT, (30, 60, 150, 85), '12'),
            ('consent', pymupdf.PDF_WIDGET_TYPE_CHECKBOX, (30, 100, 50, 120), 'Yes'),
        ):
            widget = pymupdf.Widget()
            widget.field_name, widget.field_type = name, kind
            widget.rect, widget.field_value = pymupdf.Rect(rect), value
            page.add_widget(widget)
        document.save(path)


class PdfOperationsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SCRATCH.mkdir(exist_ok=True)

    def test_fill_zero_false_preserves_source_and_geometry(self):
        pdf = helper()
        import pymupdf
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix='pdf فارسی ') as directory:
            work = Path(directory)
            source, output = work / 'form.pdf', work / 'filled.pdf'
            form_fixture(source)
            original = source.read_bytes()
            pdf.fill_pdf(source, output, {'count': 0, 'consent': False})
            self.assertEqual(source.read_bytes(), original)
            with pymupdf.open(output) as document:
                page = document[0]
                fields = {widget.field_name: widget.field_value for widget in page.widgets()}
                self.assertEqual(fields['count'], '0')
                self.assertEqual(fields['consent'], 'Off')
                self.assertEqual(tuple(page.rect), (0, 0, 420, 600))

    def test_fill_preflight_and_existing_output_survive_failures(self):
        pdf = helper()
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            source, output = (Path(directory) / name for name in ('source.pdf', 'output.pdf'))
            form_fixture(source)
            output.write_bytes(b'previous approved output')
            original = source.read_bytes()
            for values in ({'count': 0, 'unknown': 'late error'}, {'consent': 0},
                           {'count': float('nan')}, {'count': None}, {}):
                with self.subTest(values=values), self.assertRaises(ValueError):
                    pdf.fill_pdf(source, output, values)
                self.assertEqual(output.read_bytes(), b'previous approved output')
                self.assertEqual(source.read_bytes(), original)
            with self.assertRaises(ValueError):
                pdf.fill_pdf(source, source, {'count': '2'})
            with mock.patch('publication.os.replace', side_effect=OSError('injected')):
                with self.assertRaises(OSError):
                    pdf.fill_pdf(source, output, {'count': '2'})
            self.assertEqual(output.read_bytes(), b'previous approved output')
            self.assertFalse(list(Path(directory).glob('.revayat-*')))

    def test_radio_group_and_single_choice_values(self):
        pdf = helper()
        import pymupdf
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            source, output = (Path(directory) / name for name in ('form.pdf', 'filled.pdf'))
            with pymupdf.open() as document:
                page = document.new_page(width=420, height=600)
                for index, value in enumerate(('Alpha', 'Beta')):
                    widget = pymupdf.Widget()
                    widget.field_name = 'method'
                    widget.field_type = pymupdf.PDF_WIDGET_TYPE_RADIOBUTTON
                    widget.field_value = False
                    widget.rect = pymupdf.Rect(30, 30 + index * 40, 50, 50 + index * 40)
                    added = page.add_widget(widget)
                    on_state = page.load_widget(added.xref).on_state()
                    kind, appearances = document.xref_get_key(added.xref, 'AP/N')
                    if kind == 'xref':
                        appearances = document.xref_object(int(appearances.split()[0]))
                    self.assertIsNotNone(on_state)
                    document.xref_set_key(added.xref, 'AP/N', appearances.replace('/' + on_state, '/' + value))
                widget = pymupdf.Widget()
                widget.field_name = 'unit'
                widget.field_type = pymupdf.PDF_WIDGET_TYPE_COMBOBOX
                widget.choice_values = ['Celsius', 'Kelvin']
                widget.field_value = 'Celsius'
                widget.rect = pymupdf.Rect(30, 150, 180, 180)
                page.add_widget(widget)
                document.save(source)
            pdf.fill_pdf(source, output, {'method': 'Beta', 'unit': 'Kelvin'})
            with pymupdf.open(output) as result:
                page = result[0]
                widgets = list(page.widgets())
                radios = [field for field in widgets if field.field_name == 'method']
                self.assertEqual([result.xref_get_key(field.xref, 'AS')[1] for field in radios], ['/Off', '/Beta'])
                self.assertEqual(next(field.field_value for field in widgets if field.field_name == 'unit'), 'Kelvin')

    def test_text_table_image_provenance_and_original_image_stream(self):
        pdf = helper()
        import pymupdf
        from PIL import Image
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            work = Path(directory)
            source = work / 'report.pdf'
            encoded = io.BytesIO()
            Image.new('RGB', (48, 24), (25, 100, 175)).save(encoded, format='JPEG')
            original_image = encoded.getvalue()
            with pymupdf.open() as document:
                page = document.new_page(width=420, height=600)
                page.insert_text((30, 35), 'Scientific sample table')
                for x in (30, 180, 330):
                    page.draw_line((x, 60), (x, 160))
                for y in (60, 110, 160):
                    page.draw_line((30, y), (330, y))
                for point, value in (((40, 90), 'Quantity'), ((190, 90), 'Value'),
                                     ((40, 140), 'Temperature'), ((190, 140), '23.5 C')):
                    page.insert_text(point, value)
                page.insert_image(pymupdf.Rect(30, 200, 126, 248), stream=original_image)
                document.save(source)
            original = source.read_bytes()
            pdf.extract_text(source, work / 'text.json')
            pdf.extract_tables(source, work / 'tables.json')
            pdf.extract_images(source, work / 'images')
            text = json.loads((work / 'text.json').read_text(encoding='utf-8'))
            self.assertEqual(text['pages'][0]['page'], 1)
            self.assertIn('Temperature', text['pages'][0]['text'])
            tables = json.loads((work / 'tables.json').read_text(encoding='utf-8'))
            self.assertEqual(tables['pages'][0]['tables'][0]['cells'][1], ['Temperature', '23.5 C'])
            images = json.loads((work / 'images/images.json').read_text(encoding='utf-8'))
            image = images['images'][0]
            self.assertEqual((work / 'images' / image['file']).read_bytes(), original_image)
            self.assertEqual((work / 'images' / image['original_stream']).read_bytes(), original_image)
            self.assertEqual(images['placements'][0]['page'], 1)
            self.assertEqual(source.read_bytes(), original)

    def test_merge_geometry_and_late_input_failure(self):
        pdf = helper()
        import pymupdf
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            work = Path(directory)
            inputs = [work / 'first.pdf', work / 'second.pdf']
            for index, path in enumerate(inputs):
                with pymupdf.open() as document:
                    page = document.new_page(width=400 + index * 100, height=600)
                    page.insert_text((30, 30), 'page ' + str(index))
                    page.set_rotation(90 * index)
                    document.save(path)
            output = work / 'merged.pdf'
            pdf.merge_pdfs(inputs, output)
            with pymupdf.open(output) as document:
                self.assertEqual(document.page_count, 2)
                self.assertEqual(document[1].rotation, 90)
                self.assertEqual(document[1].mediabox.width, 500)
            before = output.read_bytes()
            invalid = work / 'invalid.pdf'
            invalid.write_bytes(b'not a PDF')
            with self.assertRaises(Exception):
                pdf.merge_pdfs([*inputs, invalid], output)
            self.assertEqual(output.read_bytes(), before)
            with self.assertRaises(ValueError):
                pdf.merge_pdfs(inputs, inputs[0])

    def test_ocr_preflight_and_overlay_preserve_visible_page(self):
        pdf = helper()
        import pymupdf
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            work = Path(directory)
            source, output = work / 'scan.pdf', work / 'searchable.pdf'
            with pymupdf.open() as document:
                page = document.new_page(width=320, height=480)
                page.draw_rect(pymupdf.Rect(30, 40, 120, 130), color=(0.1, 0.3, 0.5), fill=(0.2, 0.6, 0.8))
                page.set_rotation(90)
                document.save(source)
            original = source.read_bytes()
            output.write_bytes(b'previous output')
            log = logging.Logger('ocr-test')
            with mock.patch.object(pdf, 'find_tesseract', return_value=None), self.assertRaises(ValueError):
                pdf.ocr_pdf(source, output, 'eng', 300, 30, log)
            self.assertEqual(output.read_bytes(), b'previous output')

            def fake_tesseract(command, timeout, logger):
                if '--list-langs' in command:
                    return 'List of available languages (1):\neng\n'
                with pymupdf.open() as layer:
                    page = layer.new_page(width=320, height=480)
                    page.insert_text((30, 35), 'Recognized specimen', render_mode=3)
                    layer.save(Path(command[2]).with_suffix('.pdf'))
                return ''

            with mock.patch.object(pdf, 'find_tesseract', return_value='tesseract'), mock.patch.object(pdf, '_capture', side_effect=fake_tesseract):
                with self.assertRaises(ValueError):
                    pdf.ocr_pdf(source, output, 'fas', 300, 30, log)
                pdf.ocr_pdf(source, output, 'eng', 300, 30, log)
            with pymupdf.open(source) as before, pymupdf.open(output) as after:
                self.assertEqual(pdf.geometry(before), pdf.geometry(after))
                self.assertEqual(before[0].get_pixmap().samples, after[0].get_pixmap().samples)
                self.assertIn('Recognized specimen', after[0].get_text())
            self.assertEqual(source.read_bytes(), original)
            self.assertFalse(list(work.glob('.revayat-*')))

    def test_encryption_and_signature_limits(self):
        pdf = helper()
        import pymupdf
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            work = Path(directory)
            encrypted = work / 'encrypted.pdf'
            with pymupdf.open() as document:
                document.new_page()
                document.save(encrypted, encryption=pymupdf.PDF_ENCRYPT_AES_256,
                              owner_pw='fixture-owner', user_pw='fixture-user')
            with self.assertRaises(ValueError):
                pdf.inspect_pdf(encrypted)
            signature = work / 'signature.pdf'
            with pymupdf.open() as document:
                page = document.new_page()
                widget = pymupdf.Widget()
                widget.field_name = 'signature'
                widget.field_type = pymupdf.PDF_WIDGET_TYPE_SIGNATURE
                widget.rect = pymupdf.Rect(20, 20, 180, 80)
                page.add_widget(widget)
                document.save(signature)
            self.assertTrue(pdf.inspect_pdf(signature)['signature_bearing'])
            with self.assertRaises(ValueError):
                pdf.merge_pdfs([signature], work / 'out.pdf')

    def test_real_tesseract_searchable_derivative(self):
        pdf = helper()
        if not pdf.find_tesseract():
            if os.environ.get('SCIENTIFIC_REQUIRE_OCR') == '1':
                self.fail('CI requires the real Tesseract OCR backend')
            self.skipTest('real OCR requires a discoverable Tesseract and eng data')
        import pymupdf
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            work = Path(directory)
            source, output = work / 'scan.pdf', work / 'searchable.pdf'
            with pymupdf.open() as original:
                page = original.new_page(width=420, height=300)
                page.insert_text((30, 60), 'Scientific specimen 2026', fontsize=22)
                page.insert_text((30, 110), 'Temperature 23.5 degrees', fontsize=18)
                pixels = page.get_pixmap(dpi=200).tobytes('png')
            with pymupdf.open() as scanned:
                page = scanned.new_page(width=420, height=300)
                page.insert_image(page.rect, stream=pixels)
                scanned.save(source)
            before_bytes = source.read_bytes()
            pdf.ocr_pdf(source, output, 'eng', 200, 60, logging.Logger('real-ocr-test'))
            with pymupdf.open(source) as before, pymupdf.open(output) as after:
                self.assertIn('Scientific', after[0].get_text())
                self.assertEqual(before[0].get_pixmap().samples, after[0].get_pixmap().samples)
                self.assertEqual(pdf.geometry(before), pdf.geometry(after))
            self.assertEqual(source.read_bytes(), before_bytes)


if __name__ == '__main__':
    unittest.main()
