"""An OCR layer must never repaint scientific source content, even via forms."""
import importlib.util
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import pymupdf

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT/'skills/revayat-scientific/scripts'
sys.path.insert(0,str(SCRIPTS))
SPEC=importlib.util.spec_from_file_location('audit_ocr_pipeline',SCRIPTS/'document-pdf.py')
PDF=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PDF)


def make_layer(path,painting=None,width=144,height=144):
    with pymupdf.open() as layer:
        page=layer.new_page(width=width,height=height)
        if painting!='empty':
            page.insert_text((12,30),'OCRMarker',render_mode=0 if painting=='text' else 3)
        if painting in ('fill','stroke'):
            page.draw_rect(page.rect,fill=(0,0,0) if painting=='fill' else None,
                           color=None if painting=='fill' else (0,0,0))
        elif painting=='shade':
            shade=layer.get_new_xref()
            layer.update_object(shade,'<< /ShadingType 2 /ColorSpace /DeviceRGB '
                '/Coords [0 0 144 144] /Extend [true true] /Function << /FunctionType 2 '
                '/Domain [0 1] /C0 [0 0 0] /C1 [1 0 0] /N 1 >> >>')
            resource_xref=int(layer.xref_get_key(page.xref,'Resources')[1].split()[0])
            layer.xref_set_key(resource_xref,'Shading','<< /Paint '+str(shade)+' 0 R >>')
            stream=page.get_contents()[0]
            layer.update_stream(stream,layer.xref_stream(stream)+b'\nq /Paint sh Q\n')
        elif painting=='nested':
            with pymupdf.open() as form:
                nested=form.new_page(width=width,height=height)
                nested.draw_rect(nested.rect,color=None,fill=(0,0,0))
                page.show_pdf_page(page.rect,form,0)
        elif painting=='image':
            pixmap=pymupdf.Pixmap(pymupdf.csRGB,pymupdf.IRect(0,0,10,10),False)
            pixmap.clear_with(0)
            page.insert_image(page.rect,pixmap=pixmap)
        layer.save(path)


class OcrPaintingIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ocr painting audit ')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.source,self.output=self.root/'source.pdf',self.root/'output.pdf'
        self.log=logging.getLogger(self.id())
        handler=logging.StreamHandler()
        formatter=logging.Formatter('%(asctime)s UTC [%(levelname)s] %(message)s')
        formatter.converter=time.gmtime
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        self.log.setLevel(logging.DEBUG)
        self.addCleanup(self.log.removeHandler,handler)
        self.addCleanup(handler.close)
        self.log.info('running test=%s',self._testMethodName)
        self.fixture()

    def fixture(self,pages=1,rotation=0,cropped=False):
        with pymupdf.open() as document:
            for _ in range(pages):
                page=document.new_page(width=180 if cropped else 144,height=180 if cropped else 144)
                page.draw_rect((20,20,90,90),color=None,fill=(0.2,0.4,0.8))
                page.draw_line((30,100),(120,100),color=(0.8,0.1,0.2),width=3)
                if cropped: page.set_cropbox(pymupdf.Rect(18,18,162,162))
                page.set_rotation(rotation)
            document.save(self.source)
        self.output.write_bytes(b'previous approved delivery')

    def execute(self,paintings=(None,),**options):
        pages=iter(paintings)
        def backend(command,timeout,logger):
            if '--list-langs' in command: return 'eng\n'
            make_layer(Path(command[2]).with_suffix('.pdf'),next(pages),**options)
            return ''
        with mock.patch.object(PDF,'find_tesseract',return_value='synthetic-tesseract'), \
                mock.patch.object(PDF,'_capture',side_effect=backend):
            return PDF.ocr_pdf(self.source,self.output,'eng',72,20,self.log)

    def assert_refusal(self,paintings,**options):
        original=self.source.read_bytes()
        self.output.write_bytes(b'previous approved delivery')
        with self.assertRaises(ValueError): self.execute(paintings,**options)
        self.assertEqual(self.output.read_bytes(),b'previous approved delivery')
        self.assertEqual(self.source.read_bytes(),original)
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_filled_stroked_and_shaded_layers_are_rejected(self):
        for painting in ('fill','stroke','shade'):
            with self.subTest(painting=painting): self.assert_refusal((painting,))

    def test_nested_form_painting_is_rejected(self):
        self.assert_refusal(('nested',))

    def test_visible_text_and_images_still_fail(self):
        for painting in ('text','image'):
            with self.subTest(painting=painting): self.assert_refusal((painting,))

    def test_empty_layer_is_not_claimed_as_success(self):
        self.assert_refusal(('empty',))

    def test_valid_invisible_text_keeps_every_pixel_and_source_byte(self):
        original=self.source.read_bytes()
        self.execute()
        with pymupdf.open(self.source) as source,pymupdf.open(self.output) as result:
            self.assertEqual(source[0].get_pixmap().samples,result[0].get_pixmap().samples)
            self.assertIn('OCRMarker',result[0].get_text())
            self.assertEqual(PDF.geometry(source),PDF.geometry(result))
        self.assertEqual(self.source.read_bytes(),original)

    def test_late_bad_layer_rolls_back_whole_document(self):
        self.fixture(pages=2)
        self.assert_refusal((None,'fill'))

    def test_rotation_and_nonzero_crop_keep_geometry_and_pixels(self):
        for rotation in (0,90,180,270):
            with self.subTest(rotation=rotation):
                self.fixture(rotation=rotation,cropped=True)
                before=self.source.read_bytes()
                self.execute()
                with pymupdf.open(self.source) as source,pymupdf.open(self.output) as result:
                    self.assertEqual(PDF.geometry(source),PDF.geometry(result))
                    self.assertEqual(source[0].get_pixmap().samples,result[0].get_pixmap().samples)
                    self.assertIn('OCRMarker',result[0].get_text())
                self.assertEqual(self.source.read_bytes(),before)

    def test_dimension_mismatch_remains_blocking(self):
        self.assert_refusal((None,),width=150)

    def test_backend_failure_and_deadline_keep_previous_output(self):
        original=self.source.read_bytes()
        for error in (RuntimeError('injected backend failure'),subprocess.TimeoutExpired('tesseract',1)):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(PDF,'find_tesseract',return_value='synthetic-tesseract'), \
                        mock.patch.object(PDF,'_capture',side_effect=error):
                    with self.assertRaises(type(error)):
                        PDF.ocr_pdf(self.source,self.output,'eng',72,20,self.log)
                self.assertEqual(self.output.read_bytes(),b'previous approved delivery')
                self.assertEqual(self.source.read_bytes(),original)

    def test_original_alias_refuses_before_backend_invocation(self):
        before=self.source.read_bytes()
        with mock.patch.object(PDF,'_capture') as backend:
            with self.assertRaises(ValueError):
                PDF.ocr_pdf(self.source,self.source,'eng',72,20,self.log)
            backend.assert_not_called()
        self.assertEqual(self.source.read_bytes(),before)


if __name__=='__main__':
    unittest.main()
