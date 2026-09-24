"""Regression coverage for explicit formatting across simple and complex scripts."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log

SPEC = importlib.util.spec_from_file_location('docx_script_formatting', SCRIPTS / 'document-docx.py')
DOCX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOCX)
W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'


class DocxScriptFormattingTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='scientific formatting ')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.log = operation_log('test-docx-script-formatting', self.root / 'logs')
        self.logger = self.log.__enter__()
        self.addCleanup(self.log.__exit__, None, None, None)
        self.logger.info('running test=%s', self._testMethodName)

    def paragraph(self, runs, **options):
        from docx import Document
        return DOCX._paragraph(Document(), {'runs': runs, **options}, 'fa-IR', True)

    def test_explicit_true_sets_both_script_properties(self):
        for rtl in (True, False):
            with self.subTest(rtl=rtl):
                run = self.paragraph([{'text': 'علم Science', 'rtl': rtl,
                                       'bold': True, 'italic': True}]).runs[0]
                self.assertIs(run.bold, True)
                self.assertIs(run.italic, True)
                self.assertIs(run.font.cs_bold, True)
                self.assertIs(run.font.cs_italic, True)
                self.assertIs(run.font.rtl, rtl)

    def test_explicit_false_overrides_both_script_properties(self):
        run = self.paragraph([{'text': 'متن', 'bold': False, 'italic': False}],
                             style='Heading 1').runs[0]
        self.assertIs(run.bold, False)
        self.assertIs(run.italic, False)
        self.assertIs(run.font.cs_bold, False)
        self.assertIs(run.font.cs_italic, False)

    def test_omitted_properties_preserve_style_inheritance(self):
        run = self.paragraph([{'text': 'متن'}], style='Heading 1').runs[0]
        for value in (run.bold, run.italic, run.font.cs_bold, run.font.cs_italic):
            self.assertIsNone(value)

    def test_fractional_sizes_use_identical_serialized_half_points(self):
        for size in (1, 10.25, 11.3, 11.75, 12.8, 200):
            with self.subTest(size=size):
                run = self.paragraph([{'text': 'علم A', 'size_pt': size}]).runs[0]
                properties = run._r.rPr
                simple = properties.find(W + 'sz').get(W + 'val')
                complex_script = properties.find(W + 'szCs').get(W + 'val')
                self.assertEqual(simple, complex_script)
                self.assertEqual(int(simple), int(run.font.size.pt * 2))

    def content(self, run):
        paragraph = {'text': 'علم'}
        return {'sections': [{
            'width_mm': 210, 'height_mm': 297,
            'margins_mm': dict.fromkeys(('top', 'bottom', 'left', 'right'), 20),
            'header': {'runs': [run]}, 'footer': {'runs': [run]},
            'blocks': [{'type': 'paragraph', 'runs': [run]},
                       {'type': 'table', 'rows': [[{'runs': [run]}, paragraph]]}],
        }]}

    def test_created_package_keeps_body_table_header_footer_formatting(self):
        run = {'text': 'علم A', 'bold': True, 'italic': False, 'size_pt': 11.3}
        content = self.root / 'content.json'
        target = self.root / 'result.docx'
        content.write_text(json.dumps(self.content(run), ensure_ascii=False), encoding='utf-8')
        DOCX.create_document(content, target)
        DOCX.read_package(target)
        checked = 0
        with zipfile.ZipFile(target) as archive:
            for name in ('word/document.xml', 'word/header1.xml', 'word/footer1.xml'):
                root = ET.fromstring(archive.read(name))
                for item in root.iter(W + 'r'):
                    if ''.join(node.text or '' for node in item.iter(W + 't')) != run['text']:
                        continue
                    properties = item.find(W + 'rPr')
                    self.assertIsNotNone(properties.find(W + 'bCs'), name)
                    italic = properties.find(W + 'iCs')
                    self.assertIsNotNone(italic, name)
                    self.assertEqual(italic.get(W + 'val'), '0')
                    self.assertEqual(properties.find(W + 'sz').get(W + 'val'),
                                     properties.find(W + 'szCs').get(W + 'val'))
                    checked += 1
        self.assertEqual(checked, 4)

    def test_invalid_style_boolean_preserves_existing_destination(self):
        source = self.root / 'content.json'
        destination = self.root / 'previous.docx'
        previous = b'previous approved document'
        destination.write_bytes(previous)
        source.write_text(json.dumps(self.content({'text': 'علم', 'bold': 'false'})), encoding='utf-8')
        with self.assertRaises(ValueError):
            DOCX.create_document(source, destination)
        self.assertEqual(destination.read_bytes(), previous)


if __name__ == '__main__':
    unittest.main()
