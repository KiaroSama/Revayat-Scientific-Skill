"""DOCX preservation and hostile-input controls; no office renderer required."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/revayat-scientific/scripts'
SCRATCH = Path(__file__).resolve().parents[1] / '.scratch'
sys.path.insert(0, str(SCRIPTS))


def package(path, text='Original text'):
    members = {
        '[Content_Types].xml': '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="bin" ContentType="application/octet-stream"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        '_rels/.rels': '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        'word/document.xml': '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>' + text + '</w:t></w:r></w:p><w:sectPr><w:pgSz w:w="9071" w:h="13606"/></w:sectPr></w:body></w:document>',
        'word/media/unchanged.bin': b'\x00\x01scientific samples\xff',
    }
    with zipfile.ZipFile(path, 'w') as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    return members


class DocxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SCRATCH.mkdir(exist_ok=True)

    def test_edit_preserves_untouched_members_and_source(self):
        from docx_package import edit_package, inspect_package
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            source = Path(directory) / 'source.docx'
            dest = Path(directory) / 'translation.docx'
            original = package(source)
            before = source.read_bytes()
            edit_package(source, dest, [{'part': 'word/document.xml', 'index': 0,
                         'expected': 'Original text', 'text': ' ترجمهٔ علمی '}])
            self.assertEqual(source.read_bytes(), before)
            with zipfile.ZipFile(dest) as result:
                for name, value in original.items():
                    if name != 'word/document.xml':
                        self.assertEqual(result.read(name), value.encode() if isinstance(value, str) else value)
                expected = original['word/document.xml'].replace('<w:t>Original text</w:t>',
                    '<w:t xml:space="preserve"> ترجمهٔ علمی </w:t>')
                self.assertEqual(result.read('word/document.xml'), expected.encode())
            self.assertEqual(inspect_package(dest)['text_nodes'][0]['text'], ' ترجمهٔ علمی ')

    def test_rejected_edits_preserve_existing_output(self):
        from docx_package import edit_package
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            source = Path(directory) / 'source.docx'
            dest = Path(directory) / 'existing.docx'
            package(source)
            dest.write_bytes(b'previous delivery')
            valid = {'part': 'word/document.xml', 'index': 0,
                     'expected': 'Original text', 'text': 'متن'}
            for change in ({'expected': 'stale'}, {'index': -1}, {'index': True},
                           {'text': 'line\nbreak'}, {'part': '../document.xml'}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    edit_package(source, dest, [dict(valid, **change)])
                self.assertEqual(dest.read_bytes(), b'previous delivery')
            for target in (source, Path(directory)):
                with self.assertRaises(ValueError):
                    edit_package(source, target, [valid])
            with self.assertRaises(ValueError):
                edit_package(source, dest, [valid, valid])
            with mock.patch('publication.os.replace', side_effect=OSError('injected failure')):
                with self.assertRaises(OSError):
                    edit_package(source, dest, [valid])
            self.assertEqual(dest.read_bytes(), b'previous delivery')
            self.assertFalse(list(Path(directory).glob('.revayat-*')))

    def test_archive_and_xml_boundaries(self):
        from docx_package import inspect_package, read_package, require_editable
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            path = Path(directory) / 'bad.docx'
            for name in ('../escape', '/absolute', 'word\\escape', 'C:escape', 'WORD/DOCUMENT.XML'):
                package(path)
                with zipfile.ZipFile(path, 'a') as archive:
                    archive.writestr(name, b'not extracted')
                with self.subTest(name=name), self.assertRaises(ValueError):
                    read_package(path)
            members = package(path)
            for value in ('<!DOCTYPE document [<!ENTITY x "expanded">]>',
                          '<!DOCTYPE document SYSTEM "file:///outside">'):
                altered = dict(members)
                altered['word/document.xml'] = value + members['word/document.xml']
                with zipfile.ZipFile(path, 'w') as archive:
                    for name, data in altered.items():
                        archive.writestr(name, data)
                with self.assertRaises(ValueError):
                    read_package(path)
            package(path)
            with zipfile.ZipFile(path, 'a') as archive:
                archive.writestr('word/vbaProject.bin', b'opaque macro content')
            report = inspect_package(path)
            self.assertIn('macros', report['unsupported'])
            with self.assertRaises(ValueError):
                require_editable(report['unsupported'])
            with mock.patch('docx_package.MAX_MEMBER', 8), self.assertRaises(ValueError):
                read_package(path)

    def test_empty_nodes_entities_and_field_markup_preserved(self):
        from docx_package import edit_package, inspect_package
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            source, dest = (Path(directory) / name for name in ('source.docx', 'out.docx'))
            members = package(source)
            original = members['word/document.xml'].replace('<w:t>Original text</w:t>',
                '<w:fldChar w:fldCharType="begin"/><w:t/><w:t>A &amp; B</w:t><w:fldChar w:fldCharType="end"/>')
            members['word/document.xml'] = original
            with zipfile.ZipFile(source, 'w') as archive:
                for name, value in members.items():
                    archive.writestr(name, value)
            edit_package(source, dest, [
                {'part': 'word/document.xml', 'index': 0, 'expected': '', 'text': '<متن>'},
                {'part': 'word/document.xml', 'index': 1, 'expected': 'A & B', 'text': 'A & C'},
            ])
            with zipfile.ZipFile(dest) as archive:
                self.assertEqual(archive.read('word/document.xml').decode(), original.replace(
                    '<w:t/>', '<w:t>&lt;متن&gt;</w:t>').replace('A &amp; B', 'A &amp; C'))
            self.assertEqual(inspect_package(dest)['structures']['fldChar'], 2)

    def test_relationship_boundaries_and_signed_refusal(self):
        from docx_package import read_package, inspect_package, edit_package
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            path = Path(directory) / 'source.docx'
            output = Path(directory) / 'output.docx'
            members = package(path)
            relname = 'word/_rels/document.xml.rels'
            relation = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.invalid/private" TargetMode="External"/></Relationships>'
            with zipfile.ZipFile(path, 'a') as archive:
                archive.writestr(relname, relation)
            report = inspect_package(path)
            self.assertTrue(any(item['mode'] == 'External' for item in report['relationships']))
            for target in ('../../escape.xml', '%2e%2e/%2e%2e/escape.xml', 'file:///outside.xml'):
                with zipfile.ZipFile(path, 'w') as archive:
                    for name, value in members.items():
                        archive.writestr(name, value)
                    archive.writestr(relname, relation.replace('https://example.invalid/private', target).replace('External', 'Internal'))
                with self.subTest(target=target), self.assertRaises(ValueError):
                    read_package(path)
            package(path)
            with zipfile.ZipFile(path, 'a') as archive:
                archive.writestr('_xmlsignatures/sig1.xml', '<signature/>')
            self.assertIn('digital-signatures', inspect_package(path)['unsupported'])
            with self.assertRaises(ValueError):
                edit_package(path, output, [{'part': 'word/document.xml', 'index': 0,
                             'expected': 'Original text', 'text': 'متن'}])
            self.assertFalse(output.exists())

    def test_create_sections_rtl_tables_images_and_edit(self):
        spec = importlib.util.spec_from_file_location('document_docx', SCRIPTS / 'document-docx.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        from docx_package import inspect_package, edit_package, W
        import xml.etree.ElementTree as ET
        from PIL import Image

        with tempfile.TemporaryDirectory(prefix='docx فارسی ', dir=SCRATCH) as directory:
            root = Path(directory)
            image = root / 'figure.png'
            Image.new('RGB', (24, 12), (20, 80, 120)).save(image, dpi=(300, 300))
            content = json.loads((Path(__file__).parent / 'fixtures/docx-content.json').read_text(encoding='utf-8'))
            source = root / 'content.json'
            source.write_text(json.dumps(content, ensure_ascii=False), encoding='utf-8')
            output = root / 'source.docx'
            helper.create_document(source, output)
            report = inspect_package(output)
            self.assertEqual(len(report['sections']), 2)
            self.assertEqual(report['structures']['tbl'], 1)
            self.assertEqual(report['structures']['drawing'], 1)
            first = report['sections'][0]['geometry_twips']['pgSz']
            self.assertAlmostEqual(int(first['w']), 160 / 25.4 * 1440, delta=1)
            self.assertAlmostEqual(int(first['h']), 240 / 25.4 * 1440, delta=1)
            with zipfile.ZipFile(output) as archive:
                media = report['media'][0]['part']
                self.assertEqual(archive.read(media), image.read_bytes())
                tree = ET.fromstring(archive.read('word/document.xml'))
                self.assertTrue(list(tree.iter('{' + W + '}bidi')))
                self.assertTrue(list(tree.iter('{' + W + '}rtl')))
                self.assertTrue(any(node.get('{' + W + '}bidi') == 'fa-IR'
                                    for node in tree.iter('{' + W + '}lang')))
                scientific = next(paragraph for paragraph in tree.iter('{' + W + '}p')
                                  if any(node.text == '23.5 °C' for node in paragraph.iter('{' + W + '}t')))
                self.assertEqual(scientific.find('{' + W + '}pPr/{' + W + '}bidi').get('{' + W + '}val'), '0')
                run = scientific.find('{' + W + '}r/{' + W + '}rPr')
                self.assertEqual(run.find('{' + W + '}rtl').get('{' + W + '}val'), '0')
                self.assertEqual(run.find('{' + W + '}lang').get('{' + W + '}val'), 'en-US')
                requested = next(node for node in tree.iter('{' + W + '}rFonts')
                                 if node.get('{' + W + '}cs') == 'Vazirmatn')
                self.assertEqual(requested.get('{' + W + '}ascii'), 'Vazirmatn')
                self.assertEqual(requested.get('{' + W + '}hAnsi'), 'Vazirmatn')
            address = next(node for node in report['text_nodes'] if node['text'] == 'Scientific example')
            final = root / 'translated.docx'
            edit_package(output, final, [{**{key: address[key] for key in ('part', 'index')},
                                         'expected': address['text'], 'text': 'نمونهٔ علمی'}])
            with zipfile.ZipFile(output) as before, zipfile.ZipFile(final) as after:
                for name in before.namelist():
                    if name != address['part']:
                        self.assertEqual(before.read(name), after.read(name), name)
            self.assertEqual(inspect_package(final)['sections'], report['sections'])
            self.assertEqual(inspect_package(final)['media'], report['media'])


if __name__ == '__main__':
    unittest.main()
