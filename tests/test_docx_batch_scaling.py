"""Batch DOCX editing must preserve bytes without per-edit whole-story scans."""
import hashlib
import logging
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
import docx_package as package


def make_package(path, count=10):
    body = '<!-- untouched -->' + ''.join(
        '<w:p><w:r><w:t>Original ' + str(i) + '</w:t></w:r></w:p>' for i in range(count))
    members = {
        '[Content_Types].xml': '<Types xmlns="' + package.C + '"><Default Extension="xml" ContentType="application/xml"/><Default Extension="bin" ContentType="application/octet-stream"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="' + package.MAIN_TYPE + '"/></Types>',
        '_rels/.rels': '<Relationships xmlns="' + package.R + '"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        'word/document.xml': '<w:document xmlns:w="' + package.W + '"><w:body>' + body + '</w:body></w:document>',
        'word/header1.xml': '<w:hdr xmlns:w="' + package.W + '"><w:p><w:r><w:t>Header</w:t><w:t/></w:r></w:p></w:hdr>',
        'word/media/retained.bin': b'\x00unaltered-source-media\xff',
    }
    with zipfile.ZipFile(path, 'w') as archive:
        archive.comment = b'unchanged archive comment'
        for name, value in members.items():
            archive.writestr(name, value)
    return {name: value.encode() if isinstance(value, str) else value for name,value in members.items()}


def edits(count):
    return [{'part':'word/document.xml', 'index':i, 'expected':f'Original {i}',
             'text':f'ترجمه {i}'} for i in reversed(range(count))]


class DocxBatchScalingTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='docx batch ')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.source, self.output = self.root/'source.docx', self.root/'output.docx'
        self.log = logging.getLogger(self.id())
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        self.log.addHandler(handler)
        self.log.setLevel(logging.INFO)
        self.addCleanup(self.log.removeHandler, handler)
        self.addCleanup(handler.close)
        self.log.info('running synthetic DOCX batch regression')

    def test_story_tree_is_walked_once_not_once_per_patch(self):
        make_package(self.source, 300)
        original_reader = package.read_package
        visits = []

        class CountedRoot:
            def __init__(self, root):
                self.root = root
            def iter(self, tag):
                visits.append(tag)
                return self.root.iter(tag)

        def read(path):
            result = list(original_reader(path))
            if Path(path) == self.source:
                result[2] = dict(result[2])
                result[2]['word/document.xml'] = CountedRoot(result[2]['word/document.xml'])
            return tuple(result)

        with mock.patch.object(package, 'read_package', side_effect=read):
            package.edit_package(self.source, self.output, edits(300))
        self.assertEqual(len(visits), 1, 'one node index must be shared by all edits to a story')
        report = package.inspect_package(self.output)
        self.assertEqual(report['text_nodes'][299]['text'], 'ترجمه 299')

    def test_multistory_unsorted_edits_preserve_all_untouched_bytes(self):
        members = make_package(self.source, 1500)
        before = self.source.read_bytes()
        changes = edits(1500) + [
            {'part':'word/header1.xml','index':0,'expected':'Header','text':' A & <B> '},
            {'part':'word/header1.xml','index':1,'expected':'','text':'Empty filled'},
        ]
        package.edit_package(self.source, self.output, changes)
        expected = members['word/document.xml']
        for i in range(1500):
            expected = expected.replace(f'>Original {i}<'.encode(), f'>ترجمه {i}<'.encode())
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.read('word/document.xml'), expected)
            self.assertEqual(archive.read('word/header1.xml'), members['word/header1.xml'].replace(
                b'<w:t>Header</w:t>', b'<w:t xml:space="preserve"> A &amp; &lt;B&gt; </w:t>').replace(
                b'<w:t/>', b'<w:t>Empty filled</w:t>'))
            for name in members.keys() - {'word/document.xml','word/header1.xml'}:
                self.assertEqual(archive.read(name), members[name])
            self.assertEqual(archive.comment, b'unchanged archive comment')
        self.assertEqual(self.source.read_bytes(), before)

    def test_late_stale_patch_preserves_destination(self):
        make_package(self.source, 100)
        original = hashlib.sha256(self.source.read_bytes()).digest()
        self.output.write_bytes(b'previous approved output')
        changes = edits(100)
        changes[-1]['expected'] = 'stale'
        with self.assertRaisesRegex(ValueError, 'stale'):
            package.edit_package(self.source,self.output,changes)
        self.assertEqual(self.output.read_bytes(),b'previous approved output')
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).digest(),original)
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_duplicate_addresses_and_invalid_characters_remain_rejected(self):
        make_package(self.source)
        self.output.write_bytes(b'previous')
        one = edits(1)[0]
        for changes in ([one,one], [{**one,'text':'bad\x00'}], [{**one,'text':'bad\ud800'}]):
            with self.subTest(count=len(changes)), self.assertRaises(ValueError):
                package.edit_package(self.source,self.output,changes)
            self.assertEqual(self.output.read_bytes(),b'previous')

    def test_growing_part_limit_preserves_existing_delivery(self):
        make_package(self.source, 2)
        self.output.write_bytes(b'previous')
        changes = edits(2)
        changes[0]['text'] = 'x' * 2000
        with mock.patch.object(package,'MAX_XML',1024), self.assertRaises(ValueError):
            package.edit_package(self.source,self.output,changes)
        self.assertEqual(self.output.read_bytes(),b'previous')

    def test_late_publication_failure_does_not_destroy_previous_output(self):
        make_package(self.source, 40)
        self.output.write_bytes(b'previous')
        with mock.patch('publication.os.replace',side_effect=OSError('injected failure')):
            with self.assertRaises(OSError):
                package.edit_package(self.source,self.output,edits(40))
        self.assertEqual(self.output.read_bytes(),b'previous')
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_adjacent_empty_and_nonempty_text_nodes(self):
        data = ('<w:document xmlns:w="'+package.W+'"><w:body><w:p><w:r>'
                '<w:t/><w:t>A &amp; B</w:t><w:t>C</w:t>'
                '</w:r></w:p></w:body></w:document>').encode()
        parts = make_package(self.source,1)
        parts['word/document.xml'] = data
        with zipfile.ZipFile(self.source,'w') as archive:
            for name,value in parts.items():
                archive.writestr(name,value)
        changes=[{'part':'word/document.xml','index':i,'expected':old,'text':new}
                 for i,old,new in ((2,'C',''),(0,'','<New>'),(1,'A & B',' A & C '))]
        package.edit_package(self.source,self.output,changes)
        with zipfile.ZipFile(self.output) as archive:
            expected=data.replace(b'<w:t/>',b'<w:t>&lt;New&gt;</w:t>').replace(
                b'<w:t>A &amp; B</w:t>',b'<w:t xml:space="preserve"> A &amp; C </w:t>').replace(
                b'<w:t>C</w:t>',b'<w:t></w:t>')
            self.assertEqual(archive.read('word/document.xml'),expected)


if __name__ == '__main__':
    unittest.main()
