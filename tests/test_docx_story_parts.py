"""Address secondary Word stories by declared type, not a generated filename."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
import docx_package as package
from runtime import operation_log

KINDS = {'header': 'hdr', 'footer': 'ftr', 'footnotes': 'footnotes',
         'endnotes': 'endnotes', 'comments': 'comments'}
TYPE_PREFIX = 'application/vnd.openxmlformats-officedocument.wordprocessingml.'


class DocxStoryPartsTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='docx story audit ', dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source, self.output = self.root/'source.docx', self.root/'result.docx'
        self.scope = operation_log('test-docx-story-parts', self.root / 'logs')
        self.log = self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)

    def fixture(self, kind='header', part='word/stories/first.xml', *, generic=False,
                default=False, root=None, extra_type='', story=None):
        mime = 'application/xml' if generic else TYPE_PREFIX + kind + '+xml'
        node = KINDS[kind] if root is None else root
        raw = ('<w:' + node + ' xmlns:w="' + package.W + '"><w:p><w:r>'
               '<w:t>Original</w:t></w:r></w:p></w:' + node + '>').encode('utf-8')
        decl = ('<Default Extension="'+part.rsplit('.',1)[-1]+'" ContentType="'+mime+'"/>'
                if default else '<Override PartName="/'+part+'" ContentType="'+mime+'"/>')
        types = ('<Types xmlns="'+package.C+'">'
                 '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                 '<Default Extension="xml" ContentType="application/xml"/>'
                 '<Override PartName="/word/document.xml" ContentType="'+package.MAIN_TYPE+'"/>'
                 +decl+extra_type+'</Types>')
        members = {
            '[Content_Types].xml':types.encode('utf-8'),
            '_rels/.rels': ('<Relationships xmlns="'+package.R+'"><Relationship Id="r1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                'Target="word/document.xml"/></Relationships>').encode('utf-8'),
            'word/document.xml': ('<w:document xmlns:w="'+package.W+'"><w:body><w:p><w:r>'
                '<w:t>Body</w:t></w:r></w:p></w:body></w:document>').encode('utf-8'),
            'word/_rels/document.xml.rels': ('<Relationships xmlns="'+package.R+'"><Relationship Id="s1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'+kind+'" '
                'Target="/'+part+'"/></Relationships>').encode('utf-8'),
            part: raw if story is None else story,
        }
        self.write(members)
        return members

    def write(self, members):
        with zipfile.ZipFile(self.source, 'w') as archive:
            archive.comment = b'untouched package comment'
            # Reverse order to prove discovery does not depend on ZIP member order.
            for name, data in reversed(list(members.items())):
                archive.writestr(name, data)

    def test_all_five_story_kinds_use_declared_names(self):
        for kind in KINDS:
            for part in ('word/stories/named.xml', 'other/named.part', 'named'):
                with self.subTest(kind=kind,part=part):
                    self.fixture(kind,part)
                    nodes=package.inspect_package(self.source)['text_nodes']
                    self.assertIn({'part':part,'index':0,'text':'Original'},nodes)

    def test_inspected_address_is_editable_without_changing_other_bytes(self):
        for kind in KINDS:
            with self.subTest(kind=kind):
                part='shared/'+kind+'.story'
                before=self.fixture(kind,part)
                source_bytes=self.source.read_bytes()
                patch=[{'part':part,'index':0,'expected':'Original','text':' متن & <x> '}]
                package.edit_package(self.source,self.output,patch)
                with zipfile.ZipFile(self.output) as archive:
                    self.assertEqual(set(archive.namelist()),set(before))
                    self.assertEqual(archive.comment,b'untouched package comment')
                    for name,data in before.items():
                        expected=(data.replace(b'<w:t>Original</w:t>',
                            '<w:t xml:space="preserve"> متن &amp; &lt;x&gt; </w:t>'.encode('utf-8'))
                            if name==part else data)
                        self.assertEqual(archive.read(name),expected)
                self.assertEqual(self.source.read_bytes(),source_bytes)

    def test_default_story_type_and_override_precedence(self):
        part='word/custom.hdr'
        self.fixture(part=part,default=True)
        self.assertIn(part,{n['part'] for n in package.inspect_package(self.source)['text_nodes']})
        self.fixture(part=part,default=True,
            extra_type='<Override PartName="/'+part+'" ContentType="application/xml"/>')
        self.assertNotIn(part,{n['part'] for n in package.inspect_package(self.source)['text_nodes']})

    def test_content_type_keys_are_ascii_insensitive_and_unique(self):
        part = 'word/stories/first.hdr'
        variants = ('override', 'default', 'duplicate-override', 'duplicate-default', 'main-default')
        for variant in variants:
            with self.subTest(variant=variant):
                members = self.fixture(part=part, default=variant in ('default', 'duplicate-default'))
                types = members['[Content_Types].xml']
                if variant == 'override':
                    types = types.replace(b'PartName="/word/stories/first.hdr"',
                                          b'PartName="/WORD/STORIES/FIRST.HDR"')
                    types = types.replace(b'PartName="/word/document.xml"', b'PartName="/WORD/DOCUMENT.XML"')
                elif variant == 'default':
                    types = types.replace(b'Extension="hdr"', b'Extension="HDR"')
                elif variant.startswith('duplicate'):
                    declaration = ('<Override PartName="/WORD/STORIES/FIRST.HDR" ContentType="application/xml"/>'
                                   if variant == 'duplicate-override' else
                                   '<Default Extension="HDR" ContentType="application/xml"/>')
                    types = types.replace(b'</Types>', declaration.encode('utf-8') + b'</Types>')
                else:
                    types = types.replace(b'ContentType="application/xml"',
                                          ('ContentType="' + package.MAIN_TYPE + '"').encode('utf-8'))
                    types = types.replace(('<Override PartName="/word/document.xml" ContentType="'
                                           + package.MAIN_TYPE + '"/>').encode('utf-8'), b'')
                members['[Content_Types].xml'] = types
                self.write(members)
                if variant.startswith('duplicate'):
                    with self.assertRaises(ValueError):
                        package.read_package(self.source)
                else:
                    self.assertIn({'part': part, 'index': 0, 'text': 'Original'},
                                  package.inspect_package(self.source)['text_nodes'])

    def test_generic_custom_xml_is_not_authorized_by_a_text_node(self):
        part='customXml/item.xml'
        self.fixture(part=part,generic=True)
        self.assertNotIn(part,{n['part'] for n in package.inspect_package(self.source)['text_nodes']})
        with self.assertRaises(ValueError):
            package.edit_package(self.source,self.output,[{'part':part,'index':0,
                'expected':'Original','text':'Changed'}])
        self.assertFalse(self.output.exists())

    def test_legacy_canonical_generic_story_remains_supported(self):
        part='word/header1.xml'
        self.fixture(part=part,generic=True)
        package.edit_package(self.source,self.output,[{'part':part,'index':0,
            'expected':'Original','text':'Changed'}])
        self.assertIn({'part':part,'index':0,'text':'Changed'},
            package.inspect_package(self.output)['text_nodes'])

    def test_primary_document_stays_editable_with_authoritative_main_type(self):
        before = self.fixture()
        self.assertIn({'part': 'word/document.xml', 'index': 0, 'text': 'Body'},
                      package.inspect_package(self.source)['text_nodes'])
        package.edit_package(self.source, self.output, [{'part': 'word/document.xml',
            'index': 0, 'expected': 'Body', 'text': 'Changed body'}])
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.read('word/document.xml'),
                             before['word/document.xml'].replace(b'Body', b'Changed body'))
            self.assertEqual(archive.read('word/stories/first.xml'), before['word/stories/first.xml'])

    def test_canonical_names_do_not_override_custom_types_or_wrong_roots(self):
        part = 'word/header1.xml'
        for declaration, root, excluded in (('application/custom+xml', 'hdr', True),
                                             ('application/xml', 'ftr', False),
                                             ('text/xml', 'custom', False)):
            with self.subTest(declaration=declaration, root=root):
                members = self.fixture(part=part, generic=True, root=root)
                members['[Content_Types].xml'] = members['[Content_Types].xml'].replace(
                    b'PartName="/word/header1.xml" ContentType="application/xml"',
                    ('PartName="/word/header1.xml" ContentType="' + declaration + '"').encode('utf-8'))
                self.write(members)
                before = self.source.read_bytes()
                self.output.write_bytes(b'previous delivery')
                if excluded:
                    self.assertNotIn(part, {node['part'] for node in
                                           package.inspect_package(self.source)['text_nodes']})
                with self.assertRaises(ValueError):
                    package.edit_package(self.source, self.output, [{'part': part, 'index': 0,
                        'expected': 'Original', 'text': 'Changed'}])
                self.assertEqual(self.source.read_bytes(), before)
                self.assertEqual(self.output.read_bytes(), b'previous delivery')

    def test_wrong_declared_story_root_fails_before_publication(self):
        for root in ('document','ftr','custom'):
            with self.subTest(root=root):
                self.fixture(root=root)
                self.output.write_bytes(b'previous delivery')
                with self.assertRaises(ValueError):
                    package.edit_package(self.source,self.output,[{'part':'word/stories/first.xml',
                        'index':0,'expected':'Original','text':'Changed'}])
                self.assertEqual(self.output.read_bytes(),b'previous delivery')

    def test_duplicate_declarations_are_not_silently_selected(self):
        self.fixture(extra_type='<Override PartName="/word/stories/first.xml" ContentType="application/xml"/>')
        with self.assertRaises(ValueError): package.read_package(self.source)

    def test_typed_nonxml_suffix_cannot_bypass_xml_limits(self):
        samples=(b'<!DOCTYPE hdr><w:hdr xmlns:w="'+package.W.encode('utf-8')+b'"/>',
                 b'\xff', b'<broken', b' '*(package.MAX_XML+1))
        for data in samples:
            with self.subTest(size=len(data)):
                self.fixture(part='word/first.story',story=data)
                with self.assertRaises((ValueError,package.ET.ParseError)):
                    package.read_package(self.source)

    def test_late_stale_edit_keeps_source_and_destination(self):
        part='word/custom.xml'
        self.fixture(part=part)
        before=self.source.read_bytes()
        self.output.write_bytes(b'previous delivery')
        with self.assertRaisesRegex(ValueError,'stale'):
            package.edit_package(self.source,self.output,[
                {'part':'word/document.xml','index':0,'expected':'Body','text':'New body'},
                {'part':part,'index':0,'expected':'Stale','text':'New header'}])
        self.assertEqual(self.output.read_bytes(),b'previous delivery')
        self.assertEqual(self.source.read_bytes(),before)
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_duplicate_addresses_and_publication_failure_are_recoverable(self):
        part='word/custom.xml'
        self.fixture(part=part)
        patch={'part':part,'index':0,'expected':'Original','text':'Changed'}
        self.output.write_bytes(b'previous delivery')
        with self.assertRaises(ValueError): package.edit_package(self.source,self.output,[patch,patch])
        with mock.patch('publication.os.replace',side_effect=OSError('injected failure')):
            with self.assertRaises(OSError): package.edit_package(self.source,self.output,[patch])
        self.assertEqual(self.output.read_bytes(),b'previous delivery')
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_python_docx_reads_and_edits_a_renamed_real_header(self):
        from docx import Document
        document=Document()
        document.add_paragraph('Body')
        document.sections[0].header.paragraphs[0].text='Original'
        document.save(self.source)
        with zipfile.ZipFile(self.source) as archive:
            members={n:archive.read(n) for n in archive.namelist()}
        part='word/stories/first.xml'
        members[part]=members.pop('word/header1.xml')
        members['[Content_Types].xml']=members['[Content_Types].xml'].replace(
            b'/word/header1.xml',('/'+part).encode('utf-8'))
        members['word/_rels/document.xml.rels']=members['word/_rels/document.xml.rels'].replace(
            b'Target="header1.xml"',b'Target="stories/first.xml"')
        self.write(members)
        self.assertEqual(Document(self.source).sections[0].header.paragraphs[0].text,'Original')
        package.edit_package(self.source,self.output,[{'part':part,'index':0,
            'expected':'Original','text':'Changed'}])
        self.assertEqual(Document(self.output).sections[0].header.paragraphs[0].text,'Changed')


if __name__ == '__main__':
    unittest.main()
