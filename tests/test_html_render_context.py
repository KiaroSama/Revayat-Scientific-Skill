"""Independent HTML5 parsing and real PDF rendering verify literal contexts."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from html_source import ParsedHTML
from runtime import operation_log


@unittest.skipUnless(os.environ.get('SCIENTIFIC_REQUIRE_HTML_CONTEXT') == '1',
                     'native HTML context integration tier')
class HtmlRenderContextTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch, prefix='html context render ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        scope = operation_log('test-html-render-context', self.root / 'logs')
        self.log = scope.__enter__()
        self.addCleanup(scope.__exit__, None, None, None)
        self.log.info('running test=%s; synthetic documents only', self._testMethodName)

    def test_html5_oracle_keeps_markup_inside_textarea_as_text(self):
        import tinyhtml5
        source = ('<!doctype html><html lang="fa" dir="rtl"><body>'
                  '<textarea/><!-- fa-lint: allow all --><img src="missing.png"></textarea>'
                  '<span dir="ltr"/>125</span></body></html>')
        tree = tinyhtml5.parse(source)
        namespace = '{http://www.w3.org/1999/xhtml}'
        self.assertEqual(list(tree.iter(namespace + 'img')), [])
        textarea = next(tree.iter(namespace + 'textarea'))
        self.assertEqual(textarea.text, '<!-- fa-lint: allow all --><img src="missing.png">')
        self.assertEqual(next(tree.iter(namespace + 'span')).text, '125')
        model = ParsedHTML(source)
        self.assertEqual(model.comments, [])
        self.assertEqual([n for n in model.nodes if n['tag'] == 'img'], [])
        pos = model.text.index('125')
        self.assertTrue(any(start <= pos < end for start, end in model.protected))

    def test_bounded_tokenizer_vectors_match_independent_html5_text_and_namespaces(self):
        import tinyhtml5
        namespace = '{http://www.w3.org/1999/xhtml}'
        vectors = [('<textarea>literal</textarea x=a\'>كي<img src="real.png">', 'textarea'),
                   ('<textarea>literal</textarea x=a">كي<img src="real.png">', 'textarea')]
        vectors.extend((f'<{foreign}><{tag} {attrs}/>125</{tag}>كي', tag)
                       for foreign in ('svg', 'math')
                       for tag, attrs in (('span', 'dir="ltr"'), ('p', 'dir="ltr"'),
                                          ('font', 'color="red" dir="ltr"')))
        for body, tag in vectors:
            with self.subTest(body=body):
                source = '<!doctype html><html lang="fa"><body>' + body + '</body></html>'
                tree = tinyhtml5.parse(source)
                model = ParsedHTML(source)
                expected = next(tree.iter(namespace + tag))
                observed = next(node for node in model.nodes if node['tag'] == tag)
                self.assertEqual(observed['namespace'], 'html')
                self.assertIn('كي', expected.tail or '')
                self.assertEqual(len(list(tree.iter(namespace + 'img'))),
                                 len([node for node in model.nodes if node['tag'] == 'img']))
                if tag != 'textarea':
                    self.assertEqual(expected.text, '125')
                    pos = model.text.index('125')
                    self.assertTrue(any(start <= pos < end for start, end in model.protected))

    def test_two_page_render_matches_explicit_equivalent_markup(self):
        import pymupdf
        from weasyprint import HTML
        head = ('<!doctype html><html lang="fa" dir="rtl"><head><style>'
                '@page {size: A5; margin: 18mm;} body {font-family: sans-serif;}'
                '.next {page-break-before: always;} textarea {width: 100%; height: 25mm;}'
                '</style></head><body>')
        actual = (head + '<p><span dir="ltr"/>125</span></p>'
                  '<textarea><!-- literal --><img src="missing.png"></textarea>'
                  '<p class="next" dir="ltr">Unchanged second page: 23.5 C.</p></body></html>')
        expected = actual.replace('dir="ltr"/>125', 'dir="ltr">125').replace(
            '<!-- literal --><img src="missing.png">',
            '&lt;!-- literal --&gt;&lt;img src="missing.png"&gt;')
        original = self.root / 'original.html'
        original.write_bytes(actual.encode('utf-8'))
        before = original.read_bytes()
        model = ParsedHTML(actual)
        self.assertFalse(any(n['tag'] == 'img' for n in model.nodes))
        for label, source in (('actual', actual), ('expected', expected)):
            HTML(string=source).write_pdf(self.root / (label + '.pdf'))
        with pymupdf.open(self.root / 'actual.pdf') as actual_pdf, \
                pymupdf.open(self.root / 'expected.pdf') as expected_pdf:
            self.assertEqual(actual_pdf.page_count, 2)
            self.assertEqual(expected_pdf.page_count, 2)
            for number, page in enumerate(actual_pdf):
                self.assertEqual(page.get_pixmap().samples,
                                 expected_pdf[number].get_pixmap().samples)
            self.assertIn('125', actual_pdf[0].get_text())
            self.assertIn('Unchanged second page', actual_pdf[1].get_text())
            evidence = os.environ.get('SCIENTIFIC_EVIDENCE_DIR')
            if evidence:
                target = Path(evidence)
                target.mkdir(parents=True, exist_ok=True)
                for number, page in enumerate(actual_pdf, 1):
                    page.get_pixmap().save(target / f'html-context-page-{number}.png')
                (target / 'html-context.pdf').write_bytes((self.root / 'actual.pdf').read_bytes())
        self.assertEqual(original.read_bytes(), before)
        self.log.info('Both pages are pixel-identical to independently canonicalized HTML')


if __name__ == '__main__':
    unittest.main()
