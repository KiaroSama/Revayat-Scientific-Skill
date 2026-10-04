"""Text-order evidence comes from source text tokens, not serialized HTML markup."""
import importlib.util
import os
from pathlib import Path
import random
import sys
import tempfile
import unittest
import unittest.mock

from processes import run
ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log
SPEC = importlib.util.spec_from_file_location('text_order_sources', SCRIPTS / 'check-pdf-text-order.py')
ORDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORDER)
VISIBLE = 'متن علمی اصلی برای بررسی دقیق ترتیب حروف'
HIDDEN = 'داده آزمایشی غیر قابل نمایش در سند'


class TextOrderSourceTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch, prefix='order-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        scope = operation_log('test-order-sources', self.root / 'logs')
        self.log = scope.__enter__()
        self.addCleanup(scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)

    def test_hidden_attribute_text_is_not_evidence(self):
        plain = ORDER.strip_html(f'<p title="a > {HIDDEN}">{VISIBLE}</p>')
        self.assertIn(VISIBLE, plain)
        self.assertNotIn(HIDDEN, plain)
        self.assertEqual(ORDER.classify(ORDER.persian_windows(plain), HIDDEN), 'inconclusive')

    def test_ignored_end_tags_cannot_expose_hidden_source_evidence(self):
        source, extracted = self.root / 'source.html', self.root / 'extracted.txt'
        body = f'<span hidden><p>A</span><p>{VISIBLE}</p>'
        self.assertNotIn(VISIBLE, ORDER.strip_html(body))
        source.write_text('<html lang="fa"><body>' + body + '</body></html>', encoding='utf-8')
        extracted.write_text(VISIBLE, encoding='utf-8')
        before = source.read_bytes(), extracted.read_bytes()
        result = run([sys.executable, str(SCRIPTS / 'check-pdf-text-order.py'), '--source', str(source),
                      '--extracted', str(extracted), '--json'], timeout=15)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn('inconclusive', result.stdout)
        self.assertEqual((source.read_bytes(), extracted.read_bytes()), before)

    def test_comment_tail_with_angle_bracket_is_not_evidence(self):
        for comment in (f'<!-- <span>{HIDDEN}</span> -->', f'<!-- a > {HIDDEN} --!>'):
            with self.subTest(comment=comment):
                self.assertNotIn(HIDDEN, ORDER.strip_html(comment + '<p>' + VISIBLE + '</p>'))

    def test_title_head_script_style_and_hidden_subtrees_are_excluded(self):
        for start, end in (('<head><title>', '</title></head>'), ('<script>', '</script>'),
                           ('<style>', '</style>'), ('<div hidden><span>', '</span></div>')):
            with self.subTest(start=start):
                plain = ORDER.strip_html(start + HIDDEN + end + '<p>' + VISIBLE + '</p>')
                self.assertNotIn(HIDDEN, plain)
                self.assertIn(VISIBLE, plain)

    def test_textarea_markup_is_preserved_as_displayed_text(self):
        plain = ORDER.strip_html('<textarea><script>' + VISIBLE + '</script></textarea>')
        self.assertIn(VISIBLE, plain)
        self.assertIn('<script>', plain)
        self.assertEqual(ORDER.classify(ORDER.persian_windows(plain), VISIBLE), 'logical')

    def test_raw_text_entities_and_escaped_literal_tag_text_keep_semantics(self):
        plain = ORDER.strip_html('<xmp>&amp; ' + VISIBLE + '</xmp><p>&lt;b&gt; متن &amp; واژه</p>')
        self.assertIn('&amp;', plain)
        self.assertIn('<b> متن & واژه', plain)
        self.assertNotIn('<p>', plain)

    def test_inline_boundaries_preserve_words_but_block_elements_separate_them(self):
        self.assertIn('آزمایش', ORDER.strip_html('<p>آز<b>ما</b>یش</p>'))
        plain = ORDER.strip_html('<p>آزمایش</p><p>علمی</p>')
        self.assertIn('آزمایش علمی', ' '.join(plain.split()))

    def test_invalid_raw_context_is_not_certified_by_another_parser(self):
        for source in ('<textarea>unclosed', '<template>' + VISIBLE + '</template>'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                ORDER.strip_html(source)

    def test_window_results_match_legacy_algorithm_on_bounded_inputs(self):
        def legacy(plain, threshold):
            words = [ORDER.fold(w) for w in ORDER.ARABIC_WORD.findall(plain)]
            result, seen = [], set()
            for index in range(len(words)):
                total, acc = 0, []
                for word in words[index:]:
                    if not word:
                        continue
                    acc.append(word)
                    total += len(word)
                    if total >= threshold:
                        item = tuple(acc)
                        if item not in seen:
                            result.append(acc)
                            seen.add(item)
                        break
            return result
        rng = random.Random(20261004)
        for threshold in (1, 4, 12, 50):
            for _ in range(12):
                text = ' '.join(rng.choice(VISIBLE.split()) for _ in range(40))
                self.assertEqual(ORDER.persian_windows(text, threshold), legacy(text, threshold))

    def test_windows_do_not_copy_whole_remaining_source_for_every_probe(self):
        class Words(list):
            def __getitem__(self, key):
                if isinstance(key, slice) and key.stop is None:
                    raise IndexError('quadratic suffix copying')
                return super().__getitem__(key)
        # Keep folded input as the instrumented sequence at its construction site.
        with unittest.mock.patch.object(ORDER, 'fold', side_effect=lambda word: word):
            words = Words(['آزمایش', 'علمی'] * 1000)
            class WordPattern:
                def findall(self, text):
                    return words
            with unittest.mock.patch.object(ORDER, 'ARABIC_WORD', WordPattern()):
                # The exact legacy suffix allocation is independently checked below.
                result = ORDER.persian_windows('ignored')
        self.assertTrue(result)
        import ast
        tree = ast.parse(__import__('inspect').getsource(ORDER.persian_windows))
        self.assertFalse(any(isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice)
                             and n.slice.upper is None for n in ast.walk(tree)))

    def test_invalid_threshold_and_excessive_work_are_explicit_errors(self):
        for threshold in (0, -1, 4097):
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                ORDER.persian_windows(VISIBLE, threshold)
        with unittest.mock.patch.object(ORDER, 'MAX_PROBE_STEPS', 10), self.assertRaises(ValueError):
            ORDER.persian_windows(VISIBLE * 10)

    def test_cli_cannot_pass_using_attribute_only_evidence(self):
        source, extracted = self.root / 'source.html', self.root / 'extracted.txt'
        source.write_text(f'<html lang="fa"><body><p title="a > {HIDDEN}">{VISIBLE}</p></body></html>', encoding='utf-8')
        extracted.write_text(HIDDEN, encoding='utf-8')
        result = run([sys.executable, str(SCRIPTS / 'check-pdf-text-order.py'), '--source', str(source),
                      '--extracted', str(extracted), '--json'], timeout=15)
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn('inconclusive', result.stdout)

    @unittest.skipUnless(os.environ.get('SCIENTIFIC_REQUIRE_HTML_CONTEXT') == '1', 'native source-text render tier')
    def test_real_two_page_pdf_matches_source_tokens(self):
        import pymupdf
        from weasyprint import HTML
        source = ('<html lang="fa" dir="rtl"><head><style>@page{size:A5;margin:16mm}'
                  'body{font-family:DejaVu Sans} .next{break-before:page}</style></head><body>'
                  f'<p title="metadata > {HIDDEN}">{VISIBLE}</p><p class="next">{VISIBLE}</p></body></html>')
        target = self.root / 'source.pdf'
        HTML(string=source).write_pdf(target)
        plain = ORDER.strip_html(source)
        self.assertNotIn(HIDDEN, plain)
        with pymupdf.open(target) as pdf:
            self.assertEqual(pdf.page_count, 2)
            extracted = ''.join(page.get_text() for page in pdf)
            self.assertEqual(ORDER.classify(ORDER.persian_windows(plain), extracted), 'logical')
            evidence = os.environ.get('SCIENTIFIC_EVIDENCE_DIR')
            if evidence:
                output = Path(evidence)
                output.mkdir(parents=True, exist_ok=True)
                for index, page in enumerate(pdf, 1):
                    page.get_pixmap().save(output / f'order-source-page-{index}.png')


if __name__ == '__main__':
    unittest.main()
