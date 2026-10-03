"""Visible HTML text cannot manufacture structure, assets or lint waivers."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from html_source import ParsedHTML
from source_model import Source
from resource_policy import ResourcePolicy
from runtime import operation_log

SPEC = importlib.util.spec_from_file_location('context_integrity_checker', SCRIPTS / 'check-fa.py')
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class HtmlContextIntegrityTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch, prefix='html context audit ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / 'document.html'
        scope = operation_log('test-html-context-integrity', self.root / 'logs')
        self.log = scope.__enter__()
        self.addCleanup(scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)

    def source(self, body):
        self.path.write_bytes(('<html lang="fa" dir="rtl"><body>' + body
                               + '</body></html>').encode('utf-8'))
        return Source(self.path)

    def test_rcdata_comment_text_never_grants_a_waiver(self):
        for tag in ('textarea', 'title'):
            for slash in ('', '/'):
                with self.subTest(tag=tag, slash=slash):
                    model = self.source(f'<{tag}{slash}><!-- fa-lint: allow all --></{tag}>كي')
                    pos = model.text.rindex('كي')
                    self.assertFalse(model.suppressed(pos, 'arabic-letters'))
                    self.assertFalse(model.is_protected(pos))
                    self.assertEqual(model.comments, [])

    def test_rcdata_markup_is_text_not_an_asset_or_active_element(self):
        for tag in ('textarea', 'title'):
            for slash in ('', '/'):
                with self.subTest(tag=tag, slash=slash):
                    model = self.source(f'<{tag}{slash}><img src="missing.png"><script>literal</script></{tag}>متن')
                    self.assertEqual(model.image_references(), [])
                    self.assertNotIn('script', [node['tag'] for node in model.html.nodes])
                    self.assertFalse(model.is_protected(model.text.rindex('متن')))
                    ResourcePolicy(self.path)

    def test_rcdata_character_references_decode_once_with_correct_offsets(self):
        for ending in ('</textarea>', '</TEXTAREA >'):
            for newline in ('\n', '\r\n'):
                body = '<textarea>&#1603;&amp;#1603; &NotEqualTilde;' + ending + newline + 'متن'
                model = self.source(body)
                self.assertIn('ك&#1603; ≂̸', model.text)
                after = model.text.rindex('متن')
                self.assertEqual(model.line_of(after), 2)
                self.assertEqual(model.html.original_offset(after), model.html.raw.rindex('متن'))
                self.assertEqual(model.html.normalized_offset(model.html.raw.rindex('متن')), after)

    def test_rcdata_end_tag_attributes_do_not_hide_following_text(self):
        for closing in ('</textarea data-x=1>', '</textarea data-x=">">', '</textarea/>'):
            with self.subTest(closing=closing):
                model = self.source('<textarea>literal' + closing + 'كي')
                self.assertFalse(model.is_protected(model.text.rindex('كي')))
                self.assertEqual([node['tag'] for node in model.html.stack], [])

    def test_raw_text_comments_do_not_grant_a_waiver(self):
        for tag in ('style', 'script', 'xmp', 'iframe', 'noembed', 'noframes'):
            with self.subTest(tag=tag):
                model = self.source(f'<{tag}><!-- fa-lint: allow all --><img src="fake.png"></{tag}>كي')
                self.assertFalse(model.suppressed(model.text.rindex('كي'), 'arabic-letters'))
                self.assertEqual(model.image_references(), [])

    def test_templates_fail_explicitly_before_claiming_engine_independent_coverage(self):
        for attrs in ('', '/', ' shadowrootmode="open"', ' shadowrootmode="closed"'):
            for fragment in ('<img src="missing.png">', '<!-- fa-lint: allow all -->',
                             '<script>never run</script>', '</body><template>nested</template>'):
                with self.subTest(attrs=attrs, fragment=fragment), self.assertRaisesRegex(ValueError, 'static'):
                    self.source('<template' + attrs + '>' + fragment + '</template>كي')

    def test_plaintext_is_explicitly_unsupported_but_rcdata_examples_are_safe(self):
        for tag in ('<plaintext>', '<plaintext/>'):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, 'static'):
                self.source(tag + '<!-- fa-lint: allow all -->كي')
        model = self.source('<textarea><template>literal</template><plaintext>literal</textarea>كي')
        self.assertEqual(model.image_references(), [])
        self.assertFalse(model.is_protected(model.text.rindex('كي')))

    def test_nonvoid_html_slash_does_not_end_an_isolate(self):
        for tag in ('span', 'div', 'bdi'):
            with self.subTest(tag=tag):
                model = self.source(f'<{tag} dir="ltr"/>125</{tag}>كي')
                self.assertTrue(model.is_protected(model.text.index('125')))
                self.assertFalse(model.is_protected(model.text.rindex('كي')))

    def test_void_html_slash_does_not_capture_following_prose(self):
        for tag in ('br', 'hr', 'input'):
            model = self.source(f'<{tag}/>كي')
            self.assertFalse(model.is_protected(model.text.rindex('كي')))

    def test_foreign_self_closing_elements_remain_self_closing(self):
        for markup in ('<svg/>', '<math/>', '<svg><path/></svg>',
                       '<math><mspace/></math>', '<svg><foreignObject/></svg>'):
            with self.subTest(markup=markup):
                model = self.source(markup + 'كي')
                self.assertFalse(model.is_protected(model.text.rindex('كي')))
        model = self.source('<svg><foreignObject><span dir="ltr"/>125</span></foreignObject></svg>كي')
        self.assertTrue(model.is_protected(model.text.index('125')))
        self.assertFalse(model.is_protected(model.text.rindex('كي')))

    def test_unterminated_raw_context_fails_instead_of_certifying_hidden_tail(self):
        for opening in ('<textarea>', '<textarea/>', '<title>', '<xmp>', '<style>'):
            with self.subTest(opening=opening), self.assertRaises(ValueError):
                self.source(opening + 'literal<!-- fa-lint: allow all -->كي')

    def test_real_comments_still_allow_only_the_requested_check(self):
        model = self.source('<!-- fa-lint: allow arabic-letters -->كي')
        pos = model.text.rindex('كي')
        self.assertTrue(model.suppressed(pos, 'arabic-letters'))
        self.assertFalse(model.suppressed(pos, 'unisolated-number'))
        self.assertFalse(model.is_protected(pos))

    def test_comment_terminator_width_does_not_protect_following_prose(self):
        for comment in ('<!-- comment -->', '<!-- comment -- >', '<!-->'):
            with self.subTest(comment=comment):
                model = self.source(comment + 'كي')
                self.assertFalse(model.is_protected(model.text.rindex('كي')))

    def test_live_active_content_remains_denied(self):
        for markup in ('<script>active</script>', '<iframe></iframe>', '<object/>',
                       '<base href="https://example.invalid/">', '<a rel="attachment">x</a>'):
            with self.subTest(markup=markup):
                self.source(markup)
                with self.assertRaises(ValueError):
                    ResourcePolicy(self.path)

    def test_character_reference_text_cannot_become_a_node(self):
        model = self.source('<textarea>&lt;img src="fake.png"&gt;</textarea>'
                            '<span dir="ltr">&#49;&#50;&#53;</span>كي')
        self.assertEqual(model.image_references(), [])
        self.assertTrue(model.is_protected(model.text.index('125')))
        self.assertFalse(model.is_protected(model.text.rindex('كي')))

    def test_rcdata_isolate_preserves_literal_tags_instead_of_stripping_them(self):
        for body in ('<textarea dir="ltr"><A>Alpha</A></textarea>',
                     '<span dir="ltr"><textarea><A>Alpha</A></textarea></span>'):
            with self.subTest(body=body):
                model = self.source(body)
                self.assertIn('<A>Alpha</A>', [value.strip() for _, _, value in model.isolates])
                self.assertNotIn('a', [node['tag'] for node in model.html.nodes])

    def test_literal_transform_text_is_not_executable_mirroring_css(self):
        model = self.source('<textarea dir="ltr">scaleX(-1)</textarea>')
        findings = CHECKER.check(model, [], None)
        self.assertNotIn('mirrored-image', [finding.check for finding in findings])
        model = self.source('<style>img {transform: scaleX(-1)}</style>')
        self.assertIn('mirrored-image', [finding.check for finding in CHECKER.check(model, [], None)])

    def test_raw_end_tag_attributes_remain_entirely_nonprose(self):
        model = self.source('<textarea dir="ltr">Alpha</textarea data-value=">" data-ignore="NotProse">كي')
        self.assertTrue(model.is_protected(model.text.index('NotProse')))
        self.assertFalse(model.is_protected(model.text.rindex('كي')))

    def test_unquoted_end_attribute_quotes_do_not_capture_following_markup(self):
        for closing in ("</textarea x=a'>", '</textarea x=a">',
                        '</textarea x="a>b">', "</textarea x='a>b'>"):
            with self.subTest(closing=closing):
                model = self.source('<textarea>literal' + closing + 'كي<img src="real.png">')
                self.assertFalse(model.is_protected(model.text.rindex('كي')))
                self.assertEqual([name for _, name in model.image_references()], ['real.png'])
                self.assertEqual(model.comments, [])

    def test_foreign_breakout_preserves_html_isolate_and_neighbor_checks(self):
        for foreign in ('svg', 'math'):
            for tag, attrs in (('span', 'dir="ltr"'), ('p', 'dir="ltr"'),
                               ('font', 'color="red" dir="ltr"')):
                with self.subTest(foreign=foreign, tag=tag):
                    model = self.source(f'<{foreign}><{tag} {attrs}/>125</{tag}>كي')
                    self.assertTrue(model.is_protected(model.text.index('125')))
                    self.assertFalse(model.is_protected(model.text.rindex('كي')))
                    self.assertEqual(model.html.nodes[-1]['namespace'], 'html')

    def test_public_lint_keeps_a_real_error_after_a_fake_waiver(self):
        model = self.source('<textarea/><!-- fa-lint: allow all --></textarea>كي')
        findings = CHECKER.check(model, [], None)
        self.assertIn('arabic-letters', [finding.check for finding in findings])
        before = self.path.read_bytes()
        ResourcePolicy(self.path)
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
