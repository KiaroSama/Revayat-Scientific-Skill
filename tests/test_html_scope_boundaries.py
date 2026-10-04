"""Implicit HTML closures must not leak validation exemptions to later prose."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from html_source import ParsedHTML
from source_model import Source
from resource_policy import ResourcePolicy
from runtime import operation_log


class HtmlScopeBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='html-scopes-')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.path = self.root / 'document.html'
        scope = operation_log('test-html-scopes', self.root / 'logs')
        self.log = scope.__enter__()
        self.addCleanup(scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)

    def source(self, body):
        self.path.write_bytes(('<!doctype html><html lang="fa" dir="rtl">' + body + '</html>').encode())
        return Source(self.path)

    def unprotected(self, body):
        model = self.source(body)
        pos = model.text.index('كي')
        self.assertFalse(model.is_protected(pos))
        self.assertFalse(model.suppressed(pos, 'arabic-letters'))
        self.assertEqual(model.location(pos)[0], self.path)
        return model

    def test_paragraph_boundaries_end_language_hidden_and_isolate_scope(self):
        for attrs in ('lang="en"', 'hidden', 'dir="ltr"', 'class="en"'):
            for block in ('p', 'div', 'section', 'table', 'h2', 'ul'):
                tail = '<tr><td>كي</td></tr>' if block == 'table' else 'كي'
                with self.subTest(attrs=attrs, block=block):
                    self.unprotected(f'<body><p {attrs}>English<{block}>{tail}</{block}></body>')

    def test_list_and_definition_item_boundaries_are_scoped(self):
        for first, following, wrapper in (('li', 'li', 'ul'), ('li', 'li', 'ol'),
                                         ('dt', 'dd', 'dl'), ('dd', 'dt', 'dl')):
            with self.subTest(first=first, following=following):
                self.unprotected(f'<body><{wrapper}><{first} lang="en">English<{following}>كي</{wrapper}></body>')

    def test_nested_lists_preserve_outer_scope_but_end_inner_item_scope(self):
        body = '<body><ul><li><ul><li lang="en">English<li>كي</ul></li></ul></body>'
        self.unprotected(body)
        model = self.source('<body><ul><li lang="en"><ul><li>كي</li></ul></li></ul></body>')
        self.assertTrue(model.is_protected(model.text.index('كي')))

    def test_table_cells_rows_and_groups_do_not_leak_language(self):
        for first, second in (('<td lang="en">English', '<td>كي'),
                              ('<th lang="en">English', '<td>كي'),
                              ('<td lang="en">English', '<tr><td>كي'),
                              ('<td lang="en">English', '<tbody><tr><td>كي')):
            with self.subTest(second=second):
                self.unprotected('<body><table><tbody><tr>' + first + second + '</table></body>')
        self.unprotected('<body><table><tbody lang="en"><tr><td>English<tbody><tr><td>كي</table></body>')

    def test_optional_head_end_does_not_protect_body(self):
        self.unprotected('<head><title>English title</title><body><p>كي</p></body>')
        self.unprotected('<head><title>English title</title><p>كي</p>')

    def test_options_do_not_inherit_previous_option_language(self):
        self.unprotected('<body><select><option lang="en">English<option>كي</select></body>')
        self.unprotected('<body><select><optgroup lang="en"><option>English<optgroup><option>كي</select></body>')

    def test_heading_siblings_do_not_inherit_previous_heading_language(self):
        self.unprotected('<body><h1 lang="en">English<h2>كي</h2></body>')

    def test_misnested_formatting_requires_review_instead_of_silent_reconstruction(self):
        for body in ('<body><p><b lang="en">English<p>كي</body>',
                     '<body><b lang="en"><i>English</b>كي</i></body>',
                     '<body><a href="#a">A<a href="#b">B</a></body>',
                     '<body><button>One<button>Two</button></body>',
                     '<body><form>One<form>Two</form></body>'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.source(body)

    def test_table_foster_parenting_and_ignored_select_children_fail_closed(self):
        for body in ('<body><table lang="en">كي<tr><td>Cell</td></tr></table></body>',
                     '<body><table><div lang="en">كي</div></table></body>',
                     '<body><select><span lang="en">كي</span></select></body>'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.source(body)

    def test_explicit_well_nested_equivalent_has_same_live_scopes(self):
        implicit = self.unprotected('<body><p lang="en">English<p>كي</body>')
        explicit = self.unprotected('<body><p lang="en">English</p><p>كي</p></body>')
        self.assertEqual([n['language'] for n in implicit.html.nodes if n['tag'] == 'p'],
                         [n['language'] for n in explicit.html.nodes if n['tag'] == 'p'])

    def test_render_policy_uses_same_structure_gate_and_preserves_input(self):
        self.path.write_bytes(b'<html><body><table>fostered text</table></body></html>')
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            ResourcePolicy(self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_caption_colgroup_and_select_separator_boundaries(self):
        for prefix, following in (('<caption lang="en">English', '<tr><td>كي'),
                                  ('<colgroup lang="en"><col>', '<tbody><tr><td>كي')):
            with self.subTest(prefix=prefix):
                self.unprotected('<body><table>' + prefix + following + '</table></body>')
        with self.assertRaises(ValueError):
            self.source('<body><select><optgroup lang="en"><option>English<hr>كي</select></body>')

    def test_body_end_does_not_drop_scopes_for_browser_reprocessed_tail(self):
        for attrs in ('lang="en"', 'hidden', 'dir="ltr"'):
            with self.subTest(attrs=attrs):
                model = self.source('<body ' + attrs + '>English</body>كي')
                self.assertTrue(model.is_protected(model.text.index('كي')))

    def test_out_of_scope_item_end_does_not_pop_an_outer_list(self):
        model = self.source('<body><ul><li lang="en"><ul><li>X</li></li>كي</ul></ul></body>')
        self.assertTrue(model.is_protected(model.text.index('كي')))

    def test_mismatched_heading_and_duplicate_root_are_explicit_errors(self):
        for body in ('<body><h1 lang="en">English</h2>كي',
                     '<body>English<body lang="en">كي', '<html lang="en">كي'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.source(body)

    def test_table_parts_outside_a_table_do_not_create_fake_exemptions(self):
        for tag in ('td', 'th', 'tr', 'tbody', 'thead', 'tfoot', 'col', 'colgroup', 'caption'):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.source('<body><' + tag + ' lang="en">كي</' + tag + '></body>')

    @unittest.skipUnless(os.environ.get('SCIENTIFIC_REQUIRE_HTML_CONTEXT') == '1', 'HTML5 oracle tier')
    def test_bounded_sibling_matrix_matches_or_explicitly_refuses_html5_repair(self):
        import tinyhtml5
        openers = ('p', 'h1', 'li', 'dt', 'dd', 'td', 'th', 'tr', 'tbody', 'thead',
                   'tfoot', 'caption', 'colgroup', 'option', 'optgroup')
        followers = ('p', 'div', 'li', 'dt', 'dd', 'td', 'th', 'tr', 'tbody', 'caption',
                     'h1', 'h2', 'option', 'optgroup', 'hr', 'span')
        accepted = refused = 0
        for opener in openers:
            wrapper = ('table' if opener in ('td', 'th', 'tr', 'tbody', 'thead', 'tfoot', 'caption', 'colgroup')
                       else 'ul' if opener == 'li' else 'dl' if opener in ('dt', 'dd')
                       else 'select' if opener in ('option', 'optgroup') else 'div')
            for follower in followers:
                lead = ('<col>' if opener == 'colgroup' else '<tr><td>A' if opener in ('tbody', 'thead', 'tfoot')
                        else '<td>A' if opener == 'tr' else 'A')
                child = '<td>كي' if follower == 'tr' else '<tr><td>كي' if follower == 'tbody' else 'كي'
                body = f'<{wrapper}><{opener} lang="en">{lead}<{follower} id="target">{child}</{follower}></{wrapper}>'
                text = '<html lang="fa"><body>' + body + '</body></html>'
                with self.subTest(opener=opener, follower=follower):
                    try:
                        model = ParsedHTML(text)
                    except ValueError:
                        refused += 1
                        continue
                    def inherited(element, language='fa'):
                        language = element.get('lang', language)
                        if element.get('id') == 'target':
                            return language
                        for node in element:
                            value = inherited(node, language)
                            if value is not None:
                                return value
                        return None
                    expected = inherited(tinyhtml5.parse(text))
                    actual = next(n['language'] for n in model.nodes if n['attrs'].get('id') == 'target')
                    self.assertEqual(actual, expected)
                    accepted += 1
        self.assertEqual((accepted, refused), (176, 64))

    @unittest.skipUnless(os.environ.get('SCIENTIFIC_REQUIRE_HTML_CONTEXT') == '1', 'HTML5 oracle tier')
    def test_implicit_scope_vectors_match_independent_html5_tree(self):
        import tinyhtml5
        bodies = ['<body><p lang="en">English<p id="target">كي',
                  '<body><ul><li lang="en">English<li id="target">كي</ul>',
                  '<body><table><tr><td lang="en">English<td id="target">كي</table>',
                  '<head><title>English</title><body><p id="target">كي',
                  '<body><select><option lang="en">English<option id="target">كي</select>']
        for body in bodies:
            with self.subTest(body=body):
                model = self.unprotected(body)
                tree = tinyhtml5.parse(self.path.read_text(encoding='utf-8'))
                def find_language(element, inherited='fa'):
                    language = element.get('lang', inherited)
                    if element.get('id') == 'target':
                        return language
                    for child in element:
                        result = find_language(child, language)
                        if result:
                            return result
                    return None
                actual = next(n['language'] for n in model.html.nodes if n['attrs'].get('id') == 'target')
                self.assertEqual(actual, find_language(tree))


if __name__ == '__main__':
    unittest.main()
