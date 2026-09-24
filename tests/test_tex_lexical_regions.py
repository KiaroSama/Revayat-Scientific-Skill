"""Protect literal TeX while keeping real prose, assets and waivers visible."""
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from source_model import Source
from tex_source import source_closure, masked_tex


class TexLexicalRegionsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='tex lexical ')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.path = self.root / 'main.tex'
        self.log = logging.getLogger(self.id())
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        self.log.addHandler(handler)
        self.log.setLevel(logging.INFO)
        self.addCleanup(self.log.removeHandler, handler)
        self.addCleanup(handler.close)
        self.log.info('running synthetic TeX boundary regression')

    def source(self, body):
        self.path.write_bytes(('\\begin{document}\n' + body + '\n\\end{document}').encode())
        return Source(self.path)

    def test_inline_literal_is_protected(self):
        for opening in (r'\verb|', r'\verb*|'):
            with self.subTest(opening=opening):
                model = self.source(opening + 'كي 123| متن')
                self.assertTrue(model.is_protected(model.text.index('كي')))
                self.assertFalse(model.is_protected(model.text.index('متن')))

    def test_numeric_punctuation_and_starred_letter_delimiters(self):
        for literal in (r'\verb1\includegraphics{missing.png}1',
                        r'\verb*Z\includegraphics{missing.png}Z',
                        r'\verb@\includegraphics{missing.png}@'):
            with self.subTest(literal=literal):
                model = self.source(literal + ' متن')
                self.assertEqual(model.image_references(), [])
                self.assertTrue(model.is_protected(model.text.index('missing.png')))
                self.assertFalse(model.is_protected(model.text.index('متن')))

    def test_malformed_literals_fail_without_masking_following_lines(self):
        for literal in (r'\verb|unclosed', '\\verb|first\nsecond|',
                        r'\begin{verbatim}no ending', r'\begin{minted}no ending'):
            with self.subTest(literal=literal), self.assertRaises(ValueError):
                self.source(literal)

    def test_macro_with_verb_prefix_is_not_literal(self):
        model = self.source(r'\verbfoo{Label} متن')
        self.assertFalse(model.is_protected(model.text.index('متن')))
        self.assertEqual(model.literals, [])

    def test_starred_and_unstarred_literal_environments_are_protected(self):
        for env in ('verbatim', 'verbatim*', 'Verbatim', 'lstlisting', 'minted'):
            with self.subTest(env=env):
                model = self.source('\\begin{' + env + '}كي 123\\end{' + env + '} متن')
                self.assertTrue(model.is_protected(model.text.index('كي')))
                self.assertFalse(model.is_protected(model.text.index('متن')))

    def test_percent_inside_literal_does_not_hide_following_prose(self):
        for literal in (r'\verb|%|', r'\verb*|%|',
                        '\\begin{verbatim}\n%\n\\end{verbatim}'):
            with self.subTest(literal=literal):
                model = self.source(literal + ' كي 123')
                pos = model.text.index('كي')
                self.assertFalse(model.is_protected(pos))
                self.assertFalse(model.inert(pos))

    def test_literal_waiver_cannot_suppress_same_or_following_line(self):
        for separator in (' ', '\n'):
            model = self.source(r'\verb|% fa-lint: allow all|' + separator + 'كي')
            self.assertFalse(model.suppressed(model.text.index('كي'), 'arabic-letters'))

    def test_comments_after_paired_backslashes_remain_comments(self):
        for count in (0, 2, 4, 6):
            with self.subTest(count=count):
                model = self.source('Text' + '\\' * count + '% كي 123')
                self.assertTrue(model.is_protected(model.text.index('كي')))
                self.assertTrue(model.inert(model.text.index('كي')))

    def test_escaped_percent_is_not_a_comment(self):
        for count in (1, 3, 5):
            with self.subTest(count=count):
                model = self.source('Text' + '\\' * count + '% كي')
                self.assertFalse(model.is_protected(model.text.index('كي')))

    def test_real_waiver_after_linebreak_is_recognized(self):
        model = self.source('Text' + '\\' * 2 + '% fa-lint: allow arabic-letters\nكي')
        self.assertTrue(model.suppressed(model.text.index('كي'), 'arabic-letters'))
        self.assertFalse(model.suppressed(model.text.index('كي'), 'unisolated-number'))

    def test_literal_images_are_not_asset_dependencies(self):
        for body in (r'\verb|\includegraphics{missing.png}|',
                     r'\verb*|\includegraphics{missing.png}|',
                     '\\begin{verbatim}\n\\includegraphics{missing.png}\n\\end{verbatim}',
                     r'\begin{verbatim*}\includegraphics{missing.png}\end{verbatim*}',
                     'Text' + '\\' * 2 + '% \\includegraphics{missing.png}'):
            with self.subTest(body=body):
                self.assertEqual(self.source(body).image_references(), [])

    def test_live_graphics_after_linebreak_are_not_lost(self):
        for count in (1, 3, 5):
            with self.subTest(count=count):
                model = self.source('Text' + '\\' * count + 'includegraphics* [width=2cm]{real.png}')
                refs = model.image_references()
                self.assertEqual([ref for _, ref in refs], ['real.png'])
                self.assertEqual(model.text[refs[0][0]:].split('{', 1)[0], r'\includegraphics* [width=2cm]')

    def test_escaped_graphics_commands_are_not_dependencies(self):
        for count in (2, 4, 6):
            with self.subTest(count=count):
                self.assertEqual(self.source('Text' + '\\' * count + 'includegraphics{missing.png}').image_references(), [])

    def test_fake_isolates_and_math_inside_literal_do_not_affect_prose(self):
        model = self.source(r'\verb|\en{Fake} $| كي \en{Real} $x$ متن')
        self.assertEqual([body for _, _, body in model.isolates], ['Real'])
        self.assertFalse(model.is_protected(model.text.index('كي')))
        self.assertFalse(model.is_protected(model.text.index('متن')))
        self.assertTrue(model.is_protected(model.text.index('x$')))

    def test_fake_document_begin_does_not_end_preamble(self):
        text = '% \\begin{document}\n\\newcommand{\\sample}{كي}\n\\begin{document}\nمتن\n\\end{document}'
        self.path.write_bytes(text.encode())
        model = Source(self.path)
        self.assertEqual(model.preamble_end, text.rindex(r'\begin{document}') + len(r'\begin{document}'))
        self.assertTrue(model.in_preamble(text.index('كي')))
        self.assertFalse(model.is_protected(text.index('متن')))

    def test_comment_brace_does_not_close_live_argument(self):
        model = self.source('\\en{Alpha% } fake brace\nBeta} متن')
        self.assertEqual(len(model.isolates), 1)
        self.assertNotIn('fake brace', model.isolates[0][2])
        end = model.isolates[0][1]
        self.assertEqual(model.text[end-5:end], 'Beta}')
        self.assertTrue(model.is_protected(model.text.index('Beta')))
        self.assertFalse(model.is_protected(model.text.index('متن')))

    def test_nested_include_locations_and_comment_eof_boundary(self):
        child = self.root / 'child.tex'
        child.write_bytes(b'% child-only comment without newline')
        model = self.source(r'\input{child} كي')
        pos = model.text.index('كي')
        self.assertFalse(model.is_protected(pos))
        self.assertFalse(model.inert(pos))
        self.assertEqual(model.location(pos), (self.path, 2))
        self.assertEqual(model.closure.sources, (self.path, child))
        self.assertEqual(child.read_bytes(), b'% child-only comment without newline')

    def test_region_offsets_and_newline_styles(self):
        for newline in ('\n', '\r\n'):
            text = ('\\begin{document}' + newline + r'\verb|%|' + ' متن' + newline + r'\end{document}')
            self.path.write_bytes(text.encode())
            model = Source(self.path)
            pos = model.text.index('متن')
            self.assertFalse(model.is_protected(pos))
            self.assertEqual(model.location(pos), (self.path, 2))
            self.assertEqual(len(masked_tex(text)), len(text))
            self.assertEqual([i for i,c in enumerate(masked_tex(text)) if c == '\n'],
                             [i for i,c in enumerate(text) if c == '\n'])

    def test_real_tex_accepts_literal_graphics_and_keeps_parent_after_eof_comment(self):
        if not (shutil.which('xelatex') and shutil.which('pdftotext')):
            if os.environ.get('SCIENTIFIC_REQUIRE_TEX_BOUNDARY') == '1':
                self.fail('required TeX lexical regression needs XeLaTeX and Poppler')
            self.skipTest('requires real XeLaTeX and Poppler')
        (self.root / 'child.tex').write_bytes(b'% EOF comment')
        text = (r'\documentclass{article}\begin{document}' + '\n'
                + r'\verb|\includegraphics{missing.png}|' + '\n'
                + r'\input{child} ParentVisibleMarker\end{document}')
        self.path.write_bytes(text.encode())
        compiled = subprocess.run(['xelatex', '-no-shell-escape', '-halt-on-error',
            '-interaction=nonstopmode', self.path.name], cwd=self.root,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
        self.assertEqual(compiled.returncode, 0, compiled.stdout.decode(errors='replace'))
        result = subprocess.run(['pdftotext', str(self.path.with_suffix('.pdf')), '-'],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertIn('ParentVisibleMarker', result.stdout)
        model = Source(self.path)
        self.assertEqual(model.image_references(), [])
        self.assertFalse(model.is_protected(model.text.index('ParentVisibleMarker')))


if __name__ == '__main__':
    unittest.main()
