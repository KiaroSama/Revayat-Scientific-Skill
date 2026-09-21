"""The checked source is the ordered document, including every literal chapter."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from tex_source import source_closure, plain_tex
from document_context import select_source


class SourceClosureTest(unittest.TestCase):
    def test_selection_honors_explicit_engine_and_actual_source(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            tex = Path(directory) / 'document.tex'
            html = tex.with_suffix('.html')
            tex.write_text('source', encoding='utf-8')
            html.write_text('<html></html>', encoding='utf-8')
            self.assertEqual(select_source(tex, None, {'chromium'}), (html, 'chromium'))
            self.assertEqual(select_source(tex, 'weasyprint', {'tex', 'weasyprint'}), (html, 'weasyprint'))
            for source, engine, available in ((html, 'tex', {'tex'}),
                                               (html, 'chromium', {'weasyprint'}),
                                               (tex, 'tex', {'weasyprint'})):
                with self.subTest(engine=engine, source=source.name):
                    with self.assertRaises(ValueError):
                        select_source(source, engine, available)

    def test_nested_prose_and_repeated_includes_keep_order_and_location(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            chapter = root / 'chapter.tex'
            chapter.write_text('متن \\textbf{علمی \\textit{روشن}}\n', encoding='utf-8')
            main = root / 'main.tex'
            main.write_text('\\begin{document}\n\\input{chapter}\nپایان\n'
                            '\\input{chapter}\n\\end{document}', encoding='utf-8')
            closure = source_closure(main)
            plain = plain_tex(closure.text)
            self.assertEqual(plain.count('علمی روشن'), 2)
            self.assertLess(plain.index('علمی روشن'), plain.index('پایان'))
            self.assertEqual(closure.location(closure.text.index('متن')), (chapter, 1))
            chapter.write_text('\\input{main}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'cycle'):
                source_closure(main)

    def test_dynamic_and_outside_includes_are_explicit_failures(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            source = Path(directory) / 'main.tex'
            for include in ('\\input{\\chaptername}', '\\input{../outside.tex}'):
                with self.subTest(include=include):
                    source.write_text(include, encoding='utf-8')
                    with self.assertRaises(ValueError):
                        source_closure(source)


if __name__ == '__main__':
    unittest.main()
