"""The checked source is the ordered document, including every literal chapter."""
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from tex_source import source_closure, plain_tex
from document_context import select_source


def helper(name, filename):
    path = ROOT / 'skills/revayat-scientific/scripts' / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class SourceClosureTest(unittest.TestCase):
    def test_encoded_and_starred_assets_share_lint_and_build_resolution(self):
        from PIL import Image
        from source_model import Source
        checker = helper('asset_context_checker', 'check-fa.py')
        builder = helper('asset_context_builder', 'build-support.py')
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            (root / 'figures').mkdir()
            (root / 'chapters').mkdir()
            image = root / 'figures/figure one.png'
            Image.new('RGBA', (8, 8), (100, 120, 140, 128)).save(image)
            html, tex = root / 'main.html', root / 'main.tex'
            html.write_text('<html lang="fa" dir="rtl"><img dir="ltr" '
                            'src="figures/figure%20one.png"></html>', encoding='utf-8')
            tex.write_text('\\begin{document}\\input{chapters/one}\\end{document}', encoding='utf-8')
            (root / 'chapters/one.tex').write_text('\\begin{LTR}\\includegraphics* '
                '[width=2cm] {figures/figure one.png}\\end{LTR}', encoding='utf-8')
            for source in (html, tex):
                with self.subTest(source=source.suffix):
                    findings = checker.check(Source(source), [], ['figure one.png'], level='journal')
                    self.assertEqual(findings, [])
                    self.assertEqual(builder.source_assets(source), [image.resolve()])
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        self.assertEqual(builder.main(['assets', str(source)]), 1)
            Image.new('RGB', (8, 8), 'white').save(image)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(builder.main(['assets', str(tex)]), 0)
            image.unlink()
            for source in (html, tex):
                with self.subTest(missing=source.suffix):
                    self.assertIn('missing-image', [finding.check for finding in
                                  checker.check(Source(source), [], ['figure one.png'], level='journal')])
                    with self.assertRaises(ValueError):
                        builder.source_assets(source)

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
