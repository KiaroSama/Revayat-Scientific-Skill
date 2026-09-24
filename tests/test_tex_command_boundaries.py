"""Literal TeX commands must respect escaped-backslash token boundaries."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log
from tex_source import source_closure


class TexCommandBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='scientific tex boundary ')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.log = operation_log('test-tex-command-boundaries', self.root / 'logs')
        self.logger = self.log.__enter__()
        self.addCleanup(self.log.__exit__, None, None, None)
        self.logger.info('running test=%s', self._testMethodName)
        self.source = self.root / 'doc.tex'
        self.child = self.root / 'chapter.tex'
        self.child.write_text('CHAPTER CONTENT\n', encoding='utf-8')

    def closure(self, text):
        self.source.write_text(text, encoding='utf-8')
        return source_closure(self.source)

    def test_odd_backslash_runs_expand_and_preserve_linebreaks(self):
        for count in (1, 3, 5, 7, 9):
            for command in ('input', 'include'):
                with self.subTest(count=count, command=command):
                    prefix = 'Intro\n' + '\\' * (count - 1)
                    result = self.closure(prefix + '\\' + command + '{chapter}\nTail')
                    self.assertEqual(result.text, prefix + 'CHAPTER CONTENT\n\nTail')
                    self.assertEqual(result.sources, (self.source, self.child))
                    self.assertEqual(result.location(result.text.index('CHAPTER')),
                                     (self.child, 1))
                    self.assertEqual(result.location(result.text.index('Tail')),
                                     (self.source, 3))

    def test_even_backslash_runs_are_not_includes(self):
        for count in (2, 4, 6, 8):
            text = 'Intro\n' + '\\' * count + 'input{missing}\nTail'
            with self.subTest(count=count):
                result = self.closure(text)
                self.assertEqual(result.text, text)
                self.assertEqual(result.sources, (self.source,))

    def test_comments_and_verbatim_do_not_expand(self):
        text = (
            '% ' + '\\' * 3 + 'input{missing}\n'
            + r'\verb|\\\input{missing}|' + '\n'
            + r'\begin{verbatim}\\\input{missing}\end{verbatim}' + '\n'
            + r'\begin{Verbatim}\\\input{missing}\end{Verbatim}' + '\n'
        )
        result = self.closure(text)
        self.assertEqual(result.text, text)
        self.assertEqual(result.sources, (self.source,))

    def test_missing_cyclic_dynamic_and_includeonly_still_fail(self):
        self.child.write_text(r'\input{doc}', encoding='utf-8')
        for command in ('input{missing}', 'include{missing}', r'input{\macro}',
                        'includeonly{chapter}', 'input{chapter}'):
            with self.subTest(command=command), self.assertRaises(ValueError):
                self.closure('Intro' + '\\' * 3 + command)

    def test_nested_and_unbraced_include_location_mapping(self):
        nested = self.root / 'nested.tex'
        nested.write_text('NESTED\n', encoding='utf-8')
        self.child.write_text('Chapter\n' + '\\' * 3 + 'input nested\nEnd', encoding='utf-8')
        result = self.closure('Start\n' + '\\' * 3 + 'input{chapter}\nFinish')
        self.assertEqual(result.sources, (self.source, self.child, nested))
        self.assertIn('\\\\NESTED', result.text)
        self.assertEqual(result.location(result.text.index('NESTED')), (nested, 1))
        self.assertEqual(result.location(result.text.index('End')), (self.child, 3))
        self.assertEqual(result.location(result.text.index('Finish')), (self.source, 3))

    @unittest.skipUnless(shutil.which('xelatex') and shutil.which('pdftotext'),
                         'requires real XeLaTeX and Poppler')
    def test_real_tex_linebreak_then_input_agrees_with_closure(self):
        self.child.write_text('IncludedUniqueMarker', encoding='utf-8')
        text = (r'\documentclass{article}\begin{document}First'
                + '\\' * 3 + r'input{chapter}\end{document}')
        result = self.closure(text)
        compiled = subprocess.run(
            ['xelatex', '-no-shell-escape', '-interaction=nonstopmode',
             '-halt-on-error', self.source.name], cwd=self.root,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
        self.assertEqual(compiled.returncode, 0, compiled.stdout.decode(errors='replace'))
        extracted = subprocess.run(
            ['pdftotext', str(self.source.with_suffix('.pdf')), '-'],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        self.assertEqual(extracted.returncode, 0, extracted.stderr)
        self.assertIn('IncludedUniqueMarker', extracted.stdout)
        self.assertIn('IncludedUniqueMarker', result.text)


if __name__ == '__main__':
    unittest.main()
