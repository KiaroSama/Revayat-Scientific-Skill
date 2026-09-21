"""Job sidecars and declared source identity cannot leak across documents."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skills/revayat-scientific/scripts/check-fa.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('context_lint_under_test', SCRIPT)
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)


class LintContextTest(unittest.TestCase):
    def invoke(self, arguments):
        capture = io.StringIO()
        with redirect_stdout(capture), redirect_stderr(capture):
            result = checker.main(list(map(str, arguments)))
        return result, capture.getvalue()

    def test_job_sidecars_are_independent_of_argument_order(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            sources = []
            for name, text, forbidden in [('a', 'واژه', 'نمونه'), ('b', 'نمونه', 'داده')]:
                job = Path(directory) / name
                job.mkdir()
                source = job / 'main.tex'
                source.write_text('\\begin{document}\n' + text + '\n\\end{document}', encoding='utf-8')
                (job / 'terms.tsv').write_text('source\toutput\tstep\tcount\tforbidden_fa\n'
                                              'Widget\tWidget\tkeep\t1\t' + forbidden + '\n', encoding='utf-8')
                (job / 'manifest.txt').write_text('', encoding='utf-8')
                sources.append(source)
            for order in (sources, list(reversed(sources))):
                result, output = self.invoke([*order, '--level', 'journal', '--strict'])
                self.assertEqual(result, 0, output)
            missing = Path(directory) / 'missing.tsv'
            result, _ = self.invoke([sources[0], '--pairs', missing])
            self.assertEqual(result, 2)
            missing.write_text('malformed\trow\n', encoding='utf-8')
            result, _ = self.invoke([sources[0], '--pairs', missing])
            self.assertEqual(result, 2)
            unsupported = Path(directory) / 'notes.md'
            unsupported.write_text('text', encoding='utf-8')
            result, _ = self.invoke([unsupported])
            self.assertEqual(result, 2)

    def test_journal_names_and_foreign_original_identity_are_preserved(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            tex = root / 'name.tex'
            tex.write_text('\\begin{document}\nخوشه \\en{Abell}\n\\end{document}', encoding='utf-8')
            html = root / 'original.html'
            html.write_text('<html lang="fa" dir="rtl"><p lang="fr" dir="ltr">Les particules</p>'
                            '<p>عنوان <cite dir="ltr" lang="en">Deep Residual Networks</cite></p></html>', encoding='utf-8')
            for source in (tex, html):
                result, output = self.invoke([source, '--level', 'journal'])
                self.assertEqual(result, 0, output)


if __name__ == '__main__':
    unittest.main()
