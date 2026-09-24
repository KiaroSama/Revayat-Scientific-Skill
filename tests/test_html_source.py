"""Live HTML structure and visible entities determine Persian lint results."""
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
spec = importlib.util.spec_from_file_location('html_lint_under_test', SCRIPT)
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)


class LiveHTMLTest(unittest.TestCase):
    def test_live_root_entities_and_comment_only_waivers(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        cases = [
            ('<html dir="rtl" lang="fa"><style>p{color:black}</style>متن</html>', 0, None),
            ('<!-- <html lang="fa" dir="rtl"> --><html lang="en">متن</html>', 1, 'html-root'),
            ('<html lang="fa" dir="rtl"><p>&#1603;</p></html>', 1, 'arabic-letters'),
            ('<html lang="fa" dir="rtl"><p>گ&#1585;ه</p></html>', 1, 'forbidden-fa'),
            ('<html lang="fa" dir="rtl"><p data-note="fa-lint: allow all">كتاب</p></html>', 1, 'arabic-letters'),
            ('<html lang="fa" dir="rtl">\n<!-- fa-lint: allow arabic-letters -->\nكتاب</html>', 0, None),
            ('<html lang="fa" dir="rtl"><style>pre{white-space:pre-wrap}</style><pre dir="ltr">services</pre></html>', 0, None),
            ('<html lang="fa" dir="rtl"><style>code{white-space:pre-wrap}</style><code class="ltr"><span dir="ltr">services</span></code></html>', 0, None),
            ('<html lang="fa" dir="rtl"><style>code{white-space:pre-wrap}</style><span dir="ltr">value <code>services</code></span></html>', 0, None),
            ('<html lang="fa" dir="rtl"><span dir="ltr">services</span></html>', 1, 'en-plural'),
        ]
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            source = Path(directory) / 'doc.html'
            for body, expected, diagnostic in cases:
                with self.subTest(body=body):
                    source.write_text(body, encoding='utf-8')
                    output = io.StringIO()
                    with redirect_stdout(output), redirect_stderr(output):
                        result = checker.main([str(source)])
                    self.assertEqual(result, expected, output.getvalue())
                    if diagnostic:
                        self.assertIn(diagnostic, output.getvalue())
                    else:
                        self.assertNotIn('print-css', output.getvalue())


if __name__ == '__main__':
    unittest.main()
