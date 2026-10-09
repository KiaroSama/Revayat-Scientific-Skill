"""Lint formatted visible prose without joining protected or block boundaries."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from source_model import Source

spec = importlib.util.spec_from_file_location('prose_checker', ROOT / 'skills/revayat-scientific/scripts/check-fa.py')
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)


class HTMLProseProjectionTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        work = tempfile.TemporaryDirectory(prefix='html prose ', dir=scratch)
        self.addCleanup(work.cleanup)
        self.path = Path(work.name) / 'source.html'

    def findings(self, body):
        self.path.write_text('<html lang="fa" dir="rtl"><body>\n' + body + '\n</body></html>', encoding='utf-8')
        return [finding for finding in checker.check(Source(self.path), [('firewall', 'دیوار آتش', 'fixture')], None)
                if finding.check == 'forbidden-fa']

    def test_head_before_ltr_isolate_keeps_half_translation_check(self):
        for body in ('<p>خوشه <span dir="ltr">Kubernetes</span></p>',
                     '<p>خوشه <bdi dir="ltr">Kubernetes</bdi></p>'):
            with self.subTest(body=body):
                self.path.write_text('<html lang="fa" dir="rtl"><body>\n' + body + '\n</body></html>', encoding='utf-8')
                model = Source(self.path)
                found = [finding for finding in checker.check(model, [], None)
                         if finding.check == 'half-translation']
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0].line, 2)
                self.assertFalse([finding for finding in checker.check(model, [], None, level='journal')
                                  if finding.check == 'half-translation'])

    def test_inline_formatting_does_not_hide_visible_phrase(self):
        for body in ('<p>دیوار <b>آتش</b></p>', '<p><em>دیوار</em> آتش</p>',
                     '<p>دیوار &#1570;<strong>تش</strong></p>', '<p>دیوار <span>آتش</span></p>',
                     '<p>دی<b>وار</b> آتش</p>', '<p>دیوار آتش</p>'):
            with self.subTest(body=body):
                found = self.findings(body)
                self.assertEqual(len(found), 1)
                self.assertEqual((found[0].path, found[0].line), (self.path, 2))
        for body in ('<p>دیوار</p><p>آتش</p>', '<p>دیوار <span lang="en">آتش</span></p>',
                     '<p>دیوار <code>آتش</code></p>', '<p>دیوار <q>آتش</q></p>',
                     '<p>دیوار <span hidden>واسط</span>آتش</p>',
                     '<!-- fa-lint: allow forbidden-fa -->\n<p>دیوار <b>آتش</b></p>'):
            with self.subTest(body=body):
                self.assertEqual(self.findings(body), [])


if __name__ == '__main__':
    unittest.main()
