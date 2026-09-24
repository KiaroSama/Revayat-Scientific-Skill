"""Keep real listing boundaries live without exposing their literal contents."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from runtime import operation_log
from source_model import Source


class ListingBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='listing boundary ')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.path = self.root / 'source.tex'
        self.logging = operation_log('test-listing-boundaries', self.root / 'logs')
        self.logger = self.logging.__enter__()
        self.addCleanup(self.logging.__exit__, None, None, None)
        self.logger.info('running test=%s', self._testMethodName)

    def source(self, body):
        self.path.write_bytes(('\\begin{document}\n' + body + '\n\\end{document}').encode())
        return Source(self.path)

    def test_real_listing_openers_remain_available_to_direction_checks(self):
        for env in ('verbatim', 'verbatim*', 'Verbatim', 'lstlisting', 'minted'):
            with self.subTest(env=env):
                body = '\\begin{' + env + '}\nCodeMarker\n\\end{' + env + '}'
                model = self.source(body)
                opener = model.text.index('\\begin{' + env + '}')
                self.assertFalse(model.inert(opener))
                self.assertTrue(model.is_protected(opener))
                self.assertTrue(model.inert(model.text.index('CodeMarker')))
                self.assertTrue(model.is_protected(model.text.index('CodeMarker')))

    def test_fake_listing_openers_remain_inert(self):
        for body in (r'\verb|\begin{verbatim}|',
                     '% \\begin{verbatim}',
                     '\\begin{verbatim}\n\\begin{lstlisting}\n\\end{verbatim}'):
            with self.subTest(body=body):
                model = self.source(body)
                marker = r'\begin{lstlisting}' if 'lstlisting' in body else r'\begin{verbatim}'
                self.assertTrue(model.inert(model.text.index(marker)))

    def test_real_listing_inside_preamble_remains_inert(self):
        text = ('\\begin{verbatim}\nPreambleLiteral\n\\end{verbatim}\n'
                '\\begin{document}\nBodyMarker\n\\end{document}')
        self.path.write_bytes(text.encode())
        model = Source(self.path)
        self.assertTrue(model.inert(0))
        self.assertFalse(model.is_protected(model.text.index('BodyMarker')))


if __name__ == '__main__':
    unittest.main()
