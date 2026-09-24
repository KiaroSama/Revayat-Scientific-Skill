"""Renderer fetches must enforce the job boundary before reading any bytes."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from resource_policy import ResourcePolicy


class ResourceBoundaryTest(unittest.TestCase):
    def test_fetch_allows_job_assets_and_denies_outside_network_and_attachments(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            job = root / 'job'
            job.mkdir()
            source = job / 'doc.html'
            source.write_text('<html></html>', encoding='utf-8')
            (job / 'style.css').write_text('p { color: black }', encoding='utf-8')
            sentinel = root / 'outside.css'
            sentinel.write_text('private sentinel', encoding='utf-8')
            policy = ResourcePolicy(source)
            data, mime = policy.fetch('https://revayat.invalid/style.css')
            self.assertEqual(data, b'p { color: black }')
            self.assertEqual(mime, 'text/css')
            for url in (sentinel.as_uri(), 'https://example.com/style.css',
                        'https://revayat.invalid/../outside.css'):
                with self.subTest(url=url):
                    with self.assertRaises(ValueError):
                        policy.fetch(url)
            source.write_text('<html><a rel="attachment" href="style.css">x</a></html>', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'attachment'):
                ResourcePolicy(source)


if __name__ == '__main__':
    unittest.main()
