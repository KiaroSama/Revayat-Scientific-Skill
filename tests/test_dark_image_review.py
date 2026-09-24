"""Dark original review never rewrites pixels or bypasses other image gates."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log

SPEC = importlib.util.spec_from_file_location('dark_image_test_helper', SCRIPTS / 'prepare-figures.py')
FIGURES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIGURES)


class DarkImageReviewTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='scientific dark image ')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.log = operation_log('test-dark-images', self.root / 'logs')
        self.logger = self.log.__enter__()
        self.addCleanup(self.log.__exit__, None, None, None)
        self.logger.info('running test=%s', self._testMethodName)
        self.image = self.root / 'figure.png'
        # Sparse bright measurements on a genuine dark-background fixture.
        with Image.new('RGB', (100, 100), 'black') as image:
            for index in range(10, 90, 10):
                image.putpixel((index, index), (255, 255, 255))
            image.save(self.image)
        self.review = self.image.with_name(self.image.name + '.review.json')

    def approve(self, **updates):
        record = {'version': 1, 'sha256': hashlib.sha256(self.image.read_bytes()).hexdigest(),
                  'decision': 'preserve-dark-original',
                  'note': 'Compared with source page; the dark background is original.'}
        record.update(updates)
        self.review.write_text(json.dumps(record), encoding='utf-8')
        return record

    def check(self, *paths):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return FIGURES.main([*(str(path) for path in (paths or (self.image,))), '--check'])

    def test_unreviewed_dark_original_still_requires_review(self):
        original = self.image.read_bytes()
        self.assertEqual(FIGURES.main([str(self.image)]), 0)
        self.assertEqual(self.check(), 1)
        self.assertEqual(self.image.read_bytes(), original)
        self.assertFalse(self.review.exists())

    def test_valid_review_accepts_exact_original_without_mutation(self):
        original = self.image.read_bytes()
        self.approve()
        review = self.review.read_bytes()
        self.assertEqual(self.check(), 0)
        self.assertEqual(self.image.read_bytes(), original)
        self.assertEqual(self.review.read_bytes(), review)
        self.assertFalse(self.image.with_name(self.image.name + '.orig').exists())

    def test_stale_review_is_rejected(self):
        self.approve()
        with Image.open(self.image) as image:
            image.putpixel((0, 0), (100, 100, 100))
            image.save(self.image)
        current = self.image.read_bytes()
        with self.assertRaisesRegex(ValueError, 'stale'):
            self.check()
        self.assertEqual(self.image.read_bytes(), current)

    def test_invalid_schema_duplicate_keys_and_oversized_review_fail(self):
        for updates in ({'version': True}, {'version': 2}, {'sha256': '0' * 64},
                        {'decision': 'allow-all'}, {'note': ''}, {'unexpected': True}):
            with self.subTest(updates=updates):
                self.approve(**updates)
                with self.assertRaises(ValueError):
                    self.check()
        for data in (b'{"version":1,"version":1}', b'\xff', b' ' * (16 * 1024 + 1),
                     b'[' * 2000 + b']' * 2000):
            with self.subTest(length=len(data)):
                self.review.write_bytes(data)
                with self.assertRaises(ValueError):
                    self.check()

    def test_review_cannot_waive_transparency_depth_or_frames(self):
        with Image.new('RGBA', (100, 100), (0, 0, 0, 250)) as image:
            image.save(self.image)
        self.approve()
        self.assertEqual(self.check(), 1)
        with Image.new('I;16', (20, 20), 1024) as image:
            image.save(self.image)
        self.approve()
        with self.assertRaises(ValueError):
            self.check()
        multi = self.root / 'multiple.tiff'
        with Image.new('RGB', (20, 20), 'black') as image:
            image.save(multi, save_all=True, append_images=[image.copy()])
        self.image = multi
        self.review = multi.with_name(multi.name + '.review.json')
        self.approve()
        with self.assertRaises(ValueError):
            self.check()

    def test_one_review_does_not_approve_another_asset(self):
        self.approve()
        other = self.root / 'other.png'
        other.write_bytes(self.image.read_bytes())
        self.assertEqual(self.check(self.image, other), 1)
        self.assertEqual(self.check(self.image), 0)

    def test_directory_or_linked_review_is_rejected(self):
        self.review.mkdir()
        with self.assertRaises(ValueError):
            self.check()
        self.review.rmdir()
        target = self.root / 'review-target.json'
        record = self.approve()
        self.review.unlink()
        target.write_text(json.dumps(record), encoding='utf-8')
        try:
            self.review.symlink_to(target)
        except OSError:
            self.logger.warning('symlink creation unavailable; directory refusal already tested')
            return
        with self.assertRaises(ValueError):
            self.check()

    def test_opaque_light_control_needs_no_review(self):
        with Image.new('RGB', (100, 100), 'white') as image:
            image.save(self.image)
        self.assertEqual(self.check(), 0)
        self.assertFalse(self.review.exists())

    def test_public_command_honors_review_and_preserves_inputs(self):
        self.approve()
        before = (self.image.read_bytes(), self.review.read_bytes())
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / 'prepare-figures.py'), str(self.image), '--check'],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8', timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('reviewed=True', result.stdout)
        self.assertEqual((self.image.read_bytes(), self.review.read_bytes()), before)
        self.assertNotIn('Compared with source page', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
