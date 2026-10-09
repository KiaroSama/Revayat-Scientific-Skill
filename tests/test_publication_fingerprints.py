"""Counted stable file observations through recoverable public publication."""
import builtins
import os
from pathlib import Path
import sys
import shutil
import tempfile
import unittest.mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from publication import publish_files


class PublicationFingerprintTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.work = tempfile.TemporaryDirectory(dir=scratch, prefix='publication identity ')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()

    def test_publication_rejects_growth_and_revisions_during_a_counted_read(self):
        for mode in ('growth', 'rewrite', 'truncate'):
            with self.subTest(mode=mode):
                root = self.root / mode
                root.mkdir()
                dest, stage = root / 'dest', root / 'stage'
                dest.write_bytes(b'approved')
                stage.write_bytes(b'candidate')
                opening = Path.open
                read_sizes = []
                changed = False

                class Reader:
                    def __init__(self, handle):
                        self.handle = handle

                    def __enter__(self):
                        self.handle.__enter__()
                        return self

                    def __exit__(self, *args):
                        return self.handle.__exit__(*args)

                    def fileno(self):
                        return self.handle.fileno()

                    def read(self, size=-1):
                        nonlocal changed
                        read_sizes.append(size)
                        if not changed:
                            changed = True
                            before = dest.stat()
                            with builtins.open(dest, 'ab' if mode == 'growth' else 'wb') as writer:
                                writer.write(b' growth' if mode == 'growth' else
                                             b'changed!' if mode == 'rewrite' else b'cut')
                            os.utime(dest, ns=(before.st_atime_ns, before.st_mtime_ns + 10_000_000))
                        return self.handle.read(size)

                def opening_with_change(path, *args, **kwargs):
                    handle = opening(path, *args, **kwargs)
                    return Reader(handle) if path == dest and args[:1] == ('rb',) and not changed else handle

                with unittest.mock.patch.object(Path, 'open', opening_with_change):
                    with self.assertRaisesRegex(ValueError, 'grew|changed'):
                        publish_files([(stage, dest)])
                self.assertTrue(changed, 'the actual OS read seam must execute')
                self.assertTrue(read_sizes)
                self.assertTrue(all(0 < size <= 9 for size in read_sizes), read_sizes)
                self.assertEqual(dest.read_bytes(), b'approved growth' if mode == 'growth' else
                                 b'changed!' if mode == 'rewrite' else b'cut')
                self.assertEqual(stage.read_bytes(), b'candidate')
                self.assertFalse(list(root.glob('.revayat-publish-*')))

    def test_unchanged_publication_accepts_copied_file_timestamps(self):
        original, stage, dest = (self.root / name for name in ('original', 'stage', 'dest'))
        original.write_bytes(b'candidate')
        dest.write_bytes(b'approved')
        # copy2 preserves modification time but supplies a distinct file object.
        shutil.copy2(original, stage)
        before, opened = dest.stat(), None
        with dest.open('rb') as handle:
            opened = os.fstat(handle.fileno())
        self.assertEqual((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                         (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns))
        publish_files([(stage, dest)])
        self.assertEqual(dest.read_bytes(), b'candidate')
        self.assertEqual(original.read_bytes(), b'candidate')
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    def test_opened_descriptor_substitution_is_refused_before_any_replacement(self):
        dest, stage, foreign = (self.root / name for name in ('dest', 'stage', 'foreign'))
        dest.write_bytes(b'approved')
        stage.write_bytes(b'candidate')
        foreign.write_bytes(b'foreign!')
        before = dest.stat()
        os.utime(foreign, ns=(before.st_atime_ns, before.st_mtime_ns))
        opening = Path.open
        substituted = []

        def open_other(path, *args, **kwargs):
            if path == dest and args[:1] == ('rb',):
                substituted.append(path)
                return opening(foreign, *args, **kwargs)
            return opening(path, *args, **kwargs)

        with unittest.mock.patch.object(Path, 'open', open_other):
            with self.assertRaisesRegex(ValueError, 'changed'):
                publish_files([(stage, dest)])
        self.assertTrue(substituted)
        self.assertEqual(dest.read_bytes(), b'approved')
        self.assertEqual(foreign.read_bytes(), b'foreign!')
        self.assertEqual(stage.read_bytes(), b'candidate')
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    def test_replaced_path_after_descriptor_close_is_refused(self):
        dest, stage, foreign = (self.root / name for name in ('dest', 'stage', 'foreign'))
        dest.write_bytes(b'approved')
        stage.write_bytes(b'candidate')
        foreign.write_bytes(b'foreign!')
        before = dest.stat()
        os.utime(foreign, ns=(before.st_atime_ns, before.st_mtime_ns))
        opening = Path.open
        replaced = False

        class Reader:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                self.handle.__enter__()
                return self

            def __exit__(self, *args):
                nonlocal replaced
                result = self.handle.__exit__(*args)
                os.replace(foreign, dest)
                replaced = True
                return result

            def fileno(self):
                return self.handle.fileno()

            def read(self, size=-1):
                return self.handle.read(size)

        def replacing_close(path, *args, **kwargs):
            handle = opening(path, *args, **kwargs)
            return Reader(handle) if path == dest and args[:1] == ('rb',) and not replaced else handle

        with unittest.mock.patch.object(Path, 'open', replacing_close):
            with self.assertRaisesRegex(ValueError, 'changed'):
                publish_files([(stage, dest)])
        self.assertTrue(replaced)
        self.assertEqual(dest.read_bytes(), b'foreign!')
        self.assertEqual(stage.read_bytes(), b'candidate')
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    @unittest.skipUnless(os.name == 'nt', 'native Windows inherited file preparation')
    def test_inherited_preparation_refuses_substituted_foreign_temporary_files(self):
        for boundary in ('candidate', 'backup'):
            with self.subTest(boundary=boundary):
                root = self.root / boundary
                root.mkdir()
                stage, dest = root / 'stage', root / 'dest'
                stage.write_bytes(b'candidate')
                dest.write_bytes(b'approved')
                copy, close = shutil.copyfile, os.close
                changed = []

                def substitute(path):
                    before = path.stat()
                    other = root / 'foreign'
                    other.write_bytes(path.read_bytes())
                    os.utime(other, ns=(before.st_atime_ns, before.st_mtime_ns))
                    self.assertNotEqual(other.stat().st_ino, before.st_ino)
                    os.replace(other, path)
                    changed.append((path, before.st_ino, path.stat().st_ino, path.read_bytes()))

                def copied(source, destination, *args, **kwargs):
                    result = copy(source, destination, *args, **kwargs)
                    if boundary == 'candidate' and not changed:
                        substitute(Path(destination))
                    return result

                def closed(descriptor):
                    result = close(descriptor)
                    if boundary == 'backup' and not changed:
                        temps = [path for path in root.glob('.revayat-publish-*')
                                 if path.is_file() and path.suffix != '.lock']
                        # Candidate temp is closed first; the empty backup temp is
                        # closed after the journal directory has been created.
                        if any(path.is_dir() for path in root.glob('.revayat-publish-*')):
                            self.assertEqual(len(temps), 1)
                            substitute(temps[0])
                    return result

                with unittest.mock.patch('publication.shutil.copyfile', side_effect=copied), \
                        unittest.mock.patch('publication.os.close', side_effect=closed):
                    with self.assertRaisesRegex(ValueError, 'ownership'):
                        publish_files([(stage, dest)])
                self.assertEqual(len(changed), 1)
                foreign, original_inode, foreign_inode, contents = changed[0]
                self.assertNotEqual(original_inode, foreign_inode)
                self.assertEqual(foreign.stat().st_ino, foreign_inode)
                self.assertEqual(foreign.read_bytes(), contents)
                self.assertEqual(stage.read_bytes(), b'candidate')
                self.assertEqual(dest.read_bytes(), b'approved')

    def test_exact_explicit_limit_and_copied_backup_inode_remain_supported(self):
        first, second, a, b = (self.root / name for name in ('first', 'second', 'a', 'b'))
        first.write_bytes(b'approved')
        second.write_bytes(b'previous')
        a.write_bytes(b'candidate')
        b.write_bytes(b'other new')
        copy, replace = shutil.copy2, os.replace
        observed_copy = []

        def copied(source, destination, *args, **kwargs):
            result = copy(source, destination, *args, **kwargs)
            observed_copy.append((Path(source).stat().st_ino, Path(destination).stat().st_ino))
            return result

        def fail_late(source, destination):
            if Path(source) == b:
                raise OSError('controlled activation failure')
            return replace(source, destination)

        with unittest.mock.patch('publication.shutil.copy2', side_effect=copied), \
                unittest.mock.patch('publication.os.replace', side_effect=fail_late):
            with self.assertRaises(OSError):
                publish_files([(a, first), (b, second)], max_file_bytes=9)
        self.assertEqual(first.read_bytes(), b'approved')
        self.assertEqual(second.read_bytes(), b'previous')
        self.assertEqual(len(observed_copy), 2)
        self.assertTrue(all(source != backup for source, backup in observed_copy))
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    def test_explicit_limit_refuses_without_replacing_previous_destination(self):
        dest, stage = self.root / 'dest', self.root / 'stage'
        dest.write_bytes(b'approved')
        stage.write_bytes(b'candidate')
        with self.assertRaisesRegex(ValueError, 'limit'):
            publish_files([(stage, dest)], max_file_bytes=8)
        self.assertEqual(dest.read_bytes(), b'approved')
        self.assertEqual(stage.read_bytes(), b'candidate')
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    def test_missing_previous_destination_and_empty_candidate_remain_supported(self):
        dest, stage = self.root / 'dest', self.root / 'stage'
        stage.write_bytes(b'')
        publish_files([(stage, dest)], max_file_bytes=0)
        self.assertEqual(dest.read_bytes(), b'')
        self.assertFalse(stage.exists())
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))
