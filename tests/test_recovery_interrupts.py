"""Second cancellation must leave accountable bytes and recovery coordination."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest.mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from publication import publish_files
from runtime import operation_log

SPEC = importlib.util.spec_from_file_location('interrupt_installer', ROOT / 'install/install.py')
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)
HEADER = '---\nname: revayat-scientific\ndescription: Fixture\n---\n'


class RecoveryInterruptTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.work = tempfile.TemporaryDirectory(dir=scratch, prefix='recovery interruptions ')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()

    def test_interrupted_rollback_retains_previous_bytes(self):
        for cancellation in (KeyboardInterrupt, SystemExit):
            for completed in (False, True):
                with self.subTest(cancellation=cancellation.__name__, completed=completed):
                    root = self.root / (cancellation.__name__ + str(completed))
                    root.mkdir()
                    first, second, a, b = (root / name for name in ('first', 'second', 'a', 'b'))
                    for path, data in ((first, b'approved first'), (second, b'approved second'),
                                       (a, b'candidate first'), (b, b'candidate second')):
                        path.write_bytes(data)
                    replace = os.replace

                    def fault(source, destination):
                        if Path(source) == b:
                            raise OSError('controlled second activation failure')
                        if Path(source).name == 'previous' and Path(destination) == first:
                            if completed:
                                replace(source, destination)
                            raise cancellation('controlled second cancellation')
                        return replace(source, destination)

                    with unittest.mock.patch('publication.os.replace', side_effect=fault):
                        with self.assertRaises(cancellation):
                            publish_files([(a, first), (b, second)])
                    self.assertEqual(second.read_bytes(), b'approved second')
                    journals = list(root.glob('.revayat-publish-*/recovery.json'))
                    self.assertEqual(len(journals), 2, 'unresolved reconciliation must retain its records')
                    records = [json.loads(path.read_text(encoding='utf-8')) for path in journals]
                    record = next(row for row in records if row['destination'] == str(first))
                    previous = first if completed else Path(record['backup'])
                    self.assertEqual(previous.read_bytes(), b'approved first')
                    self.assertEqual(first.read_bytes(), b'approved first' if completed else b'candidate first')
                    for row in records:
                        lock = Path(row['lock'])
                        self.assertTrue(lock.is_file())
                        info = lock.stat()
                        self.assertEqual(row['lock_identity'], [info.st_dev, info.st_ino])
                        self.assertEqual(lock.read_text(encoding='utf-8').strip(), row['recovery'])

    def test_install_second_cancellation_retains_journal_backups_stages_and_locks(self):
        for cancellation in (KeyboardInterrupt, SystemExit):
            for completed in (False, True):
                with self.subTest(cancellation=cancellation.__name__, completed=completed):
                    root = self.root / (cancellation.__name__ + str(completed))
                    root.mkdir()
                    source, target = root / 'source', root / 'installed'
                    source.mkdir()
                    (source / 'SKILL.md').write_text(HEADER + 'candidate', encoding='utf-8')
                    target.mkdir()
                    (target / 'SKILL.md').write_text(HEADER + 'approved', encoding='utf-8')
                    (target / 'retained').write_bytes(b'approved owner bytes')
                    rename = Path.rename
                    output = io.StringIO()

                    def fault(path, destination):
                        if path.name.startswith('.revayat-scientific-stage-') and Path(destination) == target:
                            raise OSError('controlled activation failure')
                        if path.parent.name == 'skill-backups' and Path(destination) == target:
                            if completed:
                                rename(path, destination)
                            raise cancellation('controlled restoration cancellation')
                        return rename(path, destination)

                    with operation_log('test-recovery-interrupt', root / 'logs') as logger, \
                            unittest.mock.patch.object(INSTALLER, 'SOURCE', source), \
                            unittest.mock.patch.object(Path, 'rename', fault), contextlib.redirect_stdout(output):
                        with self.assertRaises(cancellation):
                            INSTALLER.install(target, True, logger)
                    self.assertNotIn('Installed revayat-scientific:', output.getvalue())
                    journals = list(root.glob('.revayat-install-recovery-*/recovery.json'))
                    self.assertEqual(len(journals), 1, 'interrupted rollback must retain the installation journal')
                    record = json.loads(journals[0].read_text(encoding='utf-8'))['targets'][0]
                    previous = target if completed else Path(record['backup'])
                    self.assertEqual((previous / 'retained').read_bytes(), b'approved owner bytes')
                    stage, lock = Path(record['stage']), Path(record['lock'])
                    self.assertEqual((stage / 'SKILL.md').read_bytes(), (source / 'SKILL.md').read_bytes())
                    for path, field in ((stage, 'staged_identity'), (lock, 'lock_identity')):
                        info = path.stat()
                        self.assertEqual(record[field], [info.st_dev, info.st_ino])
                    self.assertEqual(lock.read_text(encoding='utf-8').strip(), str(journals[0]))

    def test_completed_install_restoration_error_reconciles_the_previous_edition(self):
        source, target = self.root / 'source', self.root / 'installed'
        source.mkdir()
        (source / 'SKILL.md').write_text(HEADER + 'candidate', encoding='utf-8')
        target.mkdir()
        (target / 'SKILL.md').write_text(HEADER + 'approved', encoding='utf-8')
        (target / 'retained').write_bytes(b'approved owner bytes')
        rename = Path.rename

        def fault(path, destination):
            if path.name.startswith('.revayat-scientific-stage-') and Path(destination) == target:
                raise OSError('controlled activation failure')
            result = rename(path, destination)
            if path.parent.name == 'skill-backups' and Path(destination) == target:
                raise OSError('restoration completed before reporting failure')
            return result

        output = io.StringIO()
        with operation_log('test-recovery-interrupt', self.root / 'logs') as logger, \
                unittest.mock.patch.object(INSTALLER, 'SOURCE', source), \
                unittest.mock.patch.object(Path, 'rename', fault), contextlib.redirect_stdout(output):
            with self.assertRaisesRegex(OSError, 'activation failure'):
                INSTALLER.install(target, True, logger)
        self.assertEqual((target / 'retained').read_bytes(), b'approved owner bytes')
        self.assertEqual((target / 'SKILL.md').read_text(encoding='utf-8'), HEADER + 'approved')
        self.assertNotIn('Installed revayat-scientific:', output.getvalue())
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_second_install_restore_cancellation_retains_the_complete_target_plan(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'SKILL.md').write_text(HEADER + 'candidate', encoding='utf-8')
        targets = [self.root / name / 'skills/revayat-scientific' for name in ('first', 'second')]
        for index, target in enumerate(targets):
            target.mkdir(parents=True)
            (target / 'SKILL.md').write_text(HEADER + 'approved', encoding='utf-8')
            (target / 'retained').write_bytes(b'approved first' if index == 0 else b'approved second')
        rename = Path.rename

        def fault(path, destination):
            if path.name.startswith('.revayat-scientific-stage-') and Path(destination) == targets[1]:
                raise OSError('controlled second activation failure')
            if path.parent.name == 'skill-backups' and Path(destination) == targets[0]:
                raise SystemExit('controlled late restoration cancellation')
            return rename(path, destination)

        agents = {name: (name + '/skills', name + '/skills') for name in ('first', 'second')}
        output = io.StringIO()
        with unittest.mock.patch.object(INSTALLER, 'SOURCE', source), \
                unittest.mock.patch.object(INSTALLER, 'AGENTS', agents), \
                unittest.mock.patch.object(Path, 'rename', fault), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit):
                INSTALLER.main(['--scope', 'project', '--path', str(self.root), '--force'])
        self.assertNotIn('Installed revayat-scientific:', output.getvalue())
        journal = next(targets[0].parent.glob('.revayat-install-recovery-*/recovery.json'))
        records = json.loads(journal.read_text(encoding='utf-8'))['targets']
        self.assertEqual([row['destination'] for row in records], list(map(str, targets)))
        self.assertEqual((Path(records[0]['backup']) / 'retained').read_bytes(), b'approved first')
        self.assertEqual((targets[1] / 'retained').read_bytes(), b'approved second')
        self.assertTrue(all(Path(row['stage']).is_dir() and Path(row['lock']).is_file() for row in records))

    def test_completed_file_restoration_error_preserves_previous_bytes_and_cleans(self):
        first, second, a, b = (self.root / name for name in ('first', 'second', 'a', 'b'))
        for path, data in ((first, b'approved first'), (second, b'approved second'),
                           (a, b'candidate first'), (b, b'candidate second')):
            path.write_bytes(data)
        replace = os.replace

        def fault(source, destination):
            if Path(source) == b:
                raise OSError('controlled activation failure')
            result = replace(source, destination)
            if Path(source).name == 'previous':
                raise OSError('restoration completed before reporting failure')
            return result

        with unittest.mock.patch('publication.os.replace', side_effect=fault):
            with self.assertRaisesRegex(OSError, 'activation failure'):
                publish_files([(a, first), (b, second)])
        self.assertEqual(first.read_bytes(), b'approved first')
        self.assertEqual(second.read_bytes(), b'approved second')
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    def test_later_restore_failure_keeps_whole_batch_and_foreign_destination(self):
        first, second, a, b = (self.root / name for name in ('first', 'second', 'a', 'b'))
        for path, data in ((first, b'approved first'), (second, b'approved second'),
                           (a, b'candidate first'), (b, b'candidate second')):
            path.write_bytes(data)
        replace = os.replace

        def fault(source, destination):
            if Path(source) == b:
                replace(source, destination)
                first.write_bytes(b'foreign writer bytes')
                raise OSError('controlled completed late activation failure')
            if Path(source).name == 'previous' and Path(destination) == second:
                raise OSError('controlled later restore failure')
            return replace(source, destination)

        with unittest.mock.patch('publication.os.replace', side_effect=fault):
            with self.assertRaisesRegex(RuntimeError, 'rollback needs recovery'):
                publish_files([(a, first), (b, second)])
        self.assertEqual(first.read_bytes(), b'foreign writer bytes')
        self.assertEqual(second.read_bytes(), b'candidate second')
        records = [json.loads(path.read_text(encoding='utf-8'))
                   for path in self.root.glob('.revayat-publish-*/recovery.json')]
        self.assertEqual(len(records), 2)
        self.assertEqual({Path(row['backup']).read_bytes() for row in records},
                         {b'approved first', b'approved second'})
        self.assertTrue(all(Path(row['lock']).is_file() for row in records))

    def test_unchanged_publication_cleans_only_owned_paths(self):
        stage, dest = self.root / 'stage', self.root / 'dest'
        stage.write_bytes(b'candidate bytes')
        dest.write_bytes(b'approved bytes')
        foreign = self.root / '.revayat-publish-foreign'
        foreign.mkdir()
        (foreign / 'user-data').write_bytes(b'foreign bytes')
        publish_files([(stage, dest)])
        self.assertEqual(dest.read_bytes(), b'candidate bytes')
        self.assertEqual((foreign / 'user-data').read_bytes(), b'foreign bytes')
        self.assertFalse(stage.exists())
        self.assertEqual(list(self.root.glob('.revayat-publish-*')), [foreign])

    def test_absent_destination_completed_rollback_unlink_is_reconciled(self):
        first, second, a, b = (self.root / name for name in ('first', 'second', 'a', 'b'))
        second.write_bytes(b'approved second')
        a.write_bytes(b'candidate first')
        b.write_bytes(b'candidate second')
        replace, unlink = os.replace, Path.unlink

        def fault(source, destination):
            if Path(source) == b:
                raise OSError('controlled activation failure')
            return replace(source, destination)

        def completed_unlink(path, *args, **kwargs):
            result = unlink(path, *args, **kwargs)
            if path == first:
                raise OSError('unlink completed before reporting failure')
            return result

        with unittest.mock.patch('publication.os.replace', side_effect=fault), \
                unittest.mock.patch.object(Path, 'unlink', completed_unlink):
            with self.assertRaisesRegex(OSError, 'activation failure'):
                publish_files([(a, first), (b, second)])
        self.assertFalse(first.exists())
        self.assertEqual(second.read_bytes(), b'approved second')
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    def test_publication_cleanup_cancellation_retains_journal_and_owned_lock(self):
        stage, dest = self.root / 'stage', self.root / 'dest'
        stage.write_bytes(b'candidate bytes')
        dest.write_bytes(b'approved bytes')
        unlink = Path.unlink

        def fault(path, *args, **kwargs):
            if path.name == 'previous':
                raise KeyboardInterrupt('controlled backup-disposal cancellation')
            return unlink(path, *args, **kwargs)

        with unittest.mock.patch.object(Path, 'unlink', fault), self.assertRaises(KeyboardInterrupt):
            publish_files([(stage, dest)])
        self.assertEqual(dest.read_bytes(), b'candidate bytes')
        journal = next(self.root.glob('.revayat-publish-*/recovery.json'))
        record = json.loads(journal.read_text(encoding='utf-8'))
        self.assertEqual(Path(record['backup']).read_bytes(), b'approved bytes')
        self.assertTrue(Path(record['lock']).is_file())
