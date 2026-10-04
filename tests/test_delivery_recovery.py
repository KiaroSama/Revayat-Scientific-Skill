"""Delivery recovery must account for effects even when an OS call raises."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from publication import publish_files
from runtime import operation_log
import test_tex_input_snapshot as tex_fixture

spec = importlib.util.spec_from_file_location('recovery_installer', ROOT / 'install/install.py')
INSTALLER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(INSTALLER)


class DeliveryRecoveryTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.work = tempfile.TemporaryDirectory(dir=scratch, prefix='delivery recovery ')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.scope = operation_log('test-delivery-recovery', self.root / 'logs')
        self.log = self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)

    def test_completed_replace_exception_restores_whole_previous_batch(self):
        for absent in (False, True):
            with self.subTest(previous_absent=absent):
                first, second = self.root / 'first', self.root / 'second'
                a, b = self.root / 'stage-a', self.root / 'stage-b'
                first.unlink(missing_ok=True)
                if not absent:
                    first.write_bytes(b'approved first')
                second.write_bytes(b'approved second')
                a.write_bytes(b'candidate first')
                b.write_bytes(b'candidate second')
                replace = os.replace

                def completed_then_failed(source, destination):
                    result = replace(source, destination)
                    if Path(source) == b:
                        raise OSError('completed second replacement before exception')
                    return result

                with mock.patch('publication.os.replace', side_effect=completed_then_failed):
                    with self.assertRaises(OSError):
                        publish_files([(a, first), (b, second)])
                if absent:
                    self.assertFalse(first.exists())
                else:
                    self.assertEqual(first.read_bytes(), b'approved first')
                self.assertEqual(second.read_bytes(), b'approved second')
                self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    def test_corrupt_publication_backup_refuses_before_any_replacement(self):
        first, second = self.root / 'first', self.root / 'second'
        a, b = self.root / 'stage-a', self.root / 'stage-b'
        first.write_bytes(b'approved first')
        second.write_bytes(b'approved second')
        a.write_bytes(b'candidate first')
        b.write_bytes(b'candidate second')
        copy = shutil.copy2

        def corrupt_backup(source, destination, *args, **kwargs):
            result = copy(source, destination, *args, **kwargs)
            if Path(source) == first:
                Path(destination).write_bytes(b'corrupted backup')
            return result

        with mock.patch('publication.shutil.copy2', side_effect=corrupt_backup):
            with self.assertRaisesRegex(RuntimeError, 'backup'):
                publish_files([(a, first), (b, second)])
        self.assertEqual(first.read_bytes(), b'approved first')
        self.assertEqual(second.read_bytes(), b'approved second')
        self.assertEqual(a.read_bytes(), b'candidate first')
        self.assertEqual(b.read_bytes(), b'candidate second')
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    def test_changed_backup_is_retained_instead_of_restored_on_late_failure(self):
        first, second = self.root / 'first', self.root / 'second'
        a, b = self.root / 'stage-a', self.root / 'stage-b'
        for path, data in ((first, b'approved first'), (second, b'approved second'),
                           (a, b'candidate first'), (b, b'candidate second')):
            path.write_bytes(data)
        replace = os.replace

        def late_failure(source, destination):
            if Path(source) == b:
                journal = next(p for p in self.root.glob('.revayat-publish-*/recovery.json')
                               if json.loads(p.read_text(encoding='utf-8'))['destination'] == str(first))
                (journal.parent / 'previous').write_bytes(b'changed recovery bytes')
                raise OSError('controlled late failure')
            return replace(source, destination)

        with mock.patch('publication.os.replace', side_effect=late_failure):
            with self.assertRaisesRegex(RuntimeError, 'rollback needs recovery'):
                publish_files([(a, first), (b, second)])
        self.assertEqual(first.read_bytes(), b'candidate first')
        self.assertEqual(second.read_bytes(), b'approved second')
        journals = list(self.root.glob('.revayat-publish-*/recovery.json'))
        self.assertEqual(len(journals), 2)
        self.assertTrue(any((p.parent / 'previous').read_bytes() == b'changed recovery bytes'
                            for p in journals))

    def test_genuine_quoted_and_bom_installation_identity_remains_supported(self):
        target = self.root / 'installed'
        for value in ('revayat-scientific', "'revayat-scientific'", '"revayat-scientific"'):
            with self.subTest(value=value):
                target.mkdir()
                (target / 'SKILL.md').write_text('---\nname: ' + value + '\ndescription: |\n  Fixture\n---\n',
                                                encoding='utf-8-sig')
                (target / 'retained').write_bytes(b'previous owner edition')
                with contextlib.redirect_stdout(io.StringIO()):
                    INSTALLER.install(target, True, self.log)
                self.assertEqual((target / 'SKILL.md').read_bytes(), (INSTALLER.SOURCE / 'SKILL.md').read_bytes())
                self.assertTrue(any((p / 'retained').read_bytes() == b'previous owner edition'
                                    for p in (self.root / 'skill-backups').iterdir()))
                shutil.rmtree(target)

    def test_ambiguous_frontmatter_never_replaces_existing_installation(self):
        target = self.root / 'installed'
        target.mkdir()
        marker = target / 'SKILL.md'
        retained = target / 'retained.txt'
        retained.write_bytes(b'local owner content')
        names = ["name: revayat-scientific\nname: []", "name: 'revayat-scientific\"",
                 "name: revayat-scientific\nname: |\n  other",
                 "name: revayat-scientific\n? name\n: []",
                 'name: revayat-scientific\n"\\u006eame": []',
                 'name: revayat-scientific\n  name: []']
        for declaration in names:
            with self.subTest(declaration=declaration):
                data = ('---\n' + declaration + '\n---\n').encode('utf-8')
                marker.write_bytes(data)
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(ValueError):
                        INSTALLER.install(target, True, self.log)
                self.assertEqual(marker.read_bytes(), data)
                self.assertEqual(retained.read_bytes(), b'local owner content')
                self.assertFalse((self.root / 'skill-backups').exists())

    def test_partial_copy_cleanup_failure_retains_owned_stage_and_lock_evidence(self):
        target = self.root / 'installed'
        transaction = sys.modules['install_transaction']
        remove = shutil.rmtree

        def partial_copy(source, destination, *args, **kwargs):
            Path(destination).write_bytes(b'partial candidate')
            raise OSError('controlled partial copy')

        def cleanup_failure(path, *args, **kwargs):
            if Path(path).name.startswith('.revayat-scientific-stage-'):
                raise OSError('controlled stage cleanup failure')
            return remove(path, *args, **kwargs)

        with mock.patch.object(transaction.shutil, 'copy2', side_effect=partial_copy), \
                mock.patch.object(transaction.shutil, 'rmtree', side_effect=cleanup_failure):
            with self.assertRaisesRegex(RuntimeError, 'cleanup needs recovery'):
                INSTALLER.install(target, False, self.log)
        self.assertFalse(target.exists())
        journals = list(self.root.glob('.revayat-install-recovery-*/recovery.json'))
        self.assertEqual(len(journals), 1)
        record = json.loads(journals[0].read_text(encoding='utf-8'))
        entry = record['targets'][0]
        stage = Path(entry['stage'])
        self.assertTrue(stage.is_dir())
        info = stage.stat()
        self.assertEqual(entry['staged_identity'], [info.st_dev, info.st_ino])
        locks = list(self.root.glob('.revayat-install-*.lock'))
        self.assertEqual(len(locks), 1)
        self.assertEqual(entry['lock'], str(locks[0]))
        info = locks[0].stat()
        self.assertEqual(entry['lock_identity'], [info.st_dev, info.st_ino])
        self.assertEqual(locks[0].read_text(encoding='utf-8').strip(), str(journals[0]))

    def test_failed_journal_refresh_cleanup_keeps_initial_stage_identity(self):
        target = self.root / 'installed'
        transaction = sys.modules['install_transaction']
        journal, remove = transaction._journal, shutil.rmtree

        def failed_refresh(path, targets):
            if Path(path).name == 'prepared.json':
                raise OSError('controlled journal refresh failure')
            return journal(path, targets)

        def failed_cleanup(path, *args, **kwargs):
            if Path(path).name.startswith('.revayat-scientific-stage-'):
                raise OSError('controlled empty stage cleanup failure')
            return remove(path, *args, **kwargs)

        with mock.patch.object(transaction, '_journal', side_effect=failed_refresh), \
                mock.patch.object(transaction.shutil, 'rmtree', side_effect=failed_cleanup):
            with self.assertRaisesRegex(RuntimeError, 'cleanup needs recovery'):
                INSTALLER.install(target, False, self.log)
        journal_path = next(self.root.glob('.revayat-install-recovery-*/recovery.json'))
        record = json.loads(journal_path.read_text(encoding='utf-8'))
        entry = record['targets'][0]
        stage = Path(entry['stage'])
        self.assertTrue(stage.is_dir())
        info = stage.stat()
        self.assertEqual(entry['staged_identity'], [info.st_dev, info.st_ino])
        self.assertTrue(Path(entry['lock']).is_file())
        self.assertFalse(target.exists())

    def test_tex_original_revision_is_bound_before_copy_not_after(self):
        fixture = tex_fixture.TexInputSnapshotTest('test_unchanged_source_and_all_copied_resources_publish_without_mutation')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        copy = shutil.copyfile
        changed = b'concurrent edit copied as a new baseline'

        def copying(source, destination, *args, **kwargs):
            if Path(source) == fixture.child:
                fixture.child.write_bytes(changed)
            return copy(source, destination, *args, **kwargs)

        with mock.patch.object(tex_fixture.TEX.shutil, 'copyfile', side_effect=copying), \
                mock.patch.object(tex_fixture.TEX, 'call', side_effect=fixture.backend()) as backend:
            with self.assertRaisesRegex(ValueError, 'changed'):
                tex_fixture.TEX.compile_document(fixture.source, fixture.output, fixture.log)
        backend.assert_not_called()
        self.assertEqual(fixture.child.read_bytes(), changed)
        self.assertEqual(fixture.output.read_bytes(), b'previous approved output')
        self.assertFalse(list(fixture.root.glob('.revayat-tex-*')))

    def test_tex_staged_revision_mutation_is_not_certified_after_backend(self):
        fixture = tex_fixture.TexInputSnapshotTest('test_unchanged_source_and_all_copied_resources_publish_without_mutation')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original = fixture.child.read_bytes()
        render = fixture.backend()

        def changed_stage(arguments, logger, timeout):
            result = render(arguments, logger, timeout)
            directory = Path(arguments[arguments.index('--cidfile') + 1]).parent
            (directory / 'input' / fixture.child.name).write_bytes(b'changed staged input')
            return result

        with mock.patch.object(tex_fixture.TEX, 'call', side_effect=changed_stage):
            with self.assertRaisesRegex(ValueError, 'changed'):
                tex_fixture.TEX.compile_document(fixture.source, fixture.output, fixture.log)
        self.assertEqual(fixture.child.read_bytes(), original)
        self.assertEqual(fixture.output.read_bytes(), b'previous approved output')
        fixture.cleanup.assert_called_once()
        self.assertFalse(list(fixture.root.glob('.revayat-tex-*')))
