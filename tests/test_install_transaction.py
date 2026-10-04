"""Installation must plan the complete target set and preserve recoverable state."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from runtime import operation_log

SPEC = importlib.util.spec_from_file_location('audit_installer', ROOT / 'install/install.py')
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)
NAME = 'revayat-scientific'
HEADER = '---\nname: revayat-scientific\ndescription: Fixture\n---\n'


class InstallTransactionTest(unittest.TestCase):
    def setUp(self):
        (ROOT / '.scratch').mkdir(exist_ok=True)
        self.work = tempfile.TemporaryDirectory(prefix='install integrity فارسی ', dir=ROOT / '.scratch')
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name).resolve()
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'SKILL.md').write_text(HEADER + 'New release', encoding='utf-8')
        (self.source / 'scripts').mkdir()
        (self.source / 'scripts/helper.py').write_bytes(b'pass\n')
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(INSTALLER, 'SOURCE', self.source).start()
        self.scope = operation_log('test-install-transaction', self.root / 'logs')
        self.log = self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)
        self.project = self.root / 'project'
        self.project.mkdir()
        self.first = self.project / '.a/skills' / NAME
        self.second = self.project / '.b/skills' / NAME
        self.original_rename = Path.rename

    def old(self, target, marker=b'previous edition'):
        target.mkdir(parents=True)
        (target / 'SKILL.md').write_text(HEADER + 'Old release', encoding='utf-8')
        (target / 'retained-note.txt').write_bytes(marker)
        return self.snapshot(target)

    def snapshot(self, root):
        if not root.exists():
            return None
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink()}

    def install(self, target, force=False):
        with contextlib.redirect_stdout(io.StringIO()):
            return INSTALLER.install(target, force, self.log)

    def batch(self, force=False):
        for folder in (self.project / '.a', self.project / '.b'):
            folder.mkdir(exist_ok=True)
        agents = {'a': ('.a/skills', '.a/skills'), 'b': ('.b/skills', '.b/skills')}
        args = ['--scope', 'project', '--path', str(self.project)] + (['--force'] if force else [])
        with mock.patch.object(INSTALLER, 'AGENTS', agents), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return INSTALLER.main(args)

    def link(self, target, alias):
        try:
            alias.symlink_to(target, target_is_directory=target.is_dir())
        except OSError:
            self.skipTest('symlink creation unavailable for this OS account')

    def test_new_install_and_force_replacement_preserve_exact_backup(self):
        self.install(self.first)
        expected = self.snapshot(self.source)
        self.assertEqual(self.snapshot(self.first), expected)
        (self.first / 'retained-note.txt').write_bytes(b'private local note')
        previous = self.snapshot(self.first)
        with self.assertRaises(FileExistsError):
            self.install(self.first)
        self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), expected)
        backups = list((self.first.parent.parent / 'skill-backups').glob(NAME + '-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(self.snapshot(backups[0]), previous)
        self.assertEqual(self.snapshot(self.source), expected)

    def test_foreign_nonempty_directory_is_not_a_force_installation(self):
        target = self.root / 'foreign'
        target.mkdir()
        (target / 'data.txt').write_bytes(b'not a skill')
        before = self.snapshot(target)
        with self.assertRaises(ValueError):
            self.install(target, True)
        self.assertEqual(self.snapshot(target), before)

    def test_wrong_skill_name_does_not_authorize_replacement(self):
        self.first.mkdir(parents=True)
        (self.first / 'SKILL.md').write_text('---\nname: another-skill\n---\n', encoding='utf-8')
        previous = self.snapshot(self.first)
        with self.assertRaises(ValueError):
            self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), previous)

    def test_git_metadata_and_case_variant_are_never_install_targets(self):
        for name in ('.git', '.GIT'):
            with self.subTest(name=name):
                target = self.root / name
                self.old(target)
                before = self.snapshot(target)
                with self.assertRaises(ValueError):
                    self.install(target, True)
                self.assertEqual(self.snapshot(target), before)

    def test_separate_git_administration_directory_remains_intact(self):
        checkout, admin = self.root / 'checkout', self.root / 'admin'
        result = subprocess.run(['git', 'init', '--quiet', '--separate-git-dir', str(admin), str(checkout)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        before = self.snapshot(admin)
        with self.assertRaises(ValueError):
            self.install(admin, True)
        self.assertEqual(self.snapshot(admin), before)
        self.assertEqual(subprocess.run(['git', '-C', str(checkout), 'status', '--porcelain'],
                                       capture_output=True, timeout=15).returncode, 0)

    def test_parent_symlink_never_redirects_installation(self):
        actual = self.root / 'outside'
        actual.mkdir()
        alias = self.root / 'alias'
        self.link(actual, alias)
        with self.assertRaises(ValueError):
            self.install(alias / NAME)
        self.assertFalse((actual / NAME).exists())

    def test_destination_symlink_is_preserved(self):
        actual = self.root / 'outside'
        before = self.old(actual)
        self.first.parent.mkdir(parents=True)
        self.link(actual, self.first)
        with self.assertRaises(ValueError):
            self.install(self.first, True)
        self.assertTrue(self.first.is_symlink())
        self.assertEqual(self.snapshot(actual), before)

    def test_source_root_link_is_not_dereferenced(self):
        alias = self.root / 'linked-source'
        self.link(self.source, alias)
        with mock.patch.object(INSTALLER, 'SOURCE', alias), self.assertRaises(ValueError):
            self.install(self.first)
        self.assertFalse(self.first.exists())

    def test_backup_directory_link_does_not_move_the_old_install_outside(self):
        previous = self.old(self.first)
        outside = self.root / 'outside'
        outside.mkdir()
        backup = self.first.parent.parent / 'skill-backups'
        self.link(outside, backup)
        with self.assertRaises(ValueError):
            self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), previous)
        self.assertFalse(list(outside.iterdir()))

    def test_case_colliding_destination_is_refused(self):
        target = self.first.with_name('Revayat-Scientific')
        previous = self.old(target)
        # The same spelling on a case-insensitive volume must also be detected.
        with self.assertRaises(ValueError):
            self.install(self.first, True)
        self.assertEqual(self.snapshot(target), previous)

    def test_source_overlap_is_refused_without_changes(self):
        before = self.snapshot(self.source)
        for target in (self.source, self.source / 'child', self.source.parent):
            with self.subTest(target=target.name), self.assertRaises(ValueError):
                self.install(target, True)
        self.assertEqual(self.snapshot(self.source), before)

    def test_late_existing_target_preflight_does_not_install_first(self):
        previous = self.old(self.second)
        self.assertNotEqual(self.batch(), 0)
        self.assertFalse(self.first.exists())
        self.assertEqual(self.snapshot(self.second), previous)

    def test_late_invalid_target_preflight_does_not_install_first(self):
        self.second.parent.mkdir(parents=True)
        self.second.write_bytes(b'not a directory')
        self.assertNotEqual(self.batch(True), 0)
        self.assertFalse(self.first.exists())
        self.assertEqual(self.second.read_bytes(), b'not a directory')

    def test_payload_enumerated_once_for_the_entire_batch(self):
        real = INSTALLER.payload_files
        with mock.patch.object(INSTALLER, 'payload_files', wraps=real) as collect:
            self.assertEqual(self.batch(), 0)
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(self.snapshot(self.first), self.snapshot(self.second))

    def test_second_staging_copy_failure_leaves_both_old_installs(self):
        before_first = self.old(self.first, b'first')
        before_second = self.old(self.second, b'second')
        real = shutil.copy2
        copied = 0

        def copying(source, target, *args, **kwargs):
            nonlocal copied
            copied += 1
            if copied == 3:
                raise OSError('injected second staging failure')
            return real(source, target, *args, **kwargs)

        with mock.patch.object(shutil, 'copy2', side_effect=copying):
            self.assertNotEqual(self.batch(True), 0)
        self.assertEqual(self.snapshot(self.first), before_first)
        self.assertEqual(self.snapshot(self.second), before_second)

    def test_second_activation_failure_restores_both_old_installs(self):
        before_first = self.old(self.first, b'first')
        before_second = self.old(self.second, b'second')

        def rename(path, target):
            if Path(target) == self.second and '.revayat-scientific-stage-' in path.name:
                raise OSError('injected activation failure')
            return self.original_rename(path, target)

        with mock.patch.object(Path, 'rename', rename):
            self.assertNotEqual(self.batch(True), 0)
        self.assertEqual(self.snapshot(self.first), before_first)
        self.assertEqual(self.snapshot(self.second), before_second)

    def test_failed_batch_removes_a_new_first_install(self):
        previous = self.old(self.second)

        def rename(path, target):
            if Path(target) == self.second and '.revayat-scientific-stage-' in path.name:
                raise OSError('injected activation failure')
            return self.original_rename(path, target)

        with mock.patch.object(Path, 'rename', rename):
            self.assertNotEqual(self.batch(True), 0)
        self.assertFalse(self.first.exists())
        self.assertEqual(self.snapshot(self.second), previous)

    def test_copy_corruption_is_detected_before_publishing(self):
        before = self.old(self.first)
        real = shutil.copy2

        def corrupt(source, target, *args, **kwargs):
            result = real(source, target, *args, **kwargs)
            if Path(target).name == 'helper.py':
                Path(target).write_bytes(b'corrupted')
            return result

        with mock.patch.object(shutil, 'copy2', side_effect=corrupt), self.assertRaises(ValueError):
            self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), before)

    def test_changed_source_is_not_mixed_into_an_installation(self):
        before = self.old(self.first)
        real = shutil.copy2

        def change(source, target, *args, **kwargs):
            result = real(source, target, *args, **kwargs)
            if Path(target).name == 'SKILL.md':
                (self.source / 'scripts/helper.py').write_bytes(b'changed during stage')
            return result

        with mock.patch.object(shutil, 'copy2', side_effect=change), self.assertRaises(ValueError):
            self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), before)

    def test_concurrent_old_install_change_is_not_overwritten(self):
        self.old(self.first)
        real = shutil.copy2

        def change(source, target, *args, **kwargs):
            result = real(source, target, *args, **kwargs)
            (self.first / 'retained-note.txt').write_bytes(b'concurrent owner edit')
            return result

        with mock.patch.object(shutil, 'copy2', side_effect=change), self.assertRaises((ValueError, RuntimeError)):
            self.install(self.first, True)
        self.assertEqual((self.first / 'retained-note.txt').read_bytes(), b'concurrent owner edit')

    def test_failed_rollback_retains_a_located_recovery_record_and_original(self):
        before = self.old(self.first)

        def rename(path, target):
            if Path(target) == self.first:
                raise OSError('injected activation and restoration failure')
            return self.original_rename(path, target)

        with mock.patch.object(Path, 'rename', rename), self.assertRaisesRegex(RuntimeError, 'recovery'):
            self.install(self.first, True)
        records = list(self.project.rglob('recovery.json'))
        self.assertTrue(records, 'failure must identify retained recovery instructions')
        backups = list((self.first.parent.parent / 'skill-backups').glob(NAME + '-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(self.snapshot(backups[0]), before)
        record = json.loads(records[0].read_text(encoding='utf-8'))
        self.assertEqual(record['targets'][0]['destination'], str(self.first))

    def test_successful_batch_keeps_backups_outside_discovery(self):
        one = self.old(self.first, b'first')
        two = self.old(self.second, b'second')
        self.assertEqual(self.batch(True), 0)
        for target, expected in ((self.first, one), (self.second, two)):
            self.assertEqual(self.snapshot(target), self.snapshot(self.source))
            backups = list((target.parent.parent / 'skill-backups').glob(NAME + '-*'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(self.snapshot(backups[0]), expected)
            self.assertFalse(list(target.parent.glob('.revayat-scientific-stage-*')))

    def test_empty_directory_requires_force_and_is_preserved_as_a_backup(self):
        self.first.mkdir(parents=True)
        with self.assertRaises(FileExistsError):
            self.install(self.first)
        self.install(self.first, True)
        backups = list((self.first.parent.parent / 'skill-backups').glob(NAME + '-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(list(backups[0].iterdir()), [])

    def test_existing_install_with_nested_link_is_not_followed(self):
        previous = self.old(self.first)
        outside = self.root / 'private-outside.txt'
        outside.write_bytes(b'retain private outside data')
        self.link(outside, self.first / 'linked-note')
        with self.assertRaises(ValueError):
            self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), previous)
        self.assertEqual(outside.read_bytes(), b'retain private outside data')

    def test_existing_lock_is_not_removed_or_ignored(self):
        previous = self.old(self.first)
        name = hashlib.sha256(str(self.first).casefold().encode()).hexdigest()[:24]
        lock = self.first.parent / ('.revayat-install-' + name + '.lock')
        lock.write_bytes(b'another installation owns this lock')
        with self.assertRaises(FileExistsError):
            self.install(self.first, True)
        self.assertEqual(lock.read_bytes(), b'another installation owns this lock')
        self.assertEqual(self.snapshot(self.first), previous)

    def test_busy_second_lock_releases_only_owned_first_lock(self):
        before = self.old(self.second)
        name = hashlib.sha256(str(self.second).casefold().encode()).hexdigest()[:24]
        lock = self.second.parent / ('.revayat-install-' + name + '.lock')
        lock.write_bytes(b'other operation')
        self.assertNotEqual(self.batch(True), 0)
        self.assertFalse(self.first.exists())
        self.assertEqual(self.snapshot(self.second), before)
        self.assertEqual(lock.read_bytes(), b'other operation')
        self.assertFalse(list(self.first.parent.glob('.revayat-install-*.lock')))

    def test_replaced_lock_is_preserved_and_cleanup_is_not_success(self):
        self.old(self.first)
        real = shutil.copy2
        changed = False
        prevented = False

        def replace_lock(source, target, *args, **kwargs):
            nonlocal changed, prevented
            result = real(source, target, *args, **kwargs)
            if not changed:
                changed = True
                lock = next(self.first.parent.glob('.revayat-install-*.lock'))
                # Rename retains the opened inode and allows a distinct lock path.
                try:
                    lock.rename(lock.with_suffix('.retained'))
                except PermissionError:
                    if os.name != 'nt':
                        raise
                    prevented = True
                    self.log.warning('Windows denied replacement of the open lock file')
                else:
                    lock.write_bytes(b'new owner lock')
            return result

        with mock.patch.object(shutil, 'copy2', side_effect=replace_lock):
            try:
                self.install(self.first, True)
            except RuntimeError as error:
                self.assertIn('recovery', str(error))
                self.assertFalse(prevented)
            else:
                self.assertTrue(prevented, 'a replaced lock cannot be silently accepted')
                self.assertEqual(self.snapshot(self.first), self.snapshot(self.source))
                self.assertFalse(list(self.first.parent.glob('.revayat-install-*.lock')))
                return
        lock = next(self.first.parent.glob('.revayat-install-*.lock'))
        self.assertEqual(lock.read_bytes(), b'new owner lock')
        self.assertTrue(list(self.first.parent.glob('.revayat-install-recovery-*/recovery.json')))

    def test_late_backup_root_swap_is_refused_without_writing_through_link(self):
        previous = self.old(self.first)
        outside = self.root / 'outside'
        outside.mkdir()
        # Establish link capability before invoking the deliberately interrupted stage.
        probe = self.root / 'link-probe'
        self.link(outside, probe)
        probe.unlink()
        backup_root = self.first.parent.parent / 'skill-backups'
        real = shutil.copy2
        changed = False

        def replace_root(source, target, *args, **kwargs):
            nonlocal changed
            result = real(source, target, *args, **kwargs)
            if not changed:
                changed = True
                backup_root.rmdir()
                backup_root.symlink_to(outside, target_is_directory=True)
            return result

        with mock.patch.object(shutil, 'copy2', side_effect=replace_root), self.assertRaises(ValueError):
            self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), previous)
        self.assertFalse(list(outside.iterdir()))

    def test_target_created_during_staging_is_not_overwritten(self):
        real = shutil.copy2
        changed = False

        def create_target(source, target, *args, **kwargs):
            nonlocal changed
            result = real(source, target, *args, **kwargs)
            if not changed:
                changed = True
                self.first.mkdir()
                (self.first / 'other-data').write_bytes(b'new concurrent owner')
            return result

        with mock.patch.object(shutil, 'copy2', side_effect=create_target), self.assertRaises(ValueError):
            self.install(self.first)
        self.assertEqual((self.first / 'other-data').read_bytes(), b'new concurrent owner')

    def test_actual_rename_then_exception_is_reconciled_by_directory_identity(self):
        previous = self.old(self.first)
        raised = False

        def rename(path, target):
            nonlocal raised
            result = self.original_rename(path, target)
            if not raised and Path(target) == self.first and '.revayat-scientific-stage-' in path.name:
                raised = True
                raise OSError('interruption after completed rename')
            return result

        with mock.patch.object(Path, 'rename', rename), self.assertRaises(OSError):
            self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), previous)

    def test_new_destination_after_failure_is_not_deleted_to_force_rollback(self):
        previous = self.old(self.first)

        def rename(path, target):
            if Path(target) == self.first and '.revayat-scientific-stage-' in path.name:
                self.first.mkdir()
                (self.first / 'outside-writer').write_bytes(b'concurrent content')
                raise OSError('activation blocked by new writer')
            return self.original_rename(path, target)

        with mock.patch.object(Path, 'rename', rename), self.assertRaisesRegex(RuntimeError, 'recovery'):
            self.install(self.first, True)
        self.assertEqual((self.first / 'outside-writer').read_bytes(), b'concurrent content')
        backups = list((self.first.parent.parent / 'skill-backups').glob(NAME + '-*'))
        self.assertEqual(self.snapshot(backups[0]), previous)

    def test_journal_write_failure_preserves_old_installation(self):
        previous = self.old(self.first)
        transaction = sys.modules['install_transaction']
        with mock.patch.object(transaction, '_journal', side_effect=OSError('cannot write recovery manifest')):
            with self.assertRaises(OSError):
                self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), previous)
        self.assertFalse(list(self.first.parent.glob('.revayat-scientific-stage-*')))

    def test_missing_or_misidentified_source_never_creates_target(self):
        for text in ('', 'not a skill', '---\nname: other\n---\n',
                     '---\nname: revayat-scientific\nname: other\n---\n'):
            with self.subTest(text=text):
                (self.source / 'SKILL.md').write_text(text, encoding='utf-8')
                with self.assertRaises(ValueError):
                    self.install(self.first)
                self.assertFalse(self.first.exists())

    def test_payload_limit_refuses_before_any_target_mutation(self):
        previous = self.old(self.first)
        transaction = sys.modules['install_transaction']
        with mock.patch.object(transaction, 'MAX_PAYLOAD_BYTES', 1), self.assertRaises(ValueError):
            self.install(self.first, True)
        self.assertEqual(self.snapshot(self.first), previous)

    def test_nested_target_plan_is_rejected_without_changes(self):
        transaction = sys.modules['install_transaction']
        with self.assertRaises(ValueError):
            transaction.install_targets([self.first, self.first / 'nested'], True, self.log,
                source=self.source, repository=ROOT, payload_factory=INSTALLER.payload_files)
        self.assertFalse(self.first.exists())

    def test_duplicate_case_target_plan_is_rejected_without_changes(self):
        transaction = sys.modules['install_transaction']
        with self.assertRaises(ValueError):
            transaction.install_targets([self.first, self.first.with_name('Revayat-Scientific')], True, self.log,
                source=self.source, repository=ROOT, payload_factory=INSTALLER.payload_files)
        self.assertFalse(self.first.exists())

    def test_shared_agent_path_is_deduplicated_before_publication(self):
        (self.project / '.a').mkdir()
        agents = {'codex': ('.a/skills', '.a/skills'), 'antigravity': ('.a/skills', '.a/skills')}
        with mock.patch.object(INSTALLER, 'AGENTS', agents), contextlib.redirect_stdout(io.StringIO()):
            result = INSTALLER.main(['--scope', 'project', '--path', str(self.project)])
        self.assertEqual(result, 0)
        self.assertEqual(self.snapshot(self.first), self.snapshot(self.source))

    def test_success_messages_are_not_printed_for_a_failed_batch(self):
        self.old(self.second)
        (self.project / '.a').mkdir()
        output = io.StringIO()
        with mock.patch.object(INSTALLER, 'AGENTS', {'a': ('.a/skills', '.a/skills'), 'b': ('.b/skills', '.b/skills')}), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            self.assertNotEqual(INSTALLER.main(['--scope', 'project', '--path', str(self.project)]), 0)
        self.assertNotIn('Installed revayat-scientific:', output.getvalue())

    def test_valid_bom_source_identity_is_supported(self):
        (self.source / 'SKILL.md').write_text(HEADER + 'New', encoding='utf-8-sig')
        self.install(self.first)
        self.assertEqual(self.snapshot(self.first), self.snapshot(self.source))

    def test_public_cli_refuses_a_foreign_target_without_mutation(self):
        target = self.root / 'foreign'
        target.mkdir()
        (target / 'note').write_bytes(b'private user data')
        result = subprocess.run([sys.executable, str(ROOT / 'install/install.py'),
                                 '--dest', str(target), '--force'], capture_output=True,
                                text=True, encoding='utf-8', timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Installed revayat-scientific:', result.stdout)
        self.assertNotIn('private user data', result.stdout + result.stderr)
        self.assertEqual((target / 'note').read_bytes(), b'private user data')

    def test_retained_backup_is_not_reinterpreted_as_an_install_target(self):
        self.old(self.first)
        self.install(self.first, True)
        backup = next((self.first.parent.parent / 'skill-backups').glob(NAME + '-*'))
        previous = self.snapshot(backup)
        with self.assertRaises(ValueError):
            self.install(backup, True)
        self.assertEqual(self.snapshot(backup), previous)

    def test_keyboard_interrupt_during_second_activation_restores_batch(self):
        first = self.old(self.first, b'first')
        second = self.old(self.second, b'second')
        transaction = sys.modules['install_transaction']

        def rename(path, target):
            if Path(target) == self.second and '.revayat-scientific-stage-' in path.name:
                raise KeyboardInterrupt()
            return self.original_rename(path, target)

        with mock.patch.object(Path, 'rename', rename), self.assertRaises(KeyboardInterrupt):
            transaction.install_targets([self.first, self.second], True, self.log,
                source=self.source, repository=ROOT, payload_factory=INSTALLER.payload_files)
        self.assertEqual(self.snapshot(self.first), first)
        self.assertEqual(self.snapshot(self.second), second)

    def test_source_file_link_and_nonregular_old_entry_are_rejected(self):
        outside = self.root / 'outside.txt'
        outside.write_bytes(b'outside')
        self.link(outside, self.source / 'scripts/linked.py')
        with self.assertRaises(ValueError):
            self.install(self.first)
        self.assertFalse(self.first.exists())
        self.assertEqual(outside.read_bytes(), b'outside')

    def test_windows_junction_in_destination_parent_is_rejected(self):
        if os.name != 'nt':
            self.skipTest('native Windows junction contract')
        outside = self.root / 'junction-target'
        outside.mkdir()
        junction = self.root / 'junction'
        command = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(outside)],
                                 capture_output=True, timeout=15)
        self.assertEqual(command.returncode, 0, command.stderr)
        try:
            with self.assertRaises(ValueError):
                self.install(junction / NAME)
            self.assertFalse((outside / NAME).exists())
        finally:
            os.rmdir(junction)


if __name__ == '__main__':
    unittest.main()
