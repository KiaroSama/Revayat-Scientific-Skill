"""Package destinations never replace normal, relocated or shared Git metadata."""
import importlib.util
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from runtime import operation_log

SPEC = importlib.util.spec_from_file_location('git_metadata_packager', ROOT / 'tools/package.py')
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class PackageGitMetadataTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='package metadata ', dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.checkout = self.root / 'checkout'
        self.checkout.mkdir()
        self.source = self.root / 'payload'
        self.source.mkdir()
        (self.source / 'SKILL.md').write_bytes(b'Synthetic instructions\n')
        self.environment = {**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                            'GIT_AUTHOR_NAME': 'Synthetic Fixture', 'GIT_COMMITTER_NAME': 'Synthetic Fixture',
                            'GIT_AUTHOR_EMAIL': 'Kiaro.Sama.Dev@gmail.com',
                            'GIT_COMMITTER_EMAIL': 'Kiaro.Sama.Dev@gmail.com'}
        self.log_context = operation_log('test-package-git-metadata', self.root / 'logs')
        self.logger = self.log_context.__enter__()
        self.addCleanup(self.log_context.__exit__, None, None, None)
        self.logger.info('running test=%s; only disposable repositories are used', self._testMethodName)

    def git(self, *args, cwd=None):
        result = subprocess.run(['git', *args], cwd=cwd or self.checkout, env=self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                encoding='utf-8', timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def package(self, target, checkout=None):
        with mock.patch.object(PACKAGE, 'ROOT', checkout or self.checkout), \
                mock.patch.object(PACKAGE.installer, 'SOURCE', self.source), \
                mock.patch.object(sys, 'argv', ['package.py', '--output', str(target)]):
            return PACKAGE.main()

    def assert_refused(self, targets, checkout=None):
        for target in targets:
            with self.subTest(target=target.name):
                before = target.read_bytes() if target.is_file() else None
                with self.assertRaises(ValueError):
                    self.package(target, checkout)
                if before is None:
                    self.assertFalse(target.exists())
                else:
                    self.assertEqual(target.read_bytes(), before)

    def test_ordinary_git_config_index_head_and_new_objects_are_protected(self):
        self.git('init', '--quiet')
        (self.checkout / 'README.md').write_bytes(b'Synthetic tracked readme')
        self.git('add', 'README.md')
        metadata = self.checkout / '.git'
        self.assert_refused([metadata / 'config', metadata / 'index', metadata / 'HEAD',
                             metadata / 'objects' / 'new-package.skill'])
        self.assertEqual(self.git('ls-files'), 'README.md')

    def test_separate_git_directory_and_pointer_file_are_protected(self):
        metadata = self.root / 'relocated-metadata'
        self.git('init', '--quiet', '--separate-git-dir', str(metadata))
        self.assert_refused([self.checkout / '.git', metadata / 'config', metadata / 'HEAD',
                             metadata / 'new-package.skill'])
        self.assertEqual(Path(self.git('rev-parse', '--absolute-git-dir')), metadata)

    def test_linked_worktree_shared_and_private_metadata_are_protected(self):
        self.git('init', '--quiet')
        self.git('commit', '--allow-empty', '--quiet', '-m', 'Unpublished fixture')
        worktree = self.root / 'worktree'
        self.git('worktree', 'add', '--detach', str(worktree), 'HEAD')
        private = Path(self.git('rev-parse', '--absolute-git-dir', cwd=worktree))
        shared = self.checkout / '.git'
        self.assert_refused([worktree / '.git', private / 'HEAD', private / 'index',
                             shared / 'config', shared / 'objects' / 'new.skill'], worktree)
        self.assertEqual(self.git('rev-parse', 'HEAD', cwd=worktree), self.git('rev-parse', 'HEAD'))

    def test_legitimate_archive_and_exported_source_output_remain_available(self):
        self.git('init', '--quiet')
        output = self.checkout / 'dist' / 'bundle.skill'
        self.assertEqual(self.package(output), 0)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read('revayat-scientific/SKILL.md'), b'Synthetic instructions\n')
        exported = self.root / 'source-export'
        exported.mkdir()
        self.assertEqual(self.package(exported / 'bundle.skill', exported), 0)
        self.assert_refused([exported / '.git'], exported)

    def test_metadata_resolution_failure_is_not_an_empty_allowlist(self):
        self.git('init', '--quiet')
        original_run = PACKAGE.subprocess.run
        def controlled(command, **kwargs):
            if 'rev-parse' in command:
                return subprocess.CompletedProcess(command, 1, b'', b'synthetic metadata failure')
            return original_run(command, **kwargs)
        target = self.checkout / 'previous.skill'
        target.write_bytes(b'previous approved delivery')
        with mock.patch.object(PACKAGE.subprocess, 'run', side_effect=controlled):
            with self.assertRaises(ValueError):
                self.package(target)
        self.assertEqual(target.read_bytes(), b'previous approved delivery')


    def test_git_selected_external_index_and_object_store_are_protected(self):
        self.git('init', '--quiet')
        (self.checkout / 'README.md').write_bytes(b'tracked source')
        self.git('add', 'README.md')
        external_index = self.root / 'external-index'
        shutil.copy2(self.checkout / '.git' / 'index', external_index)
        external_objects = self.root / 'external-objects'
        external_objects.mkdir()
        with mock.patch.dict(os.environ, {'GIT_INDEX_FILE': str(external_index),
                                         'GIT_OBJECT_DIRECTORY': str(external_objects)}):
            self.assert_refused([external_index, external_objects / 'new.skill'])


    def test_explicit_git_dir_without_gitfile_is_protected(self):
        metadata = self.root / 'explicit-metadata'
        self.git('init', '--quiet', '--separate-git-dir', str(metadata))
        (self.checkout / '.git').unlink()
        with mock.patch.dict(os.environ, {'GIT_DIR': str(metadata),
                                         'GIT_WORK_TREE': str(self.checkout)}):
            self.assert_refused([metadata / 'config', metadata / 'HEAD', metadata / 'objects' / 'new.skill'])
            self.assertEqual(self.package(self.checkout / 'dist' / 'result.skill'), 0)

    def test_invalid_explicit_git_dir_is_not_treated_as_an_export(self):
        target = self.checkout / 'previous.skill'
        target.write_bytes(b'previous approved delivery')
        with mock.patch.dict(os.environ, {'GIT_DIR': str(self.root / 'missing-metadata')}):
            with self.assertRaises(ValueError):
                self.package(target)
        self.assertEqual(target.read_bytes(), b'previous approved delivery')


if __name__ == '__main__':
    unittest.main()
