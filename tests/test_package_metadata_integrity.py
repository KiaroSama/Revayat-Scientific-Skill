"""Package output must not replace Git administrative files or worktree pointers."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest.mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log

SPEC = importlib.util.spec_from_file_location('package_metadata_checker', ROOT / 'tools/package.py')
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)
EMAIL = 'Kiaro.Sama.Dev@gmail.com'


class PackageMetadataIntegrityTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch, prefix='package metadata audit ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.checkout = self.root / 'checkout'
        self.checkout.mkdir()
        self.environment = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull,
                            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_AUTHOR_NAME': 'Synthetic Fixture',
                            'GIT_COMMITTER_NAME': 'Synthetic Fixture', 'GIT_AUTHOR_EMAIL': EMAIL,
                            'GIT_COMMITTER_EMAIL': EMAIL}
        for key in ('GIT_DIR', 'GIT_COMMON_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
            self.environment.pop(key, None)
        scope = operation_log('test-package-metadata', self.root / 'logs')
        self.log = scope.__enter__()
        self.addCleanup(scope.__exit__, None, None, None)
        self.log.info('running test=%s; disposable repository only', self._testMethodName)
        self.addCleanup(unittest.mock.patch.stopall)
        unittest.mock.patch.dict(os.environ, self.environment, clear=True).start()
        self.git('init', '--quiet')
        self.git('symbolic-ref', 'HEAD', 'refs/heads/main')
        self.skill = self.checkout / 'skills' / 'revayat-scientific'
        self.skill.mkdir(parents=True)
        (self.skill / 'SKILL.md').write_bytes(b'# Untouched synthetic instructions\n')
        self.git('add', 'skills')
        self.git('commit', '--quiet', '-m', 'Synthetic fixture, never published')

    def git(self, *args, cwd=None):
        result = subprocess.run(['git', *args], cwd=cwd or self.checkout,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        return result.stdout.decode('utf-8').strip()

    def package(self, destination, checkout=None):
        checkout = checkout or self.checkout
        with unittest.mock.patch.object(PACKAGE, 'ROOT', checkout), \
                unittest.mock.patch.object(PACKAGE.installer, 'SOURCE', checkout / 'skills' / 'revayat-scientific'), \
                unittest.mock.patch.object(sys, 'argv', ['package.py', '--output', str(destination)]):
            return PACKAGE.main()

    def assert_refused_unchanged(self, destination, checkout=None):
        before = destination.read_bytes() if destination.exists() else None
        with self.assertRaises(ValueError):
            self.package(destination, checkout)
        self.assertEqual(destination.read_bytes() if destination.exists() else None, before)
        self.assertFalse(list(destination.parent.glob('.revayat-package-*')))
        self.assertFalse(list(destination.parent.glob('.revayat-publish-*')))

    def test_index_config_head_and_refs_remain_byte_exact(self):
        for name in ('index', 'config', 'HEAD', 'refs/heads/main'):
            with self.subTest(name=name):
                self.assert_refused_unchanged(self.checkout / '.git' / name)
        self.assertTrue(self.git('status', '--porcelain', '--untracked-files=no').strip() == '')

    def test_new_files_inside_git_objects_or_logs_are_refused(self):
        for name in ('objects/new.skill', 'logs/new.skill', 'hooks/new.skill'):
            with self.subTest(name=name):
                self.assert_refused_unchanged(self.checkout / '.git' / name)

    def test_linked_worktree_gitfile_and_private_admin_directory_are_protected(self):
        linked = self.root / 'linked worktree'
        self.git('worktree', 'add', '--quiet', '-b', 'synthetic-linked', str(linked))
        admin = Path(self.git('rev-parse', '--absolute-git-dir', cwd=linked))
        self.assertTrue((linked / '.git').is_file())
        for path in (linked / '.git', admin / 'HEAD', admin / 'index', admin / 'new.skill'):
            with self.subTest(path=path.name):
                self.assert_refused_unchanged(path, linked)
        self.git('status', '--porcelain', cwd=linked)

    def test_worktree_shared_common_directory_is_protected(self):
        linked = self.root / 'linked'
        self.git('worktree', 'add', '--quiet', '-b', 'synthetic-common', str(linked))
        for name in ('config', 'refs/heads/main', 'objects/new.skill'):
            with self.subTest(name=name):
                self.assert_refused_unchanged(self.checkout / '.git' / name, linked)

    def test_external_separate_git_directory_is_protected(self):
        relocated = self.root / 'private repository metadata'
        self.git('init', '--quiet', '--separate-git-dir', str(relocated))
        self.assertTrue((self.checkout / '.git').is_file())
        for path in (relocated / 'index', relocated / 'config', relocated / 'new.skill'):
            with self.subTest(path=path.name):
                self.assert_refused_unchanged(path)
        self.git('status', '--porcelain')

    def test_environment_selected_index_is_not_an_output(self):
        index = self.root / 'alternate-index'
        index.write_bytes((self.checkout / '.git/index').read_bytes())
        with unittest.mock.patch.dict(os.environ, {'GIT_INDEX_FILE': str(index)}):
            self.assert_refused_unchanged(index)
        self.git('status', '--porcelain')

    def test_hardlinked_critical_metadata_is_not_a_package_destination(self):
        for name in ('index', 'config', 'HEAD'):
            with self.subTest(name=name):
                original = self.checkout / '.git' / name
                alias = self.root / (name + '.skill')
                os.link(original, alias)
                self.assert_refused_unchanged(alias)
                self.assertTrue(os.path.samefile(original, alias))

    def test_valid_output_does_not_require_mutating_repository_metadata(self):
        index = self.checkout / '.git/index'
        before = index.read_bytes()
        for output in (self.checkout / 'dist/result.skill', self.root / 'outside.skill'):
            self.assertEqual(self.package(output), 0)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.read('revayat-scientific/SKILL.md'),
                                 (self.skill / 'SKILL.md').read_bytes())
        self.assertEqual(index.read_bytes(), before)
        self.git('status', '--porcelain')

    def test_exported_source_with_no_git_metadata_remains_packagable(self):
        exported = self.root / 'exported'
        skill = exported / 'skills' / 'revayat-scientific'
        skill.mkdir(parents=True)
        (skill / 'SKILL.md').write_bytes(b'# Exported instructions\n')
        output = exported / 'dist/export.skill'
        self.assertEqual(self.package(output, exported), 0)
        self.assertTrue(zipfile.is_zipfile(output))
        self.assertFalse((exported / '.git').exists())

    def test_dotgithub_and_similarly_named_outputs_are_not_metadata(self):
        for path in (self.checkout / '.github' / 'artifact.skill', self.root / '.git-notes.skill'):
            self.assertEqual(self.package(path), 0)
            self.assertTrue(zipfile.is_zipfile(path))

    def test_metadata_discovery_failure_preserves_previous_delivery(self):
        output = self.root / 'approved.skill'
        output.write_bytes(b'previous approved package')
        native = PACKAGE.subprocess.run
        def guarded(args, **kwargs):
            if 'rev-parse' in args:
                return subprocess.CompletedProcess(args, 1, b'', b'synthetic diagnostic')
            return native(args, **kwargs)
        with unittest.mock.patch.object(PACKAGE.subprocess, 'run', side_effect=guarded):
            self.assert_refused_unchanged(output)

    def test_vendored_source_uses_the_parent_repository_admin_directory(self):
        nested = self.checkout / 'components' / 'scientific'
        source = nested / 'skills' / 'revayat-scientific'
        source.mkdir(parents=True)
        (source / 'SKILL.md').write_bytes(b'# Nested source\n')
        external = self.root / 'external metadata'
        self.git('init', '--quiet', '--separate-git-dir', str(external))
        self.assert_refused_unchanged(external / 'index', nested)
        self.assertEqual(self.package(nested / 'dist/result.skill', nested), 0)

    def test_redirected_object_database_is_protected(self):
        objects = self.root / 'object-database'
        objects.mkdir()
        target = objects / 'synthetic-object'
        target.write_bytes(b'untouched object sentinel')
        with unittest.mock.patch.dict(os.environ, {'GIT_OBJECT_DIRECTORY': str(objects)}):
            self.assert_refused_unchanged(target)

    def test_configured_external_hooks_directory_is_protected(self):
        hooks = self.root / 'owner hooks'
        hooks.mkdir()
        target = hooks / 'pre-commit'
        target.write_bytes(b'untouched hook sentinel')
        self.git('config', 'core.hooksPath', str(hooks))
        self.assert_refused_unchanged(target)

    def test_explicit_repository_environment_without_a_dotgit_marker_is_respected(self):
        exported = self.root / 'no marker'
        skill = exported / 'skills' / 'revayat-scientific'
        skill.mkdir(parents=True)
        (skill / 'SKILL.md').write_bytes(b'# Explicit repository context\n')
        external = self.root / 'external metadata'
        self.git('init', '--quiet', '--separate-git-dir', str(external))
        with unittest.mock.patch.dict(os.environ, {'GIT_DIR': str(external), 'GIT_WORK_TREE': str(self.checkout)}):
            self.assert_refused_unchanged(external / 'config', exported)

    def test_ambiguous_admin_paths_fail_without_publishing(self):
        output = self.root / 'approved.skill'
        output.write_bytes(b'previous approved package')
        native = PACKAGE.subprocess.run
        for result_bytes in (b'relative\nrelative\nindex\n', b'\n', b'/one\n/two\n', b'\xff'):
            def guarded(args, **kwargs):
                if 'rev-parse' in args:
                    return subprocess.CompletedProcess(args, 0, result_bytes, b'')
                return native(args, **kwargs)
            with self.subTest(result=result_bytes), unittest.mock.patch.object(PACKAGE.subprocess, 'run', side_effect=guarded):
                self.assert_refused_unchanged(output)

    def test_index_relocation_during_staging_is_rechecked(self):
        output = self.root / 'approved.skill'
        output.write_bytes(b'previous approved package')
        native_write = zipfile.ZipFile.write
        def write_then_relocate(archive, *args, **kwargs):
            result = native_write(archive, *args, **kwargs)
            os.environ['GIT_INDEX_FILE'] = str(output)
            return result
        with unittest.mock.patch.dict(os.environ), unittest.mock.patch.object(zipfile.ZipFile, 'write', write_then_relocate):
            self.assert_refused_unchanged(output)

    def test_external_index_shared_storage_and_hardlink_remain_unchanged(self):
        external = self.root / 'external indexes'
        external.mkdir()
        index = external / 'index'
        index.write_bytes((self.checkout / '.git/index').read_bytes())
        with unittest.mock.patch.dict(os.environ, {'GIT_INDEX_FILE': str(index)}):
            self.git('update-index', '--split-index')
            shared = Path(self.git('rev-parse', '--path-format=absolute', '--shared-index-path'))
            self.assertTrue(shared.is_file())
            before = shared.read_bytes()
            self.assert_refused_unchanged(shared)
            alias = self.root / 'shared-alias.skill'
            os.link(shared, alias)
            self.assert_refused_unchanged(alias)
            self.assertEqual(shared.read_bytes(), before)
            self.git('status', '--porcelain', '--untracked-files=no')

    def test_reserved_case_variant_git_component_is_refused(self):
        output = self.root / '.GIT' / 'index'
        output.parent.mkdir()
        output.write_bytes(b'protected metadata sentinel')
        self.assert_refused_unchanged(output)


if __name__ == '__main__':
    unittest.main()
