"""A TeX renderer cannot certify a different source revision from its staged copy."""
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import pymupdf

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log

spec = importlib.util.spec_from_file_location('tex_snapshot_controller', SCRIPTS / 'tex-container.py')
TEX = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TEX)


class TexInputSnapshotTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch, prefix='tex snapshot ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'doc.tex'
        self.child = self.root / 'child.tex'
        self.image = self.root / 'image.png'
        self.font = self.root / 'fonts' / 'synthetic.ttf'
        self.font.parent.mkdir()
        self.source.write_bytes(br'\documentclass{article}\begin{document}\input{child}\includegraphics{image.png}\end{document}')
        self.child.write_bytes(b'Original checked source revision\n')
        # The controlled backend does not decode these assets. It verifies copy identity.
        self.image.write_bytes(b'Synthetic image input')
        self.font.write_bytes(b'Synthetic font input')
        self.output = self.root / 'result.pdf'
        self.output.write_bytes(b'previous approved output')
        self.scope = operation_log('test-tex-snapshot', self.root / 'logs')
        self.log = self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)
        patches = [mock.patch.dict(os.environ, {'REVAYAT_TEX_OWNER_DIR': '', 'REVAYAT_TEX_OWNER_TOKEN': ''}),
                   mock.patch.object(TEX, 'runtime_config', return_value={
                       'base': ['docker'], 'kind': 'docker', 'image': 'sha256:' + 'a' * 64}),
                   mock.patch.object(TEX, 'cleanup')]
        self.cleanup = None
        for patch in patches:
            value = patch.start()
            self.addCleanup(patch.stop)
            self.cleanup = value

    def backend(self, mutate=None, validate=True):
        def render(arguments, logger, timeout):
            stage = Path(arguments[arguments.index('--cidfile') + 1]).parent
            if validate:
                for path in (self.source, self.child, self.image, self.font):
                    self.assertEqual((stage / 'input' / path.relative_to(self.root)).read_bytes(), path.read_bytes())
            with pymupdf.open() as document:
                document.new_page(width=210, height=300).insert_text((20, 35), 'Staged revision')
                document.save(stage / 'output' / 'document.pdf')
            if mutate is not None:
                mutate()
            return 0, ''
        return render

    def test_each_consumed_input_changed_during_render_preserves_the_previous_delivery(self):
        for path in (self.source, self.child, self.image, self.font):
            with self.subTest(input=path.name):
                before = path.read_bytes()
                changed = before + b' concurrent user edit'
                try:
                    with mock.patch.object(TEX, 'call', side_effect=self.backend(lambda: path.write_bytes(changed))):
                        with self.assertRaisesRegex(ValueError, 'changed'):
                            TEX.compile_document(self.source, self.output, self.log)
                    self.assertEqual(path.read_bytes(), changed)
                    self.assertEqual(self.output.read_bytes(), b'previous approved output')
                    self.assertFalse(list(self.root.glob('.revayat-tex-*')))
                finally:
                    path.write_bytes(before)
        self.assertEqual(self.cleanup.call_count, 4)

    def test_removed_input_after_staging_is_not_certified_as_the_current_source(self):
        with mock.patch.object(TEX, 'call', side_effect=self.backend(self.child.unlink)):
            with self.assertRaises(ValueError):
                TEX.compile_document(self.source, self.output, self.log)
        self.assertFalse(self.child.exists())
        self.assertEqual(self.output.read_bytes(), b'previous approved output')
        self.cleanup.assert_called_once()
        self.assertFalse(list(self.root.glob('.revayat-tex-*')))

    def test_copy_time_source_change_refuses_before_starting_the_backend(self):
        copy = shutil.copyfile
        changed = b'new user source after staging'
        def copying(source, destination, *args, **kwargs):
            result = copy(source, destination, *args, **kwargs)
            if Path(source) == self.child:
                self.child.write_bytes(changed)
            return result
        with mock.patch.object(TEX.shutil, 'copyfile', side_effect=copying), mock.patch.object(TEX, 'call', side_effect=self.backend(validate=False)) as run:
            with self.assertRaisesRegex(ValueError, 'changed'):
                TEX.compile_document(self.source, self.output, self.log)
        run.assert_not_called()
        self.cleanup.assert_not_called()
        self.assertEqual(self.child.read_bytes(), changed)
        self.assertEqual(self.output.read_bytes(), b'previous approved output')
        self.assertFalse(list(self.root.glob('.revayat-tex-*')))

    def test_unchanged_source_and_all_copied_resources_publish_without_mutation(self):
        originals = {path: path.read_bytes() for path in (self.source, self.child, self.image, self.font)}
        with mock.patch.object(TEX, 'call', side_effect=self.backend()):
            TEX.compile_document(self.source, self.output, self.log)
        with pymupdf.open(self.output) as document:
            self.assertIn('Staged revision', document[0].get_text())
        for path, data in originals.items():
            self.assertEqual(path.read_bytes(), data)
        self.cleanup.assert_called_once()
        self.assertFalse(list(self.root.glob('.revayat-tex-*')))

    def test_guard_binds_sidecars_not_passed_to_the_tex_engine(self):
        import build_guard
        terms, manifest = self.root / 'terms.tsv', self.root / 'manifest.txt'
        terms.write_bytes(b'source\toutput\n')
        manifest.write_bytes(b'image.png\n')
        record = self.root / 'build.json'
        delivered = self.root / 'delivered.pdf'
        build_guard.create_guard(record, self.source, self.output, delivered, terms=terms, manifest=manifest)
        with mock.patch.object(TEX, 'call', side_effect=self.backend(lambda: terms.write_bytes(b'changed decisions'))):
            with self.assertRaisesRegex(ValueError, 'changed'):
                TEX.compile_document(self.source, self.output, self.log, build_guard=record)
        self.assertEqual(self.output.read_bytes(), b'previous approved output')
        self.assertFalse(delivered.exists())
        self.assertEqual(terms.read_bytes(), b'changed decisions')
        self.cleanup.assert_called_once()

    def test_guard_admits_copied_font_and_seals_exact_pdf(self):
        import build_guard
        terms, manifest = self.root / 'terms.tsv', self.root / 'manifest.txt'
        terms.write_bytes(b'source\toutput\n')
        manifest.write_bytes(b'image.png\n')
        record = self.root / 'build.json'
        build_guard.create_guard(record, self.source, self.output, self.root / 'delivered.pdf', terms=terms, manifest=manifest)
        with mock.patch.object(TEX, 'call', side_effect=self.backend()):
            TEX.compile_document(self.source, self.output, self.log, build_guard=record)
        snapshot = build_guard.check_guard(record)
        self.assertIn(str(self.font), snapshot['inputs'])
        self.assertEqual(snapshot['rendered'], {str(self.output): build_guard.file_hash(self.output)})
        self.font.write_bytes(b'changed font after compilation')
        with self.assertRaisesRegex(ValueError, 'changed'):
            build_guard.check_guard(record)


if __name__ == '__main__':
    unittest.main()
