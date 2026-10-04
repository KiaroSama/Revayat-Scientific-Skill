"""Build stages must agree on the checked inputs and the bytes being delivered."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from PIL import Image
import pymupdf

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
import build_guard as guard
from runtime import operation_log


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPPORT = load('guarded_build_support', 'build-support.py')
HTML = load('guarded_html_renderer', 'render-html.py')


def pdf(path):
    with pymupdf.open() as document:
        document.new_page(width=220, height=330).insert_text((20, 30), 'Synthetic output')
        document.save(path)


class BuildGuardTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch, prefix='build guard ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.private = self.root / 'private'
        self.private.mkdir()
        self.record = self.private / 'build.json'
        self.source, self.terms, self.manifest = (self.root / name for name in ('doc.html', 'terms.tsv', 'manifest.txt'))
        self.asset = self.root / 'figure.png'
        Image.new('RGB', (24, 24), 'white').save(self.asset)
        self.source.write_bytes(b'<html lang="fa" dir="rtl"><body><img dir="ltr" src="figure.png"></body></html>')
        self.terms.write_bytes((ROOT / 'tests/fixtures/terms-empty.tsv').read_bytes())
        self.manifest.write_bytes(b'figure.png\n')
        self.working, self.output = self.root / 'work.pdf', self.root / 'delivered.pdf'
        self.samples = [self.root / ('verify-article-' + label + '.png') for label in ('first', 'last', 'mid')]
        self.output.write_bytes(b'previous approved delivery')
        self.working.write_bytes(b'previous working file')
        self.scope = operation_log('test-build-guard', self.private / 'logs')
        self.log = self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)

    def create(self, **changes):
        args = dict(source=self.source, working=self.working, output=self.output,
                    terms=self.terms, manifest=self.manifest, samples=self.samples)
        args.update(changes)
        return guard.create_guard(self.record, **args)

    def seal(self):
        pdf(self.working)
        guard.seal_rendered(self.record, self.working, guard.file_hash(self.working))

    def test_plan_captures_explicit_inputs_assets_and_requested_fallback(self):
        requested = self.root / 'original.tex'
        requested.write_bytes(b'Unused sibling; retained as a protected source.')
        result = self.create(requested=requested)
        self.assertEqual(set(result['inputs']), set(map(str, [self.source, self.asset, self.terms, self.manifest, requested])))
        self.assertEqual(guard.check_guard(self.record), result)
        self.assertEqual(len(result['outputs']), 5)

    def test_nested_tex_closure_is_captured_without_modifying_inputs(self):
        source, child = self.root / 'doc.tex', self.root / 'part.tex'
        source.write_bytes(b'\\input{part}\n\\includegraphics{figure.png}')
        child.write_bytes(b'Child without final newline')
        before = {path: path.read_bytes() for path in (source, child, self.asset)}
        result = self.create(source=source)
        self.assertTrue(set(map(str, before)) <= set(result['inputs']))
        self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_each_preview_collision_is_rejected_before_mutation(self):
        for sample in self.samples:
            with self.subTest(sample=sample.name):
                sample.write_bytes(self.asset.read_bytes())
                self.source.write_bytes(f'<html><img src="{sample.name}"></html>'.encode('utf-8'))
                before = sample.read_bytes()
                with self.assertRaisesRegex(ValueError, 'protected source'):
                    self.create()
                self.assertEqual(sample.read_bytes(), before)
                self.assertFalse(self.record.exists())

    def test_pdf_destinations_cannot_overwrite_sidecars_or_vector_assets(self):
        for field in ('terms', 'manifest', 'asset'):
            with self.subTest(field=field):
                path = self.root / 'reserved.pdf'
                if field == 'asset':
                    pdf(path)
                    self.source.write_bytes(b'<html><img src="reserved.pdf"></html>')
                    arguments = {}
                else:
                    path.write_bytes(getattr(self, field).read_bytes())
                    arguments = {field: path}
                before = path.read_bytes()
                with self.assertRaises(ValueError):
                    self.create(output=path, **arguments)
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse(self.record.exists())
                self.source.write_bytes(b'<html><img src="figure.png"></html>')

    def test_symlink_hardlink_and_duplicate_output_aliases_are_rejected(self):
        alias = self.root / 'alias.pdf'
        os.link(self.terms, alias)
        with self.assertRaises(ValueError):
            self.create(output=alias)
        self.assertTrue(os.path.samefile(alias, self.terms))
        alias.unlink()
        os.link(self.working, alias)
        with self.assertRaisesRegex(ValueError, 'alias'):
            self.create(output=alias)
        with self.assertRaises(ValueError):
            self.create(output=self.working)
        alias.unlink()
        try:
            alias.symlink_to(self.output)
        except OSError:
            self.log.warning('symlink capability unavailable; hardlink controls ran')
        else:
            with self.assertRaises(ValueError):
                self.create(output=alias)
            self.assertTrue(alias.is_symlink())

    def test_changes_to_each_checked_input_invalidate_the_run(self):
        self.create()
        for path in (self.source, self.terms, self.manifest, self.asset):
            with self.subTest(input=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b' changed')
                with self.assertRaisesRegex(ValueError, 'changed'):
                    guard.check_guard(self.record)
                path.write_bytes(original)
                guard.check_guard(self.record)
        self.assertEqual(self.output.read_bytes(), b'previous approved delivery')

    def test_actual_runtime_resource_is_added_and_then_frozen(self):
        self.create()
        css = self.root / 'style.css'
        css.write_bytes(b'body { color: black; }')
        result = guard.check_guard(self.record, {str(css): guard.file_hash(css)})
        self.assertIn(str(css), result['inputs'])
        css.write_bytes(b'body { color: red; }')
        with self.assertRaisesRegex(ValueError, 'changed'):
            guard.check_guard(self.record)

    def test_css_only_preview_dependency_is_not_a_publish_destination(self):
        self.create()
        self.samples[0].write_bytes(self.asset.read_bytes())
        before = self.record.read_bytes()
        with self.assertRaisesRegex(ValueError, 'protected source'):
            guard.check_guard(self.record, {str(self.samples[0]): guard.file_hash(self.samples[0])})
        self.assertEqual(self.record.read_bytes(), before)
        self.assertEqual(self.samples[0].read_bytes(), self.asset.read_bytes())

    def test_runtime_cannot_substitute_an_already_checked_revision(self):
        self.create()
        with self.assertRaisesRegex(ValueError, 'revision'):
            guard.check_guard(self.record, {str(self.source): '0' * 64})
        self.assertEqual(self.working.read_bytes(), b'previous working file')

    def test_rendered_hash_prevents_delivering_another_builds_working_pdf(self):
        self.create()
        self.seal()
        self.working.write_bytes(b'concurrent build output')
        with self.assertRaisesRegex(ValueError, 'changed'):
            SUPPORT.main(['publish', str(self.working), str(self.output), '--guard', str(self.record)])
        self.assertEqual(self.output.read_bytes(), b'previous approved delivery')

    def test_unsealed_or_wrong_target_delivery_cannot_pass(self):
        self.create()
        with self.assertRaises(ValueError):
            SUPPORT.main(['publish', str(self.working), str(self.output), '--guard', str(self.record)])
        self.seal()
        with self.assertRaises(ValueError):
            SUPPORT.main(['publish', str(self.working), str(self.root / 'other.pdf'), '--guard', str(self.record)])
        with self.assertRaises(ValueError):
            guard.seal_rendered(self.record, self.output, guard.file_hash(self.output))
        self.assertFalse((self.root / 'other.pdf').exists())
        self.assertEqual(self.output.read_bytes(), b'previous approved delivery')

    def test_valid_delivery_is_byte_equal_to_the_sealed_renderer_output(self):
        self.create()
        self.seal()
        original = self.source.read_bytes()
        self.assertEqual(SUPPORT.main(['publish', str(self.working), str(self.output), '--guard', str(self.record)]), 0)
        self.assertEqual(self.output.read_bytes(), self.working.read_bytes())
        self.assertEqual(self.source.read_bytes(), original)

    def test_invalid_record_duplicate_keys_and_oversized_maps_fail_explicitly(self):
        record = self.create()
        correct = self.record.read_bytes()
        for value in ([], {**record, 'schema': True}, {**record, 'inputs': []},
                      {**record, 'outputs': [{}, str(self.output)]},
                      {**record, 'rendered': {str(self.output): '0' * 64}}):
            self.record.write_text(json.dumps(value), encoding='utf-8')
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                guard.check_guard(self.record)
        self.record.write_bytes(b'{"schema":1,"schema":1}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            guard.load_guard(self.record)
        self.record.write_bytes(correct)
        with mock.patch.object(guard, 'MAX_RECORD_BYTES', 10), self.assertRaises(ValueError):
            guard.load_guard(self.record)
        with mock.patch.object(guard, 'MAX_FILES', 1), self.assertRaises(ValueError):
            guard.check_guard(self.record)

    def test_existing_pending_record_is_never_deleted_on_exclusive_create_failure(self):
        self.create()
        pending = self.record.with_name(self.record.name + '.pending')
        pending.write_bytes(b'another writer sentinel')
        css = self.root / 'new.css'
        css.write_bytes(b'body{}')
        before = self.record.read_bytes()
        with self.assertRaises(FileExistsError):
            guard.check_guard(self.record, {str(css): guard.file_hash(css)})
        self.assertEqual(pending.read_bytes(), b'another writer sentinel')
        self.assertEqual(self.record.read_bytes(), before)

    def test_missing_and_oversized_inputs_are_not_silently_fingerprinted(self):
        with mock.patch.object(guard, 'MAX_FILE_BYTES', 2), self.assertRaises(ValueError):
            self.create()
        self.assertFalse(self.record.exists())
        self.create()
        self.asset.unlink()
        with self.assertRaises(ValueError):
            guard.check_guard(self.record)

    def test_sample_batch_validates_every_png_before_replacing_any_preview(self):
        self.create()
        self.seal()
        for sample in self.samples:
            sample.write_bytes(b'previous preview')
        stages = [self.private / sample.name for sample in self.samples]
        Image.new('RGB', (30, 40), 'white').save(stages[0])
        stages[1].write_bytes(b'not a png')
        Image.new('RGB', (30, 40), 'white').save(stages[2])
        with self.assertRaises((OSError, ValueError)):
            SUPPORT.main(['samples', str(self.record), *map(str, stages)])
        for sample in self.samples:
            self.assertEqual(sample.read_bytes(), b'previous preview')

    def test_sample_publication_rolls_back_earlier_replacements(self):
        self.create()
        self.seal()
        stages = [self.private / sample.name for sample in self.samples]
        for sample, stage in zip(self.samples, stages):
            sample.write_bytes(b'previous preview')
            Image.new('RGB', (30, 40), 'white').save(stage)
        replace = os.replace
        def fail_late(source, destination):
            if Path(source) == stages[1]:
                raise OSError('injected second-preview failure')
            return replace(source, destination)
        with mock.patch('publication.os.replace', side_effect=fail_late), self.assertRaises(OSError):
            SUPPORT.main(['samples', str(self.record), *map(str, stages)])
        for sample in self.samples:
            self.assertEqual(sample.read_bytes(), b'previous preview')
        self.assertFalse(list(self.root.glob('.revayat-publish-*')))

    def test_sample_staging_cannot_consume_unplanned_or_outside_files(self):
        self.create()
        self.seal()
        source = self.root / self.samples[0].name
        Image.new('RGB', (30, 40), 'white').save(source)
        before = source.read_bytes()
        with self.assertRaises(ValueError):
            SUPPORT.main(['samples', str(self.record), str(source)])
        self.assertEqual(source.read_bytes(), before)
        unplanned = self.private / 'unplanned.png'
        unplanned.write_bytes(before)
        with self.assertRaises(ValueError):
            SUPPORT.main(['samples', str(self.record), str(unplanned)])
        self.assertEqual(unplanned.read_bytes(), before)

    def test_partial_preview_set_and_duplicate_basenames_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'basenames'):
            self.create(samples=[self.root / 'one.png', self.private / 'one.png'])
        self.assertFalse(self.record.exists())
        self.create()
        self.seal()
        stages = [self.private / sample.name for sample in self.samples]
        for stage in stages:
            Image.new('RGB', (30, 40), 'white').save(stage)
        for selected in (stages[:2], [stages[0], stages[0], stages[2]]):
            with self.assertRaisesRegex(ValueError, 'complete'):
                SUPPORT.main(['samples', str(self.record), *map(str, selected)])
        self.assertFalse(any(path.exists() for path in self.samples))

    def test_html_actual_resources_block_a_late_collision_before_working_pdf_publication(self):
        self.create()
        self.samples[0].write_bytes(self.asset.read_bytes())
        def worker(command, *unused):
            stage = Path(command[3])
            pdf(stage)
            stage.with_suffix('.resources.json').write_text(json.dumps({str(self.source): guard.file_hash(self.source),
                str(self.samples[0]): guard.file_hash(self.samples[0])}), encoding='utf-8')
            return 0
        with mock.patch.object(HTML, 'run_command', side_effect=worker), self.assertRaises(ValueError):
            HTML.main([str(self.source), str(self.working), '--engine', 'weasyprint', '--build-guard', str(self.record)])
        self.assertEqual(self.working.read_bytes(), b'previous working file')
        self.assertEqual(self.output.read_bytes(), b'previous approved delivery')
        self.assertFalse(list(self.root.glob('.revayat-render-*')))

    def test_html_worker_cannot_deliver_after_a_terminology_revision_change(self):
        self.create()
        def worker(command, *unused):
            stage = Path(command[3])
            pdf(stage)
            stage.with_suffix('.resources.json').write_text(json.dumps({str(self.source): guard.file_hash(self.source)}), encoding='utf-8')
            self.terms.write_bytes(b'New terminology revision')
            return 0
        with mock.patch.object(HTML, 'run_command', side_effect=worker), self.assertRaisesRegex(ValueError, 'changed'):
            HTML.main([str(self.source), str(self.working), '--engine', 'weasyprint', '--build-guard', str(self.record)])
        self.assertEqual(self.working.read_bytes(), b'previous working file')
        self.assertEqual(self.terms.read_bytes(), b'New terminology revision')

    def test_html_seals_successful_output_and_does_not_allow_guard_on_worker_path(self):
        self.create()
        def worker(command, *unused):
            stage = Path(command[3])
            pdf(stage)
            stage.with_suffix('.resources.json').write_text(json.dumps({str(self.source): guard.file_hash(self.source)}), encoding='utf-8')
            return 0
        command = [str(self.source), str(self.working), '--engine', 'weasyprint', '--build-guard', str(self.record)]
        with mock.patch.object(HTML, 'run_command', side_effect=worker):
            self.assertEqual(HTML.main(command), 0)
        self.assertEqual(guard.check_guard(self.record)['rendered'], {str(self.working): guard.file_hash(self.working)})
        with self.assertRaises(ValueError):
            HTML.main(command + ['--worker'])


if __name__ == '__main__':
    unittest.main()
