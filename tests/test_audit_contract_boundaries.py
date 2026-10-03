"""Adversarial public contracts: source closure, extraction, packages and history."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import pymupdf
from processes import run

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log
from tex_source import source_closure
import pdf_input


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PAGES = load('audit_pages_contract', SCRIPTS / 'extract-pdf-pages.py')
PDF = load('audit_pdf_contract', SCRIPTS / 'document-pdf.py')
PACKAGE = load('audit_package_contract', ROOT / 'tools/package.py')
IDENTITY = load('audit_identity_contract', ROOT / 'tools/check-commit-identity.py')


class ContractFixture(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='contract audit ', dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.scope = operation_log('test-contract-boundaries', self.root / 'logs')
        self.log = self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)


class IncludeTokenContractTest(ContractFixture):
    def closure(self, command, child='2.tex'):
        path = self.root / 'main.tex'
        (self.root / child).write_text('IncludedMarker\n', encoding='utf-8')
        path.write_text('Before\n' + command + '\nAfter', encoding='utf-8')
        return source_closure(path)

    def test_unseparated_digit_and_punctuation_filenames_are_included(self):
        for command, child in ((r'\input2', '2.tex'), (r'\input2.tex', '2.tex'),
                               (r'\input_figure', '_figure.tex'),
                               (r'\input-part', '-part.tex'),
                               (r'\input./2.tex', '2.tex')):
            with self.subTest(command=command):
                closure = self.closure(command, child)
                self.assertIn('IncludedMarker', closure.text)
                self.assertEqual(closure.location(closure.text.index('IncludedMarker')),
                                 (self.root / child, 1))
                self.assertEqual(closure.location(closure.text.index('After')),
                                 (self.root / 'main.tex', 3))

    def test_custom_control_words_do_not_become_includes(self):
        for name in ('inputenc', 'inputExtra', 'includegraphics', 'includeonlyExtra'):
            with self.subTest(name=name):
                closure = self.closure('\\' + name + '{missing}')
                self.assertEqual(closure.sources, (self.root / 'main.tex',))

    def test_unseparated_missing_cycle_and_root_escape_are_blocking(self):
        path = self.root / 'main.tex'
        outside = self.root.parent / (self.root.name + '-outside.tex')
        outside.write_text('Outside sentinel', encoding='utf-8')
        self.addCleanup(outside.unlink, missing_ok=True)
        for command in (r'\input3', r'\input_undefined',
                        '\\input../' + outside.name, r'\includeonly2'):
            with self.subTest(command=command):
                path.write_text(command, encoding='utf-8')
                with self.assertRaises(ValueError):
                    source_closure(path)
        (self.root / '2.tex').write_text(r'\input{main}', encoding='utf-8')
        path.write_text(r'\input2', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'cycle'):
            source_closure(path)

    def test_literal_comments_and_even_backslashes_stay_inert(self):
        for command in (r'\verb|\input2|', '% ' + r'\input2',
                        '\\\\input2', r'\begin{verbatim}\input2\end{verbatim}'):
            with self.subTest(command=command):
                closure = self.closure(command)
                self.assertEqual(closure.sources, (self.root / 'main.tex',))
                self.assertNotIn('IncludedMarker', closure.text)
        closure = self.closure('\\\\\\input2')
        self.assertIn('IncludedMarker', closure.text)
        self.assertIn('\\\\IncludedMarker', closure.text)

    def test_real_compiler_and_source_closure_agree_on_numeric_input(self):
        ready = shutil.which('xelatex') and shutil.which('pdftotext')
        if not ready:
            if os.environ.get('SCIENTIFIC_REQUIRE_TEX_BOUNDARY') == '1':
                self.fail('required native contract needs XeLaTeX and Poppler')
            self.skipTest('native TeX tier')
        self.closure(r'\input2')
        path = self.root / 'main.tex'
        path.write_text(r'\documentclass{article}\begin{document}\input2 '
                        r'\end{document}', encoding='utf-8')
        result = run(['xelatex', '-no-shell-escape', '-halt-on-error',
                      '-interaction=nonstopmode', path.name], cwd=self.root, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout)
        extracted = run(['pdftotext', str(path.with_suffix('.pdf')), '-'], timeout=15)
        self.assertEqual(extracted.returncode, 0, extracted.stderr)
        self.assertIn('IncludedMarker', extracted.stdout)
        self.assertIn('IncludedMarker', source_closure(path).text)


class ExtractionAdmissionTest(ContractFixture):
    def fixture(self, kind='ordinary'):
        source = self.root / 'source.pdf'
        with pymupdf.open() as document:
            for index in range(3):
                page = document.new_page(width=250 + index * 20, height=400)
                page.insert_text((30, 50), 'Page ' + str(index + 1))
            if kind == 'signature-field':
                page = document[0]
                widget = pymupdf.Widget()
                widget.field_name = 'UnsignedSignature'
                widget.field_type = pymupdf.PDF_WIDGET_TYPE_SIGNATURE
                widget.rect = pymupdf.Rect(20, 100, 180, 130)
                page.add_widget(widget)
            elif kind == 'signature-dictionary':
                signature = document.get_new_xref()
                document.update_object(signature, '<< /Type /Sig /ByteRange [0 10 20 30] >>')
                document.xref_set_key(document.pdf_catalog(), 'Perms',
                                      f'<< /DocMDP {signature} 0 R >>')
            elif kind == 'xfa':
                document.xref_set_key(document.pdf_catalog(), 'AcroForm',
                                      '<< /XFA (Synthetic unsupported form) >>')
            kwargs = ({'encryption': pymupdf.PDF_ENCRYPT_AES_256,
                       'owner_pw': 'synthetic-owner', 'user_pw': ''}
                      if kind == 'empty-password-encryption' else {})
            document.save(source, **kwargs)
        if kind == 'repaired':
            # Strip only the xref/trailer so MuPDF can repair intact page objects.
            source.write_bytes(source.read_bytes().split(b'\nxref\n', 1)[0] + b'\n%%EOF\n')
            with pymupdf.open(source) as check:
                self.assertTrue(check.is_repaired)
        return source

    def test_all_transforms_use_the_same_encryption_signature_xfa_admission(self):
        for kind in ('empty-password-encryption', 'signature-field', 'signature-dictionary', 'xfa'):
            with self.subTest(kind=kind):
                source = self.fixture(kind)
                before = source.read_bytes()
                target = self.root / 'old.pdf'
                target.write_bytes(b'previous approved delivery')
                with self.assertRaises(ValueError):
                    with PDF.open_pdf(source, transform=True):
                        pass
                with self.assertRaises(ValueError):
                    PAGES.main([str(source), str(target), '1-2'])
                self.assertEqual(target.read_bytes(), b'previous approved delivery')
                self.assertEqual(source.read_bytes(), before)

    def test_parser_repaired_source_is_not_silently_certified(self):
        source = self.fixture('repaired')
        target = self.root / 'output.pdf'
        target.write_bytes(b'previous approved delivery')
        with self.assertRaises(ValueError):
            PAGES.main([str(source), str(target), '1'])
        self.assertEqual(target.read_bytes(), b'previous approved delivery')

    def test_valid_contiguous_range_keeps_geometry_pixels_and_shared_resources(self):
        source = self.fixture()
        target = self.root / 'output.pdf'
        before = source.read_bytes()
        self.assertEqual(PAGES.main([str(source), str(target), '2-3']), 0)
        with pymupdf.open(source) as original, pymupdf.open(target) as selected:
            self.assertEqual(selected.page_count, 2)
            for index in range(2):
                self.assertEqual(selected[index].rect, original[index + 1].rect)
                self.assertEqual(selected[index].get_pixmap().samples,
                                 original[index + 1].get_pixmap().samples)
                self.assertEqual(selected[index].get_text(), original[index + 1].get_text())
        self.assertEqual(source.read_bytes(), before)

    def test_late_write_failure_preserves_existing_output(self):
        source = self.fixture()
        target = self.root / 'old.pdf'
        target.write_bytes(b'previous approved delivery')
        with mock.patch('publication.os.replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                PAGES.main([str(source), str(target), '1'])
        self.assertEqual(target.read_bytes(), b'previous approved delivery')
        self.assertFalse(list(self.root.glob('.revayat-*')))


    def test_admission_limits_apply_before_publication(self):
        source = self.fixture()
        target = self.root / 'old.pdf'
        target.write_bytes(b'previous approved delivery')
        for name, value in (('MAX_PDF_BYTES', 1), ('MAX_PDF_PAGES', 2), ('MAX_PDF_OBJECTS', 1)):
            with self.subTest(limit=name), mock.patch.object(pdf_input, name, value):
                with self.assertRaises(ValueError):
                    PAGES.main([str(source), str(target), '1'])
            self.assertEqual(target.read_bytes(), b'previous approved delivery')
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_memory_mode_and_ordinary_nontransform_inspection_remain_supported(self):
        source = self.fixture('signature-field')
        with pdf_input.open_pdf(source, memory=True) as document:
            self.assertEqual(document.page_count, 3)
        with self.assertRaises(ValueError):
            with pdf_input.open_pdf(source, transform=True, memory=True):
                pass

    def test_public_pages_command_refuses_restricted_input(self):
        source = self.fixture('empty-password-encryption')
        before = source.read_bytes()
        target = self.root / 'old.pdf'
        target.write_bytes(b'previous approved delivery')
        result = run([sys.executable, str(SCRIPTS / 'revayat-scientific.py'),
                      'pages', str(source), str(target), '1'], timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('wrote ', result.stdout)
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(target.read_bytes(), b'previous approved delivery')

    def test_shared_resource_identity_and_full_page_boxes_survive(self):
        source = self.root / 'source.pdf'
        with pymupdf.open() as original:
            pixmap = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 20, 20), False)
            pixmap.clear_with(150)
            image_xref = 0
            for rotation in (0, 90, 180):
                page = original.new_page(width=250, height=400)
                page.set_cropbox(pymupdf.Rect(10, 20, 240, 380))
                page.set_trimbox(pymupdf.Rect(15, 25, 235, 375))
                page.set_bleedbox(pymupdf.Rect(12, 22, 238, 378))
                image_xref = page.insert_image((30, 40, 100, 110),
                                              xref=image_xref, pixmap=pixmap)
                page.set_rotation(rotation)
            original.save(source)
        target = self.root / 'selected.pdf'
        self.assertEqual(PAGES.main([str(source), str(target), '1-3']), 0)
        with pymupdf.open(source) as original, pymupdf.open(target) as selected:
            self.assertEqual(len({page.get_images()[0][0] for page in selected}), 1)
            for before, after in zip(original, selected):
                for attr in ('rect', 'mediabox', 'cropbox', 'trimbox', 'bleedbox', 'rotation'):
                    self.assertEqual(getattr(before, attr), getattr(after, attr), attr)
                self.assertEqual(before.get_pixmap().samples, after.get_pixmap().samples)


class PackageOutputContractTest(ContractFixture):
    def setUp(self):
        super().setUp()
        self.distribution = self.root / 'source-skill'
        self.distribution.mkdir()
        (self.distribution / 'SKILL.md').write_text('Original instructions', encoding='utf-8')
        (self.distribution / 'scripts').mkdir()
        (self.distribution / 'scripts' / 'helper.py').write_text('pass\n', encoding='utf-8')
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(PACKAGE.installer, 'SOURCE', self.distribution).start()

    def package(self, path):
        with mock.patch.object(sys, 'argv', ['package.py', '--output', str(path)]):
            return PACKAGE.main()

    def test_output_cannot_overwrite_distributed_source(self):
        for name in ('SKILL.md', 'scripts/helper.py'):
            with self.subTest(name=name):
                source = self.distribution / name
                original = source.read_bytes()
                with self.assertRaises(ValueError):
                    self.package(source)
                self.assertEqual(source.read_bytes(), original)

    def test_output_symlink_cannot_replace_or_follow_another_file(self):
        target = self.root / 'retained.txt'
        target.write_bytes(b'keep this document')
        link = self.root / 'package.skill'
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest('symlink capability unavailable')
        with self.assertRaises(ValueError):
            self.package(link)
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_bytes(), b'keep this document')

    def test_hardlink_alias_of_source_is_refused(self):
        source = self.distribution / 'SKILL.md'
        alias = self.root / 'package.skill'
        os.link(source, alias)
        before = source.read_bytes()
        with self.assertRaises(ValueError):
            self.package(alias)
        self.assertTrue(os.path.samefile(source, alias))
        self.assertEqual(source.read_bytes(), before)

    def test_case_variant_and_directory_destinations_fail_without_side_effects(self):
        existing = self.root / 'Package.skill'
        existing.write_bytes(b'previous approved package')
        lower = self.root / 'package.skill'
        if existing != lower and not lower.exists():
            with self.assertRaises(ValueError):
                self.package(lower)
            self.assertFalse(lower.exists())
        directory = self.root / 'output-directory'
        directory.mkdir()
        with self.assertRaises(ValueError):
            self.package(directory)
        self.assertFalse(list(directory.iterdir()))
        self.assertEqual(existing.read_bytes(), b'previous approved package')

    def test_valid_archive_and_repeat_build_preserve_payload(self):
        output = self.root / 'dist' / 'result.skill'
        for _ in range(2):
            self.assertEqual(self.package(output), 0)
            with zipfile.ZipFile(output) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(archive.read('revayat-scientific/SKILL.md'), b'Original instructions')
                self.assertEqual(archive.read('revayat-scientific/scripts/helper.py'), b'pass\n')
        self.assertEqual((self.distribution / 'SKILL.md').read_bytes(), b'Original instructions')


    def test_tracked_nonpayload_document_is_protected(self):
        # A disposable checkout proves protection without risking real project files.
        readme = self.root / 'README.md'
        readme.write_bytes(b'untouched tracked documentation')
        for command in (['git', 'init', '--quiet'], ['git', 'add', 'README.md']):
            completed = subprocess.run(command, cwd=self.root, capture_output=True, timeout=15)
            self.assertEqual(completed.returncode, 0, completed.stderr)
        before = readme.read_bytes()
        with mock.patch.object(PACKAGE, 'ROOT', self.root):
            with self.assertRaises(ValueError):
                self.package(readme)
        self.assertEqual(readme.read_bytes(), before)

    def test_new_output_inside_implementation_directories_is_rejected(self):
        for output in (self.distribution / 'new-package.skill', ROOT / 'tools' / 'new-package.skill',
                       ROOT / 'install' / 'new-package.skill'):
            with self.subTest(output=output.name), self.assertRaises(ValueError):
                self.package(output)
            self.assertFalse(output.exists())

    def test_missing_skill_and_late_archive_failure_keep_previous_output(self):
        target = self.root / 'previous.skill'
        target.write_bytes(b'approved package')
        members = list(PACKAGE.installer.payload_files())
        with mock.patch.object(PACKAGE.installer, 'payload_files',
                               return_value=iter(item for item in members if item[1].name != 'SKILL.md')):
            with self.assertRaises(ValueError):
                self.package(target)
        self.assertEqual(target.read_bytes(), b'approved package')
        with mock.patch.object(zipfile.ZipFile, 'write', side_effect=OSError('injected archive failure')):
            with self.assertRaises(OSError):
                self.package(target)
        self.assertEqual(target.read_bytes(), b'approved package')
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_publication_failure_keeps_approved_archive(self):
        target = self.root / 'previous.skill'
        target.write_bytes(b'approved package')
        with mock.patch('publication.os.replace', side_effect=OSError('injected replace failure')):
            with self.assertRaises(OSError):
                self.package(target)
        self.assertEqual(target.read_bytes(), b'approved package')
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_unreadable_git_index_refuses_before_packaging(self):
        target = self.root / 'previous.skill'
        target.write_bytes(b'approved package')
        with mock.patch.object(PACKAGE.subprocess, 'run',
                               return_value=subprocess.CompletedProcess(['git'], 1, b'', b'failure')):
            with self.assertRaises(ValueError):
                self.package(target)
        self.assertEqual(target.read_bytes(), b'approved package')


class IdentityCompletenessTest(ContractFixture):
    def setUp(self):
        super().setUp()
        self.environment = {**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                            'GIT_AUTHOR_NAME': 'Synthetic Fixture', 'GIT_COMMITTER_NAME': 'Synthetic Fixture',
                            'GIT_AUTHOR_EMAIL': IDENTITY.APPROVED_EMAIL,
                            'GIT_COMMITTER_EMAIL': IDENTITY.APPROVED_EMAIL}
        self.git('init', '--quiet')

    def git(self, *args, **env):
        result = subprocess.run(['git', *args], cwd=self.root,
                                env={**self.environment, **env}, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, encoding='utf-8', timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def commit(self, email=None):
        self.git('commit', '--quiet', '--allow-empty', '-m', 'Synthetic nonpublished fixture',
                 GIT_AUTHOR_EMAIL=email or IDENTITY.APPROVED_EMAIL)
        return self.git('rev-parse', 'HEAD')

    def test_replacement_refs_cannot_hide_stored_author_identity(self):
        bad = self.commit('fixture-only@example.invalid')
        good = self.commit()
        self.git('replace', bad, good)
        # Replacement may also create an apparent cycle; raw object traversal must win.
        count, failures = IDENTITY.inspect_identities(self.root, bad)
        self.assertEqual((count, failures), (1, [(bad, ('author',))]))
        self.assertEqual(self.git('replace', '-l'), bad)

    def test_shallow_history_never_passes_as_complete_history(self):
        self.commit('fixture-only@example.invalid')
        self.commit()
        clone = self.root / 'shallow-clone'
        self.git('clone', '--quiet', '--depth', '1', self.root.as_uri(), str(clone))
        with self.assertRaisesRegex(ValueError, '[Ss]hallow|complete'):
            IDENTITY.inspect_identities(clone)

    def test_complete_history_and_introduced_range_remain_available(self):
        bad = self.commit('fixture-only@example.invalid')
        good = self.commit()
        self.assertEqual(IDENTITY.inspect_identities(self.root, good, bad), (1, []))
        self.assertEqual(IDENTITY.inspect_identities(self.root), (2, [(bad, ('author',))]))


    def test_legacy_grafts_cannot_hide_bad_ancestors(self):
        bad = self.commit('fixture-only@example.invalid')
        head = self.commit()
        grafts = self.root / '.git' / 'info' / 'grafts'
        grafts.write_text(head + '\n', encoding='utf-8')
        before = grafts.read_bytes()
        with self.assertRaisesRegex(ValueError, 'grafts'):
            IDENTITY.inspect_identities(self.root)
        self.assertEqual(grafts.read_bytes(), before)
        grafts.unlink()
        self.assertEqual(IDENTITY.inspect_identities(self.root), (2, [(bad, ('author',))]))

    def test_environment_selected_grafts_are_rejected_without_removal(self):
        self.commit('fixture-only@example.invalid')
        head = self.commit()
        grafts = self.root / 'custom-grafts'
        grafts.write_text(head + '\n', encoding='utf-8')
        with mock.patch.dict(os.environ, {'GIT_GRAFT_FILE': str(grafts)}):
            with self.assertRaisesRegex(ValueError, 'grafts'):
                IDENTITY.inspect_identities(self.root)
        self.assertEqual(grafts.read_text(encoding='utf-8'), head + '\n')

    def test_shallow_range_also_requires_complete_ancestry(self):
        self.commit('fixture-only@example.invalid')
        head = self.commit()
        clone = self.root / 'shallow-clone'
        self.git('clone', '--quiet', '--depth', '1', self.root.as_uri(), str(clone))
        with self.assertRaisesRegex(ValueError, '[Ss]hallow|complete'):
            IDENTITY.inspect_identities(clone, head, head)


if __name__ == '__main__':
    unittest.main()
