"""Keep current workflow syntax visible to both pinned CI linters."""
import importlib.util
import io
import textwrap
from types import SimpleNamespace
from pathlib import Path
import subprocess
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('workflow_lint', ROOT / 'tools/check-workflows.py')
LINT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINT)


class WorkflowLintTest(unittest.TestCase):
    def test_only_three_literal_job_references_change_in_memory(self):
        original = (ROOT / '.github/workflows/ci.yml').read_bytes().decode('utf-8')
        translated = LINT.actionlint_source('.github/workflows/ci.yml', original)
        differences = [(a, b) for a, b in zip(original, translated) if a != b]
        self.assertEqual(differences, [('$', '.'), ('$', '.'), ('$', '.')])
        self.assertEqual(len(original), len(translated))
        self.assertIn('uses: ./.github/workflows/security-ci.yml', translated)
        self.assertIn('uses: ./.github/workflows/codeql.yml', translated)
        self.assertIn('uses: ./.github/workflows/dependency-review.yml', translated)
        self.assertIn('base_ref: ${{ inputs.base_ref }}', translated)
        self.assertEqual((ROOT / '.github/workflows/ci.yml').read_bytes().decode('utf-8'), original)
        crlf = original.replace('\n', '\r\n')
        self.assertEqual(LINT.actionlint_source('.github/workflows/ci.yml', crlf), translated.replace('\n', '\r\n'))

    def test_unsupported_references_never_disappear_from_validation(self):
        original = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        for altered in (
            original.replace('security-ci.yml', 'security-ci.yml@main', 1),
            original.replace('  security:\n', '  other:\n', 1),
            original.replace('    uses: $/.github/workflows/security-ci.yml',
                             '    uses: $/.github/workflows/missing.yml', 1),
            original + '\n# unsupported $/ syntax\n',
        ):
            with self.subTest(source=altered[-50:]):
                with self.assertRaises(ValueError):
                    LINT.actionlint_source('.github/workflows/ci.yml', altered)
        with self.assertRaises(ValueError):
            LINT.actionlint_source('.github/workflows/codeql.yml', original)
        ordinary = 'name: plain\non: workflow_dispatch\njobs: {}\n'
        self.assertEqual(LINT.actionlint_source('.github/workflows/codeql.yml', ordinary), ordinary)

    def test_windows_browser_selection_uses_paired_managed_binary(self):
        source = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        step = source.split('      - name: Select managed Windows browser\n', 1)[1].split('      - name:', 1)[0]
        self.assertIn("if: runner.os == 'Windows'", step)
        body = textwrap.dedent(step.split('        run: |\n', 1)[1])
        self.assertIn('run: python -m playwright install --no-shell chromium', source)
        self.assertIn('run: python -m playwright install --with-deps chromium', source)
        self.assertLess(source.index('name: Install controlled Windows browser'), source.index('name: Select managed Windows browser'))
        self.assertNotIn('windows-browser.outputs', source)
        self.assertIn('timeout-minutes: 10', source)
        for present in (True, False):
            with self.subTest(present=present):
                output = io.StringIO()
                opened = []
                selected = 'managed/chromium.exe'

                def open_output(name, mode, *, encoding):
                    self.assertEqual((name, mode, encoding), ('env', 'a', 'utf-8'))
                    opened.append(name)
                    return mock.MagicMock(__enter__=mock.Mock(return_value=output),
                                          __exit__=mock.Mock(return_value=False))

                manager = mock.MagicMock()
                manager.__enter__.return_value.chromium.executable_path = selected
                modules = {'os': SimpleNamespace(environ={'GITHUB_ENV': 'env'}),
                           'pathlib': SimpleNamespace(Path=lambda path: SimpleNamespace(is_file=lambda: present)),
                           'playwright.sync_api': SimpleNamespace(sync_playwright=lambda: manager)}
                with mock.patch.dict('sys.modules', modules):
                    if present:
                        exec(compile(body, '<windows-browser-selection>', 'exec'), {'open': open_output})
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'managed Chromium'):
                            exec(compile(body, '<windows-browser-selection>', 'exec'), {'open': open_output})
                self.assertEqual(output.getvalue(), 'REVAYAT_CHROMIUM=' + selected + '\n' if present else '')
                self.assertEqual(opened, ['env'] if present else [])

    @unittest.skipUnless(__import__('shutil').which('actionlint'), 'actual actionlint is required in the quality CI job')
    def test_actual_callee_contract_still_rejects_missing_input(self):
        original = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        translated = LINT.actionlint_source('.github/workflows/ci.yml', original)
        result = subprocess.run(['actionlint', '-stdin-filename', '.github/workflows/ci.yml', '-'],
                                input=translated.replace('      base_ref: ${{ inputs.base_ref }}\n', ''),
                                text=True, encoding='utf-8', capture_output=True, cwd=ROOT, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('input "base_ref" is required', result.stdout + result.stderr)

    def test_original_filename_and_failed_linter_exit_are_preserved(self):
        with mock.patch.object(LINT.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)) as run:
            self.assertEqual(LINT.lint_one('.github/workflows/ci.yml'), 7)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['actionlint', '-stdin-filename', '.github/workflows/ci.yml', '-'])
        self.assertEqual(kwargs['cwd'], ROOT)
        self.assertEqual(kwargs['encoding'], 'utf-8')
        self.assertEqual(kwargs['timeout'], 30)
        self.assertFalse(kwargs['check'])
        self.assertIn('uses: ./.github/workflows/security-ci.yml', kwargs['input'])


if __name__ == '__main__':
    unittest.main()
