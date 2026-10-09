"""POSIX browser discovery transports an actual executable, not its command name."""
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from processes import run

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skills/revayat-scientific/scripts/build-pdf.sh'


class BrowserDiscoveryTest(unittest.TestCase):
    def test_path_browser_is_a_resolved_executable(self):
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('requires Bash')
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='browser discovery ', dir=scratch) as directory:
            root = Path(directory).resolve()
            binary_dir = root / 'browser tools'
            binary_dir.mkdir()
            browser = binary_dir / 'google-chrome'
            browser.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            browser.chmod(0o755)
            source = SCRIPT.read_text(encoding='utf-8')
            function = source[source.index('find_chrome() {'):source.index('\navailable=""')]
            driver = root / 'discover.sh'
            driver.write_text(function + '\nfind_chrome\n', encoding='utf-8')
            environment = {'PATH': 'browser tools', 'REVAYAT_CHROMIUM': ''}
            result = run([bash, str(driver)], cwd=root, env=environment, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Git Bash reports POSIX paths; compare through the same shell's physical cwd.
            expected = run([bash, '-c', 'printf "%s/browser tools/google-chrome\\n" "$PWD"'],
                           cwd=root, timeout=10)
            self.assertEqual(result.stdout.strip(), expected.stdout.strip())
            invalid = run([bash, str(driver)], cwd=root,
                          env={**environment, 'REVAYAT_CHROMIUM': 'missing browser'}, timeout=10)
            self.assertNotEqual(invalid.returncode, 0)


    def test_selected_browser_survives_the_source_directory_change(self):
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('requires Bash')
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='browser cwd ', dir=scratch) as directory:
            root = Path(directory).resolve()
            binaries, source_dir = root / 'browser tools', root / 'source'
            binaries.mkdir()
            source_dir.mkdir()
            browser = binaries / 'google-chrome'
            browser.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            browser.chmod(0o755)
            text = SCRIPT.read_text(encoding='utf-8')
            functions = text[text.index('find_chrome() {'):text.index('\navailable=""')]
            discovery = text[text.index('available=""'):text.index('\npython3 -c \'from weasyprint')]
            launch = text[text.index('html_to_pdf() {'):text.index('\n_first_glob() {')]
            driver = root / 'flow.sh'
            driver.write_text(functions + '\nhave_xelatex() { return 1; }\n'
                              + 'python3() { if [[ $1 == -c ]]; then return 0; fi; '
                              + 'while [[ $# -gt 0 ]]; do if [[ $1 == --browser ]]; then printf "%s\\n" "$2"; return 0; fi; shift; done; }\n'
                              + 'log() { :; }\nwarn_html_copy_order() { :; }\n' + discovery + '\n' + launch
                              + '\nhere="";guard="";src="";rendered_pdf="";stem="doc";engine="chromium"\n'
                              + 'cd source\nhtml_to_pdf "$src" "$rendered_pdf"\n', encoding='utf-8')
            result = run([bash, str(driver)], cwd=root,
                         env={'PATH': 'browser tools', 'REVAYAT_CHROMIUM': ''}, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = run([bash, '-c', 'printf "%s/browser tools/google-chrome\\n" "$PWD"'], cwd=root, timeout=10)
            self.assertEqual(result.stdout.strip(), expected.stdout.strip())


if __name__ == '__main__':
    unittest.main()
