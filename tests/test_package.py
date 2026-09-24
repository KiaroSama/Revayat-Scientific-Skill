"""Portable behavior at the public installer, package and dispatcher seams."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

from processes import run as owned_run

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/revayat-scientific'


def run(*command, cwd=ROOT, timeout=30):
    return owned_run(command, timeout=timeout, cwd=cwd)


class PackageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / '.scratch').mkdir(exist_ok=True)

    def assert_native_document_commands(self, cli, project):
        import pymupdf
        content = project / 'محتوا.json'
        document = project / 'ترجمه.docx'
        report = project / 'docx-report.json'
        content.write_text(json.dumps({'language': 'fa-IR', 'rtl': True, 'sections': [{
            'width_mm': 160, 'height_mm': 240,
            'margins_mm': {'top': 15, 'bottom': 15, 'left': 15, 'right': 15},
            'blocks': [{'type': 'paragraph', 'text': 'این یک متن علمی فارسی است.'}]}]},
            ensure_ascii=False), encoding='utf-8')
        for arguments in (['docx', 'create', str(content), str(document)],
                          ['docx', 'inspect', str(document), '--output', str(report)]):
            result = run(sys.executable, str(cli), *arguments, cwd=project)
            self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(document) as package:
            self.assertIsNone(package.testzip())
            self.assertIn('متن علمی فارسی', package.read('word/document.xml').decode('utf-8'))
        metadata = json.loads(report.read_text(encoding='utf-8'))
        self.assertTrue(metadata['text_nodes'])
        source, extracted = project / 'source.pdf', project / 'pdf-text.json'
        with pymupdf.open() as pdf:
            page = pdf.new_page(width=230, height=340)
            page.insert_text((20, 30), 'Scientific package boundary')
            pdf.save(source)
        original = source.read_bytes()
        result = run(sys.executable, str(cli), 'pdf', 'text', str(source), str(extracted), cwd=project)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = json.loads(extracted.read_text(encoding='utf-8'))
        self.assertEqual(text['pages'][0]['text'].strip(), 'Scientific package boundary')
        self.assertEqual(source.read_bytes(), original)
        original_text, approved_terms = project / 'اصل.txt', project / 'terms.tsv'
        original_text.write_text('核融合 در گزارش.', encoding='utf-8')
        approved_terms.write_text('source\toutput\tconcept\tstatus\n'
            '核融合\tهمجوشی هسته‌ای\tphysics-fusion\tpreferred\n', encoding='utf-8')
        brief = run(sys.executable, str(cli), 'term-brief', str(original_text),
                    '--terms', str(approved_terms), '--language', 'ja', cwd=project)
        self.assertEqual(brief.returncode, 0, brief.stderr)
        self.assertEqual(json.loads(brief.stdout)['terms'][0]['output'], 'همجوشی هسته‌ای')

    def test_image_preparation_and_pdf_pages(self):
        from PIL import Image
        import pymupdf

        cli = str(SKILL / 'scripts/revayat-scientific.py')
        with tempfile.TemporaryDirectory(prefix='scientific figures ', dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            figures = work / 'figures'
            figures.mkdir()
            image = figures / 'diagram.png'
            Image.new('RGBA', (80, 60), (160, 190, 220, 128)).save(image)
            prepared = run(sys.executable, cli, 'figures', str(figures))
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            with Image.open(image) as flattened:
                self.assertNotIn('A', flattened.mode)
            checked = run(sys.executable, cli, 'figures', str(figures), '--check')
            self.assertEqual(checked.returncode, 0, checked.stderr)
            source = work / 'source.pdf'
            with pymupdf.open() as document:
                for _ in range(3):
                    page = document.new_page()
                    page.insert_image(pymupdf.Rect(50, 80, 210, 200), filename=str(image))
                document.save(source)
            output = work / 'range.pdf'
            extracted = run(sys.executable, cli, 'pages', str(source), str(output), '2-3')
            self.assertEqual(extracted.returncode, 0, extracted.stderr)
            with pymupdf.open(output) as document:
                self.assertEqual(document.page_count, 2)
                self.assertEqual(len(document[0].get_images()), 1)

    def test_metadata_and_references(self):
        text = (SKILL / 'SKILL.md').read_text(encoding='utf-8')
        self.assertIn('name: revayat-scientific\n', text)
        self.assertLess(len(text.splitlines()), 500)
        for reference in re.findall(r'\]\(((?:references|scripts|assets)/[^)]+)\)', text):
            self.assertTrue((SKILL / reference).is_file(), reference)
        for folder in ['.claude-plugin', '.cursor-plugin', '.codex-plugin']:
            manifest = json.loads((ROOT / folder / 'plugin.json').read_text(encoding='utf-8'))
            self.assertEqual(manifest['name'], 'revayat-scientific')
            self.assertEqual(manifest['version'], '1.0.0')
            self.assertTrue((ROOT / manifest['skills']).is_dir())

    def test_install_launchers_replacement_and_logs(self):
        if sys.platform == 'win32':
            launcher = [shutil.which('pwsh') or shutil.which('powershell'), '-NoProfile',
                        '-NonInteractive', '-File', str(ROOT / 'install/install.ps1')]
        else:
            launcher = [shutil.which('bash'), str(ROOT / 'install/install.sh')]
        with tempfile.TemporaryDirectory(prefix='revayat install فارسی ', dir=ROOT / '.scratch') as directory:
            project = Path(directory)
            for name in ['.claude', '.agents', '.cursor', '.kiro', '.cline', '.hermes', '.opencode']:
                (project / name).mkdir()
            command = [*launcher, '--scope', 'project', '--path', str(project)]
            installed = run(*command, cwd=project)
            self.assertEqual(installed.returncode, 0, installed.stderr)
            paths = list(project.glob('*/skills/revayat-scientific'))
            self.assertEqual(len(paths), 7, installed.stdout)
            source = project / '.agents/skills/revayat-scientific'
            if sys.platform == 'win32':
                acl_probe = project / 'read-acl.ps1'
                acl_probe.write_text('param($Target)\nif ((Get-Acl -LiteralPath $Target).AreAccessRulesProtected) { exit 1 }\n', encoding='utf-8')
                checked = run(launcher[0], '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
                              'Bypass', '-File', str(acl_probe), str(source))
                self.assertEqual(checked.returncode, 0, 'installed directory must inherit its parent ACL')
            marker = source / 'local-note.txt'
            marker.write_text('preserve on replacement', encoding='utf-8')
            refused = run(*launcher, '--agent', 'codex', '--scope', 'project', '--path', str(project))
            self.assertNotEqual(refused.returncode, 0)
            self.assertTrue(marker.is_file())
            updated = run(*launcher, '--agent', 'codex', '--scope', 'project', '--path', str(project), '--force')
            self.assertEqual(updated.returncode, 0, updated.stderr)
            backups = list((source.parent.parent / 'skill-backups').glob('revayat-scientific-*'))
            self.assertEqual(len(backups), 1)
            self.assertEqual((backups[0] / marker.name).read_text(encoding='utf-8'), 'preserve on replacement')
            cli = source / 'scripts/revayat-scientific.py'
            for _ in range(2):
                help_result = run(sys.executable, str(cli), 'build', '--help', cwd=project)
                self.assertEqual(help_result.returncode, 0, help_result.stderr)
                self.assertIn('--output-dir', help_result.stdout)
            logs = list((source / 'logs').glob('revayat-scientific_*_UTC*.log'))
            self.assertEqual(len(logs), 2)
            for log in logs:
                value = log.read_text(encoding='utf-8')
                self.assertIn('[INFO] [revayat-scientific] command=build', value)
                self.assertNotIn('preserve on replacement', value)
            missing = run(sys.executable, str(cli), 'lint', str(project / 'absent.tex'), cwd=project)
            self.assertNotEqual(missing.returncode, 0)
            self.assert_native_document_commands(cli, project)

    def test_archive_is_self_contained(self):
        with tempfile.TemporaryDirectory(prefix='revayat package فارسی ', dir=ROOT / '.scratch') as directory:
            package = Path(directory) / 'scientific.skill'
            result = run(sys.executable, str(ROOT / 'tools/package.py'), '--output', str(package))
            self.assertEqual(result.returncode, 0, result.stderr)
            with zipfile.ZipFile(package) as archive:
                names = archive.namelist()
                self.assertIn('revayat-scientific/LICENSE', names)
                self.assertIn('revayat-scientific/scripts/runtime.py', names)
                self.assertIn('revayat-scientific/references/terminology.md', names)
                for relative in ('scripts/document-docx.py', 'scripts/docx_package.py',
                                 'scripts/document-pdf.py', 'scripts/pdf_forms.py',
                                 'scripts/publication.py', 'scripts/tex-container.py',
                                 'assets/Dockerfile.tex', 'assets/tex-container-entry.sh',
                                 'references/docx.md', 'references/pdf-processing.md',
                                 'references/evidence-and-terminology.md', 'scripts/term-brief.py'):
                    self.assertIn('revayat-scientific/' + relative, names)
                self.assertFalse(any('/logs/' in name or '__pycache__' in name or '/tests/' in name for name in names))
                self.assertIsNone(archive.testzip())
                archive.extractall(Path(directory) / 'extracted')
            lint = Path(directory) / 'extracted/revayat-scientific/scripts/revayat-scientific.py'
            result = run(sys.executable, str(lint), 'lint', str(ROOT / 'tests/fixtures/journal.tex'),
                         '--level', 'journal', '--terms', str(ROOT / 'tests/fixtures/terms-empty.tsv'),
                         '--manifest', str(ROOT / 'tests/fixtures/manifest-empty.txt'), '--strict')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assert_native_document_commands(lint, Path(directory))


if __name__ == '__main__':
    unittest.main()
