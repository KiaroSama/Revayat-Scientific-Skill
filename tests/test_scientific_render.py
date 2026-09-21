"""Real isolated TeX and WeasyPrint checks owned by the scientific CI tier."""
import importlib.util
import logging
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from processes import run

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/revayat-scientific'
SCRIPTS = SKILL / 'scripts'
CLI = SCRIPTS / 'revayat-scientific.py'


@unittest.skipUnless(os.environ.get('SCIENTIFIC_RENDER') == '1', 'scientific CI tier')
class ScientificRenderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / '.scratch').mkdir(exist_ok=True)
        cls.evidence = Path(os.environ['SCIENTIFIC_EVIDENCE_DIR'])
        cls.evidence.mkdir(parents=True, exist_ok=True)

    def test_multipart_geometry_images_math_and_verified_delivery(self):
        import pymupdf
        from PIL import Image

        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch', prefix='scientific فارسی ') as directory:
            work = Path(directory)
            (work / 'chapters').mkdir()
            (work / 'figures').mkdir()
            Image.new('RGB', (600, 300), (120, 180, 220)).save(work / 'figures/plot.png')
            template = (SKILL / 'assets/rtl-document.tex').read_text(encoding='utf-8')
            template = template.replace('paperwidth=210mm,paperheight=297mm', 'paperwidth=180mm,paperheight=240mm')
            template = template.replace(r'\maketitle', r'\maketitle' + '\n' + r'\input{chapters/body}')
            source = work / 'document.tex'
            source.write_text(template, encoding='utf-8')
            body = (ROOT / 'tests/fixtures/build-smoke-body.tex').read_text(encoding='utf-8')
            figure = r'''
\begin{LTR}
\includegraphics[width=50mm]{figures/plot.png}
\end{LTR}
\begin{tabular}{ll}
کمیت & مقدار \\
دما & \en{23.5 C} \\
\end{tabular}
\begin{latin}
La mesure dépend des conditions expérimentales.
\end{latin}
'''
            body = body.replace(r'\clearpage', figure + r'\clearpage', 1)
            (work / 'chapters/body.tex').write_text(body, encoding='utf-8')
            shutil.copyfile(ROOT / 'tests/fixtures/terms-empty.tsv', work / 'terms.tsv')
            (work / 'manifest.txt').write_text('plot.png\n', encoding='utf-8')
            command = [sys.executable, str(CLI), '--timeout', '240', 'build', str(source),
                       'article', '--engine', 'tex', '--level', 'journal', '--verify',
                       '--output-dir', str(work / 'delivered')]
            result = run(command, timeout=260)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            output = work / 'delivered/article.pdf'
            with pymupdf.open(output) as document:
                self.assertGreaterEqual(document.page_count, 3)
                for page in document:
                    self.assertAlmostEqual(page.rect.width, 180 * 72 / 25.4, delta=0.5)
                    self.assertAlmostEqual(page.rect.height, 240 * 72 / 25.4, delta=0.5)
                first = document[0]
                content = first.get_text(clip=pymupdf.Rect(0, 0, first.rect.width, first.rect.height - 55))
                compact = re.sub(r'\s+', '', content)
                for number in ('3.14', '2.5', '0.25'):
                    self.assertIn(number, compact)
                self.assertIsNone(re.search('[\u0660-\u0669\u06f0-\u06f9]', content))
                self.assertTrue(any(image[2:4] == (600, 300) for page in document for image in page.get_images()))
                first.get_pixmap(dpi=110).save(self.evidence / 'multipart-first.png')
            shutil.copyfile(output, self.evidence / 'multipart.pdf')
            approved = output.read_bytes()
            with (work / 'chapters/body.tex').open('a', encoding='utf-8') as handle:
                handle.write('\nاين متن باید رد شود.\n')
            failed = run(command, timeout=90)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn('arabic-letters', failed.stdout + failed.stderr)
            self.assertEqual(output.read_bytes(), approved)

    def test_container_host_sentinel_and_shortened_internal_deadline(self):
        spec = importlib.util.spec_from_file_location('real_tex_container', SCRIPTS / 'tex-container.py')
        container = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(container)
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            root = Path(directory)
            work = root / 'job'
            work.mkdir()
            sentinel = root / 'outside.txt'
            sentinel.write_text('HOST_SENTINEL_MUST_NOT_BE_READ', encoding='utf-8')
            source, output = work / 'paper.tex', work / 'paper.pdf'
            source.write_text('\\documentclass{article}\n\\begin{document}\n'
                '\\newread\\probe\n\\openin\\probe="' + sentinel.as_posix() + '"\n'
                '\\ifeof\\probe SAFE\\else\\errmessage{Host file was accessible}\\fi\n'
                '\\closein\\probe\n\\end{document}', encoding='utf-8')
            container.compile_document(source, output, logging.Logger('sentinel-test'))
            approved = output.read_bytes()
            source.write_text('\\documentclass{article}\n\\begin{document}\n'
                              '\\loop\\iftrue\\repeat\n\\end{document}', encoding='utf-8')
            with patch.object(container, 'INNER_TIMEOUT', 2), self.assertRaises(RuntimeError):
                container.compile_document(source, output, logging.Logger('deadline-test'))
            self.assertEqual(output.read_bytes(), approved)
            self.assertFalse(list(work.glob('.revayat-tex-*')))

    def test_weasyprint_resource_denial_preserves_previous_output(self):
        import pymupdf
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            root = Path(directory)
            work = root / 'job'
            work.mkdir()
            source, output = work / 'paper.html', work / 'paper.pdf'
            source.write_text('<html lang="fa" dir="rtl"><style>@page{size:160mm 240mm}</style>'
                              '<p>این متن علمی برای بررسی است.</p></html>', encoding='utf-8')
            command = [sys.executable, str(SCRIPTS / 'render-html.py'), str(source), str(output),
                       '--engine', 'weasyprint']
            rendered = run(command, timeout=90)
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            with pymupdf.open(output) as document:
                self.assertAlmostEqual(document[0].rect.width, 160 * 72 / 25.4, delta=0.5)
                document[0].get_pixmap(dpi=110).save(self.evidence / 'weasyprint-first.png')
            shutil.copyfile(output, self.evidence / 'weasyprint.pdf')
            approved = output.read_bytes()
            outside = root / 'outside.css'
            outside.write_text('body{color:red}', encoding='utf-8')
            source.write_text('<html><style>@import url("' + outside.as_uri()
                              + '");</style><p>متن علمی</p></html>', encoding='utf-8')
            denied = run(command, timeout=90)
            self.assertNotEqual(denied.returncode, 0)
            self.assertEqual(output.read_bytes(), approved)
            self.assertFalse(list(work.glob('.revayat-render-*')))


if __name__ == '__main__':
    unittest.main()
