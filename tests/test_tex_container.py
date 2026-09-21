"""Container boundary controls; actual engine execution belongs to native CI."""
import importlib.util
import csv
import io
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
CONTROLLER = SCRIPTS / 'tex-container.py'


class TexContainerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / '.scratch').mkdir(exist_ok=True)
        sys.path.insert(0, str(SCRIPTS))
        if CONTROLLER.is_file():
            spec = importlib.util.spec_from_file_location('tex_container_tests', CONTROLLER)
            cls.controller = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.controller)
        cls.logger = logging.getLogger('container-test')

    def test_remote_endpoint_is_rejected_before_document_access(self):
        self.assertTrue(CONTROLLER.is_file(), 'isolated TeX controller is not implemented')
        sys.path.insert(0, str(SCRIPTS))
        spec = importlib.util.spec_from_file_location('tex_container', CONTROLLER)
        controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        for endpoint in ('tcp://example.com:2375', 'ssh://user@example.com/run/podman.sock',
                         'http://127.0.0.1:2375', 'npipe:////remote/pipe/docker_engine'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                controller.validate_endpoint(endpoint, 'docker')

    def test_endpoint_accepts_local_only_and_probe_never_pulls(self):
        controller = self.controller
        for endpoint, kind in [('unix:///var/run/docker.sock', 'docker'),
                               ('npipe:////./pipe/docker_engine', 'docker'),
                               ('ssh://user@127.0.0.1:1234/run/user/1000/podman.sock', 'podman')]:
            controller.validate_endpoint(endpoint, kind)
        with patch.object(controller.shutil, 'which', return_value='docker'), patch.dict(os.environ, {'DOCKER_HOST': 'tcp://remote.example:2375', 'DOCKER_CONTEXT': ''}), patch.object(controller, 'read_json') as query:
            with self.assertRaisesRegex(ValueError, 'local'):
                controller.runtime_config(self.logger)
            query.assert_not_called()
        replies = [{'OSType': 'linux'}, [{'Id': 'sha256:' + 'a' * 64,
                    'Config': {'Labels': {controller.IMAGE_LABEL: '1'}}}]]
        with patch.object(controller.shutil, 'which', return_value='docker'), patch.dict(os.environ, {'DOCKER_HOST': 'unix:///var/run/docker.sock', 'DOCKER_CONTEXT': '', 'REVAYAT_TEX_IMAGE': 'revayat-scientific-tex:1'}), patch.object(controller, 'read_json', side_effect=replies) as query:
            result = controller.runtime_config(self.logger)
            self.assertEqual(result['image'], 'sha256:' + 'a' * 64)
            self.assertFalse(any('pull' in call.args[0] for call in query.call_args_list))

    def test_staging_selects_closure_graphics_fonts_and_refuses_outside_assets(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            root = Path(directory)
            job = root / 'job'
            job.mkdir()
            (job / 'chapters').mkdir()
            (job / 'figures').mkdir()
            (job / 'fonts').mkdir()
            source = job / 'article.tex'
            source.write_text('\\input{chapters/one}\n\\includegraphics*[width=2cm]{figures/plot.png}', encoding='utf-8')
            (job / 'chapters/one.tex').write_text('Scientific prose.', encoding='utf-8')
            (job / 'figures/plot.png').write_bytes(b'image fixture')
            (job / 'figures/unreferenced.png').write_bytes(b'unapproved')
            (job / 'fonts/local.ttf').write_bytes(b'font fixture')
            (job / 'private.txt').write_text('not approved', encoding='utf-8')
            selected = {relative.as_posix() for _, relative in self.controller.approved_files(source)}
            self.assertEqual(selected, {'article.tex', 'chapters/one.tex', 'figures/plot.png', 'fonts/local.ttf'})
            (root / 'outside.png').write_bytes(b'outside sentinel')
            source.write_text('\\includegraphics{../outside.png}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'approved job root'):
                self.controller.approved_files(source)

    def test_mount_csv_and_resource_flags_keep_cid_host_private(self):
        root = Path('/tmp/job, Persian فارسی')
        config = {'base': ['docker', '--host', 'unix:///var/run/docker.sock'],
                  'kind': 'docker', 'image': 'sha256:' + 'a' * 64}
        arguments = self.controller.run_arguments(config, root, 'مقاله.tex', 'b' * 32)
        for flag in ('--pull=never', '--network=none', '--read-only', '--cap-drop=ALL',
                     '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=1g', '--cpus=2'):
            self.assertIn(flag, arguments)
        mounts = [arguments[index + 1] for index, value in enumerate(arguments) if value == '--mount']
        parsed = [next(csv.reader([value])) for value in mounts]
        self.assertEqual(len(parsed), 2)
        self.assertIn('readonly', parsed[0])
        self.assertIn('src=' + str((root / 'input').resolve()), parsed[0])
        self.assertEqual(arguments[arguments.index('--cidfile') + 1], str(root / 'container.cid'))
        self.assertIn('120s', arguments)
        self.assertIn('--kill-after=5s', arguments)
        self.assertNotIn(str(root), mounts)

    def test_cleanup_removes_only_verified_run_and_detects_lost_label(self):
        controller = self.controller
        config, identifier, run_id = {'base': ['docker']}, 'a' * 64, 'b' * 32
        record = {'Id': identifier, 'Name': '/revayat-tex-' + run_id,
                  'Config': {'Labels': {controller.RUN_LABEL: run_id}}}
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            root = Path(directory)
            (root / 'container.cid').write_text(identifier, encoding='utf-8')
            with patch.object(controller, 'call', side_effect=[(0, identifier), (0, ''), (0, '')]) as command, patch.object(controller, 'read_json', return_value=[record]):
                controller.cleanup(config, root, run_id, self.logger)
                self.assertIn(['docker', 'rm', '--force', identifier], [item.args[0] for item in command.call_args_list])
            record['Config']['Labels'][controller.RUN_LABEL] = 'another-job'
            with patch.object(controller, 'call', return_value=(0, identifier)) as command, patch.object(controller, 'read_json', return_value=[record]):
                with self.assertRaisesRegex(RuntimeError, 'matching ownership'):
                    controller.cleanup(config, root, run_id, self.logger)
                self.assertFalse(any('rm' in item.args[0] for item in command.call_args_list))
            with patch.object(controller, 'call', side_effect=[(0, ''), (0, identifier)]):
                with self.assertRaisesRegex(RuntimeError, 'ownership label'):
                    controller.cleanup(config, root, run_id, self.logger)

    def test_failed_renderer_valid_pdf_timeout_and_cleanup_failure_never_publish(self):
        import pymupdf
        controller = self.controller
        config = {'base': ['docker'], 'kind': 'docker', 'image': 'sha256:' + 'a' * 64}
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            root = Path(directory)
            source, output = root / 'source.tex', root / 'approved.pdf'
            source.write_text('\\documentclass{article}\\begin{document}hello\\end{document}', encoding='utf-8')
            output.write_bytes(b'previous approved PDF')
            def renderer(arguments, logger, timeout):
                for index, argument in enumerate(arguments):
                    if argument == '--mount':
                        fields = next(csv.reader([arguments[index + 1]]))
                        if 'dst=/output' in fields:
                            path = Path(next(value[4:] for value in fields if value.startswith('src=')))
                with pymupdf.open() as document:
                    document.new_page(width=230, height=340)
                    document.save(path / 'document.pdf')
                return 42, ''
            with patch.object(controller, 'runtime_config', return_value=config), patch.object(controller, 'call', side_effect=renderer), patch.object(controller, 'cleanup') as clean:
                with self.assertRaisesRegex(RuntimeError, 'XeLaTeX failed'):
                    controller.compile_document(source, output, self.logger)
                clean.assert_called_once()
            self.assertEqual(output.read_bytes(), b'previous approved PDF')
            with patch.object(controller, 'runtime_config', return_value=config), patch.object(controller, 'call', side_effect=subprocess.TimeoutExpired('docker', 150)), patch.object(controller, 'cleanup') as clean:
                with self.assertRaises(subprocess.TimeoutExpired):
                    controller.compile_document(source, output, self.logger)
                clean.assert_called_once()
            with patch.object(controller, 'runtime_config', return_value=config), patch.object(controller, 'call', return_value=(0, '')), patch.object(controller, 'cleanup', side_effect=RuntimeError('daemon unavailable')):
                with self.assertRaisesRegex(RuntimeError, 'retained evidence'):
                    controller.compile_document(source, output, self.logger)
            self.assertEqual(output.read_bytes(), b'previous approved PDF')
            recovery = list(root.glob('.revayat-tex-*/recovery.json'))
            self.assertEqual(len(recovery), 1)
            self.assertEqual(json.loads(recovery[0].read_text(encoding='utf-8'))['status'], 'cleanup_not_verified')

    def test_success_reopens_pdf_and_cleans_staging(self):
        import pymupdf
        controller = self.controller
        config = {'base': ['docker'], 'kind': 'docker', 'image': 'sha256:' + 'a' * 64}
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            root = Path(directory)
            source, output = root / 'source.tex', root / 'output.pdf'
            source.write_text('Scientific input', encoding='utf-8')
            def renderer(arguments, logger, timeout):
                cid = Path(arguments[arguments.index('--cidfile') + 1])
                self.assertFalse((cid.parent / 'input/output.pdf').exists())
                with pymupdf.open() as document:
                    document.new_page(width=250, height=360)
                    document.save(cid.parent / 'output/document.pdf')
                return 0, ''
            with patch.object(controller, 'runtime_config', return_value=config), patch.object(controller, 'call', side_effect=renderer), patch.object(controller, 'cleanup'):
                controller.compile_document(source, output, self.logger)
            with pymupdf.open(output) as document:
                self.assertEqual(tuple(document[0].rect), (0, 0, 250, 360))
            self.assertEqual(source.read_text(encoding='utf-8'), 'Scientific input')
            self.assertFalse(list(root.glob('.revayat-tex-*')))


if __name__ == '__main__':
    unittest.main()
