"""Native CI observes the production container's effective isolation controls."""
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest.mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from runtime import operation_log


class SandboxEnforcementTest(unittest.TestCase):
    def test_production_launch_enforces_isolation_and_cleans_owned_container(self):
        if os.environ.get('SCIENTIFIC_REQUIRE_SANDBOX') != '1':
            self.skipTest('native Linux sandbox enforcement tier')
        self.assertTrue(sys.platform.startswith('linux'), 'required sandbox tier needs Linux')
        self.assertIsNotNone(shutil.which('docker'), 'required sandbox tier needs Docker')
        spec = importlib.util.spec_from_file_location('sandbox_container', SCRIPTS / 'tex-container.py')
        container = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(container)
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='sandbox enforcement ', dir=scratch) as directory:
            work = Path(directory)
            incoming, outgoing = work / 'input', work / 'output'
            incoming.mkdir()
            outgoing.mkdir()
            sentinel = incoming / 'sentinel.txt'
            sentinel.write_text('public sandbox fixture', encoding='utf-8')
            original = sentinel.read_bytes()
            shutil.copyfile(ROOT / 'tests/fixtures/sandbox-probe.sh', incoming / 'probe.sh')
            with operation_log('test-sandbox-enforcement', work / 'logs') as logger:
                config = container.runtime_config(logger)
                self.assertEqual(config['kind'], 'docker', 'required CI tier must use its prepared Docker image')
                run_id = uuid.uuid4().hex
                command = container.run_arguments(config, work, 'probe.sh', run_id)
                # Preserve every production Docker option, identity and owner. Only
                # the bounded inner document payload becomes a trusted observation.
                image = command.index(config['image'])
                command = command[:image + 1] + ['--signal=TERM', '--kill-after=5s', '20s',
                                                 '/bin/bash', '/input/probe.sh']
                try:
                    with unittest.mock.patch.dict(os.environ, {'REVAYAT_HOST_ONLY_CANARY': 'public-fixture-only'}):
                        code, output = container.call(command, logger, timeout=35)
                    self.assertEqual(code, 0, output)
                    self.assertIn('readonly network environment privilege resources scratch passed', output)
                    self.assertEqual((outgoing / 'probe.txt').read_text(encoding='utf-8'), 'allowed output\n')
                    self.assertEqual(sentinel.read_bytes(), original)
                finally:
                    container.cleanup(config, work, run_id, logger)
                logger.info('sandbox_controls_verified owned_container_cleanup=complete')


if __name__ == '__main__':
    unittest.main()
