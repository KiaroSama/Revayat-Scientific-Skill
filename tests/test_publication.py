"""A failed delivery must preserve the entire previous approved output set."""
import os
import json
from pathlib import Path
import sys
import shutil
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
from publication import publish_files, validate_destination
from processes import run


class PublicationTest(unittest.TestCase):
    def test_late_replace_failure_restores_previous_outputs(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            first, second = root / 'first.pdf', root / 'second.pdf'
            staged_a, staged_b = root / 'staged-a', root / 'staged-b'
            for path, data in ((first, b'approved A'), (second, b'approved B'),
                               (staged_a, b'new A'), (staged_b, b'new B')):
                path.write_bytes(data)
            replace = os.replace

            def fail_second(source, destination):
                if Path(source).name == staged_b.name:
                    raise OSError('simulated publication failure')
                return replace(source, destination)

            with patch('os.replace', side_effect=fail_second):
                with self.assertRaises(OSError):
                    publish_files([(staged_a, first), (staged_b, second)])
            self.assertEqual((first.read_bytes(), second.read_bytes()),
                             (b'approved A', b'approved B'))
            self.assertFalse(list(root.glob('.revayat-publish-*')))

    def test_casefold_collision_is_rejected_before_mutation(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            a, b = root / 'a', root / 'b'
            a.write_bytes(b'A')
            b.write_bytes(b'B')
            with self.assertRaises(ValueError):
                publish_files([(a, root / 'Output'), (b, root / 'output')])
            self.assertEqual((a.read_bytes(), b.read_bytes()), (b'A', b'B'))

    @unittest.skipUnless(os.name == 'nt', 'Windows ACL inheritance')
    def test_publication_inherits_destination_access_instead_of_private_stage(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        work = scratch / ('publication-acl-' + uuid.uuid4().hex)
        work.mkdir()
        try:
            control, output = work / 'control', work / 'output'
            control.write_bytes(b'normal inherited access')
            with tempfile.TemporaryDirectory(dir=work) as directory:
                stage = Path(directory) / 'stage'
                stage.write_bytes(b'delivered')
                publish_files([(stage, output)])
            script = work / 'acl.ps1'
            script.write_text('param($A,$B)\n'
                '$aRules=@((Get-Acl -LiteralPath $A).Access.IdentityReference.Value | Sort-Object -Unique)\n'
                '$bRules=@((Get-Acl -LiteralPath $B).Access.IdentityReference.Value | Sort-Object -Unique)\n'
                '@{equivalent=(@(Compare-Object $aRules $bRules).Count -eq 0)} | ConvertTo-Json -Compress\n', encoding='utf-8')
            result = run([shutil.which('powershell'), '-NoProfile', '-NonInteractive',
                          '-File', str(script), str(control), str(output)], timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['equivalent'], 'publication lost destination access principals')
            self.assertEqual(output.read_bytes(), b'delivered')
        finally:
            shutil.rmtree(work)

    def test_source_alias_and_directory_are_rejected(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            source = root / 'source.pdf'
            source.write_bytes(b'original')
            for destination in (source, root):
                with self.subTest(destination=destination.name):
                    with self.assertRaises(ValueError):
                        validate_destination(destination, [source])


if __name__ == '__main__':
    unittest.main()
