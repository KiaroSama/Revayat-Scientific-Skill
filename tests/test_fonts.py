"""Font delivery checks reject incomplete and mislabeled font bundles."""
import os
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from processes import run

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('font_fetch', SCRIPTS / 'font-fetch.py')
FONTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FONTS)


def bundle(directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name in FONTS.FONTS:
        (directory / name).write_bytes(name.encode('ascii'))
    (directory / FONTS.LICENSE).write_text('Copyright Vazirmatn\nSIL OPEN FONT LICENSE\n'
                                          'Version 1.1\nPERMISSION & CONDITIONS\nDISCLAIMER\n', encoding='utf-8')


def fixture_identity(path, weight, version):
    # Transaction controls use synthetic payloads, not evidence of real font rendering.
    if path.read_bytes() != path.name.encode('ascii') or FONTS.FONTS.get(path.name) != weight:
        raise ValueError('fixture font changed')
    import hashlib
    return {'weight': weight, 'version': version, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def sfnt_identity(weight=400, family='Vazirmatn', version='Version 33.003'):
    # Deliberately minimal metadata fixture for rejection paths before font loading.
    encoded = [(key, value.encode('utf-16-be')) for key, value in ((1, family), (5, version))]
    records, strings = b'', b''
    for key, value in encoded:
        records += struct.pack('>6H', 3, 1, 1033, key, len(value), len(strings))
        strings += value
    name = struct.pack('>3H', 0, len(encoded), 6 + len(records)) + records + strings
    tables = [(b'OS/2', struct.pack('>3H', 0, 0, weight)), (b'name', name)]
    directory, content = b'', b''
    for tag, data in tables:
        directory += struct.pack('>4sIII', tag, 0, 12 + 16 * len(tables) + len(content), len(data))
        content += data
    return b'\x00\x01\x00\x00' + struct.pack('>4H', len(tables), 0, 0, 0) + directory + content


class FontDeliveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / '.scratch').mkdir(exist_ok=True)

    def test_incomplete_existing_delivery_is_not_success(self):
        (ROOT / '.scratch').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            destination = Path(directory) / 'fonts'
            destination.mkdir()
            for style in ('Regular', 'Bold'):
                (destination / f'Vazirmatn-{style}.ttf').write_bytes(b'not a validated font')
            if os.name == 'nt':
                command = [shutil.which('pwsh') or 'powershell', '-NoProfile', '-File',
                           str(SCRIPTS / 'fetch-vazirmatn.ps1'), str(destination)]
            else:
                command = ['bash', str(SCRIPTS / 'fetch-vazirmatn.sh'), str(destination)]
            result = run(command, timeout=20, env={'REVAYAT_FONT_OFFLINE': '1', 'VAZIRMATN_VERSION': '999.999'})
            self.assertNotEqual(result.returncode, 0, 'unvalidated font pair without license was accepted')
            self.assertEqual(len(list(destination.iterdir())), 2)

    def test_cache_delivery_includes_license_provenance_and_survives_failure(self):
        import publication
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            cache, destination = work / 'cache/33.003', work / 'delivery'
            bundle(cache)
            destination.mkdir()
            previous = destination / 'Vazirmatn-Regular.ttf'
            previous.write_bytes(b'previous font')
            real_replace = publication.os.replace
            def fail_license(stage, dest):
                if Path(dest).name == 'OFL.txt':
                    raise OSError('injected publication failure')
                return real_replace(stage, dest)
            with patch.object(FONTS, 'cache_directory', return_value=cache), patch.object(FONTS, 'font_identity', side_effect=fixture_identity):
                with patch.object(publication.os, 'replace', side_effect=fail_license), self.assertRaises(OSError):
                    FONTS.fetch(destination, '33.003', offline=True)
                self.assertEqual(previous.read_bytes(), b'previous font')
                self.assertEqual([p.name for p in destination.iterdir()], [previous.name])
                FONTS.fetch(destination, '33.003', offline=True)
                self.assertEqual((destination / 'OFL.txt').read_bytes(), (cache / 'OFL.txt').read_bytes())
                metadata = json.loads((destination / FONTS.PROVENANCE).read_text(encoding='utf-8'))
                self.assertEqual(metadata['source'], 'cache')
                self.assertEqual(metadata['version'], '33.003')
                before = {p.name: p.read_bytes() for p in destination.iterdir()}
                with patch.object(FONTS, 'download_bundle', side_effect=AssertionError('offline existing bundle')):
                    FONTS.fetch(destination, '33.003', offline=True)
                self.assertEqual({p.name: p.read_bytes() for p in destination.iterdir()}, before)

    def test_identity_refuses_renamed_weight_fd_wrong_version_and_bad_font(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            font = Path(directory) / 'Vazirmatn-Bold.ttf'
            for content, weight, message in [(sfnt_identity(400), 700, 'weight'),
                    (sfnt_identity(family='Vazirmatn FD'), 400, 'Western'),
                    (sfnt_identity(version='Version 32.000'), 400, 'version'), (b'invalid', 400, 'TrueType')]:
                font.write_bytes(content)
                with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                    FONTS.font_identity(font, weight, '33.003')

    def test_partial_cache_offline_and_bad_archives_do_not_publish(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            cache, destination = work / 'cache/33.003', work / 'delivery'
            bundle(cache)
            (cache / 'OFL.txt').unlink()
            with patch.object(FONTS, 'cache_directory', return_value=cache), patch.object(FONTS, 'font_identity', side_effect=fixture_identity), patch.object(FONTS, 'use_installed', return_value=False):
                with self.assertRaisesRegex(ValueError, 'offline'):
                    FONTS.fetch(destination, '33.003', offline=True)
                self.assertEqual(list(destination.iterdir()), [])
            archive = work / 'bad.zip'
            with zipfile.ZipFile(archive, 'w') as package:
                package.writestr('../Vazirmatn-Regular.ttf', b'one')
                package.writestr('duplicate/Vazirmatn-Regular.ttf', b'two')
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                FONTS.extract_bundle(archive, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_installed_pair_requires_both_real_weights_and_license(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            installed, stage = work / 'installed', work / 'stage'
            bundle(installed)
            stage.mkdir()
            with patch.object(FONTS, 'installed_fonts', return_value=list(installed.glob('*.ttf'))), patch.object(FONTS, 'font_identity', side_effect=fixture_identity):
                self.assertTrue(FONTS.use_installed(stage, '33.003', None))
            (installed / 'OFL.txt').unlink()
            with patch.object(FONTS, 'installed_fonts', return_value=list(installed.glob('*.ttf'))), patch.object(FONTS, 'font_identity', side_effect=fixture_identity):
                self.assertFalse(FONTS.use_installed(stage, '33.003', None))

    def test_legacy_cache_is_validated_before_versioned_migration(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            cache, destination = work / 'cache/33.003', work / 'delivery'
            bundle(cache.parent)
            with patch.object(FONTS, 'cache_directory', return_value=cache), patch.object(FONTS, 'font_identity', side_effect=fixture_identity):
                FONTS.fetch(destination, '33.003', offline=True)
                metadata = json.loads((destination / FONTS.PROVENANCE).read_text(encoding='utf-8'))
                self.assertEqual(metadata['source'], 'legacy-cache')
                self.assertEqual((cache / FONTS.LICENSE).read_bytes(), (destination / FONTS.LICENSE).read_bytes())


if __name__ == '__main__':
    unittest.main()
