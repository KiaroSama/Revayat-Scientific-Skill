#!/usr/bin/env python3
"""Deliver a validated Vazirmatn pair, license and provenance together."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile
import time
import urllib.request
import zipfile

from publication import publish_files, validate_destination
from runtime import operation_log, run_command

FONTS = {'Vazirmatn-Regular.ttf': 400, 'Vazirmatn-Bold.ttf': 700}
LICENSE = 'OFL.txt'
PROVENANCE = 'font-provenance.json'
MAX_FONT = 20 * 1024 * 1024
MAX_ARCHIVE = 100 * 1024 * 1024


def font_identity(path, weight, version):
    """Read bounded standard SFNT identity tables, then validate the font engine."""
    if not path.is_file() or path.stat().st_size > MAX_FONT:
        raise ValueError('font is missing or exceeds the size limit')
    data = path.read_bytes()
    if len(data) < 12 or data[:4] != b'\x00\x01\x00\x00':
        raise ValueError('expected a static TrueType font')
    count = struct.unpack_from('>H', data, 4)[0]
    if count > 256 or 12 + count * 16 > len(data):
        raise ValueError('invalid TrueType directory')
    tables = {}
    for index in range(count):
        tag, _, offset, size = struct.unpack_from('>4sIII', data, 12 + index * 16)
        if tag in tables or offset + size > len(data):
            raise ValueError('invalid TrueType table bounds')
        tables[tag] = data[offset:offset + size]
    if b'fvar' in tables or len(tables.get(b'OS/2', b'')) < 6:
        raise ValueError('static font with an OS/2 weight is required')
    actual_weight = struct.unpack_from('>H', tables[b'OS/2'], 4)[0]
    if actual_weight != weight:
        raise ValueError('font weight does not match its requested role')
    name = tables.get(b'name', b'')
    if len(name) < 6:
        raise ValueError('font name table missing')
    _, count, storage = struct.unpack_from('>HHH', name)
    if 6 + count * 12 > len(name):
        raise ValueError('invalid font name records')
    names = {}
    for index in range(count):
        platform, _, _, key, length, offset = struct.unpack_from('>6H', name, 6 + index * 12)
        if storage + offset + length > len(name):
            raise ValueError('invalid font name string bounds')
        if platform in (0, 3) and key in (1, 2, 5, 6, 16, 17):
            text = name[storage + offset:storage + offset + length].decode('utf-16-be')
            names.setdefault(key, []).append(text)
    family = ' '.join(names.get(16, names.get(1, [])))
    identity = ' '.join(text for group in names.values() for text in group)
    if 'vazirmatn' not in family.casefold() or re.search(r'(?i)(?:^|[\s_-])FD(?:$|[\s_-])|Farsi.*Digit', identity):
        raise ValueError('font is not the Western-digit Vazirmatn family')
    if not any(re.search(r'(?<![0-9.])' + re.escape(version) + r'(?![0-9.])', text)
               for text in names.get(5, [])):
        raise ValueError('font version differs from requested release')
    import pymupdf
    parsed = pymupdf.Font(fontfile=str(path))
    if not parsed.glyph_count or any(not parsed.has_glyph(ord(char)) for char in '0123456789'):
        raise ValueError('font does not contain the required numeral glyphs')
    return {'family': family, 'weight': actual_weight, 'version': version,
            'sha256': hashlib.sha256(data).hexdigest()}


def validate_bundle(directory, version, *, require_provenance=False):
    records = {name: font_identity(directory / name, weight, version) for name, weight in FONTS.items()}
    license_path = directory / LICENSE
    if not license_path.is_file() or license_path.stat().st_size > 100_000:
        raise ValueError('corresponding OFL.txt is required with the font pair')
    license_text = license_path.read_text(encoding='utf-8-sig')
    if not all(token in license_text for token in ('Vazirmatn', 'Copyright', 'SIL OPEN FONT LICENSE', 'Version 1.1', 'PERMISSION & CONDITIONS', 'DISCLAIMER')):
        raise ValueError('font license is not the expected complete Vazirmatn OFL')
    records[LICENSE] = {'sha256': hashlib.sha256(license_path.read_bytes()).hexdigest()}
    if require_provenance:
        metadata = json.loads((directory / PROVENANCE).read_text(encoding='utf-8'))
        if metadata.get('version') != version or metadata.get('files') != records:
            raise ValueError('font provenance does not match the delivered files')
    return records


def cache_directory(version):
    base = os.environ.get('LOCALAPPDATA') if os.name == 'nt' else os.environ.get('XDG_CACHE_HOME')
    return (Path(base) if base else Path.home() / '.cache') / 'fa-fonts' / version


def installed_fonts(logger):
    candidates = []
    if os.name == 'nt':
        import winreg
        for hive, base in ((winreg.HKEY_LOCAL_MACHINE, Path(os.environ.get('WINDIR', '')) / 'Fonts'),
                           (winreg.HKEY_CURRENT_USER, Path(os.environ.get('LOCALAPPDATA', '')) / 'Microsoft/Windows/Fonts')):
            try:
                with winreg.OpenKey(hive, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts') as key:
                    for index in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, index)
                        if 'vazirmatn' in name.casefold() and isinstance(value, str):
                            path = Path(value)
                            candidates.append(path if path.is_absolute() else base / path)
            except OSError:
                continue
    elif shutil.which('fc-match'):
        for style in ('Regular', 'Bold'):
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                code = run_command(['fc-match', '-f', '%{file}\n', 'Vazirmatn:style=' + style], 10, logger)
            if code == 0:
                candidates.extend(Path(line) for line in output.getvalue().splitlines() if line)
    return list(dict.fromkeys(candidates))


def use_installed(stage, version, logger):
    selected = {}
    for candidate in installed_fonts(logger):
        for name, weight in FONTS.items():
            if name in selected:
                continue
            try:
                font_identity(candidate, weight, version)
                selected[name] = candidate
            except (OSError, ValueError, RuntimeError):
                continue
    if len(selected) != len(FONTS):
        return False
    for candidate in selected.values():
        for parent in list(candidate.parents)[:3]:
            license_path = parent / LICENSE
            if license_path.is_file():
                for name, source in selected.items():
                    shutil.copy2(source, stage / name)
                shutil.copy2(license_path, stage / LICENSE)
                try:
                    validate_bundle(stage, version)
                    return True
                except (OSError, ValueError):
                    continue
    return False


def download_bundle(stage, version):
    url = f'https://github.com/rastikerdar/vazirmatn/releases/download/v{version}/vazirmatn-v{version}.zip'
    archive = stage / 'release.zip'
    started = time.monotonic()
    with urllib.request.urlopen(url, timeout=15) as response, archive.open('xb') as handle:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_ARCHIVE or time.monotonic() - started > 90:
                raise ValueError('font download exceeded its size or time bound')
            handle.write(chunk)
    extract_bundle(archive, stage)
    validate_bundle(stage, version)
    return url


def extract_bundle(archive, stage):
    with zipfile.ZipFile(archive) as package:
        for name in (*FONTS, LICENSE):
            matches = [info for info in package.infolist() if Path(info.filename).name == name]
            if len(matches) != 1 or matches[0].file_size > MAX_FONT:
                raise ValueError('font archive is incomplete, ambiguous or oversized')
            # Never extract paths from an archive: only fixed, validated output names.
            (stage / name).write_bytes(package.read(matches[0]))


def copy_bundle(source, stage):
    for name in (*FONTS, LICENSE):
        shutil.copy2(source / name, stage / name)


def fetch(destination, version, *, offline=False, logger=None):
    logger = logger or logging.getLogger('font-fetch')
    if re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,2}', version) is None:
        raise ValueError('font version must be a numeric stable release')
    destination = Path(destination)
    cache = cache_directory(version)
    for name in (*FONTS, LICENSE, PROVENANCE):
        validate_destination(destination / name)
    if destination.is_dir():
        try:
            validate_bundle(destination, version, require_provenance=True)
            return
        except (OSError, ValueError, RuntimeError):
            pass
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.revayat-fonts-', dir=destination) as directory:
        stage, source_kind = Path(directory), None
        # Legacy unversioned caches are eligible only after checking font versions.
        for candidate, kind in ((destination, 'existing'), (cache, 'cache'), (cache.parent, 'legacy-cache')):
            try:
                validate_bundle(candidate, version)
                copy_bundle(candidate, stage)
                source_kind = kind
                break
            except (OSError, ValueError, RuntimeError):
                continue
        if source_kind is None and use_installed(stage, version, logger):
            source_kind = 'installed'
        if source_kind is None:
            if offline:
                raise ValueError('no complete validated font pair and OFL available offline')
            download_bundle(stage, version)
            source_kind = 'release'
        records = validate_bundle(stage, version)
        metadata = {'schema': 1, 'version': version, 'source': source_kind,
                    'release': f'https://github.com/rastikerdar/vazirmatn/releases/tag/v{version}', 'files': records}
        (stage / PROVENANCE).write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
        validate_bundle(stage, version, require_provenance=True)
        publish_files([(stage / name, destination / name) for name in (*FONTS, LICENSE, PROVENANCE)])
    logger.info('font_bundle_published source=%s version=%s', source_kind, version)
    if destination.resolve() != cache.resolve():
        try:
            cache.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='.revayat-font-cache-', dir=cache) as directory:
                stage = Path(directory)
                for name in (*FONTS, LICENSE, PROVENANCE):
                    shutil.copy2(destination / name, stage / name)
                validate_bundle(stage, version, require_provenance=True)
                publish_files([(stage / name, cache / name) for name in (*FONTS, LICENSE, PROVENANCE)],
                              protected_sources=[destination / name for name in (*FONTS, LICENSE, PROVENANCE)])
        except (OSError, ValueError, RuntimeError):
            logger.warning('optional_font_cache_write_failed')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', nargs='?', type=Path, default=Path('fonts'))
    parser.add_argument('--version', default=os.environ.get('VAZIRMATN_VERSION', '33.003'))
    args = parser.parse_args(argv)
    with operation_log('font-fetch', Path(__file__).resolve().parent / 'logs') as logger:
        fetch(args.destination, args.version, offline=os.environ.get('REVAYAT_FONT_OFFLINE') == '1', logger=logger)
    for name in FONTS:
        print(args.destination / name)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'font-fetch: failed ({type(error).__name__}): {error}', file=sys.stderr)
        raise SystemExit(2)
