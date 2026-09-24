#!/usr/bin/env python3
"""Prepare validated PNG figures while preserving source image information.

Pillow is required. Unsupported depth, frames and color profiles fail before
publication. In-place PNG replacement retains a byte-exact .orig; other input
formats stay intact. --check never modifies image data.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import io
import math
import os
from pathlib import Path
import shutil
import sys
import tempfile

from publication import publish_files, validate_destination
from runtime import operation_log
from image_review import reviewed_dark_original

IMAGE_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.tif', '.tiff'}
DARK_MEAN = 120.0
DARK_BLACK_FRAC = 0.50


def have_pil():
    try:
        import PIL.Image  # noqa: F401
        return True
    except ImportError:
        return False


def iter_images(paths):
    files = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(p for p in path.iterdir() if p.suffix.lower() in IMAGE_EXT))
        elif path.is_file() and path.suffix.lower() in IMAGE_EXT:
            files.append(path)
        else:
            raise ValueError('input must be an image file or directory')
    keys = set()
    for index, path in enumerate(files):
        if not path.is_file() or any(p.is_symlink() or
                (hasattr(p, 'is_junction') and p.is_junction()) for p in (path, *path.parents)):
            raise ValueError('source must be a regular file without linked path components')
        key = str(path.resolve()).casefold()
        if key in keys or any(os.path.samefile(path, other) for other in files[:index]):
            raise ValueError('duplicate or aliased image input')
        keys.add(key)
    return files


def inspect_image(image):
    # getexif/n_frames may load PNG pixels and clear fp; read IHDR first.
    if image.format == 'PNG':
        if image.fp:
            position = image.fp.tell()
            image.fp.seek(24)
            depth = image.fp.read(1)
            image.fp.seek(position)
            image.info['_revayat_source_depth'] = depth[0] if depth else None
        if image.info.get('_revayat_source_depth') is None:
            raise ValueError('PNG bit depth cannot be verified after external decoding')
        if image.info['_revayat_source_depth'] > 8:
            raise ValueError('unsupported PNG bit depth; preserve original intensities')
    if any(key in image.info for key in ('gamma', 'chromaticity', 'srgb')):
        raise ValueError('PNG color metadata requires a reviewed color-preserving workflow')
    if image.getexif().get(274, 1) != 1 and any(
            key in image.info for key in ('xmp', 'XML:com.adobe.xmp')):
        raise ValueError('combined EXIF/XMP orientation metadata requires reviewed normalization')
    if getattr(image, 'n_frames', 1) != 1:
        raise ValueError('multi-frame image requires explicit reviewed frame extraction')
    bits = getattr(image, 'tag_v2', {}).get(258, (8,))
    if isinstance(bits, int):
        bits = (bits,)
    if image.mode not in ('1', 'L', 'LA', 'P', 'RGB', 'RGBA') or max(bits) > 8:
        raise ValueError('unsupported image depth or mode; preserve original intensities')
    if image.info.get('icc_profile'):
        from PIL import ImageCms
        profile = ImageCms.ImageCmsProfile(io.BytesIO(image.info['icc_profile']))
        if image.mode not in ('RGB', 'RGBA') or profile.profile.xcolor_space.strip() != 'RGB':
            raise ValueError('unsupported color-profile conversion; retain original profile')
    if 'dpi' in image.info:
        dpi = image.info['dpi']
        if len(dpi) != 2 or any(not math.isfinite(v) or v <= 0 for v in dpi):
            raise ValueError('invalid image density metadata')


def flatten_to_rgb(image, invert=False):
    from PIL import Image, ImageOps
    inspect_image(image)
    oriented = ImageOps.exif_transpose(image)
    if 'A' in oriented.getbands() or 'transparency' in oriented.info:
        rgba = oriented.convert('RGBA')
        with Image.new('RGBA', rgba.size, 'white') as background:
            result = Image.alpha_composite(background, rgba).convert('RGB')
        rgba.close()
    else:
        result = oriented.convert('RGB')
    oriented.close()
    if invert:
        result = ImageOps.invert(result)
    return result


def stats_pil(path):
    from PIL import Image
    with Image.open(path) as image:
        mode = image.mode
        with flatten_to_rgb(image) as rgb:
            rgb.thumbnail((256, 256))
            data = rgb.tobytes()
    count = max(len(data) // 3, 1)
    return (sum(data) / (3 * count), sum(
        all(v < 18 for v in data[i:i + 3]) for i in range(0, len(data), 3)) / count, mode)


def flatten_pil(source, destination, invert):
    from PIL import Image, PngImagePlugin
    with Image.open(source) as image:
        inspect_image(image)
        options = {key: image.info[key] for key in ('icc_profile', 'dpi') if key in image.info}
        xmp = image.info.get('xmp', image.info.get('XML:com.adobe.xmp'))
        if xmp is not None:
            metadata = PngImagePlugin.PngInfo()
            metadata.add_itxt('XML:com.adobe.xmp', xmp.decode('utf-8') if isinstance(xmp, bytes) else xmp)
            options['pnginfo'] = metadata
        exif = Image.Exif()
        exif.load(image.getexif().tobytes())
        orientation = exif.get(274, 1)
        if orientation in (5, 6, 7, 8) and 'dpi' in options:
            options['dpi'] = tuple(reversed(options['dpi']))
        if 274 in exif:
            del exif[274]
        if exif:
            options['exif'] = exif.tobytes()
        with flatten_to_rgb(image, invert) as prepared:
            prepared.save(destination, format='PNG', **options)
            with Image.open(destination) as check:
                check.load()
                if check.mode != 'RGB' or check.size != prepared.size or check.tobytes() != prepared.tobytes():
                    raise ValueError('staged PNG failed decoded-pixel validation')
                if check.info.get('icc_profile') != options.get('icc_profile'):
                    raise ValueError('staged PNG lost color profile')
                if xmp is not None and check.info.get('xmp') != (xmp if isinstance(xmp, bytes) else xmp.encode('utf-8')):
                    raise ValueError('staged PNG lost XMP metadata')
                if 'dpi' in options and any(abs(a - b) > 0.02 for a, b in zip(check.info.get('dpi', (0, 0)), options['dpi'])):
                    raise ValueError('staged PNG lost sampling density')


def is_dark(mean, black):
    return mean < DARK_MEAN and black >= DARK_BLACK_FRAC


def prepare_plan(files, invert_dark):
    from PIL import Image
    plan, destinations = [], set()
    for source in files:
        destination = source if source.suffix.lower() == '.png' else source.with_suffix('.png')
        key = str(destination.resolve()).casefold()
        if key in destinations:
            raise ValueError('image destination collision')
        destinations.add(key)
        for sibling in destination.parent.iterdir():
            if sibling.name.casefold() == destination.name.casefold() and sibling != destination:
                raise ValueError('case-insensitive image destination collision')
        validate_destination(destination, [other for other in files if other != source])
        if destination != source and destination.exists():
            raise ValueError('converted PNG destination already exists')
        with Image.open(source) as image:
            inspect_image(image)
            alpha = 'A' in image.getbands() or 'transparency' in image.info
            orientation = image.getexif().get(274, 1)
            mode = image.mode
        mean, black, _ = stats_pil(source)
        invert = invert_dark and is_dark(mean, black)
        if not invert and not alpha and mode == 'RGB' and orientation == 1 and source.suffix.lower() == '.png':
            continue
        backup = source.with_name(source.name + '.orig') if source == destination else None
        if backup is not None:
            validate_destination(backup, files)
            if backup.exists() and backup.read_bytes() != source.read_bytes():
                raise ValueError('existing original differs from current input; review before another transformation')
        plan.append((source, destination, backup, invert))
    return plan


def main(argv):
    parser = argparse.ArgumentParser(prog='prepare-figures.py')
    parser.add_argument('paths', nargs='+', type=Path)
    parser.add_argument('--check', action='store_true', help='inspect without changing image files')
    parser.add_argument('--invert-dark', action='store_true', help='invert reviewed dark figures')
    args = parser.parse_args(argv)
    if not have_pil():
        print('prepare-figures: Pillow required; faithful inspection unavailable', file=sys.stderr)
        return 2
    files = iter_images(args.paths)
    if not files:
        print('prepare-figures: no images', file=sys.stderr)
        return 1
    if args.check:
        from PIL import Image
        findings = 0
        for source in files:
            mean, black, mode = stats_pil(source)
            with Image.open(source) as image:
                alpha = 'A' in image.getbands() or 'transparency' in image.info
            dark = is_dark(mean, black)
            reviewed = reviewed_dark_original(source) if dark else False
            problem = alpha or (dark and not reviewed)
            findings += bool(problem)
            print(f'prepare-figures: {"review" if problem else "ok"} mode={mode} alpha={alpha} dark={dark} reviewed={reviewed}')
            if dark and not reviewed:
                print('prepare-figures: compare with the source; preserve legitimate darkness using a hash-bound .review.json', file=sys.stderr)
        return int(findings > 0)
    plan = prepare_plan(files, args.invert_dark)
    entries = []
    with ExitStack() as stack:
        for source, destination, backup, invert in plan:
            stage_dir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='.revayat-images-', dir=source.parent)))
            stage = stage_dir / 'figure.png'
            flatten_pil(source, stage, invert)
            if backup is not None and not backup.exists():
                original = stage_dir / 'original'
                shutil.copy2(source, original)
                if original.read_bytes() != source.read_bytes():
                    raise ValueError('source changed during original backup')
                entries.append((original, backup))
            entries.append((stage, destination))
        replaced = {source for source, destination, _, _ in plan if source == destination}
        protected = [p for p in files if p not in replaced]
        protected.extend(backup for _, _, backup, _ in plan if backup is not None and backup.exists())
        publish_files(entries, protected_sources=protected)
    print(f'prepare-figures: prepared={len(plan)} unchanged={len(files) - len(plan)}')
    return 0


if __name__ == '__main__':
    try:
        with operation_log('prepare-figures', Path(__file__).resolve().parent / 'logs') as log:
            result = main(sys.argv[1:])
            log.info('exit_code=%d', result)
        raise SystemExit(result)
    except (OSError, ValueError, RuntimeError) as error:
        print(f'prepare-figures: {error}', file=sys.stderr)
        raise SystemExit(2)
