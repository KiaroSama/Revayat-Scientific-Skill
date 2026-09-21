#!/usr/bin/env python3
"""Crop figure artwork out of a source PDF. Never ship a full source page.

A pdftoppm of page N is ground truth for *what the figure looks like*, not
a file you embed. Embedding that PNG puts English running headers, body
text, and page numbers into the Persian print PDF.

Usage:
    crop-source-figures.py source/doc.pdf --out figures/artwork \\
        --map figures-map.tsv
    crop-source-figures.py source/doc.pdf --out figures/artwork \\
        --cover --author-page 18

Map TSV columns (header optional): figure_id, pdf_page
Two rows with the same pdf_page become two crops, top to bottom.

Needs PyMuPDF (`pip install pymupdf`). Exit 2 if it is missing.
"""
from __future__ import annotations

import argparse
import csv
import math
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from publication import publish_files, validate_destination
from runtime import operation_log

HEADER_PT = 40.0
FOOTER_PT = 36.0
CLUSTER_GAP = 28.0
PAD_PT = 12.0
LABEL_SLACK_PT = 72.0
MAX_CROP_PIXELS = 50_000_000


def _pymupdf():
    try:
        import pymupdf
        return pymupdf
    except ImportError:
        print(
            "crop-source-figures: need PyMuPDF (pip install pymupdf)",
            file=sys.stderr,
        )
        sys.exit(2)


def collect_rects(page, pymupdf) -> list:
    rects = []
    for info in page.get_image_info():
        r = pymupdf.Rect(info["bbox"])
        if r.width < 8 or r.height < 4:
            continue
        rects.append(r)
    for d in page.get_drawings():
        r = d.get("rect")
        if r is None or r.width * r.height < 80:
            continue
        rects.append(pymupdf.Rect(r))
    return rects


def cluster(rects: list, pymupdf, gap: float = CLUSTER_GAP) -> list:
    items = [pymupdf.Rect(r) for r in rects]
    groups = []
    # Components use actual pairwise adjacency, not a growing union's empty area.
    while items:
        group = [items.pop()]
        cursor = 0
        while cursor < len(group):
            current = group[cursor]
            for index in range(len(items) - 1, -1, -1):
                other = items[index]
                if (current.x0 <= other.x1 + gap and other.x0 <= current.x1 + gap
                        and current.y0 <= other.y1 + gap and other.y0 <= current.y1 + gap):
                    group.append(items.pop(index))
            cursor += 1
        groups.append(group)
    out = []
    for g in groups:
        u = pymupdf.Rect(g[0])
        for x in g[1:]:
            u |= x
        if u.width < 40 and u.height < 24:
            continue
        out.append(u)
    return sorted(out, key=lambda r: (r.y0, r.x0))


def pad_clip(page, r, pymupdf, pad: float = PAD_PT):
    clip = (r + (-pad, -pad, pad, pad)) & page.rect
    # Axis labels and $$$ annotations often sit just outside image x1.
    clip.x1 = min(page.rect.x1, clip.x1 + LABEL_SLACK_PT)
    return clip


def crop_dpi(page, clip, pymupdf, minimum: int) -> int:
    """Retain raster sampling along both image axes, including rotated images."""
    density = float(minimum)
    for info in page.get_image_info():
        if not pymupdf.Rect(info['bbox']).intersects(clip):
            continue
        a, b, c, d, _, _ = info['transform']
        width_pt, height_pt = math.hypot(a, b), math.hypot(c, d)
        if width_pt <= 0 or height_pt <= 0:
            raise ValueError('image has invalid placement dimensions')
        density = max(density, 72 * info['width'] / width_pt,
                      72 * info['height'] / height_pt)
    if not math.isfinite(density):
        raise ValueError('image has invalid sampling density')
    return math.ceil(density)


def render_clip(page, clip, dest: Path, pymupdf, dpi: int = 300) -> None:
    if (not all(math.isfinite(value) for value in clip) or clip.is_empty
            or not page.rect.contains(clip)):
        raise ValueError('crop rectangle must be finite, nonempty and inside the page')
    dpi = crop_dpi(page, clip, pymupdf, dpi)
    width = math.ceil(clip.width * dpi / 72) + 2
    height = math.ceil(clip.height * dpi / 72) + 2
    if width <= 0 or height <= 0 or width * height > MAX_CROP_PIXELS:
        raise ValueError('crop exceeds 50 million pixels; extract the original asset '
                         'or choose a smaller faithful crop instead of downsampling')
    dest.parent.mkdir(parents=True, exist_ok=True)
    pix = page.get_pixmap(dpi=dpi, clip=clip, alpha=False)
    pix.save(dest)
    check = pymupdf.Pixmap(dest)
    if (check.width, check.height, check.samples) != (pix.width, pix.height, pix.samples):
        raise ValueError('staged crop failed decoded-pixel validation')
    print(f'raster dpi={dpi} pixels={pix.width}x{pix.height}')


def pick_clusters(clusters: list, n: int) -> list:
    if n <= 0 or len(clusters) != n:
        raise ValueError('ambiguous figure boundaries; supply reviewed x0,y0,x1,y1 map columns')
    return sorted(clusters, key=lambda r: r.y0)


def load_map(path: Path) -> dict:
    """Strict CSV/TSV with optional reviewed page-space rectangle columns."""
    text = path.read_text(encoding='utf-8-sig')
    if not text.strip():
        raise ValueError('crop map is empty')
    delimiter = '\t' if '\t' in text.splitlines()[0] else ','
    rows = csv.reader(text.splitlines(), delimiter=delimiter, strict=True)
    by_page: dict[int, list[str]] = defaultdict(list)
    header, seen, width = None, set(), None
    for row in rows:
        line = rows.line_num
        if not row or all(not c.strip() for c in row):
            raise ValueError(f'crop map row {line}: empty row')
        cells = [c.strip() for c in row]
        if line == 1 and cells[0] == 'figure_id':
            header = cells
            if header not in (['figure_id', 'pdf_page'], ['figure_id', 'printed', 'pdf_page'],
                              ['figure_id', 'pdf_page', 'x0', 'y0', 'x1', 'y1']):
                raise ValueError('unsupported crop map header')
            width = len(header)
            continue
        if width is None:
            width = len(cells)
        if len(cells) != width or width not in (2, 3, 6) or (width == 6 and header is None):
            raise ValueError(f'crop map row {line}: invalid column count')
        fid = cells[0]
        if (not fid or fid.endswith(('.', ' ')) or fid in ('.', '..')
                or any(char in fid for char in '/\\:*?"<>|') or any(ord(char) < 32 for char in fid)):
            raise ValueError(f'crop map row {line}: unsafe figure_id')
        if fid.casefold() in seen:
            raise ValueError(f'crop map row {line}: duplicate figure_id')
        seen.add(fid.casefold())
        page_s = cells[1] if width == 6 else cells[-1]
        if not re.fullmatch(r'[1-9][0-9]*', page_s):
            raise ValueError(f'crop map row {line}: pdf_page must be a positive integer')
        rectangle = None
        if width == 6:
            rectangle = tuple(float(value) for value in cells[2:])
            if (not all(math.isfinite(value) for value in rectangle)
                    or rectangle[0] >= rectangle[2] or rectangle[1] >= rectangle[3]):
                raise ValueError(f'crop map row {line}: invalid rectangle')
        by_page[int(page_s)].append((fid, rectangle))
    if not by_page:
        raise ValueError('crop map contains no figures')
    return dict(by_page)


def crop_cover(page, dest: Path, pymupdf, dpi: int = 300) -> None:
    """Illustration only: drop title-plate chrome (spine, gold title, logo)."""
    infos = page.get_image_info()
    page_area = page.rect.width * page.rect.height
    candidates = []
    for info in infos:
        r = pymupdf.Rect(info["bbox"])
        area = r.width * r.height
        if area < 80 or area > 0.55 * page_area:
            continue
        candidates.append(r)
    if len(candidates) != 1:
        raise ValueError('ambiguous cover illustration; use a reviewed crop-map rectangle')
    clip = pad_clip(page, candidates[0], pymupdf, 4)
    render_clip(page, clip, dest, pymupdf, dpi)
    print(f"cover {dest.name} {clip}")


def crop_author(page, dest: Path, pymupdf, dpi: int = 300) -> None:
    infos = page.get_image_info()
    if not infos:
        print("crop-source-figures: no image on author page", file=sys.stderr)
        sys.exit(1)
    page_area = page.rect.width * page.rect.height
    usable = []
    for info in infos:
        r = pymupdf.Rect(info["bbox"])
        if r.width * r.height > 0.5 * page_area:
            continue
        if r.width < 24 or r.height < 24:
            continue
        usable.append(r)
    if len(usable) != 1:
        raise ValueError('ambiguous author photo; use a reviewed crop-map rectangle')
    best = usable[0]
    clip = pad_clip(page, best, pymupdf, 2)
    clip.x1 = min(page.rect.x1, best.x1 + 4)
    clip.x0 = max(page.rect.x0, best.x0 - 2)
    render_clip(page, clip, dest, pymupdf, dpi)
    print(f"author {dest.name} {clip}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="crop-source-figures.py")
    ap.add_argument("pdf", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--map", type=Path, help="TSV: figure_id, pdf_page")
    ap.add_argument("--cover", action="store_true",
                    help="write cover-illustration.png from PDF page 1")
    ap.add_argument("--cover-page", type=int, default=1)
    ap.add_argument("--author-page", type=int, default=0,
                    help="1-based PDF page of the author photo")
    ap.add_argument("--dpi", type=int, default=300,
                    help="minimum raster DPI, 72-2400; preserve higher source density (default: 300)")
    args = ap.parse_args(argv)
    if not 72 <= args.dpi <= 2400:
        ap.error('--dpi must be between 72 and 2400')

    if not args.pdf.is_file():
        print(f"crop-source-figures: not a file: {args.pdf}", file=sys.stderr)
        return 2
    if not args.map and not args.cover and not args.author_page:
        print("crop-source-figures: need --map, --cover, or --author-page",
              file=sys.stderr)
        return 2

    pymupdf = _pymupdf()
    doc = pymupdf.open(args.pdf)
    try:
        return crop_document(doc, args, pymupdf)
    finally:
        doc.close()


def crop_document(doc, args, pymupdf) -> int:
    if doc.needs_pass:
        raise ValueError('encrypted PDF requires an unlocked source')
    by_page = load_map(args.map) if args.map else {}
    requested = ([args.cover_page] if args.cover else []) + ([args.author_page] if args.author_page else [])
    if any(page < 1 or page > doc.page_count for page in [*requested, *by_page]):
        raise ValueError('requested PDF page is out of range')
    # Normalize only the in-memory coordinate system; never save over the source PDF.
    for page in doc:
        if page.rotation:
            page.remove_rotation()
    planned = []
    for number, figures in sorted(by_page.items()):
        page = doc[number - 1]
        explicit = [rectangle is not None for _, rectangle in figures]
        if any(explicit) and not all(explicit):
            raise ValueError('one PDF page cannot mix automatic and explicit crop rectangles')
        rectangles = ([pymupdf.Rect(rectangle) for _, rectangle in figures] if all(explicit)
                      else [pad_clip(page, rectangle, pymupdf) for rectangle in
                            pick_clusters(cluster(collect_rects(page, pymupdf), pymupdf), len(figures))])
        for (fid, _), rectangle in zip(figures, rectangles):
            if not all(math.isfinite(value) for value in rectangle) or rectangle.is_empty or not page.rect.contains(rectangle):
                raise ValueError('reviewed rectangle must be finite and entirely inside the page')
            planned.append((number, rectangle, args.out / f'fig-{fid}.png'))
    specials = []
    if args.cover:
        specials.append((crop_cover, args.cover_page, args.out / 'cover-illustration.png'))
    if args.author_page:
        specials.append((crop_author, args.author_page, args.out / 'author.png'))
    destinations = [dest for _, _, dest in [*planned, *specials]]
    protected = [args.pdf] + ([args.map] if args.map else [])
    for destination in destinations:
        validate_destination(destination, protected)
        if destination.parent.exists():
            for sibling in destination.parent.iterdir():
                if sibling.name.casefold() == destination.name.casefold() and sibling != destination:
                    raise ValueError('case-insensitive crop destination collision')
    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.revayat-crops-', dir=args.out) as directory:
        staging, entries = Path(directory), []
        for number, rectangle, destination in planned:
            stage = staging / destination.name
            render_clip(doc[number - 1], rectangle, stage, pymupdf, args.dpi)
            entries.append((stage, destination))
        for cropper, number, destination in specials:
            stage = staging / destination.name
            cropper(doc[number - 1], stage, pymupdf, args.dpi)
            entries.append((stage, destination))
        publish_files(entries, protected_sources=protected)
    print(f'crop-source-figures: published={len(destinations)}')
    return 0


if __name__ == "__main__":
    try:
        with operation_log('crop-source-figures', Path(__file__).resolve().parent / 'logs') as log:
            result = main(sys.argv[1:])
            log.info('exit_code=%d', result)
        raise SystemExit(result)
    except (OSError, ValueError, RuntimeError, csv.Error) as error:
        print(f'crop-source-figures: {error}', file=sys.stderr)
        raise SystemExit(2)
