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
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

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
    h = page.rect.height
    rects = []
    for info in page.get_image_info():
        r = pymupdf.Rect(info["bbox"])
        if r.width < 8 or r.height < 4:
            continue
        if r.y1 < HEADER_PT or r.y0 > h - FOOTER_PT:
            continue
        rects.append(r)
    for d in page.get_drawings():
        r = d.get("rect")
        if r is None or r.width * r.height < 80:
            continue
        if r.y1 < HEADER_PT or r.y0 > h - FOOTER_PT:
            continue
        rects.append(pymupdf.Rect(r))
    return rects


def cluster(rects: list, pymupdf, gap: float = CLUSTER_GAP) -> list:
    if not rects:
        return []
    items = sorted(rects, key=lambda r: (r.y0, r.x0))
    groups: list[list] = []
    for r in items:
        placed = False
        for g in groups:
            u = g[0]
            for x in g[1:]:
                u |= x
            close_y = r.y0 <= u.y1 + gap and u.y0 <= r.y1 + gap
            close_x = r.x0 <= u.x1 + gap and u.x0 <= r.x1 + gap
            if close_y and close_x:
                g.append(r)
                placed = True
                break
        if not placed:
            groups.append([r])
    out = []
    for g in groups:
        u = g[0]
        for x in g[1:]:
            u |= x
        if u.width < 40 and u.height < 24:
            continue
        out.append(u)
    return out


def pad_clip(page, r, pymupdf, pad: float = PAD_PT):
    clip = (r + (-pad, -pad, pad, pad)) & page.rect
    # Axis labels and $$$ annotations often sit just outside image x1.
    clip.x1 = min(page.rect.x1 - 28, clip.x1 + LABEL_SLACK_PT)
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
    dpi = crop_dpi(page, clip, pymupdf, dpi)
    width = math.ceil(clip.width * dpi / 72) + 2
    height = math.ceil(clip.height * dpi / 72) + 2
    if width <= 0 or height <= 0 or width * height > MAX_CROP_PIXELS:
        raise ValueError('crop exceeds 50 million pixels; extract the original asset '
                         'or choose a smaller faithful crop instead of downsampling')
    dest.parent.mkdir(parents=True, exist_ok=True)
    pix = page.get_pixmap(dpi=dpi, clip=clip, alpha=False)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=dest.parent, suffix='.png', delete=False) as handle:
            temporary = Path(handle.name)
        pix.save(temporary)
        os.replace(temporary, dest)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print(f'raster dpi={dpi} pixels={pix.width}x{pix.height}')


def pick_clusters(clusters: list, n: int) -> list:
    if n <= 0:
        return []
    if len(clusters) < n:
        if n == 1 and clusters:
            u = clusters[0]
            for c in clusters[1:]:
                u |= c
            return [u]
        return clusters
    if len(clusters) > n:
        ranked = sorted(clusters, key=lambda r: r.width * r.height, reverse=True)[:n]
        return sorted(ranked, key=lambda r: r.y0)
    return sorted(clusters, key=lambda r: r.y0)


def load_map(path: Path) -> dict[int, list[str]]:
    """TSV/CSV: figure_id, pdf_page  or  figure_id, printed, pdf_page."""
    text = path.read_text(encoding="utf-8")
    dialect = csv.Sniffer().sniff(text[:2048], delimiters="\t,")
    rows = csv.reader(text.splitlines(), dialect)
    by_page: dict[int, list[str]] = defaultdict(list)
    for i, row in enumerate(rows):
        if not row or all(not c.strip() for c in row):
            continue
        cells = [c.strip() for c in row]
        if i == 0 and not any(c.isdigit() for c in cells):
            continue
        if len(cells) < 2:
            continue
        fid = cells[0]
        if (not fid or any(char in fid for char in '/\\:*?"<>|')
                or any(ord(char) < 32 for char in fid)):
            raise ValueError('figure_id must be a filename component without path separators')
        page_s = cells[-1]
        if not page_s.isdigit():
            continue
        by_page[int(page_s)].append(fid)
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
    if candidates:
        clip = pad_clip(page, max(candidates, key=lambda r: r.width * r.height), pymupdf, 4)
    else:
        # Manning-style: art lives on the right of a dark spine + title.
        w, h = page.rect.width, page.rect.height
        clip = pymupdf.Rect(w * 0.50, h * 0.04, w * 0.99, h * 0.96)
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
    best = max(usable or [pymupdf.Rect(info["bbox"]) for info in infos],
               key=lambda r: r.width * r.height)
    clip = pad_clip(page, best, pymupdf, 2)
    clip.x1 = min(page.rect.x1 - 8, best.x1 + 4)  # no label slack on a photo
    clip.x0 = max(page.rect.x0 + 4, best.x0 - 2)
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
    requested = ([args.cover_page] if args.cover else []) + ([args.author_page] if args.author_page else [])
    if any(page < 1 or page > doc.page_count for page in requested):
        raise ValueError('cover or author page is out of range')
    # Normalize only the in-memory coordinate system; never save over the source PDF.
    for page in doc:
        if page.rotation:
            page.remove_rotation()
    args.out.mkdir(parents=True, exist_ok=True)

    if args.cover:
        crop_cover(doc[args.cover_page - 1], args.out / "cover-illustration.png", pymupdf, args.dpi)
    if args.author_page:
        crop_author(doc[args.author_page - 1], args.out / "author.png", pymupdf, args.dpi)

    if args.map:
        by_page = load_map(args.map)
        for pdf_page, fids in sorted(by_page.items()):
            if pdf_page < 1 or pdf_page > doc.page_count:
                print(f"crop-source-figures: page {pdf_page} out of range",
                      file=sys.stderr)
                return 1
            page = doc[pdf_page - 1]
            clusters = pick_clusters(cluster(collect_rects(page, pymupdf), pymupdf),
                                     len(fids))
            if len(clusters) != len(fids):
                print(
                    f"crop-source-figures: pdf page {pdf_page}: "
                    f"{len(clusters)} crop(s) for {fids}",
                    file=sys.stderr,
                )
            for fid, rect in zip(fids, clusters):
                dest = args.out / f"fig-{fid}.png"
                render_clip(page, pad_clip(page, rect, pymupdf), dest, pymupdf, args.dpi)
                print(f"fig {fid} pdf={pdf_page} {dest.name}")
            if len(clusters) < len(fids):
                return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError, csv.Error) as error:
        print(f'crop-source-figures: {error}', file=sys.stderr)
        raise SystemExit(2)
