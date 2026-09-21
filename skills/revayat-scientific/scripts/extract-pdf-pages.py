#!/usr/bin/env python3
"""Extract a contiguous PDF page range without duplicating shared XObjects.

Looping insert_pdf (or pdfseparate + a naive merge) one page at a time
copies every image and font onto every page. A 2 MB WeasyPrint file
becomes tens of megabytes that way. Always extract the range in one call.

Usage:
    extract-pdf-pages.py in.pdf out.pdf 1-20
    extract-pdf-pages.py in.pdf out.pdf --from 1 --to 20

Needs PyMuPDF (`pip install pymupdf`). Exit 2 if it is missing.
Page numbers are 1-based and inclusive.
"""
from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

from publication import publish_files, validate_destination
from runtime import operation_log


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("src", type=Path, help="source PDF")
    ap.add_argument("dest", type=Path, help="output PDF")
    ap.add_argument(
        "range",
        nargs="?",
        help="inclusive 1-based range, e.g. 1-20 or 5",
    )
    ap.add_argument("--from", dest="first", type=int, help="first page (1-based)")
    ap.add_argument("--to", dest="last", type=int, help="last page (1-based)")
    args = ap.parse_args(argv)

    first = args.first
    last = args.last
    if args.range:
        if first is not None or last is not None:
            ap.error('choose either positional range or --from/--to')
        match = re.fullmatch(r'([1-9][0-9]*)(?:-([1-9][0-9]*))?', args.range)
        if match is None:
            ap.error('range must contain positive integer page numbers')
        first = int(match[1])
        last = int(match[2] or match[1])
    if first is None or last is None:
        ap.error("need a range (1-20) or --from and --to")
    if first < 1 or last < first:
        ap.error("pages are 1-based and --from must be <= --to")

    try:
        import pymupdf
    except ImportError:
        print("extract-pdf-pages.py: PyMuPDF is required (pip install pymupdf)",
              file=sys.stderr)
        return 2

    if not args.src.is_file():
        print(f"extract-pdf-pages.py: not a file: {args.src}", file=sys.stderr)
        return 1

    validate_destination(args.dest, [args.src])
    with pymupdf.open(args.src) as src:
        if not src.is_pdf or src.needs_pass:
            raise ValueError('source must be an unlocked PDF')
        if last > src.page_count:
            raise ValueError('requested page range exceeds source page count')
        expected = [tuple(src[number].rect) for number in range(first - 1, last)]
        args.dest.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.revayat-pages-', dir=args.dest.parent) as directory:
            stage = Path(directory) / 'pages.pdf'
            with pymupdf.open() as out:
                # One range keeps shared XObjects; never insert one page at a time.
                out.insert_pdf(src, from_page=first - 1, to_page=last - 1)
                out.save(stage, garbage=4, deflate=True, clean=True)
            with pymupdf.open(stage) as reopened:
                if not reopened.is_pdf or reopened.needs_pass or reopened.page_count != last - first + 1:
                    raise ValueError('staged extraction failed PDF validation')
                if [tuple(page.rect) for page in reopened] != expected:
                    raise ValueError('staged extraction changed page geometry')
            publish_files([(stage, args.dest)], protected_sources=[args.src])
    print(f"wrote {args.dest} pages {first}-{last}")
    return 0


if __name__ == "__main__":
    try:
        with operation_log('extract-pdf-pages', Path(__file__).resolve().parent / 'logs') as log:
            result = main()
            log.info('exit_code=%d', result)
        sys.exit(result)
    except Exception as error:
        print(f'extract-pdf-pages: failed ({type(error).__name__}): {error}', file=sys.stderr)
        sys.exit(2)
