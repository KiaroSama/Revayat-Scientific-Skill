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
import sys
from pathlib import Path


def main() -> int:
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
    args = ap.parse_args()

    first = args.first
    last = args.last
    if args.range:
        if "-" in args.range:
            a, b = args.range.split("-", 1)
            first = int(a)
            last = int(b)
        else:
            first = last = int(args.range)
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

    src = pymupdf.open(args.src)
    n = src.page_count
    if last > n:
        print(f"extract-pdf-pages.py: {args.src} has {n} pages, not {last}",
              file=sys.stderr)
        src.close()
        return 1

    out = pymupdf.open()
    # One range: keeps shared XObjects. Do not loop insert_pdf per page.
    out.insert_pdf(src, from_page=first - 1, to_page=last - 1)
    args.dest.parent.mkdir(parents=True, exist_ok=True)
    out.save(args.dest, garbage=4, deflate=True, clean=True)
    out.close()
    src.close()
    print(f"wrote {args.dest} pages {first}-{last}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
