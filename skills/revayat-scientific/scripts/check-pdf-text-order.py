#!/usr/bin/env python3
"""Check Persian extraction order with PyMuPDF, honoring PDF ActualText.

Compare source phrases with unsorted PyMuPDF text extraction. This measures
that extractor's output, not every viewer's clipboard. Poppler's pdftotext
adds bidi controls and can reverse RTL fragments even with -raw, so stripping
those controls does not reveal the PDF's stored Unicode order.

Usage:
    check-pdf-text-order.py doc.pdf --source doc.tex
    check-pdf-text-order.py --extracted dump.txt --source doc.tex

Exit 0: logical order, or not enough evidence.
Exit 1: usage / missing tools.
Exit 2: source phrases are reversed in this extractor's output.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from tex_source import source_closure, plain_tex
from html_source import ParsedHTML
from runtime import operation_log
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

MAX_PROBE_STEPS = 2_000_000

ARABIC_WORD = re.compile(
    r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF"
    r"\uFB50-\uFDFF\uFE70-\uFEFF\u200c]+"
)
_BIDI_MARKS = dict.fromkeys(
    map(
        ord,
        "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069",
    )
)


def strip_bidi(s: str) -> str:
    return s.translate(_BIDI_MARKS)


def fold(s: str) -> str:
    s = unicodedata.normalize('NFKC', s)
    return re.sub(r"\s+", "", strip_bidi(s).replace("\u200c", ""))


def strip_tex(text: str) -> str:
    return plain_tex(text)


def strip_html(text: str) -> str:
    return ParsedHTML(text).text_content()


def source_plain(path: Path, text: str | None = None) -> str:
    if text is None:
        text = source_closure(path).text if path.suffix.lower() in {".tex", ".ltx"} else path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".tex", ".ltx"}:
        return strip_tex(text)
    if suffix in {".html", ".htm"}:
        return strip_html(text)
    return text


def persian_windows(plain: str, min_letters: int = 12) -> list[list[str]]:
    if type(min_letters) is not int or not 1 <= min_letters <= 4096:
        raise ValueError('minimum probe length must be an integer from 1 to 4096')
    # Empty folded tokens only duplicate the next legacy window. Filtering them
    # lets a monotonic end cursor replace repeated full-suffix copies and scans.
    words = [word for raw in ARABIC_WORD.findall(plain) if (word := fold(raw))]
    windows, seen = [], set()
    end = letters = steps = 0
    for start in range(len(words)):
        while letters < min_letters and end < len(words):
            letters += len(words[end])
            end += 1
            steps += 1
        if letters < min_letters:
            break
        steps += end - start
        if steps > MAX_PROBE_STEPS:
            raise ValueError('text-order probe work limit exceeded; check bounded document parts')
        acc = words[start:end]
        key = tuple(acc)
        if key not in seen:
            seen.add(key)
            windows.append(acc)
        letters -= len(words[start])
    return windows


def classify(
    windows: list[list[str]], extracted: str, min_letters: int = 12
) -> str:
    hay = fold(extracted)
    if not hay or not windows:
        return "inconclusive"
    logical = visual = 0
    for acc in windows:
        logi = "".join(acc)
        if len(logi) < min_letters:
            continue
        char_vis = logi[::-1]
        word_vis = "".join(reversed(acc))
        in_log = logi in hay
        in_vis = (char_vis in hay and char_vis != logi) or (
            word_vis in hay and word_vis != logi
        )
        if in_log and not in_vis:
            logical += 1
        elif in_vis and not in_log:
            visual += 1
    if visual >= 1 and visual > logical:
        return "visual"
    if logical >= 1 and logical > visual:
        return "logical"
    return "inconclusive"


def pdf_text(pdf: Path) -> str:
    if importlib.util.find_spec('pymupdf') is None:
        print('check-pdf-text-order: PyMuPDF is required; install the skill requirements',
              file=sys.stderr)
        sys.exit(1)
    code = (
        'import sys,pymupdf; sys.stdout.reconfigure(encoding="utf-8"); '
        'doc=pymupdf.open(sys.argv[1]); '
        'print("\\f".join(page.get_text("text", sort=False) for page in doc),end=""); '
        'doc.close()'
    )
    try:
        proc = subprocess.run(
            [sys.executable, '-c', code, str(pdf)],
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        print("check-pdf-text-order: PyMuPDF extraction timed out", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("check-pdf-text-order: Python extractor could not start",
              file=sys.stderr)
        sys.exit(1)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        print(f"check-pdf-text-order: PyMuPDF extraction failed: {err}", file=sys.stderr)
        sys.exit(1)
    return proc.stdout or ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("pdf", nargs="?", type=Path, help="PDF to inspect")
    ap.add_argument("--source", type=Path, required=True,
                    help="print source (.tex or .html)")
    ap.add_argument("--extracted", type=Path,
                    help="classify an already extracted text dump")
    ap.add_argument("--min-letters", type=int, default=12)
    ap.add_argument("--json", action="store_true", help="write structured verification status to stdout")
    args = ap.parse_args()

    if not args.source.is_file():
        print(f"check-pdf-text-order: not a file: {args.source}", file=sys.stderr)
        return 1
    if args.extracted is None and args.pdf is None:
        print("check-pdf-text-order: pass a PDF or --extracted", file=sys.stderr)
        return 1

    try:
        plain = source_plain(args.source)
        windows = persian_windows(plain, min_letters=args.min_letters)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"check-pdf-text-order: source closure failed: {error}", file=sys.stderr)
        return 1
    if args.extracted is not None:
        extracted = args.extracted.read_text(encoding="utf-8")
    else:
        if not args.pdf.is_file():
            print(f"check-pdf-text-order: not a file: {args.pdf}", file=sys.stderr)
            return 1
        extracted = pdf_text(args.pdf)

    kind = classify(windows, extracted, min_letters=args.min_letters)
    n = len(windows)
    if args.json:
        print(json.dumps({"check": "text-order", "status": "passed" if kind == "logical" else "failed" if kind == "visual" else "inconclusive", "order": kind, "probes": n}))
        return 0 if kind == "logical" else 2 if kind == "visual" else 3
    print(
        f"check-pdf-text-order: {kind} ({n} Persian phrase probes)",
        file=sys.stderr,
    )
    if kind == "visual":
        print(
            "check-pdf-text-order: PyMuPDF extraction is visual order; "
            "selectable Persian is not verified. Check the font and ActualText mapping.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    with operation_log('check-pdf-text-order', Path(__file__).resolve().parent / 'logs') as logger:
        result = main()
        logger.info('exit_code=%d', result)
    sys.exit(result)
