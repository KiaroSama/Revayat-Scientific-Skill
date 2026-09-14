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
import html as html_mod
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

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
    return re.sub(r"\s+", "", strip_bidi(s).replace("\u200c", ""))


def strip_tex(text: str) -> str:
    lines = []
    for line in text.splitlines():
        out = []
        i = 0
        while i < len(line):
            if line[i] == "%" and (i == 0 or line[i - 1] != "\\"):
                break
            out.append(line[i])
            i += 1
        lines.append("".join(out))
    text = "\n".join(lines)
    text = re.sub(
        r"\\begin\{latin\}.*?\\end\{latin\}", " ", text, flags=re.S
    )
    for _ in range(8):
        nxt = re.sub(
            r"\\(?:lr|en|texttt|textbf|textit)\{([^{}]*)\}", " ", text
        )
        if nxt == text:
            break
        text = nxt
    text = re.sub(r"\\[a-zA-Z@]+\*?(?:\[[^\]]*\])?", " ", text)
    return re.sub(r"[{}\\]", " ", text)


def strip_html(text: str) -> str:
    text = re.sub(r"(?is)<script\b.*?</script>", " ", text)
    text = re.sub(r"(?is)<style\b.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return html_mod.unescape(text)


def source_plain(path: Path, text: str | None = None) -> str:
    if text is None:
        text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".tex", ".ltx"}:
        return strip_tex(text)
    if suffix in {".html", ".htm"}:
        return strip_html(text)
    return text


def persian_windows(plain: str, min_letters: int = 12) -> list[list[str]]:
    words = [fold(w) for w in ARABIC_WORD.findall(plain)]
    windows: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for i in range(len(words)):
        letters = 0
        acc: list[str] = []
        for w in words[i:]:
            if not w:
                continue
            acc.append(w)
            letters += len(w)
            if letters >= min_letters:
                key = tuple(acc)
                if key not in seen:
                    seen.add(key)
                    windows.append(acc)
                break
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
    args = ap.parse_args()

    if not args.source.is_file():
        print(f"check-pdf-text-order: not a file: {args.source}", file=sys.stderr)
        return 1
    if args.extracted is None and args.pdf is None:
        print("check-pdf-text-order: pass a PDF or --extracted", file=sys.stderr)
        return 1

    plain = source_plain(args.source)
    windows = persian_windows(plain, min_letters=args.min_letters)
    if args.extracted is not None:
        extracted = args.extracted.read_text(encoding="utf-8")
    else:
        if not args.pdf.is_file():
            print(f"check-pdf-text-order: not a file: {args.pdf}", file=sys.stderr)
            return 1
        extracted = pdf_text(args.pdf)

    kind = classify(windows, extracted, min_letters=args.min_letters)
    n = len(windows)
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
    sys.exit(main())
