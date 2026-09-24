#!/usr/bin/env python3
"""fa-lint: mechanical checks for scientific Persian translation output.

Usage:
    check-fa.py FILE [FILE ...] [--level system-docs|journal]
                [--pairs FILE] [--terms FILE] [--strict] [--manifest FILE]

Accepts `.tex` and `.html`/`.htm` sources. Every rule here is one of the
mechanical items from the skill's quality checklist, so the checklist that
stays in SKILL.md is only the part a machine cannot judge. Register
fluency (does the Persian read like normal formal prose?) is a model
judgement in `references/translation-policy.md`, not a pattern list here.

`--level journal` drops house operational-term bans (`گره`, `پیاده‌سازی`,
`مجموعه داده`, …) so a paper that follows terminology.md does not fail.
`--pairs FILE` is added on top of `references/term-pairs.tsv`, never a
replacement. `--terms FILE` reads a job `terms.tsv` (concept-oriented:
required `source/output/step/count/forbidden_fa`, optional
`concept/status/admitted/deprecated`). Keep-English rows must name a
`forbidden_fa` calque; an empty calque column is an error, not a skip.
Pipe-separated `deprecated` forms are also forbidden. `--strict`
requires `--terms` and `--manifest` (or `terms.tsv` / `manifest.txt`
next to the source). English `-s` plurals of kept terms (`services`,
`APIs`) fail; the stem plus ها after the isolate is the surviving form.

Exit codes: 0 clean, 1 findings at error level, 2 usage error.

Suppress one finding by putting `fa-lint: allow <check-id>` (or
`fa-lint: allow all`) in a comment on the same or preceding line.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from document_context import DocumentContext
from runtime import operation_log

# Every finding this tool prints quotes Persian, and on Windows an
# unredirected stdout defaults to the console ANSI code page (cp1252), which
# cannot encode a single Persian letter. The first finding then dies with
# UnicodeEncodeError and every check after it goes unreported - a lint that
# exits non-zero for the wrong reason and hides the rest of its own output.
# Force UTF-8 rather than depending on the locale.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):  # not a TextIOWrapper (test capture)
        pass

ZWNJ = "\u200c"
FA_RANGE = "\u0600-\u06ff\ufb50-\ufdff\ufe70-\ufeff"
FA_CHAR = re.compile(f"[{FA_RANGE}]")

ERROR, WARN = "error", "warn"

# Persian head nouns that, immediately followed by a Latin run, mean the
# source noun phrase was half-translated. Deliberately narrow: heads like
# «الگوریتم Adam» and «معماری transformer» are correct and must not fire.
HALF_TRANSLATION_HEADS = [
    "خوشه",
    "خوشه‌های",
    "سرویس‌های",
    "بسته‌های",
    "بستهٔ",
    "مخزن",
    "مخازن",
    "گره‌های",
    "نیازمندی‌های",
    "جریان‌های",
    "دیوارهای",
    "بلوک",
    "بلوک‌های",
]

# ZWNJ-less spellings of common verb forms. An explicit list avoids the false
# positives a generic «می» rule would produce on میان / میز / میلاد.
ZWNJ_VERBS = [
    "میشود", "میشوند", "میشد", "میکند", "میکنند", "میکنید", "میکنم",
    "میکرد", "میتوان", "میتواند", "میتوانند", "میتوانید", "میدهد",
    "میدهند", "میگیرد", "میگیرند", "میباشد", "میباشند", "میگردد",
    "میرود", "میآید", "میسازد", "میخواهد", "میگوید", "میداند",
    "میآورد", "میماند", "میافتد", "میپردازد", "میکنیم", "میدانیم",
    "نمیشود", "نمیشوند", "نمیکند", "نمیکنند", "نمیتوان", "نمیتواند",
    "نمیدهد", "نمیباشد", "نمیگردد", "نمیآید",
]

# TeX plumbing that is Latin but is not prose: units, float placements,
# environment and size keywords. Excluded from the unisolated-Latin scan.
TEX_STOPWORDS = {
    "pt", "em", "ex", "cm", "mm", "bp", "dd", "cc", "sp", "true",
    "htbp", "htb", "hbp", "tbp", "here", "center", "left", "right",
    "linewidth", "textwidth", "columnwidth", "paperwidth", "paperheight",
    "figure", "table", "tabular", "longtable", "itemize", "enumerate",
    "description", "quote", "quotation", "flushleft", "flushright",
    "small", "footnotesize", "scriptsize", "tiny", "large", "Large",
    "LARGE", "huge", "Huge", "normalsize", "single", "frame", "framesep",
    "fontsize", "baselinestretch", "numbers", "none", "width", "height",
    "scale", "angle", "keepaspectratio", "page", "trim", "clip",
}

# Names and non-plurals that end in s. A regular kept-term plural is the
# singular stem plus ها, but Kubernetes / HTTPS / analysis are not plurals.
EN_PLURAL_EXCEPTIONS = frozenset({
    "windows", "kubernetes", "redis", "postgres", "ios", "macos",
    "https", "http", "tls", "ssl", "aws", "gcs", "nfs", "dns", "bios",
    "cosmos", "analysis", "thesis", "basis", "crisis", "physics",
    "mathematics", "economics", "news", "series", "species", "means",
    "always", "towards", "perhaps", "plus", "minus", "canvas", "atlas",
    "this", "is", "was", "has", "does", "his", "its", "as", "us",
    "across", "process", "access", "address", "status", "bus",
})


def english_plural_stem(word: str) -> str | None:
    """Singular stem if *word* is a regular English plural, else None."""
    if re.fullmatch(r"[A-Z]{2,}s", word):
        return word[:-1]
    if len(word) < 4 or word.isupper():
        return None
    lower = word.lower()
    if lower in EN_PLURAL_EXCEPTIONS:
        return None
    if lower.endswith("ies") and len(word) > 4:
        return word[:-3] + ("Y" if word[-4].isupper() else "y")
    if lower.endswith("es") and len(word) > 4:
        if lower.endswith(("ches", "shes")) or lower[-3] in "sxz":
            return word[:-2]
    if lower.endswith("s") and not lower.endswith("ss"):
        if lower.endswith(("us", "is", "os", "as")):
            return None
        return word[:-1]
    return None


@dataclass
class Finding:
    level: str
    check: str
    line: int
    message: str
    excerpt: str = ""
    path: Path | None = None


from source_model import Source


def fa_pattern(word: str) -> str:
    """Match a Persian term whether it uses ZWNJ or a plain space.

    Bounded by non-Persian so «گره» does not fire inside «کنگره».
    """
    escaped = [re.escape(part) for part in re.split(f"[{ZWNJ} ]", word)]
    body = f"[{ZWNJ} ]?".join(escaped)
    return rf"(?<![{FA_RANGE}])(?:{body})(?![{FA_RANGE}])"


def _joiner_gap(gap: str) -> bool:
    """True when two LTR isolates have only space/punctuation between them."""
    stripped = gap.replace("&nbsp;", " ").replace("->", "")
    return re.fullmatch(r"[\s~/\(\)\[\]\{\}:.,+=<>\-–—]*", stripped) is not None


def check(src: Source, pairs: list[tuple[str, str, str]],
          manifest: list[str] | None, *, level='system-docs') -> list[Finding]:
    out: list[Finding] = []
    text = src.text

    def add(level: str, check_id: str, pos: int, message: str) -> None:
        if src.suppressed(pos, check_id):
            return
        source_path, source_line = src.location(pos)
        out.append(Finding(level, check_id, source_line, message,
                           src.excerpt(pos), source_path))

    def prose_finditer(pattern: str, flags: int = 0):
        for m in re.finditer(pattern, text, flags):
            if not src.is_protected(m.start()):
                yield m

    def live_finditer(pattern: str, flags: int = 0):
        """Structural scan of the raw text, skipping preamble and comments."""
        for m in re.finditer(pattern, text, flags):
            if not src.inert(m.start()):
                yield m

    # 1. Orthography -----------------------------------------------------
    for m in prose_finditer(r"[\u0643\u064a]"):
        name = unicodedata.name(m.group(0), "?")
        add(ERROR, "arabic-letters", m.start(),
            f"Arabic letter {m.group(0)!r} ({name}); use ک / ی")

    for m in prose_finditer(r"[\u06f0-\u06f9\u0660-\u0669\u066B\u066C]"):
        add(ERROR, "eastern-digits", m.start(),
            f"eastern digit or Arabic decimal {m.group(0)!r}; "
            "digits stay Western (3.14)")

    for verb in ZWNJ_VERBS:
        for m in prose_finditer(rf"(?<![{FA_RANGE}]){re.escape(verb)}"):
            add(ERROR, "zwnj-verb", m.start(),
                f"missing ZWNJ in {verb!r}; write "
                f"{verb[:2] + ZWNJ + verb[2:]!r}")

    for m in prose_finditer(rf"[{FA_RANGE}]ه(ها|های|هایی)(?![{FA_RANGE}])"):
        add(ERROR, "zwnj-plural", m.start(),
            f"{m.group(0)!r} looks like a missing ZWNJ before the plural")

    for m in prose_finditer(rf"[{FA_RANGE}]\s?[,;]|[,;]\s?[{FA_RANGE}]"):
        add(ERROR, "latin-punct", m.start(),
            "Latin comma/semicolon in Persian prose; use ، or ؛")

    for m in prose_finditer(rf"[{FA_RANGE}]\s?\?"):
        add(ERROR, "latin-punct", m.start(),
            "Latin question mark in Persian prose; use ؟")

    # 2. Terminology -----------------------------------------------------
    # Longest form first, so «دیوارهای آتش» is reported once rather than also
    # matching a shorter row that overlaps it.
    consumed: list[tuple[int, int]] = []
    for en, fa, scope in sorted(pairs, key=lambda r: -len(r[1])):
        for m in prose_finditer(fa_pattern(fa)):
            if any(s < m.end() and m.start() < e for s, e in consumed):
                continue
            consumed.append((m.start(), m.end()))
            add(ERROR, "forbidden-fa", m.start(),
                f"{m.group(0)!r} is a calque of {en!r} ({scope}); "
                f"keep {en!r} in an LTR isolate")

    heads = "|".join(fa_pattern(h) for h in HALF_TRANSLATION_HEADS)
    latin_start = (r"(?:\\(?:lr|en|textenglish)\s*\{|<span[^>]*>|<bdi>|)"
                   r"\s*[A-Za-z]")
    for m in (prose_finditer(rf"(?:{heads})\s*{latin_start}") if level == 'system-docs' else []):
        add(ERROR, "half-translation", m.start(),
            "Persian head noun in front of an English name; keep the whole "
            "source noun phrase English in one isolate")

    for m in live_finditer(
            rf"(?:\}}|</span>|</bdi>|[A-Za-z])(?!ها)(ی)"
            rf"(?![{FA_RANGE}])"):
        add(ERROR, "fa-morphology", m.start(),
            f"Persian suffix {m.group(1)!r} attached to an English token; "
            "do not add ezafe (Goی). Plurals are ها after the isolate "
            "(serviceها, platformها, APIها)")

    for pos, _end, body in src.isolates:
        if any(start <= pos < end for start, end in src.identity):
            continue
        if "/" in body or "://" in body or "@" in body or "->" in body:
            continue
        for token in re.finditer(r"[A-Za-z]+", body):
            word = token.group(0)
            stem = english_plural_stem(word)
            if stem is None:
                continue
            add(ERROR, "en-plural", pos,
                f"English plural {word!r}; write the singular stem in the "
                f"isolate and Persian ها after it ({stem}ها, not {word})")

    # Adjacent LTR isolates reverse on an RTL page. Compare isolate *ranges*
    # so `\textbf{درست} \en{node}` is not a false split, while
    # `\en{1.0.1}~(\en{2026-08-09})` still is.
    ordered = sorted(src.isolates, key=lambda r: r[0])
    for i in range(len(ordered) - 1):
        _start_a, end_a, _body_a = ordered[i]
        start_b, _end_b, _body_b = ordered[i + 1]
        if start_b <= end_a:
            continue
        gap = text[end_a:start_b]
        if _joiner_gap(gap):
            add(ERROR, "split-isolate", end_a,
                "two LTR isolates with only space or punctuation between them; "
                "wrap the whole cluster in one isolate "
                "(3.1 Title, OP_IF/OP_NOTIF, 1.0.1 (2026-08-09))")

    # 3. Isolation of Latin runs and number clusters ---------------------
    for m in prose_finditer(r"[A-Za-z][A-Za-z0-9._/+-]{2,}"):
        run = m.group(0)
        if run in TEX_STOPWORDS or run.rstrip("0123456789") in TEX_STOPWORDS:
            continue
        add(ERROR, "unisolated-latin", m.start(),
            f"Latin run {run!r} is not inside an LTR isolate")

    for m in prose_finditer(r"\d+(?:[.\-–/:]\d+)*"):
        add(ERROR, "unisolated-number", m.start(),
            f"number cluster {m.group(0)!r} is not inside an LTR isolate "
            "(ranges and dates reverse on an RTL page)")

    seen: dict[str, str] = {}
    for pos, _end, body in src.isolates:
        if any(start <= pos < end for start, end in src.identity):
            continue
        term = " ".join(body.split())
        if not term or not re.search(r"[A-Za-z]", term):
            continue
        key = re.sub(r"s$", "", term.lower())
        if key in seen and seen[key] != term:
            add(ERROR, "terminology-drift", pos,
                f"isolate {term!r} also appears as {seen[key]!r}; "
                "use one English form per concept")
        seen.setdefault(key, term)

    # 4. Code, images, structure -----------------------------------------
    if src.kind == "html":
        nodes = src.html.nodes
        for node in nodes:
            attrs, pos = node['attrs'], node['start']
            direction = (attrs.get('dir') or '').lower()
            if node['tag'] == 'pre' and direction != 'ltr':
                add(ERROR, 'code-direction', pos, '<pre> requires dir="ltr"')
            if node['tag'] in ('pre', 'code') and (direction == 'rtl' or
                    re.search(r'text-align\s*:\s*right', attrs.get('style') or '', re.I)):
                add(ERROR, 'code-direction', pos, 'listing forced RTL or right-aligned')
        roots = [node for node in nodes if node['tag'] == 'html']
        if (len(roots) != 1 or (roots[0]['attrs'].get('lang') or '').lower() != 'fa'
                or (roots[0]['attrs'].get('dir') or '').lower() != 'rtl'):
            add(ERROR, 'html-root', 0, 'root element must be <html lang="fa" dir="rtl">')
        code_nodes = [node for node in nodes if node['tag'] in ('pre', 'code')]
        if code_nodes and 'pre-wrap' not in text:
            add(WARN, 'print-css', code_nodes[0]['start'],
                'no white-space: pre-wrap on pre; long code lines are clipped on paper')
        for m in live_finditer(r"scaleX\(\s*-1\s*\)"):
            add(ERROR, 'mirrored-image', m.start(), 'horizontal flip on artwork is forbidden')
        images = src.image_references()
        for node in nodes:
            if node['tag'] != 'img':
                continue
            attrs, pos = node['attrs'], node['start']
            if (attrs.get('dir') or '').lower() != 'ltr':
                add(ERROR, 'figure-direction', pos, '<img> requires dir="ltr"')
    else:
        for env in ("verbatim", "Verbatim", "lstlisting"):
            for m in live_finditer(r"\\begin\{" + env + r"\}"):
                window = text[max(0, m.start() - 400):m.start()]
                if "\\begin{latin}" not in window:
                    add(ERROR, "code-direction", m.start(),
                        f"{env} is not wrapped in \\begin{{latin}}; "
                        "listings are never RTL")
        guard = re.search(r"\\(?:section|subsection|subsubsection|chapter"
                          r"|caption)\*?\{[^}]*\\(?:lr|en)\b", text)
        if guard and "pdfstringdefDisableCommands" not in text:
            add(WARN, "bookmark-guard", guard.start(),
                "\\lr/\\en used in a heading or caption without "
                "\\pdfstringdefDisableCommands; hyperref bookmarks will "
                "break")
        images = src.image_references()
        for pos, ref in images:
            before = text[:pos]
            last_begin = max(
                before.rfind("\\begin{LTR}"),
                before.rfind("\\begin{latin}"),
                before.rfind("\\LR{"),
            )
            last_end = max(
                before.rfind("\\end{LTR}"),
                before.rfind("\\end{latin}"),
            )
            if last_begin < 0 or last_begin < last_end:
                add(ERROR, "figure-direction", pos,
                    "\\includegraphics is not inside LTR/latin; xepersian "
                    "can paint the figure black or mirrored")

    context = DocumentContext(src.path.resolve(), src.path.resolve().parent, [], None)
    found: list[str] = []
    for pos, ref in images:
        name = os.path.basename(ref)
        try:
            asset = context.asset(ref)
            name = asset.name
            found.append(name)
        except (OSError, ValueError) as error:
            add(ERROR, 'missing-image', pos, str(error))
        if re.match(r'(?:srcpage|page)-\d+\.(?:png|jpe?g|webp)$', name, re.I):
            add(ERROR, 'full-page-figure', pos,
                f'image {name!r} is a full source-page raster; crop to the artwork')

    if manifest is not None:
        missing = [n for n in manifest if n not in found]
        for name in missing:
            add(ERROR, "missing-image", 0,
                f"{name!r} is in the source manifest but not in the "
                "translation")

    return out


def main(argv: list[str]) -> int:
    here = Path(__file__).resolve().parent
    house = here.parent / "references" / "term-pairs.tsv"
    ap = argparse.ArgumentParser(
        prog="check-fa.py",
        description="Mechanical checks for scientific Persian output.")
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--level", choices=("system-docs", "journal"),
                    default="system-docs",
                    help="terminology.md level (default system-docs)")
    ap.add_argument("--pairs", type=Path, default=None,
                    help="extra TSV merged on top of term-pairs.tsv")
    ap.add_argument("--terms", type=Path, default=None,
                    help="job terms.tsv; keep-English rows need forbidden_fa")
    ap.add_argument("--manifest", type=Path,
                    help="file listing expected image basenames, one per line")
    ap.add_argument("--strict", action="store_true",
                    help="warnings become errors; requires --terms and "
                         "--manifest (or sidecars next to the source)")
    ap.add_argument("--max", type=int, default=40,
                    help="findings printed per check (default 40)")
    args = ap.parse_args(argv)

    errors = warnings = 0
    for path in args.files:
        try:
            context = DocumentContext.load(path, house=house, level=args.level,
                pairs=args.pairs, terms=args.terms, manifest=args.manifest, strict=args.strict)
            src = Source(context.source)
            findings = check(src, context.pairs, context.manifest, level=args.level)
        except (OSError, UnicodeError, ValueError) as error:
            print(f"check-fa: {error}", file=sys.stderr)
            return 2
        errors += sum(1 for f in findings if f.level == ERROR)
        warnings += sum(1 for f in findings if f.level == WARN)

        print(f"== {path}")
        if not findings:
            print("   clean")
            continue
        by_check: dict[str, list[Finding]] = {}
        for f in findings:
            by_check.setdefault(f.check, []).append(f)
        for check_id in sorted(by_check,
                               key=lambda c: (by_check[c][0].level != ERROR,
                                              c)):
            group = by_check[check_id]
            head = group[0]
            print(f"   [{head.level}] {check_id} ({len(group)})")
            for f in group[:args.max]:
                print(f"     {f.path or path}:{f.line}: {f.message}")
                if f.excerpt:
                    print(f"       … {f.excerpt}")
            if len(group) > args.max:
                print(f"     … {len(group) - args.max} more")

    print(f"\ncheck-fa: {errors} error(s), {warnings} warning(s)")
    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    with operation_log('check-fa', Path(__file__).resolve().parent / 'logs') as logger:
        result = main(sys.argv[1:])
        logger.info('exit_code=%d', result)
    sys.exit(result)
