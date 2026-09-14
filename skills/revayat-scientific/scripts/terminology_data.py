"""Load house terminology bans and job-specific term ledgers."""
from __future__ import annotations

from pathlib import Path
import re


DEFAULT_PAIRS = [
    ("node", "گره"),
    ("deployment", "استقرار"),
    ("configuration", "پیکربندی"),
    ("implementation", "پیاده‌سازی"),
    ("integration", "یکپارچه‌سازی"),
    ("firewall", "دیوار آتش"),
    ("encryption", "رمزنگاری"),
    ("command", "فرمان"),
]

def load_pairs(paths: list[Path], level: str
               ) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    loaded = False
    for path in paths:
        if not path.exists():
            continue
        loaded = True
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("\t") if p.strip()]
            if len(parts) < 3 or parts[0] == "english":
                continue
            en, fa, scope = parts[0], parts[1], parts[2]
            levels = parts[3] if len(parts) > 3 else "all"
            if levels == "system-docs" and level == "journal":
                continue
            key = (en, fa)
            if key in seen:
                continue
            seen.add(key)
            rows.append((en, fa, scope))
    if rows or loaded:
        return rows
    return [(en, fa, "universal") for en, fa in DEFAULT_PAIRS]

def load_terms_pairs(path: Path) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Keep-English rows from a job terms.tsv.

    Required columns: source, output, step, count, forbidden_fa.
    Optional trailing columns (ignored when absent): concept, status,
    admitted, deprecated. A keep-English row (Latin in *output*) must
    set *forbidden_fa*; otherwise this is a contract error, not a silent
    skip. Forms listed in *deprecated* (pipe-separated) are also
    forbidden. Persian-output rows (prose / chrome) are not calque pairs.
    """
    rows: list[tuple[str, str, str]] = []
    errors: list[str] = []
    if not path.is_file():
        return rows, [f"no such file: {path}"]
    seen: set[tuple[str, str]] = set()
    header_cols: list[str] | None = None
    for lineno, raw in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("\t")]
        if not parts:
            continue
        if parts[0] in ("source", "english"):
            header_cols = [c.lower() for c in parts]
            continue
        if len(parts) < 2:
            errors.append(f"{path}:{lineno}: need source and output columns")
            continue
        en, output = parts[0], parts[1]
        if not re.search(r"[A-Za-z]", output):
            continue

        def col(name: str, index: int) -> str:
            if header_cols and name in header_cols:
                i = header_cols.index(name)
                return parts[i] if i < len(parts) else ""
            return parts[index] if len(parts) > index else ""

        forbidden = col("forbidden_fa", 4)
        if not forbidden:
            errors.append(
                f"{path}:{lineno}: keep-English {en!r} has empty "
                "forbidden_fa (terms-calque)")
            continue
        deprecated = col("deprecated", 8)
        forms = [forbidden] + [
            f.strip() for f in deprecated.split("|") if f.strip()]
        for form in forms:
            key = (en, form)
            if key in seen:
                continue
            seen.add(key)
            rows.append((en, form, "job"))
    return rows, errors
