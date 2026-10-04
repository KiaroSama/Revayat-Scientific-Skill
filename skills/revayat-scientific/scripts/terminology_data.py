"""Load house terminology bans and job-specific term ledgers."""
from __future__ import annotations

from pathlib import Path
import re

from term_ledger import read_ledger, approved


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
        record_seen = False
        for lineno, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("\t")]
            if parts[:2] == ["english", "forbidden_fa"]:
                if record_seen:
                    raise ValueError(f'{path}:{lineno}: duplicate terminology header')
                record_seen = True
                if parts not in (['english', 'forbidden_fa', 'scope'],
                                 ['english', 'forbidden_fa', 'scope', 'levels']):
                    raise ValueError(f'{path}:{lineno}: invalid terminology header')
                continue
            record_seen = True
            if len(parts) not in (3, 4) or not all(parts[:3]):
                raise ValueError(f'{path}:{lineno}: expected english, forbidden_fa, scope and optional levels')
            en, fa, scope = parts[0], parts[1], parts[2]
            levels = parts[3] if len(parts) > 3 else "all"
            if levels not in ('all', 'system-docs', 'journal'):
                raise ValueError(f'{path}:{lineno}: unsupported terminology level')
            if levels == 'journal' and level != 'journal':
                continue
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
    """Build job bans only from a complete valid ledger and eligible decisions.

    Required columns: source, output, step, count, forbidden_fa. Optional status
    restricts decisions to approved/preferred; legacy ledgers omit this column.
    Keep-original Latin outputs require a counterform; deprecated forms add bans.
    """
    rows, errors, seen = [], [], set()
    try:
        records = read_ledger(path, ('source', 'output', 'step', 'count', 'forbidden_fa'))
    except (OSError, UnicodeError, ValueError) as error:
        message = str(error) if type(error) is ValueError else 'terms.tsv cannot be read as bounded UTF-8'
        return [], [message]
    for record in records:
        if not approved(record) or not re.search(r'[A-Za-z]', record['output']):
            continue
        source, forbidden = record['source'], record['forbidden_fa']
        if not forbidden:
            errors.append(f"terms.tsv row {record['ledger_line']}: keep-English output has empty forbidden_fa (terms-calque)")
            continue
        for form in [forbidden] + [value.strip() for value in record.get('deprecated', '').split('|') if value.strip()]:
            if (source, form) not in seen:
                seen.add((source, form))
                rows.append((source, form, 'job'))
    return ([] if errors else rows), errors
