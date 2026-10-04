#!/usr/bin/env python3
"""Select document-approved terminology found in one extracted source text."""
import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import sys

from runtime import operation_log
from term_ledger import ledger_records, approved

MAX_SOURCE = 4 * 1024 * 1024
MAX_TERMS = 1024 * 1024
MAX_ROWS = 512
MAX_HITS = 64


def bounded_text(path, limit):
    path = Path(path)
    if not path.is_file():
        raise ValueError('required UTF-8 input is not a file: ' + str(path))
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError('input exceeds its byte limit: ' + str(path))
    return data.decode('utf-8'), hashlib.sha256(data).hexdigest()


def approved_rows(text):
    rows = []
    for record in ledger_records(text):
        if not approved(record):
            continue
        rows.append({name: record[name] for name in ('source', 'output', 'ledger_line')}
                    | {'concept': record.get('concept', '')})
        if len(rows) > MAX_ROWS:
            raise ValueError('term brief exceeds 512 approved rows')
    return rows


def cjk(value):
    return any('\u3040' <= char <= '\u30ff' or '\u3400' <= char <= '\u9fff'
               for char in value)


def candidate_brief(source_text, rows):
    results = []
    line_starts = [0] + [hit.end() for hit in re.finditer('\n', source_text)]
    for row in rows:
        token = row['source']
        continuous_script = cjk(token)
        matches = []
        overflow = False
        for hit in re.finditer(re.escape(token), source_text, re.IGNORECASE):
            start, end = hit.span()
            if not continuous_script and ((start and (source_text[start - 1].isalnum() or source_text[start - 1] == '_'))
                                   or (end < len(source_text) and (source_text[end].isalnum() or source_text[end] == '_'))):
                continue
            if len(matches) == MAX_HITS:
                overflow = True
                break
            line = bisect_right(line_starts, start)
            matches.append({'line': line, 'column': start - line_starts[line - 1] + 1})
        if matches:
            results.append({**row, 'locations': matches, 'more_matches': overflow})
    results.sort(key=lambda row: (row['locations'][0]['line'], row['locations'][0]['column'], row['ledger_line']))
    variants = {}
    for row in results:
        variants.setdefault(row['source'].casefold(), set()).add((row['output'], row['concept']))
    for row in results:
        row['ambiguous'] = len(variants[row['source'].casefold()]) > 1
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='reviewed UTF-8 extracted source text')
    parser.add_argument('--terms', type=Path, required=True, help='approved job terms.tsv')
    parser.add_argument('--language', required=True, help='identified source language or variety')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{1,31}', args.language):
        parser.error('--language requires a language/variety identifier')
    with operation_log('term-brief', Path(__file__).resolve().parent / 'logs') as logger:
        if args.source.suffix.lower() not in ('.txt', '.text', '.md'):
            raise ValueError('term brief requires reviewed UTF-8 extracted text or Markdown')
        source, source_hash = bounded_text(args.source, MAX_SOURCE)
        if source.startswith('%PDF-') or '\x00' in source:
            raise ValueError('binary source is not reviewed extracted text')
        ledger, ledger_hash = bounded_text(args.terms, MAX_TERMS)
        rows = candidate_brief(source, approved_rows(ledger))
        logger.info('source_language=%s approved_matches=%d', args.language, len(rows))
        print(json.dumps({'source_language': args.language, 'source_sha256': source_hash,
                          'terms_sha256': ledger_hash, 'status': 'candidates' if rows else 'no-matches',
                          'terms': rows}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(f'term-brief: {error}', file=sys.stderr)
        raise SystemExit(2)
