#!/usr/bin/env python3
"""Select document-approved terminology found in one extracted source text."""
import argparse
from bisect import bisect_right
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys

from runtime import operation_log

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
    reader = csv.reader(io.StringIO(text), delimiter='\t', strict=True)
    header = next(reader, None)
    if not header or len(header) != len(set(header)) or not {'source', 'output'} <= set(header):
        raise ValueError('terms.tsv requires unique source and output columns')
    index = {name: position for position, name in enumerate(header)}
    rows = []
    for line, values in enumerate(reader, 2):
        if not values or values[0].startswith('#'):
            continue
        if len(values) != len(header):
            raise ValueError(f'terms.tsv row {line} does not match the header')
        source, output = values[index['source']].strip(), values[index['output']].strip()
        if not source or len(source) > 256 or len(output) > 256:
            raise ValueError(f'terms.tsv row {line} has an invalid source or output')
        if any(ord(char) < 32 for char in source + output):
            raise ValueError(f'terms.tsv row {line} contains a control character')
        status = values[index['status']].strip().lower() if 'status' in index else ''
        if not output or ('status' in index and status not in ('preferred', 'approved')):
            continue
        rows.append({'source': source, 'output': output,
                     'concept': values[index['concept']].strip() if 'concept' in index else '',
                     'ledger_line': line})
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
    except (OSError, UnicodeError, ValueError, csv.Error) as error:
        print(f'term-brief: {error}', file=sys.stderr)
        raise SystemExit(2)
