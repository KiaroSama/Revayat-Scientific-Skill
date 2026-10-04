"""Bounded, located TSV records shared by terminology consumers; no decisions inferred."""
import csv
import io
from pathlib import Path

MAX_LEDGER_BYTES = 1024 * 1024
MAX_LEDGER_ROWS = 10000
APPROVED = {'preferred', 'approved'}


def ledger_records(text, required=('source', 'output')):
    """Return fully validated records with physical starting lines, not CSV row ordinals."""
    if len(text.encode('utf-8')) > MAX_LEDGER_BYTES:
        raise ValueError('terms.tsv exceeds 1 MiB')
    reader = csv.reader(io.StringIO(text.removeprefix('\ufeff'), newline=''), delimiter='\t', strict=True)
    header, records = None, []
    try:
        while True:
            line = reader.line_num + 1
            values = next(reader, None)
            if values is None:
                break
            if not values or not any(value.strip() for value in values) or values[0].lstrip().startswith('#'):
                continue
            if header is None:
                header = [value.strip().lower() for value in values]
                if (not all(header) or len(header) != len(set(header))
                        or not set(required) <= set(header)):
                    raise ValueError('terms.tsv requires unique columns: ' + ', '.join(required))
                continue
            if len(values) != len(header):
                source = values[header.index('source')] if header.index('source') < len(values) else ''
                label = repr(source[:256])
                raise ValueError(f'terms.tsv row {line} source {label} does not match the header')
            record = dict(zip(header, (value.strip() for value in values)))
            for name in ('source', 'output'):
                value = record[name]
                if (len(value) > 256 or (name == 'source' and not value)
                        or any(ord(char) < 32 for char in value)):
                    raise ValueError(f'terms.tsv row {line} has invalid source/output text')
            record['ledger_line'] = line
            records.append(record)
            if len(records) > MAX_LEDGER_ROWS:
                raise ValueError('terms.tsv exceeds 10000 records')
    except csv.Error as error:
        raise ValueError(f'terms.tsv has invalid TSV at physical line {reader.line_num}') from error
    if header is None:
        raise ValueError('terms.tsv is missing its header')
    return records


def approved(record):
    return bool(record['output']) and ('status' not in record or record['status'].lower() in APPROVED)


def read_ledger(path, required=('source', 'output')):
    with Path(path).open('rb') as handle:
        data = handle.read(MAX_LEDGER_BYTES + 1)
    if len(data) > MAX_LEDGER_BYTES:
        raise ValueError('terms.tsv exceeds 1 MiB')
    return ledger_records(data.decode('utf-8-sig'), required)
