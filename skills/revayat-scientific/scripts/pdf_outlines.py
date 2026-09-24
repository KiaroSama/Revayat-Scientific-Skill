"""Preserve supported PDF outline destinations without coordinate reinterpretation."""
import math
import re

REFERENCE = re.compile(r'^\s*(\d+)\s+\d+\s+R\s*$')
DESTINATION = re.compile(r'^\[\s*(\d+)\s+\d+\s+R\s*/(XYZ|Fit|FitH|FitV|FitR|FitB|FitBH|FitBV)\b(.*?)\]\s*$', re.S)
NUMBER = re.compile(r'^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$')
COUNTS = {'XYZ': 3, 'Fit': 0, 'FitH': 1, 'FitV': 1, 'FitR': 4,
          'FitB': 0, 'FitBH': 1, 'FitBV': 1}


def _destination(document, kind, value, pages):
    seen = set()
    while kind == 'xref':
        match = REFERENCE.fullmatch(value)
        if match is None or len(seen) >= 16 or int(match[1]) in seen:
            raise ValueError('unsupported or cyclic outline destination reference')
        xref = int(match[1])
        seen.add(xref)
        value = document.xref_object(xref, compressed=True)
        kind = 'array' if value.lstrip().startswith('[') else 'unsupported'
    match = DESTINATION.fullmatch(value) if kind == 'array' else None
    if match is None or int(match[1]) not in pages:
        raise ValueError('outline needs a supported local page destination; named destinations require review')
    mode, arguments = match[2], match[3].split()
    if len(arguments) != COUNTS[mode]:
        raise ValueError('unsupported outline destination argument count')
    values = []
    for token in arguments:
        if token == 'null':
            values.append(None)
        elif NUMBER.fullmatch(token) and math.isfinite(float(token)):
            values.append(float(token))
        else:
            raise ValueError('unsupported outline destination coordinate')
    return pages[int(match[1])], '/' + mode + (' ' + ' '.join(arguments) if arguments else ''), (mode, tuple(values))


def outline_plan(document, offset=0):
    """Read supported actions as data; never open URLs or run outline actions."""
    pages = {}
    for index in range(document.page_count):
        pages.setdefault(document.page_xref(index), index)
    result = []
    for level, title, _, detail in document.get_toc(simple=False):
        xref = detail['xref']
        direct = document.xref_get_key(xref, 'Dest')
        action = document.xref_get_key(xref, 'A')
        if document.xref_get_key(xref, 'A/Next')[0] != 'null':
            raise ValueError('chained outline actions require a separately reviewed copy')
        record = {'level': level, 'title': title, 'kind': 'none', 'page': -1,
                  'bold': bool(detail.get('bold')), 'italic': bool(detail.get('italic')),
                  'color': tuple(detail.get('color', (0, 0, 0))),
                  'collapsed': bool(detail.get('collapse', False))}
        if direct[0] != 'null':
            if action[0] != 'null':
                raise ValueError('ambiguous outline contains both Dest and an action')
            destination = direct
        elif action[0] != 'null':
            action_type = document.xref_get_key(xref, 'A/S')
            if action_type == ('name', '/URI'):
                uri = document.xref_get_key(xref, 'A/URI')
                is_map = document.xref_get_key(xref, 'A/IsMap')
                if uri[0] != 'string' or is_map not in (('null', 'null'), ('bool', 'true'), ('bool', 'false')):
                    raise ValueError('unsupported URI outline action')
                record.update(kind='uri', uri=uri[1], is_map=is_map[1] == 'true')
                result.append(record)
                continue
            if action_type != ('name', '/GoTo'):
                raise ValueError('advanced outline action requires a separately reviewed copy')
            destination = document.xref_get_key(xref, 'A/D')
        else:
            result.append(record)
            continue
        page, tail, signature = _destination(document, *destination, pages)
        record.update(kind='local', page=page + offset, tail=tail, destination=signature)
        result.append(record)
    return result


def apply_outlines(document, plan):
    """Remap page references but retain original PDF-space coordinates and fits."""
    import pymupdf
    document.set_toc([[row['level'], row['title'], row['page'] + 1 if row['kind'] == 'local' else -1]
                      for row in plan], collapse=0)
    for xref, row in zip(document.get_outline_xrefs(), plan):
        document.xref_set_key(xref, 'A', 'null')
        document.xref_set_key(xref, 'Dest', 'null')
        if row['kind'] == 'local':
            destination = f"[{document.page_xref(row['page'])} 0 R {row['tail']}]"
            document.xref_set_key(xref, 'Dest', destination)
        elif row['kind'] == 'uri':
            action = '<< /S /URI /URI ' + pymupdf.get_pdf_str(row['uri'])
            if row['is_map']:
                action += ' /IsMap true'
            document.xref_set_key(xref, 'A', action + ' >>')
        document.xref_set_key(xref, 'F', str(int(row['italic']) + 2 * int(row['bold'])))
        color = row['color']
        document.xref_set_key(xref, 'C', '[' + ' '.join(format(v, '.8f') for v in color) + ']')
        kind, count = document.xref_get_key(xref, 'Count')
        if kind == 'int' and int(count):
            document.xref_set_key(xref, 'Count', str((-1 if row['collapsed'] else 1) * abs(int(count))))


def verify_outlines(document, expected):
    actual = outline_plan(document)
    if len(actual) != len(expected):
        raise ValueError('staged PDF lost outline entries')
    for wanted, found in zip(expected, actual):
        for key in ('level', 'title', 'kind', 'page', 'bold', 'italic', 'collapsed', 'uri', 'is_map'):
            if wanted.get(key) != found.get(key):
                raise ValueError('staged PDF changed outline semantics')
        if any(abs(a - b) > 1e-6 for a, b in zip(wanted['color'], found['color'])):
            raise ValueError('staged PDF changed outline color')
        if wanted.get('destination') != found.get('destination'):
            raise ValueError('staged PDF changed outline destination coordinates')
