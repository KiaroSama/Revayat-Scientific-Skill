"""Read PDF button names once from serialized appearance dictionaries.

Only the bounded name-to-stream-reference subset used by button appearances is
accepted. No content stream, JavaScript or external resource is executed.
"""
import re

_ENTRY = re.compile(r'\s*/([^\s/<>{}\[\]()%]+)\s+(\d+)\s+(\d+)\s+R(?=\s|/|$)')
_REFERENCE = re.compile(r'(\d+)\s+\d+\s+R\Z')
MAX_APPEARANCE_BYTES = 65536
MAX_STATES = 1024


def _decode_name(token):
    try:
        raw = bytearray()
        index = 0
        while index < len(token):
            if token[index] == '#':
                digits = token[index + 1:index + 3]
                if len(digits) != 2 or re.fullmatch('[0-9A-Fa-f]{2}', digits) is None:
                    raise ValueError('invalid serialized button name')
                raw.append(int(digits, 16))
                index += 3
            else:
                raw.extend(token[index].encode('ascii'))
                index += 1
        value = raw.decode('utf-8')
    except (UnicodeError, OverflowError) as error:
        raise ValueError('button names require a lossless UTF-8 representation') from error
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('unsupported control character in button name')
    return value


def _appearance(document, xref, appearance):
    kind, value = document.xref_get_key(xref, 'AP/' + appearance)
    if kind == 'null':
        return None
    if kind == 'xref':
        reference = _REFERENCE.fullmatch(value)
        if reference is None:
            raise ValueError('invalid appearance dictionary reference')
        number = int(reference[1])
        if document.xref_is_stream(number):
            return None
        value = document.xref_object(number, compressed=True, ascii=True)
    elif kind != 'dict':
        raise ValueError('unsupported button appearance type')
    if len(value) > MAX_APPEARANCE_BYTES or not value.startswith('<<') or not value.endswith('>>'):
        raise ValueError('button appearance dictionary exceeds supported limits')
    value = value[2:-2]
    names, position = [], 0
    while value[position:].strip():
        match = _ENTRY.match(value, position)
        if match is None:
            raise ValueError('button appearances must reference individual streams')
        name = _decode_name(match[1])
        if name in names or len(names) >= MAX_STATES:
            raise ValueError('ambiguous or excessive button appearance states')
        if not document.xref_is_stream(int(match[2])):
            raise ValueError('button appearance does not reference a stream')
        names.append(name)
        position = match.end()
    return names


def button_states(document, field):
    """Return decoded labels independently of Widget.button_states serialization."""
    import pymupdf
    if field.field_type not in (pymupdf.PDF_WIDGET_TYPE_CHECKBOX, pymupdf.PDF_WIDGET_TYPE_RADIOBUTTON):
        return None
    return {'normal': _appearance(document, field.xref, 'N'),
            'down': _appearance(document, field.xref, 'D')}


def on_state(states, *, strict=True):
    normal = (states or {}).get('normal') or []
    selected = [name for name in normal if name != 'Off']
    if 'Off' not in normal or len(selected) != 1:
        if not strict:
            return None
        raise ValueError('button needs Off and one unambiguous normal on-state')
    return selected[0]


def stored_value(document, xref):
    """Resolve the effective V entry, not a widget's appearance-derived value."""
    visited = set()
    while xref not in visited and len(visited) < 64:
        visited.add(xref)
        kind, value = document.xref_get_key(xref, 'V')
        if kind == 'name':
            return value[1:]
        if kind == 'string':
            # MuPDF writes some radio group values as strings, not PDF names.
            return value
        if kind != 'null':
            raise ValueError('unsupported stored button value type')
        kind, parent = document.xref_get_key(xref, 'Parent')
        if kind == 'null':
            return 'Off'
        match = _REFERENCE.fullmatch(parent) if kind == 'xref' else None
        if match is None:
            raise ValueError('unsupported button parent reference')
        xref = int(match[1])
    raise ValueError('button parent chain is cyclic or exceeds 64 objects')
