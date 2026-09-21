"""Typed PDF form plans: validate every requested value before changing widgets."""
import math


def widgets(document):
    for page in document:
        for widget in page.widgets() or ():
            yield page, widget


def inventory(document):
    result = []
    for page, field in widgets(document):
        result.append({'page': page.number + 1, 'xref': field.xref,
                       'name': field.field_name, 'type': field.field_type_string,
                       'value': field.field_value, 'flags': field.field_flags,
                       'rect': list(field.rect), 'choices': field.choice_values,
                       'on_state': field.on_state(), 'button_states': field.button_states(),
                       'signed': field.is_signed})
    return result


def signature_present(document):
    import pymupdf
    if document.get_sigflags() > 0:
        return True
    if any(field.field_type == pymupdf.PDF_WIDGET_TYPE_SIGNATURE for _, field in widgets(document)):
        return True
    # SigFlags are optional. Also inspect signature dictionaries, including
    # certification signatures with no visible page widget.
    for xref in range(1, document.xref_length()):
        if document.xref_get_key(xref, 'Type')[1] == '/Sig':
            return True
        if document.xref_get_key(xref, 'ByteRange')[0] == 'array':
            return True
    return False


def ensure_transformable(document):
    if signature_present(document):
        raise ValueError('signed or signature-bearing PDF requires an explicitly reviewed unsigned copy')
    if document.xref_get_key(document.pdf_catalog(), 'AcroForm/XFA')[0] != 'null':
        raise ValueError('XFA forms are unsupported; use a reviewed AcroForm copy')


def plan_fill(document, values):
    import pymupdf as fitz
    if not isinstance(values, dict) or not values or len(values) > 10000:
        raise ValueError('fields JSON must be a nonempty object with at most 10000 entries')
    groups = {}
    for page, field in widgets(document):
        groups.setdefault(field.field_name, []).append((page.number, field.xref))
    if set(values) - set(groups):
        raise ValueError('fields JSON contains an unknown field name')
    planned = []
    for name, value in values.items():
        fields = []
        for page_number, xref in groups[name]:
            page = document[page_number]
            field = page.load_widget(xref)
            fields.append((page, field))
        kinds = {field.field_type for _, field in fields}
        if len(kinds) != 1:
            raise ValueError('one field name resolves to incompatible widget types')
        if any(field.field_flags & 1 for _, field in fields):
            raise ValueError('cannot modify a read-only field')
        if any(getattr(field, attr, None) for _, field in fields
               for attr in ('script', 'script_stroke', 'script_format', 'script_change',
                            'script_calc', 'script_blur', 'script_focus')):
            raise ValueError('scripted field validation/calculation requires an interactive reviewed workflow')
        kind = next(iter(kinds))
        if kind == fitz.PDF_WIDGET_TYPE_TEXT:
            if isinstance(value, str):
                normalized = value
            elif type(value) is int or (type(value) is float and math.isfinite(value)):
                normalized = str(value)
            else:
                raise ValueError('text fields accept strings or finite numbers, including zero')
            if len(normalized) > 100000 or '\x00' in normalized:
                raise ValueError('text field value exceeds supported limits')
            if any(field.text_maxlen and len(normalized) > field.text_maxlen for _, field in fields):
                raise ValueError('text field value exceeds the document maximum length')
            for page, field in fields:
                planned.append((page.number, field.xref, normalized, normalized, False))
        elif kind == fitz.PDF_WIDGET_TYPE_CHECKBOX:
            for page, field in fields:
                states = (field.button_states() or {}).get('normal', [])
                on = [state for state in states if state != 'Off']
                if len(on) != 1:
                    raise ValueError('checkbox must expose one unambiguous on-state')
                if type(value) is bool:
                    normalized = on[0] if value else 'Off'
                elif isinstance(value, str) and value in states:
                    normalized = value
                else:
                    raise ValueError('checkbox accepts a boolean or its exact documented state')
                planned.append((page.number, field.xref, normalized, normalized, True))
        elif kind == fitz.PDF_WIDGET_TYPE_RADIOBUTTON:
            states = [field.on_state() for _, field in fields]
            if not isinstance(value, str) or value not in states or states.count(value) != 1:
                raise ValueError('radio value must select one exact unique on-state')
            for page, field in fields:
                selected = value if field.on_state() == value else 'Off'
                planned.append((page.number, field.xref, False if selected == 'Off' else selected, selected, True))
        elif kind in (fitz.PDF_WIDGET_TYPE_COMBOBOX, fitz.PDF_WIDGET_TYPE_LISTBOX):
            if not isinstance(value, str):
                raise ValueError('choice fields require one string selection')
            for page, field in fields:
                if field.field_flags & (1 << 21):
                    raise ValueError('multi-select fields need a reviewed interactive workflow')
                choices = field.choice_values or []
                allowed = [item[0] if isinstance(item, (list, tuple)) else item for item in choices]
                editable = kind == fitz.PDF_WIDGET_TYPE_COMBOBOX and field.field_flags & (1 << 18)
                if value not in allowed and not editable:
                    raise ValueError('value is not an allowed field choice')
                planned.append((page.number, field.xref, value, value, False))
        else:
            raise ValueError('unsupported field type; signatures and pushbuttons cannot be filled')
    # Radio groups must be cleared before activating the chosen option.
    return sorted(planned, key=lambda item: item[3] != 'Off')


def apply_fill(document, plan):
    for page_number, xref, value, _, _ in plan:
        page = document[page_number]
        field = page.load_widget(xref)
        field.field_value = value
        field.update()


def verify_fill(document, plan):
    for page_number, xref, _, expected, button in plan:
        page = document[page_number]
        field = page.load_widget(xref)
        actual = document.xref_get_key(xref, 'AS')[1].lstrip('/') if button else field.field_value
        if actual != expected:
            raise ValueError('saved form value or button appearance failed verification')
