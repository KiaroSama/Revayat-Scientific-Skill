"""Real PDF buttons retain decoded state identity and verified field values."""
from pathlib import Path
import importlib.util
import json
import sys
import tempfile
import unittest.mock

import pymupdf

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skills/revayat-scientific/scripts'))
import pdf_forms as forms
import pdf_button_states as state_reader
from processes import run
from runtime import operation_log


def encoded_name(value):
    """Generate an unambiguous PDF name for synthetic fixtures only."""
    return ''.join(chr(byte) if 33 <= byte <= 126 and chr(byte) not in '#%()/<>[]{}'
                   else f'#{byte:02X}' for byte in value.encode('utf-8'))


def add_button(document, page, name, state, *, radio=False, indirect=False, y=50):
    widget = pymupdf.Widget()
    widget.field_name = name
    widget.field_type = (pymupdf.PDF_WIDGET_TYPE_RADIOBUTTON if radio else
                         pymupdf.PDF_WIDGET_TYPE_CHECKBOX)
    widget.field_value = False
    widget.rect = pymupdf.Rect(30, y, 55, y + 25)
    added = page.add_widget(widget)
    current = page.load_widget(added.xref)
    on = next(value for value in current.button_states()['normal'] if value != 'Off')
    kind, appearance = document.xref_get_key(added.xref, 'AP/N')
    if kind == 'xref':
        appearance = document.xref_object(int(appearance.split()[0]))
    appearance = appearance.replace('/' + on + ' ', '/' + encoded_name(state) + ' ')
    if indirect:
        normal = document.get_new_xref()
        document.update_object(normal, appearance)
        appearance = f'{normal} 0 R'
    document.xref_set_key(added.xref, 'AP/N', appearance)
    return added.xref


class PdfButtonNamesTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix='pdf state identity ', dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        context = operation_log('test-pdf-button-names', self.root / 'logs')
        self.logger = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.logger.info('running test=%s; all form values are synthetic', self._testMethodName)

    def document(self, state='Yes', **options):
        doc = pymupdf.open()
        page = doc.new_page(width=300, height=200)
        page.insert_text((30, 30), 'Untouched scientific form')
        xref = add_button(doc, page, 'consent', state, **options)
        return doc, xref

    def roundtrip(self, document, values):
        plan = forms.plan_fill(document, values)
        forms.apply_fill(document, plan)
        output = self.root / 'result.pdf'
        document.save(output)
        with pymupdf.open(output) as result:
            forms.verify_fill(result, plan)
            states = [result.xref_get_key(field.xref, 'AS')[1][1:]
                      for page in result for field in page.widgets() or ()]
            value = [field.field_value for page in result for field in page.widgets() or ()]
        return states, value

    def test_checkbox_booleans_select_all_supported_name_encodings(self):
        for state in ('Yes', 'On State', 'A/B', '/Leading', 'A#B', 'A#20B', 'État', 'تایید'):
            for indirect in (False, True):
                with self.subTest(state=state, indirect=indirect):
                    doc, _ = self.document(state, indirect=indirect)
                    with doc:
                        actual, values = self.roundtrip(doc, {'consent': True})
                    self.assertEqual(actual, [state])
                    self.assertEqual(values, [state])

    def test_inventory_advertises_decoded_names_that_are_valid_fill_inputs(self):
        for state in ('On State', '/Leading', 'A#20B', 'تایید'):
            with self.subTest(state=state):
                doc, _ = self.document(state)
                with doc:
                    record = forms.inventory(doc)[0]
                    self.assertEqual(record['on_state'], state)
                    self.assertIn(state, record['button_states']['normal'])
                    self.assertEqual(self.roundtrip(doc, {'consent': record['on_state']})[0], [state])

    def test_false_and_exact_off_keep_checkbox_unselected(self):
        for requested in (False, 'Off'):
            with self.subTest(requested=requested):
                doc, _ = self.document('On State')
                with doc:
                    self.assertEqual(self.roundtrip(doc, {'consent': requested})[0], ['Off'])

    def test_serialized_escape_spelling_is_not_a_second_alias(self):
        doc, _ = self.document('On State')
        with doc:
            before = doc.tobytes(no_new_id=True)
            with self.assertRaises(ValueError):
                forms.plan_fill(doc, {'consent': 'On#20State'})
            self.assertEqual(doc.tobytes(no_new_id=True), before)

    def test_radio_names_are_decoded_and_only_requested_option_is_selected(self):
        for selected in ('Option A', 'A#20B', 'تایید'):
            with self.subTest(selected=selected), pymupdf.open() as doc:
                page = doc.new_page(width=300, height=200)
                add_button(doc, page, 'method', 'Not selected', radio=True, y=30)
                add_button(doc, page, 'method', selected, radio=True, indirect=True, y=80)
                records = forms.inventory(doc)
                self.assertEqual([record['on_state'] for record in records], ['Not selected', selected])
                actual, _ = self.roundtrip(doc, {'method': selected})
                self.assertEqual(actual, ['Off', selected])

    def test_mismatched_stored_value_cannot_pass_by_matching_appearance(self):
        for state in ('Yes', 'On State'):
            with self.subTest(state=state):
                doc, xref = self.document(state)
                with doc:
                    plan = [(0, xref, True, state, True)]
                    doc.xref_set_key(xref, 'AS', '/' + encoded_name(state))
                    doc.xref_set_key(xref, 'V', '/Off')
                    with self.assertRaises(ValueError):
                        forms.verify_fill(doc, plan)

    def test_mismatched_appearance_type_or_value_remains_rejected(self):
        for appearance in ('/Off', '(Yes)', 'null'):
            with self.subTest(appearance=appearance):
                doc, xref = self.document()
                with doc:
                    doc.xref_set_key(xref, 'AS', appearance)
                    doc.xref_set_key(xref, 'V', '/Yes')
                    with self.assertRaises(ValueError):
                        forms.verify_fill(doc, [(0, xref, True, 'Yes', True)])

    def test_duplicate_on_states_across_radio_widgets_are_rejected_before_writes(self):
        with pymupdf.open() as doc:
            page = doc.new_page()
            add_button(doc, page, 'method', 'Same name', radio=True, y=30)
            add_button(doc, page, 'method', 'Same name', radio=True, y=80)
            before = doc.tobytes(no_new_id=True)
            with self.assertRaises(ValueError):
                forms.plan_fill(doc, {'method': 'Same name'})
            self.assertEqual(doc.tobytes(no_new_id=True), before)

    def test_unrelated_prose_and_unselected_render_stay_intact(self):
        doc, xref = self.document('On State')
        with doc:
            off = doc[0].get_pixmap(annots=True).samples
            body = doc[0].get_pixmap(annots=False).samples
            plan = forms.plan_fill(doc, {'consent': True})
            forms.apply_fill(doc, plan)
            data = doc.tobytes()
        with pymupdf.open(stream=data, filetype='pdf') as result:
            forms.verify_fill(result, plan)
            self.assertEqual(result[0].get_pixmap(annots=False).samples, body)
            self.assertNotEqual(result[0].get_pixmap(annots=True).samples, off)
            off_plan = forms.plan_fill(result, {'consent': False})
            forms.apply_fill(result, off_plan)
            deselected = result.tobytes()
        with pymupdf.open(stream=deselected, filetype='pdf') as result:
            forms.verify_fill(result, off_plan)
            self.assertEqual(result[0].get_pixmap(annots=True).samples, off)


    def radio_group(self):
        doc = pymupdf.open()
        page = doc.new_page(width=300, height=200)
        refs = [add_button(doc, page, 'method', name, radio=True, y=30 + index * 50)
                for index, name in enumerate(('Option A', 'Option B'))]
        parent = doc.get_new_xref()
        doc.update_object(parent, '<< /FT /Btn /Ff 32768 /T (method) /V /Off /Kids ['
                          + ' '.join(f'{xref} 0 R' for xref in refs) + '] >>')
        for xref in refs:
            for key in ('FT', 'Ff', 'T', 'V'):
                doc.xref_set_key(xref, key, 'null')
            doc.xref_set_key(xref, 'Parent', f'{parent} 0 R')
        doc.xref_set_key(doc.pdf_catalog(), 'AcroForm/Fields', f'[{parent} 0 R]')
        data = doc.tobytes()
        doc.close()
        return pymupdf.open(stream=data, filetype='pdf'), parent

    def test_shared_parent_radio_value_is_verified_after_reopening(self):
        doc, _ = self.radio_group()
        with doc:
            actual, _ = self.roundtrip(doc, {'method': 'Option B'})
        self.assertEqual(actual, ['Off', 'Option B'])

    def test_appearance_derived_radio_value_cannot_hide_wrong_parent_value(self):
        doc, parent = self.radio_group()
        with doc:
            plan = forms.plan_fill(doc, {'method': 'Option B'})
            forms.apply_fill(doc, plan)
            doc.xref_set_key(parent, 'V', '/Off')
            data = doc.tobytes()
        with pymupdf.open(stream=data, filetype='pdf') as result:
            # MuPDF's Widget.field_value is derived from AS for radio children.
            self.assertEqual(list(result[0].widgets())[1].field_value, 'Option B')
            with self.assertRaises(ValueError):
                forms.verify_fill(result, plan)

    def test_appearance_dictionary_refuses_nonstreams_and_ambiguous_states(self):
        for value in ('<< /Off 0 0 R /Yes 0 0 R >>', '<< /Off null /Yes null >>', '<< >>'):
            with self.subTest(value=value):
                doc, xref = self.document()
                with doc:
                    doc.xref_set_key(xref, 'AP/N', value)
                    with self.assertRaises(ValueError):
                        forms.plan_fill(doc, {'consent': True})

    def test_native_serialized_names_do_not_depend_on_widget_parser(self):
        doc, _ = self.document('A#20B')
        with doc, unittest.mock.patch.object(pymupdf.Widget, 'button_states', side_effect=AssertionError('old parser used')):
            record = forms.inventory(doc)[0]
            self.assertEqual(record['on_state'], 'A#20B')
            plan = forms.plan_fill(doc, {'consent': 'A#20B'})
            self.assertEqual(plan[0][3], 'A#20B')



    def test_public_inspect_and_fill_accept_the_same_decoded_labels(self):
        source, target = self.root / 'source.pdf', self.root / 'filled.pdf'
        report, fields = self.root / 'inventory.json', self.root / 'fields.json'
        doc, _ = self.document('On State')
        with doc:
            doc.save(source)
        original = source.read_bytes()
        command = [sys.executable, str(ROOT / 'skills/revayat-scientific/scripts/revayat-scientific.py')]
        inspected = run([*command, 'pdf', 'inspect', str(source), '--output', str(report)], timeout=25)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        state = json.loads(report.read_text(encoding='utf-8'))['fields'][0]['on_state']
        self.assertEqual(state, 'On State')
        fields.write_text(json.dumps({'consent': state}), encoding='utf-8')
        filled = run([*command, 'pdf', 'fill', str(source), str(target), '--fields', str(fields)], timeout=25)
        self.assertEqual(filled.returncode, 0, filled.stderr)
        with pymupdf.open(target) as result:
            self.assertEqual(forms.inventory(result)[0]['value'], state)
        self.assertEqual(source.read_bytes(), original)

    def test_late_saved_value_verification_failure_preserves_previous_delivery(self):
        spec = importlib.util.spec_from_file_location('button_delivery_helper',
            ROOT / 'skills/revayat-scientific/scripts/document-pdf.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        source, target = self.root / 'source.pdf', self.root / 'filled.pdf'
        doc, _ = self.document('On State')
        with doc:
            doc.save(source)
        original = source.read_bytes()
        target.write_bytes(b'previous approved delivery')
        with unittest.mock.patch.object(helper, 'verify_fill', side_effect=ValueError('injected mismatch')):
            with self.assertRaises(ValueError):
                helper.fill_pdf(source, target, {'consent': True})
        self.assertEqual(target.read_bytes(), b'previous approved delivery')
        self.assertEqual(source.read_bytes(), original)
        self.assertFalse(list(self.root.glob('.revayat-*')))

    def test_state_reader_limits_and_non_utf8_names_fail_without_mutation(self):
        for limit, value in (('MAX_APPEARANCE_BYTES', 1), ('MAX_STATES', 1)):
            doc, _ = self.document('Yes')
            with doc, unittest.mock.patch.object(state_reader, limit, value), self.assertRaises(ValueError):
                forms.plan_fill(doc, {'consent': True})
        for raw in ('#FF', '#E9', '#0A'):
            doc, xref = self.document('Yes')
            with doc:
                kind, dictionary = doc.xref_get_key(xref, 'AP/N')
                self.assertEqual(kind, 'dict')
                doc.xref_set_key(xref, 'AP/N', dictionary.replace('/Yes', '/' + raw))
                before = doc.tobytes(no_new_id=True)
                with self.assertRaises(ValueError):
                    forms.plan_fill(doc, {'consent': True})
                self.assertEqual(doc.tobytes(no_new_id=True), before)

    def test_stored_value_parent_cycles_fail_instead_of_looping(self):
        with pymupdf.open() as doc:
            first, second = doc.get_new_xref(), doc.get_new_xref()
            doc.update_object(first, f'<< /Parent {second} 0 R >>')
            doc.update_object(second, f'<< /Parent {first} 0 R >>')
            with self.assertRaisesRegex(ValueError, 'cyclic'):
                state_reader.stored_value(doc, first)


if __name__ == '__main__':
    unittest.main()
