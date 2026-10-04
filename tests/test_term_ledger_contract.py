"""All terminology consumers agree on one bounded, located TSV schema."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

from processes import run
ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/revayat-scientific/scripts'
sys.path.insert(0, str(SCRIPTS))
from terminology_data import load_terms_pairs, load_pairs
from runtime import operation_log
SPEC = importlib.util.spec_from_file_location('term_ledger_contract_brief', SCRIPTS / 'term-brief.py')
BRIEF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BRIEF)
HEADER = 'source\toutput\tstep\tcount\tforbidden_fa'


class TermLedgerContractTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch, prefix='ledger-contract-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / 'terms.tsv'
        scope = operation_log('test-term-ledger', self.root / 'logs')
        self.log = scope.__enter__()
        self.addCleanup(scope.__exit__, None, None, None)
        self.log.info('running test=%s', self._testMethodName)

    def lint(self, text):
        self.path.write_bytes(text.encode('utf-8'))
        return load_terms_pairs(self.path)

    def test_source_and_english_are_data_after_the_header(self):
        for source in ('source', 'english'):
            with self.subTest(source=source):
                pairs, errors = self.lint(HEADER + f'\n{source}\tOriginal\t1\t1\tمنبع\n')
                self.assertEqual(errors, [])
                self.assertEqual(pairs, [(source, 'منبع', 'job')])

    def test_raw_record_boundaries_are_validated_before_decision_selection(self):
        quoted = HEADER + '\n"#node"\tNode\t1\t1\tگره\n'
        with self.subTest(kind='quoted source'):
            self.assertEqual(self.lint(quoted), ([('#node', 'گره', 'job')], []))
            self.assertEqual(BRIEF.approved_rows(quoted)[0]['source'], '#node')
        valid = HEADER + '\nnode\tNode\t1\t1\tگره\n'
        for row in ('\t\t\n', '\t\t\t\t\n',
                    'node\t"Node\n"\t1\t1\tگره\n',
                    '"\t node"\tNode\t1\t1\tگره\n',
                    'node\t"Node\x7f"\t1\t1\tگره\n'):
            with self.subTest(row=row):
                self.assertEqual(self.lint(valid + row)[0], [])
                self.assertTrue(self.lint(valid + row)[1])
                with self.assertRaises(ValueError):
                    BRIEF.approved_rows(valid + row)
        self.assertEqual(self.lint(valid + '  \n# retained comment\n'),
                         ([('node', 'گره', 'job')], []))

    def test_reordered_columns_resolve_by_header_not_position(self):
        text = 'output\tcount\tforbidden_fa\tsource\tstep\nOriginal\t1\tمنبع\tsource\t1\n'
        self.assertEqual(self.lint(text), ([('source', 'منبع', 'job')], []))
        self.assertEqual(BRIEF.approved_rows(text)[0]['source'], 'source')

    def test_bom_comments_blank_lines_and_crlf_share_the_same_parser(self):
        text = '\ufeff# approved fixture\r\n\r\n' + HEADER + '\r\nnode\tNode\t1\t1\tگره\r\n'
        self.assertEqual(self.lint(text), ([('node', 'گره', 'job')], []))
        rows = BRIEF.approved_rows(text)
        self.assertEqual(rows[0]['ledger_line'], 4)

    def test_short_and_long_rows_fail_even_for_persian_output(self):
        for row in ('node\tگره', 'node\tNode\t1\t1\tگره\textra'):
            with self.subTest(row=row):
                pairs, errors = self.lint(HEADER + '\n' + row + '\n')
                self.assertEqual(pairs, [])
                self.assertTrue(errors)
                with self.assertRaises(ValueError):
                    BRIEF.approved_rows(HEADER + '\n' + row + '\n')

    def test_missing_and_duplicate_headers_are_not_accepted(self):
        for text in ('', '# comment only\n', 'node\tNode\t1\t1\tگره\n',
                     'source\toutput\tstep\tcount\tforbidden_fa\toutput\n',
                     'source\tOutput\tstep\tcount\tforbidden_fa\tOUTPUT\n'):
            with self.subTest(text=text):
                self.assertTrue(self.lint(text)[1])
                with self.assertRaises(ValueError):
                    BRIEF.approved_rows(text)

    def test_lint_requires_its_documented_columns_but_brief_keeps_minimal_schema(self):
        text = 'source\toutput\nnode\tگره\n'
        self.assertTrue(self.lint(text)[1])
        self.assertEqual(BRIEF.approved_rows(text)[0]['output'], 'گره')

    def test_only_approved_rows_drive_bans_when_status_is_present(self):
        for status in ('rejected', 'unresolved', 'provisional', ''):
            text = HEADER + '\tstatus\nnode\tNode\t1\t1\tگره\t' + status + '\n'
            with self.subTest(status=status):
                self.assertEqual(self.lint(text), ([], []))
                self.assertEqual(BRIEF.approved_rows(text), [])
        for status in ('preferred', 'approved', ' APPROVED '):
            text = HEADER + '\tstatus\nnode\tNode\t1\t1\tگره\t' + status + '\n'
            with self.subTest(status=status):
                self.assertEqual(self.lint(text), ([('node', 'گره', 'job')], []))
                self.assertEqual(len(BRIEF.approved_rows(text)), 1)

    def test_quoted_cells_and_multiline_notes_keep_physical_row_locations(self):
        text = HEADER + '\tevidence\nnode\tNode\t1\t1\tگره\t"line one\nline two"\nsource\tOriginal\t1\t1\tمنبع\tnote\n'
        self.assertEqual(self.lint(text), ([('node', 'گره', 'job'), ('source', 'منبع', 'job')], []))
        self.assertEqual([row['ledger_line'] for row in BRIEF.approved_rows(text)], [2, 4])

    def test_header_only_is_valid_and_does_not_invent_bans(self):
        self.assertEqual(self.lint(HEADER + '\n'), ([], []))
        self.assertEqual(BRIEF.approved_rows(HEADER + '\n'), [])

    def test_deprecated_bans_and_missing_counterform_remain_enforced(self):
        text = HEADER + '\tdeprecated\nnode\tNode\t1\t1\tگره\tرأس|نود\n'
        self.assertEqual(self.lint(text), ([('node', value, 'job') for value in ('گره', 'رأس', 'نود')], []))
        self.assertTrue(self.lint(HEADER + '\nnode\tNode\t1\t1\t\n')[1])

    def test_late_invalid_row_returns_no_partial_bans(self):
        text = HEADER + '\nnode\tNode\t1\t1\tگره\nbroken\tخراب\n'
        pairs, errors = self.lint(text)
        self.assertEqual(pairs, [])
        self.assertTrue(errors)

    def test_oversized_and_malformed_csv_fail_before_any_bans(self):
        for text in (HEADER + '\n' + 'x' * (1024 * 1024), HEADER + '\n"unterminated'):
            with self.subTest(length=len(text)):
                self.assertTrue(self.lint(text)[1])
                with self.assertRaises(ValueError):
                    BRIEF.approved_rows(text)

    def test_house_pairs_allow_english_as_a_real_data_term(self):
        for header in ('', 'english\tforbidden_fa\tscope\tlevels\n'):
            with self.subTest(header=header):
                self.path.write_bytes(('\ufeff' + header + 'english\tانگلیسی\tuniversal\tall\n').encode('utf-8'))
                self.assertEqual(load_pairs([self.path], 'journal'), [('english', 'انگلیسی', 'universal')])

    def test_duplicate_house_header_is_not_a_term_or_silent_reset(self):
        header = 'english\tforbidden_fa\tscope\n'
        self.path.write_text(header + 'node\tگره\tuniversal\n' + header, encoding='utf-8')
        with self.assertRaises(ValueError):
            load_pairs([self.path], 'journal')

    def test_cli_rejects_malformed_ledger_without_changing_inputs(self):
        self.path.write_text(HEADER + '\nnode\tگره\n', encoding='utf-8')
        source = self.root / 'source.tex'
        source.write_text('\\begin{document}متن درست\\end{document}', encoding='utf-8')
        before = (source.read_bytes(), self.path.read_bytes())
        result = run([sys.executable, str(SCRIPTS / 'revayat-scientific.py'), 'lint', str(source),
                      '--terms', str(self.path), '--level', 'journal'], timeout=15)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual((source.read_bytes(), self.path.read_bytes()), before)


if __name__ == '__main__':
    unittest.main()
