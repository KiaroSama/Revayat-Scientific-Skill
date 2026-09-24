"""A packaged term brief selects evidence from a job ledger across scripts."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from processes import run

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'skills/revayat-scientific/scripts/revayat-scientific.py'
HEADER = 'source\toutput\tstep\tcount\tforbidden_fa\tconcept\tstatus\tadmitted\tdeprecated\n'


class TermBriefTest(unittest.TestCase):
    def test_multilingual_source_locations_and_ambiguity(self):
        (ROOT / '.scratch').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch', prefix='terms فارسی ') as directory:
            work = Path(directory)
            source, ledger = work / 'source.txt', work / 'terms.tsv'
            source.write_text('核融合 در متن اصلی.\nAbhängigkeit و nodes.\nnode\n', encoding='utf-8')
            ledger.write_text(HEADER +
                '核融合\tهمجوشی هسته‌ای\t3 subject-lexicon\t1\t\tphysics-fusion\tpreferred\t\t\n'
                'Abhängigkeit\tوابستگی\t3 subject-lexicon\t1\t\tdependency\tpreferred\t\t\n'
                'node\tگره\t3 subject-lexicon\t1\t\tgraph-node\tpreferred\t\t\n'
                'node\tراس\t3 subject-lexicon\t1\t\tgraph-vertex\tpreferred\t\t\n'
                'node\tنامشخص\t3 subject-lexicon\t1\t\tundecided\t\t\t\n'
                'nodes\tگره‌ها\t3 subject-lexicon\t1\t\tgraph-nodes\trejected\t\t\n', encoding='utf-8')
            before = (source.read_bytes(), ledger.read_bytes())
            result = run([sys.executable, str(CLI), 'term-brief', str(source),
                          '--terms', str(ledger), '--language', 'ja'], timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['source_language'], 'ja')
            self.assertEqual(report['source_sha256'], hashlib.sha256(before[0]).hexdigest())
            self.assertEqual(report['terms_sha256'], hashlib.sha256(before[1]).hexdigest())
            self.assertEqual([(row['source'], row['locations'][0]['line']) for row in report['terms']],
                             [('核融合', 1), ('Abhängigkeit', 2), ('node', 3), ('node', 3)])
            self.assertTrue(all(row['ambiguous'] for row in report['terms'][-2:]))
            self.assertEqual((source.read_bytes(), ledger.read_bytes()), before)

    def test_missing_malformed_or_binary_inputs_fail_without_mutation(self):
        (ROOT / '.scratch').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.scratch') as directory:
            work = Path(directory)
            source, ledger = work / 'source.txt', work / 'terms.tsv'
            source.write_text('علوم داده', encoding='utf-8')
            ledger.write_text(HEADER + 'علوم داده\tعلم داده\n', encoding='utf-8')
            cases = [(source, ledger), (source, work / 'missing.tsv')]
            for selected_source, selected_ledger in cases:
                result = run([sys.executable, str(CLI), 'term-brief', str(selected_source),
                              '--terms', str(selected_ledger), '--language', 'fa'], timeout=15)
                self.assertNotEqual(result.returncode, 0)
            ledger.write_text(HEADER, encoding='utf-8')
            source.write_bytes(b'%PDF-1.7\n')
            result = run([sys.executable, str(CLI), 'term-brief', str(source),
                          '--terms', str(ledger), '--language', 'fa'], timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(source.read_bytes(), b'%PDF-1.7\n')


if __name__ == '__main__':
    unittest.main()
