"""Synthetic local Git histories exercise the exact published-email policy."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'skills/revayat-scientific/scripts'))
from runtime import operation_log

SPEC=importlib.util.spec_from_file_location('audit_identity_checker',ROOT/'tools/check-commit-identity.py')
IDENTITY=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITY)


class CommitIdentityTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='identity fixture ')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.scope=operation_log('test-commit-identity',self.root/'logs')
        self.log=self.scope.__enter__()
        self.addCleanup(self.scope.__exit__,None,None,None)
        self.log.info('running test=%s; synthetic commits are never published',self._testMethodName)
        self.environment={**os.environ,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,
            'GIT_AUTHOR_NAME':'Synthetic Fixture','GIT_COMMITTER_NAME':'Synthetic Fixture',
            'GIT_AUTHOR_EMAIL':IDENTITY.APPROVED_EMAIL,'GIT_COMMITTER_EMAIL':IDENTITY.APPROVED_EMAIL}
        self.git('init','--quiet')

    def git(self,*arguments,**environment):
        result=subprocess.run(['git',*arguments],cwd=self.root,env={**self.environment,**environment},
            stdin=subprocess.DEVNULL,capture_output=True,text=True,encoding='utf-8',timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        return result.stdout.strip()

    def commit(self,author=None,committer=None):
        self.git('commit','--allow-empty','--quiet','-m','Synthetic identity fixture',
            GIT_AUTHOR_EMAIL=author or IDENTITY.APPROVED_EMAIL,
            GIT_COMMITTER_EMAIL=committer or IDENTITY.APPROVED_EMAIL)
        return self.git('rev-parse','HEAD')

    def test_matching_complete_history_passes(self):
        self.commit();self.commit()
        self.assertEqual(IDENTITY.inspect_identities(self.root),(2,[]))

    def test_author_and_committer_are_checked_independently(self):
        bad='fixture-only@example.invalid'
        first=self.commit(author=bad)
        second=self.commit(committer=bad)
        third=self.commit(author=bad,committer=bad)
        count,failures=IDENTITY.inspect_identities(self.root)
        self.assertEqual(count,3)
        self.assertEqual(dict(failures),{first:('author',),second:('committer',),third:('author','committer')})

    def test_introduced_range_does_not_claim_legacy_history_passed(self):
        base=self.commit(author='fixture-only@example.invalid')
        head=self.commit()
        self.assertEqual(IDENTITY.inspect_identities(self.root,head,base),(1,[]))
        self.assertEqual(len(IDENTITY.inspect_identities(self.root,head)[1]),1)

    def test_mailmap_cannot_hide_stored_identity_mismatch(self):
        sha=self.commit(author='fixture-only@example.invalid')
        (self.root/'.mailmap').write_text(IDENTITY.APPROVED_EMAIL.join(('<','> <fixture-only@example.invalid>\n')),encoding='utf-8')
        self.assertEqual(IDENTITY.inspect_identities(self.root)[1],[(sha,('author',))])

    def test_empty_introduced_range_and_invalid_refs_are_distinct(self):
        head=self.commit()
        self.assertEqual(IDENTITY.inspect_identities(self.root,head,head),(0,[]))
        for head,base in (('missing',None),('HEAD','missing'),('--all',None)):
            with self.subTest(head=head,base=base),self.assertRaises(ValueError):
                IDENTITY.inspect_identities(self.root,head,base)

    def test_email_comparison_is_exact(self):
        sha=self.commit(author=IDENTITY.APPROVED_EMAIL.lower())
        self.assertEqual(IDENTITY.inspect_identities(self.root)[1],[(sha,('author',))])


if __name__=='__main__':
    unittest.main()
