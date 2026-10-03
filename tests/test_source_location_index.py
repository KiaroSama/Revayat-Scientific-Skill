"""Repeated source attribution must use indexes, preserving exact old locations."""
from bisect import bisect_right
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'skills/revayat-scientific/scripts'))
from tex_source import SourceClosure, source_closure
from runtime import operation_log


def reference(closure,offset):
    if not closure.segments:
        return closure.sources[0],1
    starts=[item[0] for item in closure.segments]
    start,path,original_offset,original=closure.segments[max(0,bisect_right(starts,offset)-1)]
    return path,original.count('\n',0,original_offset+offset-start)+1


class SourceLocationIndexTest(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.scratch'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='source index audit ', dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.scope = operation_log('test-source-location-index', self.root / 'logs')
        self.log = self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)
        self.log.info('running test=%s',self._testMethodName)

    def test_repeated_queries_do_not_rescan_source_prefixes(self):
        class CountedText(str):
            calls=0
            def count(self,*args):
                self.calls+=1
                return super().count(*args)
        text=CountedText('line\n'*1000)
        closure=SourceClosure(text,[(0,self.root/'main.tex',0,text)],(self.root/'main.tex',))
        for i in range(2000): closure.location(i%len(text))
        self.assertEqual(text.calls,0,'line attribution must use a precomputed newline index')

    def test_segment_start_keys_are_not_rebuilt_per_query(self):
        class CountedSegments(list):
            walks=0
            def __iter__(self):
                self.walks+=1
                return super().__iter__()
        text='line\n'*200
        segments=CountedSegments((i,self.root/'main.tex',i,text) for i in range(0,len(text),5))
        closure=SourceClosure(text,segments,(self.root/'main.tex',))
        initial=segments.walks
        for i in range(len(text)+1): closure.location(i)
        self.assertEqual(segments.walks,initial,'segment starts must be indexed once')

    def test_every_offset_matches_old_mapping_for_nested_repeated_mixed_sources(self):
        source=self.root/'main.tex'
        for a in ('\n','\r\n'):
            for b in ('\n','\r\n'):
                with self.subTest(parent=repr(a),child=repr(b)):
                    source.write_bytes(('Intro'+a+r'\input{child}'+a+r'\input{child} Tail').encode('utf-8'))
                    (self.root/'child.tex').write_bytes(('Child'+b+r'\input{nested} End').encode('utf-8'))
                    (self.root/'nested.tex').write_bytes(b'% EOF comment')
                    closure=source_closure(source)
                    for offset in range(len(closure.text)+1):
                        self.assertEqual(closure.location(offset),reference(closure,offset))
                    pos=closure.text.index('Tail')
                    self.assertEqual(closure.location(pos),(source,3))

    def test_empty_closure_and_newline_boundaries(self):
        path=self.root/'empty.tex'
        path.write_bytes(b'')
        empty=source_closure(path)
        self.assertEqual(empty.location(0),(path,1))
        for text in ('x\ny','\n','\r\n','no newline','\n\n\n'):
            path.write_bytes(text.encode('utf-8'))
            closure=source_closure(path)
            for offset in range(-len(text)-2,len(text)+3):
                self.assertEqual(closure.location(offset),reference(closure,offset))

    def test_same_path_distinct_original_snapshots_have_distinct_indexes(self):
        path=self.root/'same.tex'
        first,second='first\nline','no breaks in second'
        closure=SourceClosure(first+second,[(0,path,0,first),(len(first),path,0,second)],(path,))
        for offset in range(len(closure.text)+1):
            self.assertEqual(closure.location(offset),reference(closure,offset))

    def test_newline_index_has_bounded_compact_storage(self):
        text='\n'*10000
        path=self.root/'dense.tex'
        closure=SourceClosure(text,[(0,path,0,text)],(path,))
        indexes=getattr(closure,'_line_breaks',None)
        self.assertIsNotNone(indexes)
        self.assertLess(sys.getsizeof(indexes[id(text)]),len(text)*5)
        self.assertEqual(closure.location(len(text)),(path,10001))


if __name__=='__main__':
    unittest.main()
