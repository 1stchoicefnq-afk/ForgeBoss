from __future__ import annotations
import unittest
from forgeboss.control.scheduler import WorkItem,conflicts,smart_parallel_batches


def item(task,files=(),roots=()):
    return WorkItem(task_id=task,family='test',files=set(files),write_roots=set(roots))


class SchedulerConflictTests(unittest.TestCase):
    def test_exact_same_file_conflicts(self):
        self.assertTrue(conflicts(item('a',files=['src/a.js']),item('b',files=['src/a.js'])))

    def test_file_under_peer_root_conflicts_both_directions(self):
        a=item('a',files=['src/a.js']);b=item('b',roots=['src'])
        self.assertTrue(conflicts(a,b));self.assertTrue(conflicts(b,a))

    def test_windows_case_variants_conflict(self):
        self.assertTrue(conflicts(item('a',files=['SRC/A.JS']),item('b',files=['src/a.js'])))

    def test_slash_variants_conflict(self):
        self.assertTrue(conflicts(item('a',files=[r'src\\a.js']),item('b',files=['src/a.js'])))

    def test_dot_segment_equivalents_conflict(self):
        self.assertTrue(conflicts(item('a',files=['./src/lib/../a.js']),item('b',files=['src/a.js'])))

    def test_win32_trailing_dot_space_file_equivalence(self):
        self.assertTrue(conflicts(item('a',files=['src/a.js']),item('b',files=[r'SRC\\a.js.'])))
        self.assertTrue(conflicts(item('a',files=['src/a.js']),item('b',files=[r'src\\a.js '])))

    def test_win32_trailing_dot_space_file_root_equivalence(self):
        self.assertTrue(conflicts(item('a',files=['src/lib/a.js']),item('b',roots=[r'SRC\\LIB.'])))
        self.assertTrue(conflicts(item('a',roots=['src/lib']),item('b',files=[r'src\\lib \\a.js'])))

    def test_win32_trailing_dot_space_root_equivalence(self):
        self.assertTrue(conflicts(item('a',roots=['src/lib']),item('b',roots=[r'SRC\\LIB.\\deep'])))

    def test_win32_dotdot_with_trailing_space_collapses_before_comparison(self):
        self.assertTrue(conflicts(item('a',files=['src/a.js']),item('b',files=[r'src\\child\\.. \\a.js'])))
        self.assertTrue(conflicts(item('a',roots=['src']),item('b',files=[r'src\\child\\.. \\a.js'])))

    def test_win32_dot_with_trailing_space_is_current_directory(self):
        self.assertTrue(conflicts(item('a',files=['src/a.js']),item('b',files=[r'src\\. \\a.js'])))
        self.assertTrue(conflicts(item('a',roots=['src']),item('b',files=[r'src\\. \\a.js'])))

    def test_root_ancestor_descendant_conflict(self):
        self.assertTrue(conflicts(item('a',roots=['src']),item('b',roots=['src/lib'])))
        self.assertTrue(conflicts(item('a',roots=['SRC\\LIB']),item('b',roots=['src/lib/deep'])))

    def test_sibling_prefixes_do_not_conflict(self):
        self.assertFalse(conflicts(item('a',roots=['src/a']),item('b',roots=['src/ab'])))

    def test_safe_non_overlap_remains_parallel(self):
        a=item('a',files=['src/a.js']);b=item('b',files=['tests/b.js']);c=item('c',roots=['docs'])
        batches=smart_parallel_batches([a,b,c],max_workers=4)
        self.assertEqual([[x.task_id for x in batch] for batch in batches],[['a','b','c']])

    def test_batches_never_contain_conflicting_pair(self):
        items=[
            item('a',files=['SRC/a.js']),
            item('b',roots=['src']),
            item('c',files=['tests/c.js']),
            item('d',roots=['tests\\unit']),
            item('e',files=['tests/unit/e.js']),
            item('f',roots=['src/ab']),
        ]
        batches=smart_parallel_batches(items,max_workers=6)
        for batch in batches:
            for i,left in enumerate(batch):
                for right in batch[i+1:]:
                    self.assertFalse(conflicts(left,right),f'{left.task_id} conflicts with {right.task_id} in one batch')


if __name__=='__main__':
    unittest.main()
