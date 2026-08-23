from __future__ import annotations
import unittest
from forgeboss.control.scheduler import WorkItem,conflicts,smart_parallel_batches


def item(task,files=(),roots=(),priority=100,cost=0.0):
    return WorkItem(
        task_id=task,
        family='test',
        files=set(files),
        write_roots=set(roots),
        priority=priority,
        estimated_cost=cost,
    )


class SchedulerConflictTests(unittest.TestCase):
    def test_exact_same_file_conflicts(self):
        self.assertTrue(conflicts(item('a',files=['src/a.js']),item('b',files=['src/a.js'])))

    def test_file_under_peer_root_conflicts_both_directions(self):
        a=item('a',files=['src/lib/a.js']);b=item('b',roots=['src/lib'])
        self.assertTrue(conflicts(a,b));self.assertTrue(conflicts(b,a))

    def test_windows_case_variants_conflict(self):
        self.assertTrue(conflicts(item('a',files=['SRC/A.JS']),item('b',files=['src/a.js'])))

    def test_slash_variants_conflict(self):
        self.assertTrue(conflicts(item('a',files=[r'src\a.js']),item('b',files=['src/a.js'])))

    def test_dot_segment_equivalents_conflict(self):
        self.assertTrue(conflicts(item('a',files=['./src/lib/../a.js']),item('b',files=['src/a.js'])))

    def test_win32_trailing_dot_space_file_equivalents_conflict(self):
        base=item('a',files=['src/a.js'])
        self.assertTrue(conflicts(base,item('b',files=[r'SRC\a.js.'])))
        self.assertTrue(conflicts(base,item('c',files=[r'src\a.js '])))

    def test_win32_trailing_dot_space_file_root_conflicts(self):
        self.assertTrue(conflicts(item('a',files=['src/lib/a.js']),item('b',roots=[r'SRC\lib. '])))
        self.assertTrue(conflicts(item('a',roots=['src/lib']),item('b',files=[r'SRC\lib.\a.js'])))

    def test_win32_trailing_dot_space_root_equivalents_conflict(self):
        self.assertTrue(conflicts(item('a',roots=['src/lib']),item('b',roots=[r'SRC\lib. '])))
        self.assertTrue(conflicts(item('a',roots=[r'src\lib.']),item('b',roots=['src/lib/deep'])))

    def test_win32_parent_segment_with_trailing_space_file_file(self):
        self.assertTrue(conflicts(
            item('a',files=['src/child/.. /a.js']),
            item('b',files=['src/a.js']),
        ))

    def test_win32_parent_segment_with_trailing_space_file_root(self):
        self.assertTrue(conflicts(
            item('a',files=['src/child/.. /a.js']),
            item('b',roots=['src']),
        ))
        self.assertTrue(conflicts(
            item('a',roots=['src/child/.. /lib']),
            item('b',files=['src/lib/a.js']),
        ))

    def test_win32_current_segment_with_trailing_space_file_file(self):
        self.assertTrue(conflicts(
            item('a',files=['src/. /a.js']),
            item('b',files=['src/a.js']),
        ))

    def test_win32_current_segment_with_trailing_space_file_root(self):
        self.assertTrue(conflicts(
            item('a',files=['src/. /lib/a.js']),
            item('b',roots=['src/lib']),
        ))
        self.assertTrue(conflicts(
            item('a',roots=['src/. /lib']),
            item('b',files=['src/lib/a.js']),
        ))

    def test_root_ancestor_descendant_conflict(self):
        self.assertTrue(conflicts(item('a',roots=['src']),item('b',roots=['src/lib'])))
        self.assertTrue(conflicts(item('a',roots=[r'SRC\LIB']),item('b',roots=['src/lib/deep'])))

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
            item('d',roots=[r'tests\unit']),
            item('e',files=['tests/unit/e.js']),
            item('f',roots=['src/ab']),
        ]
        batches=smart_parallel_batches(items,max_workers=6)
        for batch in batches:
            for i,left in enumerate(batch):
                for right in batch[i+1:]:
                    self.assertFalse(conflicts(left,right),f'{left.task_id} conflicts with {right.task_id} in one batch')

    def test_batching_is_deterministic(self):
        items=[
            item('z',files=['z.js'],priority=20,cost=2.0),
            item('a',files=['src/a.js'],priority=10,cost=1.0),
            item('b',roots=['src'],priority=10,cost=1.0),
            item('c',files=['tests/c.js'],priority=10,cost=0.5),
        ]
        first=[[x.task_id for x in batch] for batch in smart_parallel_batches(items,max_workers=3)]
        second=[[x.task_id for x in batch] for batch in smart_parallel_batches(list(reversed(items)),max_workers=3)]
        self.assertEqual(first,second)


if __name__=='__main__':
    unittest.main()
