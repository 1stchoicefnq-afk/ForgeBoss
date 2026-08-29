from __future__ import annotations
import tempfile,unittest
from pathlib import Path
from forgeboss.control.store import ControlStore,StoreAuthorityError

class StoreAuthorityLegacyCompatibilityTests(unittest.TestCase):
    def test_unbound_release_requires_retry_but_does_not_become_assignment_bound(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);root=base/"worktrees";root.mkdir();store=ControlStore(base/"state"/"control.sqlite3")
            try:
                store.create_task({"taskId":"L","repository":"owner/repo","purpose":"legacy","baseSha":"a"*40,"branch":"legacy","allowedPaths":["src/l.py"],"requiredTests":[],"budgetUsd":5})
                first=store.claim_workspace("L","r1",root/"L","legacy","a"*40,worktree_root=root,budget_reserved=1)
                store.release("L","r1",first["owner_epoch"],outcome="released")
                task=store.get_task("L");self.assertEqual(task["assignment_generation"],0);self.assertIsNone(task["budget_run_id"])
                with self.assertRaises(StoreAuthorityError) as cm:
                    store.claim_workspace("L","r2",root/"L","legacy","a"*40,worktree_root=root,budget_reserved=1)
                self.assertEqual(cm.exception.code,"TASK_RETRY_REQUIRED")
                store.retry_task("L","controller continuation")
                task=store.get_task("L");self.assertEqual(task["assignment_generation"],0);self.assertIsNone(task["assigned_builder_id"])
                second=store.claim_workspace("L","r2",root/"L","legacy","a"*40,worktree_root=root,budget_reserved=1)
                self.assertEqual(second["attempt"],2);self.assertEqual(store.get_task("L")["budget_spent"],2.0)
            finally:store.db.close()

if __name__=="__main__":unittest.main()
