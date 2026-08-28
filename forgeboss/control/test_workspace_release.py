from __future__ import annotations
import tempfile, threading, unittest
from pathlib import Path
import forgeboss.control.store as store_module


class WorkspaceReleaseRaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.worktree_root = root / "worktrees"
        self.worktree_root.mkdir()
        self.store = store_module.ControlStore(root / "t.sqlite")
        self.addCleanup(self.store.db.close)
        self.store.create_task({
            "taskId": "T1", "repository": "o/r", "purpose": "p", "baseSha": "a" * 40,
            "allowedPaths": [], "requiredTests": [], "budgetUsd": 1.0,
        })
        work = self.worktree_root / "w1"
        work.mkdir()
        lease = self.store.claim_workspace(
            "T1", "R1", str(work), "branch", "a" * 40, ttl_seconds=60,
            runtime_id="rt", worktree_root=self.worktree_root,
        )
        self.epoch = lease["owner_epoch"]

    def test_sequential_double_release_is_rejected(self):
        self.store.release("T1", "R1", self.epoch, result_head="b" * 40, outcome="success")
        self.assertEqual(self.store.get_task("T1")["revision"], 3)
        with self.assertRaises(PermissionError):
            self.store.release("T1", "R1", self.epoch, result_head="c" * 40, outcome="failed")
        self.assertEqual(self.store.get_task("T1")["status"], "success")
        self.assertEqual(self.store.get_task("T1")["revision"], 3)

    def test_concurrent_double_release_cannot_double_complete(self):
        # Force the exact interleaving a race would produce: both callers pass
        # the writer-authority check before either has written released_at, by
        # synchronizing on a barrier right after assert_writer's internal read.
        # A regression here means release() lost its atomicity and can double
        # -complete a task (duplicate events, double revision bump, clobbered
        # outcome) when two release calls race for the same run/epoch.
        barrier = threading.Barrier(2)
        orig_assert_writer = store_module.ControlStore.assert_writer

        def racy_assert_writer(self_, *a, **k):
            result = orig_assert_writer(self_, *a, **k)
            barrier.wait(timeout=5)
            return result

        store_module.ControlStore.assert_writer = racy_assert_writer
        self.addCleanup(setattr, store_module.ControlStore, "assert_writer", orig_assert_writer)

        results, errors = [], []

        def do_release(outcome, head):
            try:
                self.store.release("T1", "R1", self.epoch, result_head=head, outcome=outcome)
                results.append(outcome)
            except Exception as ex:
                errors.append(ex)

        t1 = threading.Thread(target=do_release, args=("success", "b" * 40))
        t2 = threading.Thread(target=do_release, args=("failed", "c" * 40))
        t1.start(); t2.start(); t1.join(10); t2.join(10)

        self.assertEqual(len(results), 1, f"expected exactly one release to win, got {results}")
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], PermissionError)

        task = self.store.get_task("T1")
        self.assertEqual(task["revision"], 3)
        self.assertEqual(task["status"], results[0])

        released_events = self.store.db.execute(
            "SELECT COUNT(*) FROM task_events WHERE event_type='workspace.released'"
        ).fetchone()[0]
        self.assertEqual(released_events, 1)


if __name__ == "__main__":
    unittest.main()
