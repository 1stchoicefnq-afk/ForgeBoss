from __future__ import annotations

import concurrent.futures
from pathlib import Path
import tempfile
import threading
import time
import unittest

from forgeboss.control.store import (
    ControlStore,
    TaskCancellationError,
)


class TaskCancellationStoreTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.worktrees = self.root / "worktrees"
        self.worktrees.mkdir()
        self.db = self.root / "state" / "control.sqlite3"
        self.store = ControlStore(self.db)

    def tearDown(self):
        try:
            self.store.db.close()
        except Exception:
            pass
        self.td.cleanup()

    def create(self, task_id="T1", budget=2.0, governed=False):
        task = {
            "taskId": task_id,
            "repository": "owner/repo",
            "purpose": "test cancellation fence",
            "baseSha": "a" * 40,
            "branch": "b-" + task_id,
            "allowedPaths": ["src/a.py"],
            "requiredTests": [],
            "budgetUsd": budget,
        }
        if governed:
            task.update({
                "governanceMode": "reuse-v1",
                "workKind": "substantial-subsystem",
                "subsystem": "test-subsystem",
                "reuseReviewSha256": "1" * 64,
                "reuseReviewReceiptSha256": "2" * 64,
            })
        return self.store.create_task(task)

    def claim(self, store=None, task_id="T1", run_id="R1", budget=0.25):
        store = store or self.store
        path = self.worktrees / (task_id + "-" + run_id)
        return store.claim_workspace(
            task_id,
            run_id,
            path,
            "b-" + task_id,
            "a" * 40,
            ttl_seconds=1200,
            runtime_id="mini-swe",
            worktree_root=self.worktrees,
            budget_reserved=budget,
        )

    def event_count(self, task_id, event_type):
        return self.store.db.execute(
            "SELECT COUNT(*) FROM task_events WHERE task_id=? AND event_type=?",
            (task_id, event_type),
        ).fetchone()[0]

    def test_cancel_queued_task_is_durable_and_idempotent(self):
        before = self.create()
        cancelled = self.store.cancel_task("T1")
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertIsNotNone(cancelled["cancel_requested_at"])
        self.assertEqual(cancelled["terminal_outcome"], "cancelled")
        self.assertEqual(cancelled["revision"], before["revision"] + 1)
        self.assertEqual(self.event_count("T1", "task.cancelled"), 1)

        again = self.store.cancel_task("T1")
        self.assertEqual(again["revision"], cancelled["revision"])
        self.assertEqual(
            again["cancel_requested_at"],
            cancelled["cancel_requested_at"],
        )
        self.assertEqual(self.event_count("T1", "task.cancelled"), 1)

    def test_cancel_active_lease_revokes_run_and_preserves_spend(self):
        self.create(budget=1.0)
        lease = self.claim(budget=0.4)
        before_spent = float(self.store.get_task("T1")["budget_spent"])
        self.assertEqual(before_spent, 0.4)

        cancelled = self.store.cancel_task("T1")
        after_lease = self.store.get_lease("T1")
        run = self.store.db.execute(
            "SELECT * FROM task_runs WHERE run_id='R1'"
        ).fetchone()

        self.assertEqual(cancelled["status"], "cancelled")
        self.assertIsNotNone(after_lease["released_at"])
        self.assertEqual(run["status"], "cancelled")
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual(float(cancelled["budget_spent"]), before_spent)
        self.assertEqual(float(after_lease["budget_reserved"]), 0.4)

        event = self.store.db.execute(
            "SELECT payload_json FROM task_events "
            "WHERE task_id='T1' AND event_type='task.cancelled'"
        ).fetchone()
        self.assertIn('"revokedRunId":"R1"', event["payload_json"])
        self.assertIn(
            f'"revokedOwnerEpoch":{int(lease["owner_epoch"])}',
            event["payload_json"],
        )

    def test_stale_owner_cannot_assert_heartbeat_or_release_after_cancel(self):
        self.create()
        lease = self.claim()
        epoch = int(lease["owner_epoch"])
        self.store.cancel_task("T1")

        with self.assertRaises(PermissionError):
            self.store.assert_writer("T1", "R1", epoch)
        with self.assertRaises(PermissionError):
            self.store.heartbeat("T1", "R1", epoch)
        with self.assertRaises(PermissionError):
            self.store.release("T1", "R1", epoch)

    def test_future_claim_after_cancel_fails_without_budget_run_or_new_lease(self):
        self.create(budget=1.0)
        self.store.cancel_task("T1")
        before = self.store.get_task("T1")
        with self.assertRaises(TaskCancellationError) as ctx:
            self.claim(run_id="R2", budget=0.5)
        self.assertEqual(ctx.exception.code, "TASK_CANCELLED")
        after = self.store.get_task("T1")
        self.assertEqual(float(after["budget_spent"]), float(before["budget_spent"]))
        self.assertEqual(
            self.store.db.execute(
                "SELECT COUNT(*) FROM task_runs WHERE task_id='T1'"
            ).fetchone()[0],
            0,
        )
        self.assertIsNone(self.store.get_lease("T1"))

    def test_cancel_marks_worker_instance_cancelled(self):
        self.create()
        now = time.time()
        self.store.db.execute(
            """INSERT INTO worker_instances(
                worker_id,task_id,run_id,owner_epoch,runtime_id,envelope_hash,status,last_seen_at
            ) VALUES(?,?,?,?,?,?,?,?)""",
            ("W1", "T1", None, None, "mini-swe", "h", "waiting", now),
        )
        self.store.cancel_task("T1")
        row = self.store.db.execute(
            "SELECT status FROM worker_instances WHERE worker_id='W1'"
        ).fetchone()
        self.assertEqual(row["status"], "cancelled")

    def test_cancel_event_failure_still_revokes_authority_and_marks_audit_pending(self):
        self.create()
        lease = self.claim()
        now = time.time()
        self.store.db.execute(
            """INSERT INTO worker_instances(
                worker_id,task_id,run_id,owner_epoch,runtime_id,envelope_hash,status,last_seen_at
            ) VALUES(?,?,?,?,?,?,?,?)""",
            ("W1", "T1", "R1", int(lease["owner_epoch"]), "mini-swe", "h", "running", now),
        )
        self.store.db.execute(
            """CREATE TRIGGER reject_task_cancelled
            BEFORE INSERT ON task_events
            WHEN NEW.event_type='task.cancelled'
            BEGIN SELECT RAISE(ABORT,'cancel event rejected'); END"""
        )

        cancelled = self.store.cancel_task("T1")

        after_lease = self.store.get_lease("T1")
        run = self.store.db.execute(
            "SELECT status,finished_at FROM task_runs WHERE run_id='R1'"
        ).fetchone()
        worker = self.store.db.execute(
            "SELECT status FROM worker_instances WHERE worker_id='W1'"
        ).fetchone()

        self.assertIsNotNone(cancelled["cancel_requested_at"])
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["current_step"], "cancelled-audit-pending")
        self.assertIsNotNone(after_lease["released_at"])
        self.assertEqual(run["status"], "cancelled")
        self.assertIsNotNone(run["finished_at"])
        self.assertEqual(worker["status"], "cancelled")
        self.assertEqual(self.event_count("T1", "task.cancelled"), 0)
        with self.assertRaises(PermissionError):
            self.store.assert_writer("T1", "R1", int(lease["owner_epoch"]))

    def test_active_lease_run_state_mismatch_does_not_restore_authority(self):
        self.create()
        lease = self.claim()
        self.store.db.execute(
            "UPDATE task_runs SET status='broken' WHERE run_id='R1'"
        )
        cancelled = self.store.cancel_task("T1")
        after_lease = self.store.get_lease("T1")
        event = self.store.db.execute(
            "SELECT payload_json FROM task_events "
            "WHERE task_id='T1' AND event_type='task.cancelled'"
        ).fetchone()

        self.assertEqual(cancelled["status"], "cancelled")
        self.assertIsNotNone(after_lease["released_at"])
        self.assertIn('"activeRunStateMismatch":true', event["payload_json"])
        with self.assertRaises(PermissionError):
            self.store.assert_writer("T1", "R1", int(lease["owner_epoch"]))

    def test_cancel_applies_to_governed_and_legacy_tasks(self):
        self.create("LEGACY", governed=False)
        self.create("GOV", governed=True)
        self.assertEqual(self.store.cancel_task("LEGACY")["status"], "cancelled")
        self.assertEqual(self.store.cancel_task("GOV")["status"], "cancelled")

    def test_concurrent_cancel_and_claim_cannot_leave_live_authority(self):
        self.create(budget=1.0)
        cancel_store = ControlStore(self.db)
        claim_store = ControlStore(self.db)
        barrier = threading.Barrier(2)

        def cancel():
            barrier.wait()
            try:
                return ("cancel", "ok", cancel_store.cancel_task("T1"))
            except Exception as ex:
                return ("cancel", "err", ex)

        def claim():
            barrier.wait()
            try:
                return ("claim", "ok", self.claim(
                    store=claim_store,
                    run_id="RACE",
                    budget=0.25,
                ))
            except Exception as ex:
                return ("claim", "err", ex)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda fn: fn(), [cancel, claim]))
        finally:
            cancel_store.db.close()
            claim_store.db.close()

        cancel_result = next(x for x in results if x[0] == "cancel")
        self.assertEqual(cancel_result[1], "ok")
        task = self.store.get_task("T1")
        lease = self.store.get_lease("T1")
        self.assertIsNotNone(task["cancel_requested_at"])
        if lease is not None:
            self.assertIsNotNone(lease["released_at"])
        running = self.store.db.execute(
            "SELECT COUNT(*) FROM task_runs WHERE task_id='T1' AND status='running'"
        ).fetchone()[0]
        self.assertEqual(running, 0)
        self.assertIn(float(task["budget_spent"]), (0.0, 0.25))


if __name__ == "__main__":
    unittest.main()