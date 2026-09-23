from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest

from forgeboss.security.executor_guard import SecurityError, _assert_live_control_lease


class LiveControlLeaseTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.db = self.root / "forgeboss.db"
        self.work = self.root / "work"
        self.work.mkdir()
        conn = sqlite3.connect(self.db)
        conn.executescript("""
        CREATE TABLE tasks(
          task_id TEXT PRIMARY KEY,
          status TEXT,
          cancel_requested_at REAL,
          assigned_runtime TEXT,
          governance_mode TEXT
        );
        CREATE TABLE workspace_leases(
          task_id TEXT PRIMARY KEY,
          owner_run_id TEXT,
          owner_epoch INTEGER,
          released_at REAL,
          expires_at REAL,
          worktree_path TEXT
        );
        """)
        conn.execute(
            "INSERT INTO tasks(task_id,status,cancel_requested_at,assigned_runtime,governance_mode) VALUES(?,?,?,?,?)",
            ("T1", "running", None, "mini-swe", "reuse-v1"),
        )
        conn.execute(
            "INSERT INTO workspace_leases(task_id,owner_run_id,owner_epoch,released_at,expires_at,worktree_path) VALUES(?,?,?,?,?,?)",
            ("T1", "RUN1", 7, None, 2000.0, str(self.work)),
        )
        conn.commit()
        conn.close()
        self.authority = {
            "taskId": "T1",
            "runId": "RUN1",
            "ownerEpoch": 7,
            "worktreePath": str(self.work),
        }

    def mutate(self, sql, params):
        conn = sqlite3.connect(self.db)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def check(self, **changes):
        authority = dict(self.authority)
        authority.update(changes)
        return _assert_live_control_lease(
            authority,
            "mini-swe",
            db_path=self.db,
            now=1500.0,
        )

    def test_exact_live_governed_lease_passes(self):
        self.assertTrue(self.check())

    def test_released_expired_cancelled_or_nonrunning_fails_closed(self):
        cases = [
            ("UPDATE workspace_leases SET released_at=? WHERE task_id='T1'", (1499.0,), "released"),
            ("UPDATE workspace_leases SET expires_at=? WHERE task_id='T1'", (1499.0,), "expired"),
            ("UPDATE tasks SET cancel_requested_at=? WHERE task_id='T1'", (1499.0,), "cancellation"),
            ("UPDATE tasks SET status=? WHERE task_id='T1'", ("queued",), "not running"),
        ]
        for sql, params, match in cases:
            with self.subTest(match=match):
                self.setUp()
                self.mutate(sql, params)
                with self.assertRaisesRegex(SecurityError, match):
                    self.check()
                self.tearDown()

    def test_wrong_run_epoch_runtime_workspace_or_governance_fails_closed(self):
        with self.assertRaisesRegex(SecurityError, "run identity"):
            self.check(runId="OTHER")
        with self.assertRaisesRegex(SecurityError, "owner epoch"):
            self.check(ownerEpoch=8)
        with self.assertRaisesRegex(SecurityError, "runtime identity"):
            _assert_live_control_lease(
                self.authority,
                "openhands",
                db_path=self.db,
                now=1500.0,
            )
        other = self.root / "other"
        other.mkdir()
        with self.assertRaisesRegex(SecurityError, "workspace mismatch"):
            self.check(worktreePath=str(other))
        self.mutate(
            "UPDATE tasks SET governance_mode=? WHERE task_id='T1'",
            ("legacy",),
        )
        with self.assertRaisesRegex(SecurityError, "not governed"):
            self.check()

    def test_missing_control_db_or_task_fails_closed(self):
        with self.assertRaisesRegex(SecurityError, "control DB unavailable"):
            _assert_live_control_lease(
                self.authority,
                "mini-swe",
                db_path=self.root / "missing.db",
                now=1500.0,
            )
        self.mutate("DELETE FROM workspace_leases WHERE task_id='T1'", ())
        with self.assertRaisesRegex(SecurityError, "lease missing"):
            self.check()


if __name__ == "__main__":
    unittest.main()
