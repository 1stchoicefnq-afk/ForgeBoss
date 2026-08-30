from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from forgeboss.control.store import ControlStore, StoreAuthorityError

A40 = "a" * 40


def make_task(task_id="task-1"):
    return {
        "taskId": task_id,
        "repository": "owner/repo",
        "purpose": "store-r6",
        "baseSha": A40,
        "branch": f"fb/{task_id}",
        "allowedPaths": ["src/a.py"],
        "requiredTests": ["t"],
        "budgetUsd": "5",
    }


class StoreAuthorityR6MigrationTests(unittest.TestCase):
    def test_assigned_event_survives_all_current_assignment_fields_cleared(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            st = ControlStore(db)
            st.create_budget_run("budget-1", "20")
            st.create_task(make_task())
            st.assign_builder("task-1", "worker-a", "budget-1")
            st.db.execute(
                """UPDATE tasks SET assignment_mode='legacy', assigned_builder_id=NULL,
                    assignment_generation=0, assignment_token_hash=NULL, assignment_sha256=NULL
                    WHERE task_id='task-1'"""
            )
            st.db.close()

            st = ControlStore(db)
            self.assertEqual(st.get_task("task-1")["assignment_mode"], "controller-bound")
            st.db.close()

            st = ControlStore(db)
            self.assertEqual(st.get_task("task-1")["assignment_mode"], "controller-bound")
            st.db.close()

    def test_budget_binding_without_assigned_event_remains_legacy(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            st = ControlStore(db)
            st.create_budget_run("budget-1", "20")
            st.create_task(make_task())
            st.db.execute(
                "UPDATE tasks SET budget_run_id='budget-1', assignment_mode='controller-bound' WHERE task_id='task-1'"
            )
            st.db.close()

            st = ControlStore(db)
            self.assertEqual(st.get_task("task-1")["assignment_mode"], "legacy")
            st.db.close()

    def test_positive_generation_without_assigned_event_remains_legacy(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            st = ControlStore(db)
            st.create_task(make_task())
            st.db.execute(
                "UPDATE tasks SET assignment_generation=9, assignment_mode='legacy' WHERE task_id='task-1'"
            )
            st.db.close()

            st = ControlStore(db)
            task = st.get_task("task-1")
            self.assertEqual(task["assignment_mode"], "legacy")
            self.assertEqual(task["assignment_generation"], 9)
            st.db.close()

    def test_stale_current_assignment_fields_without_event_do_not_bind(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            st = ControlStore(db)
            st.create_budget_run("budget-1", "20")
            st.create_task(make_task())
            st.db.execute(
                """UPDATE tasks SET budget_run_id='budget-1', assigned_builder_id='stale-worker',
                    assignment_token_hash=?, assignment_sha256=?, assignment_generation=0,
                    assignment_mode='legacy' WHERE task_id='task-1'""",
                ("1" * 64, "2" * 64),
            )
            st.db.close()

            st = ControlStore(db)
            self.assertEqual(st.get_task("task-1")["assignment_mode"], "legacy")
            st.db.close()

    def test_malformed_assigned_event_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            st = ControlStore(db)
            st.create_task(make_task())
            version = int(st.db.execute("SELECT COALESCE(MAX(state_version),0)+1 v FROM task_events").fetchone()["v"])
            st.db.execute(
                """INSERT INTO task_events(task_id,run_id,event_type,payload_json,state_version,created_at)
                    VALUES(?,NULL,'task.assigned',?,?,?)""",
                ("task-1", "{", version, time.time()),
            )
            st.db.close()

            with self.assertRaises(StoreAuthorityError) as cm:
                ControlStore(db)
            self.assertEqual(cm.exception.code, "ASSIGNMENT_HISTORY_INVALID")

    def test_contradictory_duplicate_assignment_generation_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            st = ControlStore(db)
            st.create_budget_run("budget-1", "20")
            st.create_task(make_task())
            st.assign_builder("task-1", "worker-a", "budget-1")
            original = st.db.execute(
                "SELECT payload_json FROM task_events WHERE task_id='task-1' AND event_type='task.assigned'"
            ).fetchone()["payload_json"]
            version = int(st.db.execute("SELECT COALESCE(MAX(state_version),0)+1 v FROM task_events").fetchone()["v"])
            st.db.execute(
                """INSERT INTO task_events(task_id,run_id,event_type,payload_json,state_version,created_at)
                    VALUES(?,NULL,'task.assigned',?,?,?)""",
                ("task-1", original, version, time.time()),
            )
            st.db.close()

            with self.assertRaises(StoreAuthorityError) as cm:
                ControlStore(db)
            self.assertEqual(cm.exception.code, "ASSIGNMENT_HISTORY_INVALID")

    def test_assignment_event_digest_tamper_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            st = ControlStore(db)
            st.create_budget_run("budget-1", "20")
            st.create_task(make_task())
            st.assign_builder("task-1", "worker-a", "budget-1")
            row = st.db.execute(
                "SELECT seq,payload_json FROM task_events WHERE task_id='task-1' AND event_type='task.assigned'"
            ).fetchone()
            payload = json.loads(row["payload_json"])
            payload["assignmentSha256"] = "0" * 64
            st.db.execute(
                "UPDATE task_events SET payload_json=? WHERE seq=?",
                (json.dumps(payload, separators=(",", ":")), int(row["seq"])),
            )
            st.db.close()

            with self.assertRaises(StoreAuthorityError) as cm:
                ControlStore(db)
            self.assertEqual(cm.exception.code, "ASSIGNMENT_HISTORY_INVALID")

    def test_orphan_assigned_event_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            st = ControlStore(db)
            version = int(st.db.execute("SELECT COALESCE(MAX(state_version),0)+1 v FROM task_events").fetchone()["v"])
            payload = {
                "builderId": "worker-a",
                "assignmentGeneration": 1,
                "assignmentSha256": "0" * 64,
                "budgetRunId": "budget-1",
            }
            st.db.execute(
                """INSERT INTO task_events(task_id,run_id,event_type,payload_json,state_version,created_at)
                    VALUES(?,NULL,'task.assigned',?,?,?)""",
                ("missing-task", json.dumps(payload, separators=(",", ":")), version, time.time()),
            )
            st.db.close()

            with self.assertRaises(StoreAuthorityError) as cm:
                ControlStore(db)
            self.assertEqual(cm.exception.code, "ASSIGNMENT_HISTORY_INVALID")


if __name__ == "__main__":
    unittest.main()
