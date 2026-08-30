from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from forgeboss.control.store import ControlStore, StoreAuthorityError

A40 = "a" * 40


def make_task(task_id: str):
    return {
        "taskId": task_id,
        "repository": "owner/repo",
        "purpose": "store-v3-r6-atomic-migration",
        "baseSha": A40,
        "branch": f"fb/{task_id}",
        "allowedPaths": [f"src/{task_id}.py"],
        "requiredTests": ["t"],
        "budgetUsd": "5",
    }


class StoreAuthorityV3AtomicMigrationTests(unittest.TestCase):

    def test_late_invalid_history_rolls_back_entire_migration_attempt(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"

            st = ControlStore(db)
            st.create_budget_run("budget-1", "20")
            st.create_task(make_task("task-a"))
            st.assign_builder("task-a", "worker-a", "budget-1")
            st.create_task(make_task("task-b"))

            # Simulate a pre-R6 reopen where task A has durable assignment
            # history that would be reclassified, while a later task contains
            # invalid assignment history. Also force a budget-normalization
            # write so rollback covers more than assignment_mode.
            st.db.execute(
                "UPDATE tasks SET assignment_mode='legacy', budget_cap_exact=NULL "
                "WHERE task_id='task-a'"
            )
            st.db.execute(
                "UPDATE meta SET value='5' WHERE key='schema_version'"
            )
            next_version = int(
                st.db.execute(
                    "SELECT COALESCE(MAX(state_version),0)+1 FROM task_events"
                ).fetchone()[0]
            )
            st.db.execute(
                "INSERT INTO task_events(task_id,run_id,event_type,payload_json,state_version,created_at) "
                "VALUES(?,NULL,'task.assigned',?,?,?)",
                (
                    "task-b",
                    json.dumps({"builderId": "broken"}),
                    next_version,
                    time.time(),
                ),
            )
            st.db.close()

            with self.assertRaises(StoreAuthorityError) as caught:
                ControlStore(db)
            self.assertEqual(caught.exception.code, "ASSIGNMENT_HISTORY_INVALID")

            # Inspect with a raw connection so a second migration attempt cannot
            # mask partial writes from the failed constructor.
            raw = sqlite3.connect(str(db))
            try:
                task_a = raw.execute(
                    "SELECT assignment_mode,budget_cap_exact FROM tasks WHERE task_id='task-a'"
                ).fetchone()
                schema_version = raw.execute(
                    "SELECT value FROM meta WHERE key='schema_version'"
                ).fetchone()[0]
            finally:
                raw.close()

            self.assertEqual(task_a[0], "legacy")
            self.assertIsNone(task_a[1])
            self.assertEqual(schema_version, "5")


if __name__ == "__main__":
    unittest.main()
