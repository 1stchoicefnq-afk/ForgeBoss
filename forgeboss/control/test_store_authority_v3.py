from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from forgeboss.control.store import ControlStore, StoreAuthorityError

A40="a"*40


def make_task(task_id="task-1"):
    return {
        "taskId":task_id,
        "repository":"owner/repo",
        "purpose":"store-v3",
        "baseSha":A40,
        "branch":f"fb/{task_id}",
        "allowedPaths":["src/a.py"],
        "requiredTests":["t"],
        "budgetUsd":"5",
    }


class StoreAuthorityV3Tests(unittest.TestCase):

    def test_new_task_is_legacy(self):
        with tempfile.TemporaryDirectory() as td:
            st=ControlStore(Path(td)/"state.db")
            t=st.create_task(make_task())
            self.assertEqual(t["assignment_mode"],"legacy")
            st.db.close()

    def test_assign_builder_permanently_binds_mode(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            st=ControlStore(root/"state.db")
            st.create_budget_run("budget-1","20")
            st.create_task(make_task())
            a=st.assign_builder("task-1","worker-a","budget-1")

            self.assertEqual(
                st.get_task("task-1")["assignment_mode"],
                "controller-bound"
            )
            self.assertGreater(a["assignmentGeneration"],0)
            st.db.close()

    def test_legacy_claim_release_reclaim_remains_compatible(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            st=ControlStore(root/"state.db")
            st.create_task(make_task())

            wr=root/"worktrees"
            wr.mkdir()
            w1=wr/"one"
            w2=wr/"two"
            w1.mkdir()
            w2.mkdir()

            l1=st.claim_workspace(
                "task-1","run-1",w1,"fb/task-1",A40,
                worktree_root=wr,budget_reserved="1"
            )

            st.release(
                "task-1","run-1",l1["owner_epoch"],A40
            )

            l2=st.claim_workspace(
                "task-1","run-2",w2,"fb/task-1",A40,
                worktree_root=wr,budget_reserved="1"
            )

            self.assertEqual(
                st.get_task("task-1")["assignment_mode"],
                "legacy"
            )
            self.assertGreater(l2["owner_epoch"],l1["owner_epoch"])
            st.db.close()

    def test_bound_history_cannot_downgrade_after_release(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            st=ControlStore(root/"state.db")
            st.create_budget_run("budget-1","20")
            st.create_task(make_task())

            a=st.assign_builder("task-1","worker-a","budget-1")

            wr=root/"worktrees"
            wr.mkdir()
            w1=wr/"one"
            w2=wr/"two"
            w1.mkdir()
            w2.mkdir()

            l1=st.claim_workspace(
                "task-1","run-1",w1,"fb/task-1",A40,
                worktree_root=wr,
                budget_reserved="1",
                builder_id="worker-a",
                assignment_token=a["assignmentToken"],
                assignment_generation=a["assignmentGeneration"],
                assignment_sha256=a["assignmentSha256"],
                budget_run_revision=a["budgetRunRevision"],
            )

            st.release(
                "task-1","run-1",l1["owner_epoch"],A40
            )

            task=st.get_task("task-1")
            self.assertEqual(task["assignment_mode"],"controller-bound")

            with self.assertRaises(StoreAuthorityError):
                st.claim_workspace(
                    "task-1","run-2",w2,"fb/task-1",A40,
                    worktree_root=wr,
                    budget_reserved="1",
                )

            st.db.close()

    def test_assignment_identity_is_store_generated_and_stable(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            st=ControlStore(root/"state.db")
            st.create_budget_run("budget-1","20")
            st.create_task(make_task())

            a=st.assign_builder("task-1","worker-a","budget-1")

            wr=root/"worktrees"
            wr.mkdir()
            wt=wr/"one"
            wt.mkdir()

            lease=st.claim_workspace(
                "task-1","run-1",wt,"fb/task-1",A40,
                worktree_root=wr,
                budget_reserved="1",
                builder_id="worker-a",
                assignment_token=a["assignmentToken"],
                assignment_generation=a["assignmentGeneration"],
                assignment_sha256=a["assignmentSha256"],
                budget_run_revision=a["budgetRunRevision"],
            )

            packet=st.assignment_identity(
                "task-1","run-1",lease["owner_epoch"]
            )

            ident=packet["identity"]

            expected=hashlib.sha256(
                json.dumps(
                    ident,
                    sort_keys=True,
                    separators=(",",":"),
                    ensure_ascii=False
                ).encode("utf-8")
            ).hexdigest()

            self.assertEqual(
                packet["assignmentIdentitySha256"],
                expected
            )

            self.assertEqual(ident["builderPrincipal"],"worker-a")
            self.assertEqual(ident["workspaceContentIdentity"],A40)
            self.assertEqual(ident["workspaceGeneration"],lease["owner_epoch"])
            self.assertEqual(ident["repository"],"owner/repo")

            st.db.close()

    def test_restart_preserves_bound_mode_and_identity_fencing(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            db=root/"state.db"

            st=ControlStore(db)
            st.create_budget_run("budget-1","20")
            st.create_task(make_task())
            a=st.assign_builder("task-1","worker-a","budget-1")
            st.db.close()

            st=ControlStore(db)
            self.assertEqual(
                st.get_task("task-1")["assignment_mode"],
                "controller-bound"
            )

            wr=root/"worktrees"
            wr.mkdir()
            wt=wr/"one"
            wt.mkdir()

            lease=st.claim_workspace(
                "task-1","run-1",wt,"fb/task-1",A40,
                worktree_root=wr,
                budget_reserved="1",
                builder_id="worker-a",
                assignment_token=a["assignmentToken"],
                assignment_generation=a["assignmentGeneration"],
                assignment_sha256=a["assignmentSha256"],
                budget_run_revision=a["budgetRunRevision"],
            )

            packet=st.assignment_identity(
                "task-1","run-1",lease["owner_epoch"]
            )

            self.assertTrue(packet["assignmentIdentitySha256"])
            st.db.close()

    def test_restart_budget_bound_never_assigned_remains_legacy(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            db=root/"state.db"
            st=ControlStore(db)
            st.create_budget_run("budget-1","20")
            st.create_task(make_task())
            st.db.execute("""UPDATE tasks SET budget_run_id='budget-1',assignment_mode='legacy',
                assigned_builder_id=NULL,assignment_generation=0,assignment_token_hash=NULL,assignment_sha256=NULL
                WHERE task_id='task-1'""")
            st.db.close()

            st=ControlStore(db)
            self.assertEqual(st.get_task("task-1")["assignment_mode"],"legacy")
            wr=root/"worktrees";wr.mkdir();w1=wr/"one";w2=wr/"two";w1.mkdir();w2.mkdir()
            l1=st.claim_workspace("task-1","run-1",w1,"fb/task-1",A40,worktree_root=wr,budget_reserved="1")
            st.release("task-1","run-1",l1["owner_epoch"],A40)
            l2=st.claim_workspace("task-1","run-2",w2,"fb/task-1",A40,worktree_root=wr,budget_reserved="1")
            self.assertGreater(l2["owner_epoch"],l1["owner_epoch"])
            self.assertEqual(st.get_task("task-1")["assignment_mode"],"legacy")
            st.db.close()

    def test_restart_infers_genuine_assignment_history_after_nullable_fields_clear(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            db=root/"state.db"
            st=ControlStore(db)
            st.create_budget_run("budget-1","20")
            st.create_task(make_task())
            a=st.assign_builder("task-1","worker-a","budget-1")
            self.assertGreater(a["assignmentGeneration"],0)
            st.db.execute("""UPDATE tasks SET assignment_mode='legacy',assigned_builder_id=NULL,
                assignment_token_hash=NULL,assignment_sha256=NULL WHERE task_id='task-1'""")
            st.db.close()

            st=ControlStore(db)
            task=st.get_task("task-1")
            self.assertEqual(task["assignment_mode"],"controller-bound")
            self.assertGreater(task["assignment_generation"],0)
            st.db.close()


    def test_failed_history_migration_rolls_back_all_prior_r6_changes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            db=root/"state.db"

            st=ControlStore(db)
            st.create_budget_run("budget-1","20")

            st.create_task(make_task("task-a"))
            st.create_task(make_task("task-b"))

            a=st.assign_builder(
                "task-a",
                "worker-a",
                "budget-1",
            )
            self.assertGreater(a["assignmentGeneration"],0)

            # Simulate pre-R6 durable state:
            # task-a has genuine assignment history but current mode is legacy.
            st.db.execute(
                """UPDATE tasks
                   SET assignment_mode='legacy',
                       assigned_builder_id=NULL,
                       assignment_token_hash=NULL,
                       assignment_sha256=NULL
                   WHERE task_id='task-a'"""
            )

            # Make migration visibly attempt an old -> new schema transition.
            st.db.execute(
                "UPDATE meta SET value='5' WHERE key='schema_version'"
            )

            # task-b has malformed durable assignment history.
            next_version=int(
                st.db.execute(
                    "SELECT COALESCE(MAX(state_version),0)+1 FROM task_events"
                ).fetchone()[0]
            )

            st.db.execute(
                """INSERT INTO task_events(
                       task_id,
                       run_id,
                       event_type,
                       payload_json,
                       state_version,
                       created_at
                   )
                   VALUES(?,NULL,'task.assigned',?,?,?)""",
                (
                    "task-b",
                    "{}",
                    next_version,
                    1.0,
                ),
            )

            st.db.close()

            # The constructor/migration must fail closed.
            with self.assertRaises(StoreAuthorityError):
                ControlStore(db)

            # Inspect durable bytes directly after failed migration.
            raw=sqlite3.connect(str(db))
            try:
                mode=raw.execute(
                    "SELECT assignment_mode FROM tasks WHERE task_id='task-a'"
                ).fetchone()[0]

                schema=raw.execute(
                    "SELECT value FROM meta WHERE key='schema_version'"
                ).fetchone()[0]

                self.assertEqual(
                    mode,
                    "legacy",
                    "task-a classification partially committed despite failed migration",
                )

                self.assertEqual(
                    schema,
                    "5",
                    "schema/meta version partially committed despite failed migration",
                )
            finally:
                raw.close()


if __name__=="__main__":unittest.main()