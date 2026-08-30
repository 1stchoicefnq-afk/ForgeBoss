from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from forgeboss.control.receipts import CandidateHandoff, ReceiptError, policy_path_key, POLICY_PATH_KEY_VERSION
from forgeboss.control.run_budget import GlobalRunBudget, RunBudgetError, STATE_PAID_STARTED
from forgeboss.control.store import ControlStore

A40 = "a" * 40
B40 = "b" * 40
C40 = "c" * 40
AUTH_KEY = b"receipts-r4-run-budget-auth-key-32b"


def _task():
    return {
        "taskId": "task-r4",
        "repository": "owner/repo",
        "purpose": "receipts-r4",
        "baseSha": A40,
        "branch": "fb/task-r4",
        "allowedPaths": ["src/a.py"],
        "requiredTests": ["receipts"],
        "budgetUsd": "5",
    }


def _path(path="src/a.py"):
    return {"gitPath": path, "policyPathKey": policy_path_key(path), "policyVersion": POLICY_PATH_KEY_VERSION}


def _handoff(packet):
    return {
        "assignment": packet,
        "candidateSha": B40,
        "candidateTreeSha": C40,
        "changedPaths": [_path()],
        "requiredTestReceipts": ["2" * 64],
        "scopeDiffSha256": "3" * 64,
        "additions": 1,
        "deletions": 0,
        "measuredCostUsd": "1.25",
        "reservedCostUsd": "1",
        "contributors": ["worker-a"],
        "knownUncertainty": [],
    }


class ReceiptsR4CompositionTests(unittest.TestCase):
    def _live_store(self, root: Path):
        db = root / "state.db"
        st = ControlStore(db)
        st.create_budget_run("budget-r4", "20")
        st.create_task(_task())
        assignment = st.assign_builder("task-r4", "worker-a", "budget-r4")
        worktrees = root / "worktrees"
        worktrees.mkdir(exist_ok=True)
        wt = worktrees / "task-r4"
        wt.mkdir(exist_ok=True)
        lease = st.claim_workspace(
            "task-r4",
            "run-r4",
            wt,
            "fb/task-r4",
            A40,
            worktree_root=worktrees,
            budget_reserved="1",
            builder_id="worker-a",
            assignment_token=assignment["assignmentToken"],
            assignment_generation=assignment["assignmentGeneration"],
            assignment_sha256=assignment["assignmentSha256"],
            budget_run_revision=assignment["budgetRunRevision"],
        )
        return st, db, assignment, lease

    def test_exact_store_identity_survives_restart_while_writer_is_live(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            st, db, _, lease = self._live_store(root)
            packet = st.assignment_identity("task-r4", "run-r4", lease["owner_epoch"])
            h1 = CandidateHandoff.from_dict(_handoff(packet), store=st)
            st.db.close()

            st2 = ControlStore(db)
            try:
                packet2 = st2.assignment_identity("task-r4", "run-r4", lease["owner_epoch"])
                self.assertEqual(packet2, packet)
                h2 = CandidateHandoff.from_dict(_handoff(packet), store=st2)
                self.assertEqual(h2.assignment.identity_sha256, h1.assignment.identity_sha256)
            finally:
                st2.db.close()

    def test_stale_assignment_identity_is_denied_after_release_and_restart(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            st, db, _, lease = self._live_store(root)
            packet = st.assignment_identity("task-r4", "run-r4", lease["owner_epoch"])
            st.release("task-r4", "run-r4", lease["owner_epoch"], A40)
            with self.assertRaises(Exception):
                CandidateHandoff.from_dict(_handoff(packet), store=st)
            st.db.close()

            st2 = ControlStore(db)
            try:
                with self.assertRaises(Exception):
                    CandidateHandoff.from_dict(_handoff(packet), store=st2)
            finally:
                st2.db.close()

    def test_self_hashed_caller_substitution_cannot_replace_store_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            st, _, _, lease = self._live_store(root)
            try:
                packet = st.assignment_identity("task-r4", "run-r4", lease["owner_epoch"])
                forged = copy.deepcopy(packet)
                forged["identity"]["builderPrincipal"] = "attacker"
                import hashlib, json
                forged["assignmentIdentitySha256"] = hashlib.sha256(
                    json.dumps(forged["identity"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                ).hexdigest()
                with self.assertRaises(ReceiptError):
                    CandidateHandoff.from_dict(_handoff(forged), store=st)
            finally:
                st.db.close()

    def test_receipts_do_not_refund_paid_run_budget_and_restore_requires_auth(self):
        budget = GlobalRunBudget("5")
        budget.reserve("receipt-work", "1", worker_id="worker-a")
        _, token = budget.start_paid("receipt-work")
        self.assertEqual(budget.get("receipt-work").state, STATE_PAID_STARTED)

        with self.assertRaises(RunBudgetError) as release_error:
            budget.release("receipt-work")
        self.assertEqual(release_error.exception.code, "PAID_WORK_STARTED")

        with self.assertRaises(RunBudgetError) as plain_restore:
            GlobalRunBudget.from_snapshot(budget.snapshot())
        self.assertEqual(plain_restore.exception.code, "SNAPSHOT_AUTH_REQUIRED")

        wrapped = budget.authenticated_snapshot(AUTH_KEY)
        restored = GlobalRunBudget.from_snapshot(wrapped, authentication_key=AUTH_KEY)
        self.assertEqual(restored.get("receipt-work").state, STATE_PAID_STARTED)
        with self.assertRaises(RunBudgetError) as wrong_token:
            restored.settle("receipt-work", ".75", authority_token="wrong")
        self.assertEqual(wrong_token.exception.code, "AUTHORITY_TOKEN_INVALID")
        restored.settle("receipt-work", ".75", authority_token=token)
        self.assertEqual(str(restored.committed), "0.75")


if __name__ == "__main__":
    unittest.main()
