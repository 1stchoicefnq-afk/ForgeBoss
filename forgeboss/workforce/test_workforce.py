from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from forgeboss.workforce.chief_of_staff import CHIEF_OF_STAFF_CONTRACT, ExpectedRoutine, build_brief, reconcile_fleet
from forgeboss.workforce.contracts import (
    RoutineContract,
    RunRecord,
    WorkerContract,
    WorkforceContractError,
    outbound_action_allowed,
    should_run_period,
    validate_capability_routes,
)

UTC = timezone.utc
START = datetime(2026, 9, 22, 1, 0, tzinfo=UTC)


def run(worker: str, routine: str, period: str, state: str = "ok", evidence: str = "ev-1") -> RunRecord:
    return RunRecord(worker, routine, period, state, START, START + timedelta(minutes=1), evidence)


class WorkforceContractTests(unittest.TestCase):
    def test_worker_contract_is_descriptive_and_cannot_grant_authority(self):
        routine = RoutineContract("daily-review", "YYYY-MM-DD", ("repo.read",), 300)
        worker = WorkerContract("reviewer", "Reviewer", "1.0.0", (routine,))
        self.assertEqual(worker.authority_grant, "NONE")
        with self.assertRaises(WorkforceContractError):
            WorkerContract("reviewer", "Reviewer", "1.0.0", (routine,), authority_grant="WRITE")

    def test_outbound_release_and_runtime_authority_are_both_required(self):
        self.assertFalse(outbound_action_allowed("deploy", released_actions=("deploy",), runtime_authority=False))
        self.assertFalse(outbound_action_allowed("deploy", released_actions=(), runtime_authority=True))
        self.assertTrue(outbound_action_allowed("deploy", released_actions=("deploy",), runtime_authority=True))

    def test_period_key_prevents_duplicate_routine_run(self):
        records = [run("cos", "daily-review", "2026-09-22")]
        self.assertFalse(should_run_period(records, "cos", "daily-review", "2026-09-22"))
        self.assertTrue(should_run_period(records, "cos", "daily-review", "2026-09-23"))

    def test_capabilities_resolve_to_routes_without_embedding_provider_in_contract(self):
        resolved = validate_capability_routes(("repo.read", "evidence.read"), {"repo.read": "github", "evidence.read": "local-store"})
        self.assertEqual(resolved["repo.read"], "github")
        with self.assertRaises(WorkforceContractError):
            validate_capability_routes(("repo.read", "evidence.read"), {"repo.read": "github"})

    def test_chief_of_staff_contract_is_observer_only(self):
        self.assertEqual(CHIEF_OF_STAFF_CONTRACT.authority_grant, "NONE")
        self.assertTrue(all(not routine.outbound_actions for routine in CHIEF_OF_STAFF_CONTRACT.routines))


class ChiefOfStaffTests(unittest.TestCase):
    def test_reconcile_detects_silent_failed_paused_approval_and_healthy(self):
        expected = [
            ExpectedRoutine("builder", "build", "p1"),
            ExpectedRoutine("tester", "test", "p1"),
            ExpectedRoutine("reviewer", "review", "p1"),
            ExpectedRoutine("release", "prove", "p1"),
            ExpectedRoutine("repair", "repair", "p1", paused=True),
        ]
        records = [
            run("builder", "build", "p1"),
            run("tester", "test", "p1", state="failed", evidence="test-fail"),
            run("release", "prove", "p1", state="needs-approval", evidence="approval-gate"),
        ]
        status = {(item.worker_id, item.routine_id): item.status for item in reconcile_fleet(expected, records)}
        self.assertEqual(status[("builder", "build")], "healthy")
        self.assertEqual(status[("tester", "test")], "failed")
        self.assertEqual(status[("reviewer", "review")], "silent")
        self.assertEqual(status[("release", "prove")], "needs-approval")
        self.assertEqual(status[("repair", "repair")], "paused")

    def test_duplicate_run_evidence_fails_closed(self):
        expected = [ExpectedRoutine("builder", "build", "p1")]
        with self.assertRaises(WorkforceContractError):
            reconcile_fleet(expected, [run("builder", "build", "p1", evidence="a"), run("builder", "build", "p1", evidence="b")])

    def test_brief_is_derived_from_evidence_and_pending_approvals(self):
        expected = [ExpectedRoutine("builder", "build", "p1"), ExpectedRoutine("reviewer", "review", "p1")]
        brief = build_brief(expected, [run("builder", "build", "p1")], pending_approvals=[{"id": "ap-1", "action": "deploy"}])
        self.assertEqual(brief["counts"]["healthy"], 1)
        self.assertEqual(brief["counts"]["silent"], 1)
        self.assertEqual(len(brief["attention"]), 1)
        self.assertEqual(brief["pending_approvals"][0]["action"], "deploy")


if __name__ == "__main__":
    unittest.main()
