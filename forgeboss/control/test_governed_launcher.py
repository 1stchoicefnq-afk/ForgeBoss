from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

from forgeboss.control.governed_launcher import (
    GovernedLauncherError,
    prepare_governed_launch,
)
from forgeboss.control.store import ControlStore
from forgeboss.policy.reuse_review_authority import issue_reuse_review_receipt
from forgeboss.policy.task_governance_authority import sign_governed_task_authority


class FakeDaemon:
    pass


class GovernedLauncherTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.workspace = self.root / "worktree"
        self.workspace.mkdir()
        self.db = self.root / "state" / "control.sqlite3"
        self.store = ControlStore(self.db)
        self.addCleanup(self.store.db.close)
        self.daemon = FakeDaemon()
        self.daemon.store = self.store
        self.daemon.secret = b"d" * 32
        self.daemon.policy_secret = b"p" * 32
        self.daemon.launch_secret = b"l" * 32
        self.daemon.repo_root = Path(__file__).resolve().parents[2]
        self.daemon.worktree_root = self.root
        self.daemon.idempotency = {}
        self.daemon.lock = threading.RLock()
        self.daemon.started = time.time()

        # Use the real dispatch implementation without constructing global daemon state.
        from forgeboss.control.daemon import ForgeBossDaemon
        self.daemon.dispatch = ForgeBossDaemon.dispatch.__get__(self.daemon, FakeDaemon)

        self.review = {
            "schema": 1,
            "subsystem": "terminal-execution",
            "search_performed": ["upstream search"],
            "candidates": [{
                "name": "example/broker",
                "source": "https://example.invalid/broker",
                "exact_identity": "abc123",
                "license": "MIT",
                "license_status": "compatible",
                "maintenance_status": "active",
                "platform_fit": "fit",
                "security_fit": "partial",
                "disposition": "selected",
                "notes": "",
            }],
            "decision": "adapt",
            "custom_build_reason": "",
        }
        self.task = {
            "taskId": "T-LAUNCH",
            "repository": "owner/repo",
            "purpose": "Build exact terminal subsystem.",
            "baseSha": "a" * 40,
            "allowedPaths": ["src/a.py", "tests/test_a.py"],
            "requiredTests": [],
            "budgetUsd": 1.0,
            "subsystem": "terminal-execution",
        }
        receipt = issue_reuse_review_receipt(
            task_id=self.task["taskId"],
            repository=self.task["repository"],
            base_sha=self.task["baseSha"],
            objective=self.task["purpose"],
            allowed_paths=self.task["allowedPaths"],
            subsystem=self.task["subsystem"],
            reuse_review=self.review,
            secret=self.daemon.policy_secret,
            ttl_seconds=600,
        )
        governed = dict(self.task)
        governed.update({
            "governanceMode": "reuse-v1",
            "workKind": "substantial-subsystem",
            "reuseReviewSha256": "1" * 64,
            "reuseReviewReceiptSha256": "2" * 64,
            "smallRepairExemptionSha256": None,
        })
        governed["governanceAuthorityReceipt"] = sign_governed_task_authority(
            governed, self.daemon.policy_secret
        )
        self.store.create_task(governed)
        self.packet = self.root / "packet.json"
        self.write_packet()

    def write_packet(self, **changes):
        value = {
            "objective": self.task["purpose"],
            "allowed_files": ["src/a.py"],
            "context_files": [],
            "expected_head_revision": self.task["baseSha"],
            "acceptance_criteria": [],
        }
        value.update(changes)
        self.packet.write_text(json.dumps(value), encoding="utf-8")

    def fake_lease(self):
        return {"ok": True, "lease": str(self.root / "lease.json"), "token": "lease-token"}

    def fake_claim(self, request, connected):
        self.assertTrue(connected)
        p = request["params"]
        from forgeboss.control.governed_launch import resolve_runner_identity
        identity = resolve_runner_identity(p["runtimeId"], repo_root=self.daemon.repo_root)
        return {
            "lease": {
                "owner_run_id": p["runId"],
                "owner_epoch": 1,
                "worktree_path": p["worktreePath"],
                "budget_reserved": float(p["budgetUsd"]),
            },
            "launchEnvelope": {
                "runtime": {
                    "adapter": identity.adapter,
                    "runnerPath": identity.runner_path,
                    "runnerSha256": identity.runner_sha256,
                    "interpreterPath": identity.interpreter_path,
                    "interpreterSha256": identity.interpreter_sha256,
                },
                "taskId": p["taskId"],
                "runId": p["runId"],
            },
        }

    @mock.patch("forgeboss.control.governed_launcher.issue_lease")
    def test_prepare_derives_exact_command_and_governed_environment(self, issue_mock):
        issue_mock.return_value = self.fake_lease()
        self.daemon.dispatch = self.fake_claim
        prepared = prepare_governed_launch(
                self.daemon,
                task_id=self.task["taskId"],
                packet_path=self.packet,
                workspace_path=self.workspace,
                adapter="mini-swe",
                allowed_tools=["python"],
                budget_usd=0.25,
        )
        self.assertEqual(prepared.task_id, self.task["taskId"])
        self.assertEqual(prepared.adapter, "mini-swe")
        self.assertEqual(prepared.authoritative_head, self.task["baseSha"])
        self.assertEqual(prepared.argv[0], prepared.launch_envelope["runtime"]["interpreterPath"])
        self.assertEqual(prepared.argv[1], prepared.launch_envelope["runtime"]["runnerPath"])
        self.assertEqual(prepared.env["FORGEBOSS_GOVERNED_LAUNCH"], "YES")
        self.assertIn("FORGEBOSS_CONTROL_ENVELOPE", prepared.env)
        self.assertEqual(prepared.env["FORGEBOSS_EXECUTOR_LEASE_TOKEN"], "lease-token")
        with self.assertRaises(TypeError):
            prepared.env["X"] = "Y"
        with self.assertRaises(TypeError):
            prepared.launch_envelope["runtime"]["adapter"] = "changed"

    @mock.patch("forgeboss.control.governed_launcher.issue_lease")
    def test_packet_objective_and_head_are_canonical_authority(self, issue_mock):
        issue_mock.return_value = self.fake_lease()
        self.daemon.dispatch = self.fake_claim
        self.write_packet(objective="Different objective")
        with self.assertRaisesRegex(GovernedLauncherError, "objective differs"):
            prepare_governed_launch(
                    self.daemon, task_id=self.task["taskId"], packet_path=self.packet,
                    workspace_path=self.workspace, adapter="mini-swe",
                    allowed_tools=["python"], budget_usd=0.25,
            )

        self.write_packet(expected_head_revision="b" * 40)
        with self.assertRaisesRegex(GovernedLauncherError, "exact head differs"):
            prepare_governed_launch(
                    self.daemon, task_id=self.task["taskId"], packet_path=self.packet,
                    workspace_path=self.workspace, adapter="mini-swe",
                    allowed_tools=["python"], budget_usd=0.25,
            )

    @mock.patch("forgeboss.control.governed_launcher.issue_lease")
    def test_packet_scope_can_narrow_but_not_widen_task_scope(self, issue_mock):
        issue_mock.return_value = self.fake_lease()
        self.daemon.dispatch = self.fake_claim
        prepare_governed_launch(
                self.daemon, task_id=self.task["taskId"], packet_path=self.packet,
                workspace_path=self.workspace, adapter="mini-swe",
                allowed_tools=["python"], budget_usd=0.25,
        )

        self.write_packet(allowed_files=["src/other.py"])
        with self.assertRaisesRegex(GovernedLauncherError, "exceeds canonical task scope"):
            prepare_governed_launch(
                    self.daemon, task_id=self.task["taskId"], packet_path=self.packet,
                    workspace_path=self.workspace, adapter="mini-swe",
                    allowed_tools=["python"], budget_usd=0.25,
            )

    @mock.patch("forgeboss.control.governed_launcher.issue_lease")
    def test_executor_security_preflight_happens_before_workspace_claim(self, issue_mock):
        issue_mock.side_effect = Exception("preflight failed")
        called = {"claim": False}
        def claim(*args, **kwargs):
            called["claim"] = True
            return {}
        self.daemon.dispatch = claim
        with self.assertRaises(Exception):
            prepare_governed_launch(
                    self.daemon, task_id=self.task["taskId"], packet_path=self.packet,
                    workspace_path=self.workspace, adapter="mini-swe",
                    allowed_tools=["python"], budget_usd=0.25,
            )
        self.assertFalse(called["claim"])

    @mock.patch("forgeboss.control.governed_launcher.issue_lease")
    def test_forged_direct_store_governed_row_cannot_launch(self, issue_mock):
        forged = dict(self.task)
        forged["taskId"] = "FORGED"
        forged.update({
            "governanceMode": "reuse-v1",
            "workKind": "substantial-subsystem",
            "reuseReviewSha256": "1" * 64,
            "reuseReviewReceiptSha256": "2" * 64,
            "smallRepairExemptionSha256": None,
            "governanceAuthorityReceipt": "hmac-sha256:" + ("0" * 64),
        })
        self.store.create_task(forged)
        with self.assertRaisesRegex(GovernedLauncherError, "task authority is invalid"):
            prepare_governed_launch(
                self.daemon, task_id="FORGED", packet_path=self.packet,
                workspace_path=self.workspace, adapter="mini-swe",
                allowed_tools=["python"], budget_usd=0.25,
            )
        issue_mock.assert_not_called()

    @mock.patch("forgeboss.control.governed_launcher.issue_lease")
    def test_non_governed_task_is_refused(self, issue_mock):
        legacy = {
            "taskId": "LEGACY",
            "repository": "owner/repo",
            "purpose": self.task["purpose"],
            "baseSha": self.task["baseSha"],
            "allowedPaths": ["src/a.py"],
            "requiredTests": [],
            "budgetUsd": 1.0,
        }
        self.store.create_task(legacy)
        with self.assertRaisesRegex(GovernedLauncherError, "not governed"):
            prepare_governed_launch(
                self.daemon, task_id="LEGACY", packet_path=self.packet,
                workspace_path=self.workspace, adapter="mini-swe",
                allowed_tools=["python"], budget_usd=0.25,
            )


if __name__ == "__main__":
    unittest.main()