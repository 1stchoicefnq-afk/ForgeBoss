from __future__ import annotations

import importlib
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

import forgeboss.control.envelope as envelope_module
import forgeboss.control.store as store_module
from forgeboss.policy.reuse_review_authority import issue_reuse_review_receipt
from forgeboss.policy.small_repair_authority import issue_small_repair_exemption
from forgeboss.control.governed_launch import issue_governed_launch_attestation


class BootstrapStore:
    def __init__(self, path):
        self.path = path


class GovernedTaskCreateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.worktrees = cls.root / "worktrees"
        cls.worktrees.mkdir()
        fake_secret = lambda root: (cls.root / "secret.bin", b"s" * 32)
        fake_policy_secret = lambda root: (cls.root / "policy-secret.bin", b"p" * 32)
        fake_launch_secret = lambda root: (cls.root / "launch-secret.bin", b"l" * 32)
        with (
            mock.patch.object(store_module, "ControlStore", BootstrapStore),
            mock.patch.object(envelope_module, "secret_file", fake_secret),
            mock.patch.object(envelope_module, "policy_secret_file", fake_policy_secret),
            mock.patch.object(envelope_module, "launch_secret_file", fake_launch_secret),
            mock.patch.dict(os.environ, {"FORGEBOSS_WORKTREE_ROOT": str(cls.worktrees)}),
        ):
            sys.modules.pop("forgeboss.control.daemon", None)
            cls.mod = importlib.import_module("forgeboss.control.daemon")

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("forgeboss.control.daemon", None)
        cls.temp.cleanup()

    def setUp(self):
        self.store = store_module.ControlStore(
            self.root / f"{uuid.uuid4().hex}.sqlite"
        )
        self.addCleanup(self.store.db.close)
        self.daemon = self.mod.ForgeBossDaemon.__new__(self.mod.ForgeBossDaemon)
        self.daemon.store = self.store
        self.daemon.secret = b"k" * 32
        self.daemon.policy_secret = b"p" * 32
        self.daemon.launch_secret = b"l" * 32
        self.daemon.idempotency = {}
        self.daemon.lock = threading.RLock()
        self.daemon.started = time.time()

    def params(self, task_id="T1"):
        return {
            "taskId": task_id,
            "repository": "owner/repo",
            "purpose": "Build the terminal execution subsystem.",
            "baseSha": "a" * 40,
            "allowedPaths": ["src/terminal.py", "tests/test_terminal.py"],
            "requiredTests": ["python -m unittest"],
            "budgetUsd": 1.0,
            "subsystem": "terminal-execution",
        }

    def review(self):
        return {
            "schema": 1,
            "subsystem": "terminal-execution",
            "search_performed": [
                "GitHub terminal process broker",
                "existing ForgeBoss executors",
            ],
            "candidates": [
                {
                    "name": "example/process-broker",
                    "source": "https://example.invalid/process-broker",
                    "exact_identity": "commit-abc123",
                    "license": "MIT",
                    "license_status": "compatible",
                    "maintenance_status": "active",
                    "platform_fit": "fit",
                    "security_fit": "partial",
                    "disposition": "selected",
                    "notes": "requires ForgeBoss wrapper",
                }
            ],
            "decision": "adapt",
            "custom_build_reason": "",
        }

    def request(self, params, method="task.create_governed"):
        return {
            "method": method,
            "idempotencyKey": uuid.uuid4().hex,
            "params": params,
        }

    def event_count(self, task_id):
        return self.store.db.execute(
            "SELECT COUNT(*) FROM task_events WHERE task_id=?",
            (task_id,),
        ).fetchone()[0]

    def test_missing_reuse_review_blocks_atomically(self):
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(self.request(self.params()), True)
        self.assertEqual(ctx.exception.code, "REUSE_GATE_BLOCKED")
        self.assertIsNone(self.store.get_task("T1"))
        self.assertEqual(self.event_count("T1"), 0)

    def test_structural_review_without_signed_receipt_blocks_atomically(self):
        p = self.params()
        p["reuseReview"] = self.review()
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(self.request(p), True)
        self.assertEqual(ctx.exception.code, "REUSE_GATE_BLOCKED")
        self.assertIsNone(self.store.get_task("T1"))
        self.assertEqual(self.event_count("T1"), 0)

    def test_valid_substantial_review_and_receipt_persist_nonsecret_evidence(self):
        p = self.params()
        p["reuseReview"] = self.review()
        p["reuseReviewReceipt"] = issue_reuse_review_receipt(
            task_id=p["taskId"],
            repository=p["repository"],
            base_sha=p["baseSha"],
            objective=p["purpose"],
            allowed_paths=p["allowedPaths"],
            subsystem=p["subsystem"],
            reuse_review=p["reuseReview"],
            secret=self.daemon.policy_secret,
            ttl_seconds=600,
        )
        created = self.daemon.dispatch(self.request(p), True)
        self.assertEqual(created["governance_mode"], "reuse-v1")
        self.assertEqual(created["work_kind"], "substantial-subsystem")
        self.assertEqual(created["subsystem"], "terminal-execution")
        self.assertRegex(created["reuse_review_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(created["reuse_review_receipt_sha256"], r"^[0-9a-f]{64}$")
        self.assertIsNone(created["small_repair_exemption_sha256"])
        self.assertEqual(self.event_count("T1"), 1)

    def test_valid_small_repair_exemption_needs_no_broad_review(self):
        p = self.params()
        p["purpose"] = "Fix exact null check."
        p["smallRepairExemption"] = issue_small_repair_exemption(
            task_id=p["taskId"],
            repository=p["repository"],
            base_sha=p["baseSha"],
            objective=p["purpose"],
            allowed_paths=p["allowedPaths"],
            secret=self.daemon.policy_secret,
            ttl_seconds=600,
        )
        created = self.daemon.dispatch(self.request(p), True)
        self.assertEqual(created["work_kind"], "small-repair")
        self.assertRegex(created["small_repair_exemption_sha256"], r"^[0-9a-f]{64}$")
        self.assertIsNone(created["reuse_review_sha256"])
        self.assertIsNone(created["reuse_review_receipt_sha256"])

    def test_daemon_auth_key_cannot_mint_policy_approval(self):
        p = self.params()
        p["reuseReview"] = self.review()
        p["reuseReviewReceipt"] = issue_reuse_review_receipt(
            task_id=p["taskId"],
            repository=p["repository"],
            base_sha=p["baseSha"],
            objective=p["purpose"],
            allowed_paths=p["allowedPaths"],
            subsystem=p["subsystem"],
            reuse_review=p["reuseReview"],
            secret=self.daemon.secret,
            ttl_seconds=600,
        )
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(self.request(p), True)
        self.assertEqual(ctx.exception.code, "REUSE_AUTHORITY_INVALID")
        self.assertIsNone(self.store.get_task("T1"))
        self.assertEqual(self.event_count("T1"), 0)

    def test_connect_reports_actual_store_schema_version(self):
        with mock.patch.object(self.mod, "verify_connect_proof", lambda payload, secret: None):
            request = {
                "method": "connect",
                "params": {
                    "protocolVersion": 1,
                    "capabilities": [],
                    "nonce": uuid.uuid4().hex,
                },
            }
            out = self.daemon.dispatch(request, False)
        self.assertEqual(out["schemaVersion"], store_module.SCHEMA_VERSION)
        self.assertEqual(out["state"]["schemaVersion"], store_module.SCHEMA_VERSION)

    def test_mismatched_small_repair_token_fails_before_store_mutation(self):
        p = self.params()
        p["smallRepairExemption"] = issue_small_repair_exemption(
            task_id="OTHER",
            repository=p["repository"],
            base_sha=p["baseSha"],
            objective=p["purpose"],
            allowed_paths=p["allowedPaths"],
            secret=self.daemon.policy_secret,
            ttl_seconds=600,
        )
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(self.request(p), True)
        self.assertEqual(ctx.exception.code, "REUSE_AUTHORITY_INVALID")
        self.assertIsNone(self.store.get_task("T1"))
        self.assertEqual(self.event_count("T1"), 0)

    def test_legacy_task_create_remains_legacy_in_this_packet(self):
        p = self.params()
        p.pop("subsystem")
        created = self.daemon.dispatch(self.request(p, method="task.create"), True)
        self.assertIsNone(created["governance_mode"])
        self.assertIsNone(created["work_kind"])
        self.assertIsNone(created["reuse_review_sha256"])

    def test_store_rejects_impossible_governance_combinations(self):
        p = self.params()
        p.update({
            "governanceMode": "reuse-v1",
            "workKind": "small-repair",
            "smallRepairExemptionSha256": None,
        })
        with self.assertRaisesRegex(ValueError, "small-repair governance evidence"):
            self.store.create_task(p)
        self.assertIsNone(self.store.get_task("T1"))

        p = self.params(task_id="T2")
        p.update({
            "governanceMode": "reuse-v1",
            "workKind": "substantial-subsystem",
            "reuseReviewSha256": "1" * 64,
            "reuseReviewReceiptSha256": None,
        })
        with self.assertRaisesRegex(ValueError, "substantial governance evidence"):
            self.store.create_task(p)
        self.assertIsNone(self.store.get_task("T2"))

    def _create_governed_substantial(self, task_id="T-GOV"):
        p = self.params(task_id=task_id)
        p["reuseReview"] = self.review()
        p["reuseReviewReceipt"] = issue_reuse_review_receipt(
            task_id=p["taskId"],
            repository=p["repository"],
            base_sha=p["baseSha"],
            objective=p["purpose"],
            allowed_paths=p["allowedPaths"],
            subsystem=p["subsystem"],
            reuse_review=p["reuseReview"],
            secret=self.daemon.policy_secret,
            ttl_seconds=600,
        )
        return p, self.daemon.dispatch(self.request(p), True)

    def _claim_request(self, task_id, runtime_id):
        work = self.worktrees / uuid.uuid4().hex
        work.mkdir()
        return {
            "method": "workspace.claim",
            "idempotencyKey": uuid.uuid4().hex,
            "params": {
                "taskId": task_id,
                "repository": "owner/repo",
                "baseSha": "a" * 40,
                "allowedPaths": ["src/terminal.py", "tests/test_terminal.py"],
                "allowedTools": ["python"],
                "worktreePath": str(work),
                "runId": uuid.uuid4().hex,
                "currentHead": "a" * 40,
                "ttlSeconds": 60,
                "runtimeId": runtime_id,
                "budgetUsd": 0.25,
            },
        }

    def test_governed_task_claim_requires_attestation(self):
        p, _ = self._create_governed_substantial("T-GOV")
        req = self._claim_request(p["taskId"], "mini-swe")
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(req, True)
        self.assertEqual(ctx.exception.code, "GOVERNED_LAUNCH_ATTESTATION_REQUIRED")
        self.assertIsNone(self.store.get_lease("T-GOV"))

    def test_valid_governed_launch_attestation_allows_exact_claim(self):
        p, _ = self._create_governed_substantial("T-GOV-OK")
        req = self._claim_request(p["taskId"], "mini-swe")
        q = req["params"]
        q["governedLaunchAttestation"] = issue_governed_launch_attestation(
            task_id=q["taskId"],
            repository=q["repository"],
            base_sha=q["baseSha"],
            run_id=q["runId"],
            adapter=q["runtimeId"],
            repo_root=self.mod.ROOT,
            workspace_path=q["worktreePath"],
            worktree_root=self.mod.WORKTREE_ROOT,
            allowed_paths=q["allowedPaths"],
            allowed_tools=q["allowedTools"],
            budget_usd=q["budgetUsd"],
            secret=self.daemon.launch_secret,
            ttl_seconds=300,
        )
        out = self.daemon.dispatch(req, True)
        self.assertEqual(out["lease"]["owner_run_id"], q["runId"])
        runtime = self.mod.verify_envelope(
            out["launchEnvelope"], self.daemon.secret, now=time.time()
        )["runtime"]
        self.assertEqual(runtime["adapter"], "mini-swe")
        self.assertRegex(runtime["runnerSha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(runtime["interpreterSha256"], r"^[0-9a-f]{64}$")

    def test_governed_launch_token_cannot_rebind_runtime_or_run(self):
        p, _ = self._create_governed_substantial("T-GOV-BIND")
        req = self._claim_request(p["taskId"], "mini-swe")
        q = req["params"]
        token = issue_governed_launch_attestation(
            task_id=q["taskId"],
            repository=q["repository"],
            base_sha=q["baseSha"],
            run_id=q["runId"],
            adapter=q["runtimeId"],
            repo_root=self.mod.ROOT,
            workspace_path=q["worktreePath"],
            worktree_root=self.mod.WORKTREE_ROOT,
            allowed_paths=q["allowedPaths"],
            allowed_tools=q["allowedTools"],
            budget_usd=q["budgetUsd"],
            secret=self.daemon.launch_secret,
            ttl_seconds=300,
        )
        q["governedLaunchAttestation"] = token
        q["runId"] = "DIFFERENT"
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(req, True)
        self.assertEqual(ctx.exception.code, "GOVERNED_LAUNCH_ATTESTATION_INVALID")
        self.assertIsNone(self.store.get_lease("T-GOV-BIND"))

        req2 = self._claim_request(p["taskId"], "opencode")
        req2["params"]["governedLaunchAttestation"] = token
        with self.assertRaises(self.mod.ProtocolError) as ctx2:
            self.daemon.dispatch(req2, True)
        self.assertEqual(ctx2.exception.code, "GOVERNED_LAUNCH_ATTESTATION_INVALID")

    def test_store_rejects_governance_evidence_without_governance_mode(self):
        p = self.params(task_id="T3")
        p["workKind"] = "small-repair"
        p["smallRepairExemptionSha256"] = "1" * 64
        with self.assertRaisesRegex(ValueError, "requires governanceMode"):
            self.store.create_task(p)
        self.assertIsNone(self.store.get_task("T3"))

    def test_protocol_and_client_share_governed_mutation_set(self):
        from forgeboss.control.client import Client
        protocol_mutations = self.mod.__dict__["parse_frame"].__globals__["MUTATIONS"]
        client_mutations = Client.call.__globals__["MUTATIONS"]
        self.assertIs(protocol_mutations, client_mutations)
        self.assertIn("task.create_governed", client_mutations)


if __name__ == "__main__":
    unittest.main()