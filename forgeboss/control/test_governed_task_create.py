from __future__ import annotations

import importlib
import json
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
        runner = cls.root / "forgeboss" / "executors" / "mini_swe_runner.py"
        runner.parent.mkdir(parents=True)
        reviewed_runner = Path(__file__).resolve().parents[1] / "executors" / "mini_swe_runner.py"
        runner.write_bytes(reviewed_runner.read_bytes())
        with (
            mock.patch.object(store_module, "ControlStore", BootstrapStore),
            mock.patch.object(envelope_module, "secret_file", fake_secret),
            mock.patch.object(envelope_module, "policy_secret_file", fake_policy_secret),
            mock.patch.object(envelope_module, "launch_secret_file", fake_launch_secret),
            mock.patch.dict(os.environ, {"FORGEBOSS_WORKTREE_ROOT": str(cls.worktrees)}),
        ):
            sys.modules.pop("forgeboss.control.daemon", None)
            cls.mod = importlib.import_module("forgeboss.control.daemon")
            cls.mod.ROOT = cls.root

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
        self.daemon.governed_launch_capability = "cap-" + ("x" * 40)
        self.daemon.active_governed_runs = {}
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
                "budgetUsd": 0.0,
            },
        }

    def test_governed_task_claim_fails_closed_until_attested_launch_exists(self):
        p, _ = self._create_governed_substantial("T-GOV")
        for runtime_id in ("mini-swe", "openhands", "opencode", "", "unknown"):
            with self.subTest(runtime_id=runtime_id):
                with self.assertRaises(self.mod.ProtocolError) as ctx:
                    self.daemon.dispatch(self._claim_request(p["taskId"], runtime_id), True)
                self.assertEqual(ctx.exception.code, "GOVERNED_DIRECT_CLAIM_DENIED")
        self.assertIsNone(self.store.get_lease("T-GOV"))

    def test_even_valid_signed_direct_claim_is_denied_without_daemon_memory_capability(self):
        p, _ = self._create_governed_substantial("T-GOV-OK")
        req = self._claim_request(p["taskId"], "mini-swe")
        q = req["params"]
        q["launchAttestation"] = issue_governed_launch_attestation(
            root=self.root,
            secret=self.daemon.launch_secret,
            task_id=q["taskId"],
            repository=q["repository"],
            base_sha=q["baseSha"],
            run_id=q["runId"],
            worktree_path=q["worktreePath"],
            runtime_id=q["runtimeId"],
            allowed_paths=q["allowedPaths"],
            allowed_tools=q["allowedTools"],
            provider=q.get("provider"),
            model=q.get("model"),
            budget_usd=q.get("budgetUsd", 0),
            ttl_seconds=60,
        )
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(req, True)
        self.assertEqual(ctx.exception.code, "GOVERNED_DIRECT_CLAIM_DENIED")
        self.assertIsNone(self.store.get_lease(p["taskId"]))

    def test_internal_attested_claim_with_memory_capability_creates_lease(self):
        p, _ = self._create_governed_substantial("T-GOV-INTERNAL")
        req = self._claim_request(p["taskId"], "mini-swe")
        q = req["params"]
        q["_governedLaunchCapability"] = self.daemon.governed_launch_capability
        q["launchAttestation"] = issue_governed_launch_attestation(
            root=self.root,
            secret=self.daemon.launch_secret,
            task_id=q["taskId"],
            repository=q["repository"],
            base_sha=q["baseSha"],
            run_id=q["runId"],
            worktree_path=q["worktreePath"],
            runtime_id=q["runtimeId"],
            allowed_paths=q["allowedPaths"],
            allowed_tools=q["allowedTools"],
            provider=q.get("provider"),
            model=q.get("model"),
            budget_usd=q.get("budgetUsd", 0),
            ttl_seconds=60,
        )
        out = self.daemon.dispatch(req, True)
        self.assertEqual(out["lease"]["task_id"], p["taskId"])
        self.assertEqual(out["launchEnvelope"]["runtime"]["adapter"], "mini-swe")

    def test_attestation_signed_with_daemon_key_is_rejected_atomically(self):
        p, _ = self._create_governed_substantial("T-GOV-BADKEY")
        req = self._claim_request(p["taskId"], "mini-swe")
        q = req["params"]
        q["_governedLaunchCapability"] = self.daemon.governed_launch_capability
        q["launchAttestation"] = issue_governed_launch_attestation(
            root=self.root,
            secret=self.daemon.secret,
            task_id=q["taskId"],
            repository=q["repository"],
            base_sha=q["baseSha"],
            run_id=q["runId"],
            worktree_path=q["worktreePath"],
            runtime_id=q["runtimeId"],
            allowed_paths=q["allowedPaths"],
            allowed_tools=q["allowedTools"],
            budget_usd=q.get("budgetUsd", 0),
            ttl_seconds=60,
        )
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(req, True)
        self.assertEqual(ctx.exception.code, "GOVERNED_LAUNCH_ATTESTATION_INVALID")
        self.assertIsNone(self.store.get_lease(p["taskId"]))

    def test_attestation_rebinding_is_rejected_atomically(self):
        p, _ = self._create_governed_substantial("T-GOV-REBIND")
        req = self._claim_request(p["taskId"], "mini-swe")
        q = req["params"]
        q["_governedLaunchCapability"] = self.daemon.governed_launch_capability
        q["launchAttestation"] = issue_governed_launch_attestation(
            root=self.root,
            secret=self.daemon.launch_secret,
            task_id=q["taskId"],
            repository=q["repository"],
            base_sha=q["baseSha"],
            run_id=q["runId"],
            worktree_path=q["worktreePath"],
            runtime_id=q["runtimeId"],
            allowed_paths=q["allowedPaths"],
            allowed_tools=q["allowedTools"],
            budget_usd=q.get("budgetUsd", 0),
            ttl_seconds=60,
        )
        q["runId"] = uuid.uuid4().hex
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(req, True)
        self.assertEqual(ctx.exception.code, "GOVERNED_LAUNCH_ATTESTATION_INVALID")
        self.assertIsNone(self.store.get_lease(p["taskId"]))

    def _launch_request(self, task_id, run_id="RUN-1", runtime_id="mini-swe"):
        work = self.worktrees / ("launch-" + uuid.uuid4().hex)
        (work / "src").mkdir(parents=True)
        (work / "tests").mkdir(parents=True)
        (work / "src" / "terminal.py").write_text("x = 1\n", encoding="utf-8")
        (work / "tests" / "test_terminal.py").write_text("def test_ok(): pass\n", encoding="utf-8")
        return {
            "method": "run.launch_governed",
            "idempotencyKey": uuid.uuid4().hex,
            "params": {
                "taskId": task_id,
                "runId": run_id,
                "runtimeId": runtime_id,
                "worktreePath": str(work),
                "currentHead": "a" * 40,
                "budgetUsd": 0.25,
                "provider": "openai",
                "model": "openai/gpt-5.6-luna",
                # These must never override the stored task authority.
                "repository": "attacker/other",
                "baseSha": "b" * 40,
                "allowedPaths": ["outside.txt"],
            },
        }

    def test_daemon_owned_governed_launch_uses_stored_task_authority_and_releases(self):
        p, _ = self._create_governed_substantial("T-LAUNCH")
        req = self._launch_request(p["taskId"], run_id="RUN-LAUNCH")
        fake = {
            "returncode": 0,
            "stdout_tail": "done",
            "stderr_tail": "",
            "result_head": "a" * 40,
            "runner_relpath": "forgeboss/executors/mini_swe_runner.py",
            "runner_sha256": "f" * 64,
        }
        with mock.patch.object(self.mod, "run_governed_worker", return_value=fake) as worker:
            out = self.daemon.dispatch(req, True)
        self.assertEqual(out["outcome"], "worker-complete")
        self.assertEqual(out["runId"], "RUN-LAUNCH")
        self.assertIsNotNone(self.store.get_lease(p["taskId"]))
        self.assertIsNotNone(self.store.get_lease(p["taskId"])["released_at"])
        self.assertEqual(self.store.get_run("RUN-LAUNCH")["status"], "worker-complete")
        task = self.store.get_task(p["taskId"])
        self.assertEqual(task["status"], "worker-complete")
        kwargs = worker.call_args.kwargs
        self.assertEqual(kwargs["task"]["repository"], "owner/repo")
        self.assertEqual(kwargs["task"]["base_sha"], "a" * 40)
        self.assertEqual(
            json.loads(kwargs["task"]["allowed_paths_json"]),
            ["src/terminal.py", "tests/test_terminal.py"],
        )

    def test_finished_run_id_replays_without_second_paid_worker(self):
        p, _ = self._create_governed_substantial("T-REPLAY")
        first = self._launch_request(p["taskId"], run_id="RUN-REPLAY")
        fake = {
            "returncode": 0,
            "stdout_tail": "",
            "stderr_tail": "",
            "result_head": "a" * 40,
            "runner_relpath": "forgeboss/executors/mini_swe_runner.py",
            "runner_sha256": "f" * 64,
        }
        with mock.patch.object(self.mod, "run_governed_worker", return_value=fake) as worker:
            out1 = self.daemon.dispatch(first, True)
            second = self._launch_request(p["taskId"], run_id="RUN-REPLAY")
            out2 = self.daemon.dispatch(second, True)
        self.assertEqual(out1["outcome"], "worker-complete")
        self.assertTrue(out2["replayed"])
        self.assertEqual(out2["outcome"], "worker-complete")
        self.assertEqual(worker.call_count, 1)

    def test_failed_worker_is_released_and_same_run_cannot_pay_twice(self):
        p, _ = self._create_governed_substantial("T-FAIL")
        req = self._launch_request(p["taskId"], run_id="RUN-FAIL")
        fake = {
            "returncode": 13,
            "stdout_tail": "",
            "stderr_tail": "denied",
            "result_head": "a" * 40,
            "runner_relpath": "forgeboss/executors/mini_swe_runner.py",
            "runner_sha256": "f" * 64,
        }
        with mock.patch.object(self.mod, "run_governed_worker", return_value=fake) as worker:
            out1 = self.daemon.dispatch(req, True)
            out2 = self.daemon.dispatch(self._launch_request(p["taskId"], run_id="RUN-FAIL"), True)
        self.assertEqual(out1["outcome"], "worker-failed")
        self.assertTrue(out2["replayed"])
        self.assertEqual(out2["outcome"], "worker-failed")
        self.assertEqual(worker.call_count, 1)

    def test_host_launcher_exception_releases_run_before_error(self):
        p, _ = self._create_governed_substantial("T-HOST-FAIL")
        req = self._launch_request(p["taskId"], run_id="RUN-HOST-FAIL")
        err = self.mod.GovernedHostLaunchError("guard refused")
        with mock.patch.object(self.mod, "run_governed_worker", side_effect=err) as worker:
            with self.assertRaises(self.mod.ProtocolError) as ctx:
                self.daemon.dispatch(req, True)
        self.assertEqual(ctx.exception.code, "GOVERNED_HOST_LAUNCH_FAILED")
        self.assertEqual(self.store.get_run("RUN-HOST-FAIL")["status"], "worker-failed")
        with mock.patch.object(self.mod, "run_governed_worker") as second_worker:
            replay = self.daemon.dispatch(self._launch_request(p["taskId"], run_id="RUN-HOST-FAIL"), True)
        self.assertTrue(replay["replayed"])
        second_worker.assert_not_called()
        self.assertEqual(worker.call_count, 1)

    def test_governed_host_launch_rejects_unapproved_runtime_before_claim(self):
        p, _ = self._create_governed_substantial("T-RUNTIME")
        req = self._launch_request(p["taskId"], run_id="RUN-RUNTIME", runtime_id="openhands")
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(req, True)
        self.assertEqual(ctx.exception.code, "RUNTIME_NOT_APPROVED")
        self.assertIsNone(self.store.get_run("RUN-RUNTIME"))
        self.assertIsNone(self.store.get_lease(p["taskId"]))

    def test_wrong_memory_capability_cannot_unlock_direct_governed_claim(self):
        p, _ = self._create_governed_substantial("T-CAP")
        req = self._claim_request(p["taskId"], "mini-swe")
        req["params"]["_governedLaunchCapability"] = "wrong-capability"
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(req, True)
        self.assertEqual(ctx.exception.code, "GOVERNED_DIRECT_CLAIM_DENIED")
        self.assertIsNone(self.store.get_lease(p["taskId"]))

    def test_legacy_task_cancel_is_not_overclaimed(self):
        p=self.params(task_id="T-LEGACY-CANCEL")
        p.pop("subsystem")
        created=self.daemon.dispatch(self.request(p,method="task.create"),True)
        self.assertIsNone(created["governance_mode"])
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(
                {"method":"task.cancel","idempotencyKey":uuid.uuid4().hex,"params":{"taskId":p["taskId"]}},
                True,
            )
        self.assertEqual(ctx.exception.code,"CANCEL_NOT_SUPPORTED")
        self.assertIsNone(self.store.get_task(p["taskId"])["cancel_requested_at"])

    def test_queued_cancel_is_terminal_and_blocks_governed_launch(self):
        p, _ = self._create_governed_substantial("T-CANCEL-QUEUED")
        out = self.daemon.dispatch(
            {"method":"task.cancel","idempotencyKey":uuid.uuid4().hex,"params":{"taskId":p["taskId"]}},
            True,
        )
        self.assertEqual(out["status"], "cancelled")
        task = self.store.get_task(p["taskId"])
        self.assertIsNotNone(task["cancel_requested_at"])
        self.assertEqual(task["terminal_outcome"], "cancelled")
        req = self._launch_request(p["taskId"], run_id="RUN-CANCELLED")
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(req, True)
        self.assertEqual(ctx.exception.code, "TASK_CANCELLED")
        self.assertIsNone(self.store.get_run("RUN-CANCELLED"))

    def test_cancel_revokes_existing_writer_and_heartbeat_authority(self):
        p, _ = self._create_governed_substantial("T-CANCEL-AUTH")
        req = self._claim_request(p["taskId"], "mini-swe")
        q = req["params"]
        q["_governedLaunchCapability"] = self.daemon.governed_launch_capability
        q["launchAttestation"] = issue_governed_launch_attestation(
            root=self.root,secret=self.daemon.launch_secret,
            task_id=q["taskId"],repository=q["repository"],base_sha=q["baseSha"],
            run_id=q["runId"],worktree_path=q["worktreePath"],runtime_id=q["runtimeId"],
            allowed_paths=q["allowedPaths"],allowed_tools=q["allowedTools"],
            budget_usd=q.get("budgetUsd",0),ttl_seconds=60,
        )
        claim = self.daemon.dispatch(req, True)
        lease = claim["lease"]
        self.store.request_cancel(p["taskId"])
        with self.assertRaisesRegex(PermissionError, "cancellation"):
            self.store.assert_writer(p["taskId"], q["runId"], lease["owner_epoch"])
        with self.assertRaisesRegex(PermissionError, "cancellation"):
            self.store.heartbeat(p["taskId"], q["runId"], lease["owner_epoch"], 60)

    def test_release_transaction_forces_cancelled_over_worker_success(self):
        p, _ = self._create_governed_substantial("T-CANCEL-RACE")
        req = self._claim_request(p["taskId"], "mini-swe")
        q = req["params"]
        q["_governedLaunchCapability"] = self.daemon.governed_launch_capability
        q["launchAttestation"] = issue_governed_launch_attestation(
            root=self.root,secret=self.daemon.launch_secret,
            task_id=q["taskId"],repository=q["repository"],base_sha=q["baseSha"],
            run_id=q["runId"],worktree_path=q["worktreePath"],runtime_id=q["runtimeId"],
            allowed_paths=q["allowedPaths"],allowed_tools=q["allowedTools"],
            budget_usd=q.get("budgetUsd",0),ttl_seconds=60,
        )
        claim = self.daemon.dispatch(req, True)
        self.store.request_cancel(p["taskId"])
        self.store.release(
            p["taskId"],q["runId"],claim["lease"]["owner_epoch"],
            "a"*40,"worker-complete",
        )
        self.assertEqual(self.store.get_run(q["runId"])["status"], "cancelled")
        task=self.store.get_task(p["taskId"])
        self.assertEqual(task["status"], "cancelled")
        self.assertEqual(task["terminal_outcome"], "cancelled")

    def test_task_cancel_sets_live_governed_cancel_event(self):
        p, _ = self._create_governed_substantial("T-CANCEL-LIVE")
        event=threading.Event()
        self.daemon.active_governed_runs[p["taskId"]]={"runId":"RUN-LIVE","event":event}
        out=self.daemon.dispatch(
            {"method":"task.cancel","idempotencyKey":uuid.uuid4().hex,"params":{"taskId":p["taskId"]}},
            True,
        )
        self.assertEqual(out["activeRunId"], "RUN-LIVE")
        self.assertTrue(event.is_set())

    def test_cancel_after_finished_run_blocks_new_run_but_preserves_replay(self):
        p, _ = self._create_governed_substantial("T-CANCEL-FUTURE")
        first=self._launch_request(p["taskId"],run_id="RUN-FINISHED")
        fake={
            "returncode":13,"stdout_tail":"","stderr_tail":"failed",
            "result_head":"a"*40,"runner_relpath":"forgeboss/executors/mini_swe_runner.py",
            "runner_sha256":"f"*64,
        }
        with mock.patch.object(self.mod,"run_governed_worker",return_value=fake) as worker:
            out1=self.daemon.dispatch(first,True)
        self.assertEqual(out1["outcome"],"worker-failed")
        cancel=self.daemon.dispatch(
            {"method":"task.cancel","idempotencyKey":uuid.uuid4().hex,"params":{"taskId":p["taskId"]}},
            True,
        )
        self.assertEqual(cancel["status"],"worker-failed")
        replay=self.daemon.dispatch(self._launch_request(p["taskId"],run_id="RUN-FINISHED"),True)
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["outcome"],"worker-failed")
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(self._launch_request(p["taskId"],run_id="RUN-NEW"),True)
        self.assertEqual(ctx.exception.code,"TASK_CANCELLED")
        self.assertEqual(worker.call_count,1)

    def test_cancelled_run_replays_without_second_paid_worker(self):
        p, _ = self._create_governed_substantial("T-CANCEL-REPLAY")
        req = self._launch_request(p["taskId"], run_id="RUN-CANCEL-REPLAY")
        def cancelled_worker(**kwargs):
            self.store.request_cancel(kwargs["task"]["task_id"])
            kwargs["cancel_event"].set()
            raise self.mod.GovernedHostLaunchCancelled("cancelled")
        with mock.patch.object(self.mod, "run_governed_worker", side_effect=cancelled_worker) as worker:
            out1=self.daemon.dispatch(req,True)
            out2=self.daemon.dispatch(self._launch_request(p["taskId"],run_id="RUN-CANCEL-REPLAY"),True)
        self.assertEqual(out1["outcome"], "cancelled")
        self.assertTrue(out2["replayed"])
        self.assertEqual(out2["outcome"], "cancelled")
        self.assertEqual(worker.call_count,1)

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
        self.assertIn("run.launch_governed", client_mutations)
        self.assertIn("task.cancel", client_mutations)


if __name__ == "__main__":
    unittest.main()