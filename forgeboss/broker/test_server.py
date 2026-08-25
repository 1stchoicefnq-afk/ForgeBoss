from __future__ import annotations

import concurrent.futures
import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from forgeboss.broker import server


class FakeSigner:
    def sign(self, obj):
        return {"signedReceipt": obj, "receiptSignature": "test"}


class GoodVerifier:
    def verify(self, req):
        return SimpleNamespace(
            attestation_id="protected-attestation-1",
            result_ref=req["resultRef"],
            runtime=req["runtime"],
            paid_lease=req["paidLease"],
        )


class BadPaidLeaseVerifier:
    def verify(self, req):
        bad = dict(req["paidLease"])
        bad["leaseSha256"] = "f" * 64
        return SimpleNamespace(
            attestation_id="protected-attestation-1",
            result_ref=req["resultRef"],
            runtime=req["runtime"],
            paid_lease=bad,
        )


def envelope(work, allowed=("x.py",)):
    return {
        "envelopeVersion": 1,
        "protocolVersion": 1,
        "taskId": "task-1",
        "repository": "1stchoicefnq-afk/ForgeBoss",
        "baseSha": "a" * 40,
        "branch": "w",
        "worktreePath": str(work.resolve()),
        "runId": "run-1",
        "attempt": 1,
        "ownerEpoch": 7,
        "runtime": {"adapter": "mini-swe", "provider": "openai", "model": "openai/gpt-test"},
        "allowedPaths": list(allowed),
        "deniedPaths": [],
        "allowedTools": ["python"],
        "contextBundleHash": None,
        "transcript": {},
        "events": {},
        "budgetUsd": 0.25,
        "expiresAt": time.time() + 120,
        "signature": "hmac-sha256:legacy-worker-readable",
    }


def write_request(work: Path, state: Path, allowed=("x.py",)):
    packet = {"objective": "x", "allowed_files": list(allowed), "context_files": []}
    packet_path = work / "packet.json"
    packet_path.write_text(json.dumps(packet, separators=(",", ":")), encoding="utf-8")
    packet_sha = hashlib.sha256(packet_path.read_bytes()).hexdigest()
    env = envelope(work, allowed)
    unsigned = dict(env)
    unsigned.pop("signature")
    envelope_sha = server._digest(unsigned)
    pre = {"ordinary": {}, "git": {}, "head": "a" * 40, "worktree": str(work.resolve())}
    targets = {}
    token = "lease-secret"
    lease_expiry = time.time() + 90
    spend_expiry = time.time() + 60
    workspace_lease_id = server._digest(
        {
            "taskId": "task-1",
            "runId": "run-1",
            "ownerEpoch": 7,
            "worktreePath": str(work.resolve()),
            "currentHead": "a" * 40,
            "budgetReservedUsd": 0.25,
            "budgetRunId": "budget-run-1",
        }
    )
    spend = {
        "schema": 1,
        "budgetRunId": "budget-run-1",
        "workspaceLeaseId": workspace_lease_id,
        "taskId": "task-1",
        "runId": "run-1",
        "ownerEpoch": 7,
        "worktreePath": str(work.resolve()),
        "currentHead": "a" * 40,
        "budgetReservedUsd": 0.25,
        "taskBudgetAllocatedUsd": 1.0,
        "taskBudgetSpentUsd": 0.25,
        "budgetRunCapUsd": 10.0,
        "budgetRunReservedUsd": 1.0,
        "provider": "openai",
        "model": "openai/gpt-test",
        "expiresAt": spend_expiry,
        "status": "active",
        "allowedPathsSha256": server._digest(list(allowed)),
        "envelopeSha256": envelope_sha,
    }
    lease = {
        "schema": 3,
        "executor": "mini-swe",
        "workspace": str(work.resolve()),
        "packet_sha256": packet_sha,
        "allowed_files": list(allowed),
        "allowed_keys": [x.casefold() for x in allowed],
        "issued_at": time.time() - 1,
        "expires_at": lease_expiry,
        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "baseline": {},
        "git_metadata": {},
        "isolation_verified": True,
        "paid_consumed": False,
        "paid_authority": None,
        "spend_authority": spend,
    }
    state.mkdir(parents=True, exist_ok=True)
    lease_path = state / "lease.json"
    lease_path.write_text(json.dumps(lease, sort_keys=True), encoding="utf-8")
    request = {
        "schema": 3,
        "operation": "run-mini-swe-v3",
        "workspace": str(work.resolve()),
        "packetPath": str(packet_path.resolve()),
        "packet": packet,
        "leasePath": str(lease_path.resolve()),
        "leaseToken": token,
        "controlEnvelope": json.dumps(env),
        "budgetUsd": 0.25,
        "model": "openai/gpt-test",
        "image": "node:22-bookworm",
        "expectedAuthority": {
            "taskId": "task-1",
            "runId": "run-1",
            "ownerEpoch": 7,
            "envelopeSha256": envelope_sha,
            "budgetUsd": 0.25,
            "worktreePath": str(work.resolve()),
            "baseSha": "a" * 40,
            "allowedPaths": list(allowed),
            "expiresAt": unsigned["expiresAt"],
        },
        "preAuthority": pre,
        "preAuthoritySha256": server._digest(pre),
        "preTargets": targets,
        "preTargetsSha256": server._digest(targets),
    }
    return request, lease_path


class BrokerServerV2Tests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        root = Path(self.td.name)
        self.broker_root = root / "broker"
        self.broker_root.mkdir()
        self.work = root / "work"
        self.work.mkdir()
        self.state = root / "executor-security"

    def tearDown(self):
        self.td.cleanup()

    def patches(self):
        return (
            mock.patch.object(server, "broker_root", return_value=self.broker_root),
            mock.patch.object(server.guard, "STATE", self.state),
        )

    def request(self):
        return write_request(self.work, self.state)

    def mutate_lease(self, lease_path, fn):
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        fn(lease)
        lease_path.write_text(json.dumps(lease, sort_keys=True), encoding="utf-8")

    def test_legacy_hmac_without_protected_attestation_stops_before_materializer(self):
        request, _ = self.request()
        verifier = mock.Mock()
        verifier.verify.side_effect = RuntimeError("protected authority unavailable")
        materializer = mock.Mock()
        broker = server.BrokerServer(authority_verifier=verifier, signer=FakeSigner(), materializer=materializer)
        p1, p2 = self.patches()
        with p1, p2, self.assertRaisesRegex(RuntimeError, "protected authority unavailable"):
            broker.handle(request)
        materializer.assert_not_called()

    def test_denied_real_lease_or_spend_authority_never_constructs_runtime(self):
        cases = (
            ("missing", lambda req, lease: lease.unlink(), "cannot read paid lease"),
            ("bad-token", lambda req, lease: req.__setitem__("leaseToken", "wrong"), "lease token mismatch"),
            ("expired", lambda req, lease: self.mutate_lease(lease, lambda x: x.__setitem__("expires_at", time.time() - 1)), "expired/invalid"),
            ("consumed", lambda req, lease: self.mutate_lease(lease, lambda x: x.__setitem__("paid_consumed", True)), "already consumed"),
            ("no-spend", lambda req, lease: self.mutate_lease(lease, lambda x: x.pop("spend_authority", None)), "durable spend reservation"),
            ("inactive", lambda req, lease: self.mutate_lease(lease, lambda x: x["spend_authority"].__setitem__("status", "released")), "not active"),
            ("provider", lambda req, lease: self.mutate_lease(lease, lambda x: x["spend_authority"].__setitem__("provider", "evil")), "provider/model mismatch"),
            ("reserved-budget", lambda req, lease: self.mutate_lease(lease, lambda x: x["spend_authority"].__setitem__("budgetReservedUsd", 9.0)), "reserved budget mismatch"),
            ("budget-run", lambda req, lease: self.mutate_lease(lease, lambda x: x["spend_authority"].__setitem__("budgetRunId", "other")), "lease identity mismatch"),
            ("oversubscribed", lambda req, lease: self.mutate_lease(lease, lambda x: x["spend_authority"].__setitem__("budgetRunReservedUsd", 11.0)), "backing invalid"),
        )
        for name, mutate, pattern in cases:
            with self.subTest(name=name):
                request, lease_path = self.request()
                mutate(request, lease_path)
                materializer = mock.Mock()
                runner = mock.Mock()
                verifier = mock.Mock()
                broker = server.BrokerServer(authority_verifier=verifier, signer=FakeSigner(), materializer=materializer, runner=runner)
                p1, p2 = self.patches()
                with p1, p2, self.assertRaisesRegex(server.BrokerServerError, pattern):
                    broker.handle(request)
                materializer.assert_not_called()
                runner.assert_not_called()
                verifier.verify.assert_not_called()

    def test_protected_attestation_must_bind_exact_real_paid_lease(self):
        request, _ = self.request()
        materializer = mock.Mock()
        broker = server.BrokerServer(authority_verifier=BadPaidLeaseVerifier(), signer=FakeSigner(), materializer=materializer)
        p1, p2 = self.patches()
        with p1, p2, self.assertRaisesRegex(server.BrokerServerError, "paid-lease mismatch"):
            broker.handle(request)
        materializer.assert_not_called()

    def test_valid_paid_authority_consumes_before_materializer_and_restart_replay_is_denied(self):
        request, _ = self.request()
        materializer = mock.Mock(side_effect=RuntimeError("crash after protected consume"))
        broker = server.BrokerServer(authority_verifier=GoodVerifier(), signer=FakeSigner(), materializer=materializer)
        p1, p2 = self.patches()
        with p1, p2:
            first = broker.handle(request)
        signed = first["signedReceipt"]
        receipt = signed["reintegrationReceipt"]
        self.assertFalse(signed["completed"])
        self.assertTrue(signed["paidConsumed"])
        self.assertEqual(receipt["paidBudgetRunId"], "budget-run-1")
        self.assertEqual(receipt["paidBudgetReservedUsd"], 0.25)
        self.assertTrue(receipt["paidWorkspaceLeaseId"])
        restarted = server.BrokerServer(authority_verifier=GoodVerifier(), signer=FakeSigner(), materializer=materializer)
        p1, p2 = self.patches()
        with p1, p2, self.assertRaisesRegex(server.BrokerServerError, "consumed/replay"):
            restarted.handle(request)
        self.assertEqual(materializer.call_count, 1)

    def test_concurrent_same_workspace_spend_lease_has_exactly_one_runtime_winner(self):
        request, _ = self.request()
        count = 0
        lock = threading.Lock()

        def materialize(*_):
            nonlocal count
            with lock:
                count += 1
            time.sleep(0.05)
            raise RuntimeError("stop after consume")

        broker = server.BrokerServer(authority_verifier=GoodVerifier(), signer=FakeSigner(), materializer=materialize)

        def run_once():
            p1, p2 = self.patches()
            try:
                with p1, p2:
                    return ("return", broker.handle(request))
            except Exception as ex:
                return ("raise", ex)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: run_once(), range(2)))
        self.assertEqual(count, 1)
        self.assertEqual(sum(kind == "return" for kind, _ in results), 1)
        self.assertEqual(sum(kind == "raise" for kind, _ in results), 1)
        self.assertIn("consumed/replay", str(next(value for kind, value in results if kind == "raise")))

    def test_paid_runtime_failure_receipt_keeps_truthful_cost_calls_and_spend_identity(self):
        request, _ = self.request()
        repo = self.work / "private"
        repo.mkdir()
        result = SimpleNamespace(completed=False, cost_usd=0.17, calls=4, error="provider failed")
        broker = server.BrokerServer(authority_verifier=GoodVerifier(), signer=FakeSigner(), materializer=lambda *_: repo, runner=lambda *_: result)
        p1, p2 = self.patches()
        with p1, p2:
            envelope = broker.handle(request)
        signed = envelope["signedReceipt"]
        receipt = signed["reintegrationReceipt"]
        self.assertFalse(signed["completed"])
        self.assertFalse(signed["reintegrated"])
        self.assertEqual(signed["cost_usd"], 0.17)
        self.assertEqual(signed["calls"], 4)
        self.assertTrue(receipt["failedBeforeResult"])
        self.assertEqual(receipt["paidBudgetRunId"], "budget-run-1")
        self.assertEqual(receipt["paidTaskBudgetAllocatedUsd"], 1.0)
        self.assertEqual(receipt["paidTaskBudgetSpentUsd"], 0.25)

    def test_success_receipt_binds_real_spend_authority_and_result_cas(self):
        request, _ = self.request()
        repo = self.work / "private"
        repo.mkdir()
        run_result = SimpleNamespace(completed=True, cost_usd=0.1, calls=2, error=None)
        result_ref = server.make_result_ref("task-1", "run-1")
        handoff = SimpleNamespace(
            base_commit="a" * 40,
            result_commit="b" * 40,
            result_tree="c" * 40,
            result_ref=result_ref,
            old_oid="0" * 40,
            new_oid="b" * 40,
            applied_paths=("x.py",),
            diff_sha256="d" * 64,
            handoff_repo_id="e" * 64,
        )
        broker = server.BrokerServer(authority_verifier=GoodVerifier(), signer=FakeSigner(), materializer=lambda *_: repo, runner=lambda *_: run_result, handoff=lambda *_: handoff)
        p1, p2 = self.patches()
        with p1, p2:
            envelope = broker.handle(request)
        signed = envelope["signedReceipt"]
        receipt = signed["reintegrationReceipt"]
        self.assertTrue(signed["completed"])
        self.assertEqual(signed["changes"], [])
        self.assertFalse(receipt["hostWorktreeAuthoritative"])
        self.assertEqual(receipt["resultCommit"], "b" * 40)
        self.assertEqual(receipt["resultRef"], result_ref)
        self.assertEqual(receipt["paidBudgetRunId"], "budget-run-1")
        self.assertEqual(receipt["paidBudgetRunCapUsd"], 10.0)
        self.assertEqual(receipt["paidBudgetRunReservedUsd"], 1.0)
        self.assertTrue(receipt["paidConsumeId"])


if __name__ == "__main__":
    unittest.main()
