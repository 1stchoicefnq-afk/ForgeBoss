from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from forgeboss.control.envelope import sign_envelope
from forgeboss.control.governed_launch import resolve_runner_identity
from forgeboss.control.governed_launcher import (
    GovernedLauncherError,
    prepare_governed_launch,
)


DAEMON_SECRET = b"d" * 32
LAUNCH_SECRET = b"l" * 32


class FakeLeaseIssuer:
    def __init__(self, repo_root: Path, *, fail: bool = False, corrupt_packet: bool = False):
        self.repo_root = repo_root
        self.fail = fail
        self.corrupt_packet = corrupt_packet
        self.calls = []
        self.last_path = None

    def __call__(self, packet, workspace, executor, ttl):
        self.calls.append((Path(packet), Path(workspace), executor, ttl))
        if self.fail:
            raise RuntimeError("forced lease failure")
        state = self.repo_root / "state" / "executor-security"
        state.mkdir(parents=True, exist_ok=True)
        path = state / "lease-test.json"
        token = "lease-token-" + "x" * 40
        packet_bytes = Path(packet).read_bytes()
        packet_sha = hashlib.sha256(packet_bytes).hexdigest()
        if self.corrupt_packet:
            packet_sha = "f" * 64
        packet_doc = json.loads(packet_bytes.decode("utf-8"))
        lease = {
            "schema": 3,
            "executor": executor,
            "workspace": str(Path(workspace).resolve()),
            "packet_sha256": packet_sha,
            "allowed_files": list(packet_doc["allowed_files"]),
            "allowed_keys": [str(x).casefold() for x in packet_doc["allowed_files"]],
            "issued_at": time.time(),
            "expires_at": time.time() + ttl,
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "baseline": {},
            "git_metadata": {},
            "isolation_verified": True,
            "paid_consumed": False,
            "paid_authority": None,
        }
        path.write_text(json.dumps(lease), encoding="utf-8")
        self.last_path = path
        return {"ok": True, "lease": str(path), "token": token}


class FakeClient:
    def __init__(
        self,
        *,
        task,
        repo_root: Path,
        daemon_secret: bytes,
        fail_claim: bool = False,
        tamper_envelope: bool = False,
    ):
        self.task = dict(task)
        self.repo_root = repo_root
        self.daemon_secret = daemon_secret
        self.fail_claim = fail_claim
        self.tamper_envelope = tamper_envelope
        self.calls = []
        self.last_claim = None
        self.releases = []

    def call(self, method, params=None, mutation=None):
        params = dict(params or {})
        self.calls.append((method, params, mutation))
        if method == "task.get":
            return dict(self.task)
        if method == "workspace.claim":
            self.last_claim = dict(params)
            if self.fail_claim:
                raise RuntimeError("forced claim failure")
            identity = resolve_runner_identity("mini-swe", repo_root=self.repo_root)
            lease = {
                "task_id": params["taskId"],
                "owner_run_id": params["runId"],
                "owner_epoch": 1,
                "worktree_path": params["worktreePath"],
                "budget_reserved": params["budgetUsd"],
                "current_head": params["currentHead"],
                "released_at": None,
                "expires_at": time.time() + 1200,
            }
            env = {
                "envelopeVersion": 1,
                "protocolVersion": 1,
                "taskId": params["taskId"],
                "repository": params["repository"],
                "baseSha": params["baseSha"],
                "branch": params.get("branch"),
                "worktreePath": params["worktreePath"],
                "runId": params["runId"],
                "attempt": 1,
                "ownerEpoch": 1,
                "runtime": {
                    "adapter": params["runtimeId"],
                    "provider": params["provider"],
                    "model": params["model"],
                    "runnerPath": identity.runner_path,
                    "runnerSha256": identity.runner_sha256,
                    "interpreterPath": identity.interpreter_path,
                    "interpreterSha256": identity.interpreter_sha256,
                },
                "allowedPaths": list(params["allowedPaths"]),
                "deniedPaths": [],
                "allowedTools": list(params["allowedTools"]),
                "packetSha256": params["packetSha256"],
                "contextBundleHash": None,
                "transcript": {},
                "events": {},
                "budgetUsd": params["budgetUsd"],
                "expiresAt": time.time() + 600,
            }
            signed = sign_envelope(env, self.daemon_secret)
            if self.tamper_envelope:
                signed["packetSha256"] = "f" * 64
            return {"lease": lease, "launchEnvelope": signed}
        if method == "worker.admit":
            env = params["envelope"]
            return {
                "admitted": True,
                "taskId": env["taskId"],
                "runId": env["runId"],
                "ownerEpoch": env["ownerEpoch"],
            }
        if method == "workspace.release":
            self.releases.append(dict(params))
            return {"released": True}
        raise AssertionError("unexpected client method: " + method)


class GovernedLauncherTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.repo = self.root / "forgeboss-root"
        self.worktrees = self.root / "worktrees"
        self.workspace = self.worktrees / "task-work"
        self.packet_dir = self.root / "control"
        self.workspace.mkdir(parents=True)
        self.packet_dir.mkdir(parents=True)
        runner = self.repo / "forgeboss" / "executors" / "mini_swe_runner.py"
        runner.parent.mkdir(parents=True)
        runner.write_text("# trusted fake runner\n", encoding="utf-8")

        self.base = "a" * 40
        self.task = {
            "task_id": "T1",
            "repository": "Owner/Repo",
            "purpose": "Build the exact governed subsystem.",
            "base_sha": self.base,
            "branch": "feature/test",
            "status": "queued",
            "revision": 1,
            "allowed_paths_json": json.dumps(["src/a.py", "tests/a.test.py"]),
            "budget_allocated": 2.0,
            "budget_spent": 0.25,
            "cancel_requested_at": None,
            "result_head": None,
            "governance_mode": "reuse-v1",
            "work_kind": "substantial-subsystem",
            "subsystem": "test-subsystem",
        }
        self.packet_path = self.packet_dir / "packet.json"
        self.write_packet()

    def write_packet(self, **changes):
        doc = {
            "objective": self.task["purpose"],
            "expected_head_revision": self.base,
            "allowed_files": ["src/a.py", "tests/a.test.py"],
            "context_files": [],
            "acceptance_criteria": ["tests pass"],
        }
        doc.update(changes)
        self.packet_path.write_text(json.dumps(doc), encoding="utf-8")
        return doc

    def prepare(
        self,
        *,
        task=None,
        client=None,
        lease_issuer=None,
        packet_path=None,
        workspace_path=None,
        budget=0.5,
        provider="openai",
        model="openai/gpt-5.6-luna",
        provider_env=None,
    ):
        task = dict(self.task if task is None else task)
        client = client or FakeClient(
            task=task,
            repo_root=self.repo,
            daemon_secret=DAEMON_SECRET,
        )
        lease_issuer = lease_issuer or FakeLeaseIssuer(self.repo)
        result = prepare_governed_launch(
            client=client,
            repo_root=self.repo,
            worktree_root=self.worktrees,
            task_id=task["task_id"],
            packet_path=packet_path or self.packet_path,
            workspace_path=workspace_path or self.workspace,
            budget_usd=budget,
            provider=provider,
            model=model,
            provider_env=provider_env or {"OPENAI_API_KEY": "secret-key"},
            daemon_secret=DAEMON_SECRET,
            launch_secret=LAUNCH_SECRET,
            lease_issuer=lease_issuer,
        )
        return result, client, lease_issuer

    def test_success_prepares_exact_immutable_launch_without_control_secrets(self):
        prepared, client, issuer = self.prepare()
        identity = resolve_runner_identity("mini-swe", repo_root=self.repo)
        self.assertEqual(prepared.task_id, "T1")
        self.assertEqual(prepared.adapter, "mini-swe")
        self.assertEqual(prepared.provider, "openai")
        self.assertEqual(prepared.model, "openai/gpt-5.6-luna")
        self.assertEqual(prepared.argv[0], identity.interpreter_path)
        self.assertEqual(prepared.argv[1], identity.runner_path)
        self.assertEqual(prepared.argv[2], str(self.packet_path.resolve()))
        self.assertEqual(prepared.argv[3], str(self.workspace.resolve()))
        self.assertEqual(prepared.argv[4], "0.5")
        self.assertEqual(
            prepared.packet_sha256,
            hashlib.sha256(self.packet_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(prepared.authority_env["OPENAI_API_KEY"], "secret-key")
        self.assertEqual(prepared.authority_env["FORGEBOSS_GOVERNED_LAUNCH"], "YES")
        self.assertNotIn("GH_TOKEN", prepared.authority_env)
        self.assertNotIn("GITHUB_TOKEN", prepared.authority_env)
        self.assertNotIn("FORGEBOSS_LAUNCH_SECRET", prepared.authority_env)
        self.assertTrue(issuer.last_path.exists())

        claim = client.last_claim
        self.assertEqual(claim["repository"], "Owner/Repo")
        self.assertEqual(claim["packetSha256"], prepared.packet_sha256)
        self.assertEqual(claim["provider"], prepared.provider)
        self.assertEqual(claim["model"], prepared.model)
        self.assertEqual(
            [name for name, _, _ in client.calls],
            ["task.get", "workspace.claim", "worker.admit"],
        )

        with self.assertRaises(TypeError):
            prepared.authority_env["X"] = "Y"
        with self.assertRaises(TypeError):
            prepared.launch_envelope["runtime"]["model"] = "changed"

    def test_packet_objective_head_and_scope_mismatches_fail_before_lease(self):
        cases = [
            {"objective": "Different objective"},
            {"expected_head_revision": "b" * 40},
            {"allowed_files": ["src/other.py"]},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                self.write_packet(**changes)
                issuer = FakeLeaseIssuer(self.repo)
                with self.assertRaises(GovernedLauncherError):
                    self.prepare(lease_issuer=issuer)
                self.assertEqual(issuer.calls, [])
        self.write_packet()

    def test_duplicate_json_keys_in_packet_fail_closed_before_lease(self):
        self.packet_path.write_text(
            '{"objective":"Build the exact governed subsystem.",'
            '"objective":"Different",'
            '"expected_head_revision":"' + self.base + '",'
            '"allowed_files":["src/a.py","tests/a.test.py"],'
            '"context_files":[]}',
            encoding="utf-8",
        )
        issuer = FakeLeaseIssuer(self.repo)
        with self.assertRaisesRegex(GovernedLauncherError, "duplicate JSON object key"):
            self.prepare(lease_issuer=issuer)
        self.assertEqual(issuer.calls, [])
        self.write_packet()

    def test_alias_scope_spelling_is_rejected_even_if_canonical_identity_matches(self):
        task = dict(self.task)
        task["allowed_paths_json"] = json.dumps(["SRC/A.PY.", "tests/a.test.py"])
        with self.assertRaisesRegex(GovernedLauncherError, "alias spelling"):
            self.prepare(task=task)

    def test_budget_cannot_exceed_canonical_remaining_budget(self):
        with self.assertRaisesRegex(GovernedLauncherError, "remaining budget"):
            self.prepare(budget=2.0)

    def test_provider_model_and_secret_allowlist_fail_closed(self):
        with self.assertRaisesRegex(GovernedLauncherError, "namespaced"):
            self.prepare(model="anthropic/model")
        with self.assertRaisesRegex(GovernedLauncherError, "non-allowlisted"):
            self.prepare(provider_env={"OPENAI_API_KEY": "x", "GH_TOKEN": "bad"})
        with self.assertRaisesRegex(GovernedLauncherError, "whitespace"):
            self.prepare(provider_env={"OPENAI_API_KEY": " secret "})
        with self.assertRaisesRegex(GovernedLauncherError, "not enabled"):
            self.prepare(provider="unknown", model="unknown/model", provider_env={"X": "y"})

    def test_non_governed_nonqueued_or_cancelled_task_fails_before_lease(self):
        variants = []
        t = dict(self.task)
        t["governance_mode"] = None
        variants.append(t)
        t = dict(self.task)
        t["status"] = "running"
        variants.append(t)
        t = dict(self.task)
        t["cancel_requested_at"] = time.time()
        variants.append(t)
        for task in variants:
            issuer = FakeLeaseIssuer(self.repo)
            with self.assertRaises(GovernedLauncherError):
                self.prepare(task=task, lease_issuer=issuer)
            self.assertEqual(issuer.calls, [])

    def test_packet_inside_workspace_is_rejected_before_lease(self):
        inside = self.workspace / "packet.json"
        inside.write_bytes(self.packet_path.read_bytes())
        issuer = FakeLeaseIssuer(self.repo)
        with self.assertRaisesRegex(GovernedLauncherError, "outside the writable workspace"):
            self.prepare(packet_path=inside, lease_issuer=issuer)
        self.assertEqual(issuer.calls, [])

    def test_claim_failure_removes_unused_executor_lease(self):
        client = FakeClient(
            task=self.task,
            repo_root=self.repo,
            daemon_secret=DAEMON_SECRET,
            fail_claim=True,
        )
        issuer = FakeLeaseIssuer(self.repo)
        with self.assertRaisesRegex(GovernedLauncherError, "workspace claim failed"):
            self.prepare(client=client, lease_issuer=issuer)
        self.assertIsNotNone(issuer.last_path)
        self.assertFalse(issuer.last_path.exists())
        self.assertEqual(client.releases, [])

    def test_tampered_daemon_envelope_releases_claim_and_removes_executor_lease(self):
        client = FakeClient(
            task=self.task,
            repo_root=self.repo,
            daemon_secret=DAEMON_SECRET,
            tamper_envelope=True,
        )
        issuer = FakeLeaseIssuer(self.repo)
        with self.assertRaisesRegex(GovernedLauncherError, "envelope verification failed"):
            self.prepare(client=client, lease_issuer=issuer)
        self.assertFalse(issuer.last_path.exists())
        self.assertEqual(len(client.releases), 1)
        self.assertEqual(client.releases[0]["outcome"], "queued")

    def test_corrupt_executor_lease_is_rejected_before_workspace_claim(self):
        client = FakeClient(
            task=self.task,
            repo_root=self.repo,
            daemon_secret=DAEMON_SECRET,
        )
        issuer = FakeLeaseIssuer(self.repo, corrupt_packet=True)
        with self.assertRaisesRegex(GovernedLauncherError, "packet hash mismatch"):
            self.prepare(client=client, lease_issuer=issuer)
        self.assertEqual([name for name, _, _ in client.calls], ["task.get"])
        self.assertIsNone(client.last_claim)
        self.assertFalse(issuer.last_path.exists())

    def test_executor_lease_failure_happens_before_workspace_claim(self):
        client = FakeClient(
            task=self.task,
            repo_root=self.repo,
            daemon_secret=DAEMON_SECRET,
        )
        issuer = FakeLeaseIssuer(self.repo, fail=True)
        with self.assertRaisesRegex(GovernedLauncherError, "executor lease preparation failed"):
            self.prepare(client=client, lease_issuer=issuer)
        self.assertEqual([name for name, _, _ in client.calls], ["task.get"])
        self.assertIsNone(client.last_claim)

    def test_same_daemon_and_launch_key_is_rejected(self):
        client = FakeClient(
            task=self.task,
            repo_root=self.repo,
            daemon_secret=DAEMON_SECRET,
        )
        issuer = FakeLeaseIssuer(self.repo)
        with self.assertRaisesRegex(GovernedLauncherError, "key material must differ"):
            prepare_governed_launch(
                client=client,
                repo_root=self.repo,
                worktree_root=self.worktrees,
                task_id="T1",
                packet_path=self.packet_path,
                workspace_path=self.workspace,
                budget_usd=0.5,
                provider="openai",
                model="openai/gpt-5.6-luna",
                provider_env={"OPENAI_API_KEY": "secret-key"},
                daemon_secret=DAEMON_SECRET,
                launch_secret=DAEMON_SECRET,
                lease_issuer=issuer,
            )
        self.assertEqual(client.calls, [])


if __name__ == "__main__":
    unittest.main()