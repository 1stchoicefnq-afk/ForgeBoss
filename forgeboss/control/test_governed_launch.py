from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from forgeboss.control.governed_launch import (
    GovernedLaunchAttestationError,
    issue_governed_launch_attestation,
    verify_governed_launch_attestation,
)


class GovernedLaunchAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = self.root / "forgeboss" / "executors" / "mini_swe_runner.py"
        self.runner.parent.mkdir(parents=True)
        reviewed_runner = Path(__file__).resolve().parents[1] / "executors" / "mini_swe_runner.py"
        self.runner.write_bytes(reviewed_runner.read_bytes())
        self.workspace = self.root / "worktrees" / "run-1"
        self.workspace.mkdir(parents=True)
        self.secret = b"l" * 32
        self.kw = {
            "root": self.root,
            "task_id": "T1",
            "repository": "owner/repo",
            "base_sha": "a" * 40,
            "run_id": "R1",
            "worktree_path": str(self.workspace),
            "runtime_id": "mini-swe",
            "allowed_paths": ["src/a.py", "tests/test_a.py"],
            "allowed_tools": ["python", "pytest"],
            "provider": "openai",
            "model": "example-model",
            "budget_usd": 1.25,
        }

    def issue(self, **overrides):
        args = dict(self.kw)
        args.update(overrides)
        return issue_governed_launch_attestation(
            **args,
            secret=self.secret,
            ttl_seconds=60,
            now=1000,
            nonce="n" * 32,
        )

    def verify(self, token, **overrides):
        args = dict(self.kw)
        args.update(overrides)
        return verify_governed_launch_attestation(
            token,
            **args,
            secret=self.secret,
            now=1030,
        )

    def test_valid_attestation_verifies(self):
        token = self.issue()
        out = self.verify(token)
        self.assertEqual(out["runtimeId"], "mini-swe")
        self.assertRegex(out["runnerSha256"], r"^[0-9a-f]{64}$")

    def test_governed_container_timeout_stays_below_control_lease(self):
        text = self.runner.read_text(encoding="utf-8")
        self.assertIn('container_timeout="18m"', text)
        self.assertLess(18 * 60, 1800)
        self.assertLess(18 * 60, 1200)

    def test_runner_content_change_invalidates_existing_attestation(self):
        token = self.issue()
        self.runner.write_text("print('replaced')\n", encoding="utf-8")
        with self.assertRaisesRegex(GovernedLaunchAttestationError, "reviewed SHA-256"):
            self.verify(token)

    def test_runtime_label_substitution_is_rejected(self):
        token = self.issue()
        with self.assertRaises(GovernedLaunchAttestationError):
            self.verify(token, runtime_id="openhands")

    def test_scope_rebinding_is_rejected(self):
        token = self.issue()
        with self.assertRaisesRegex(GovernedLaunchAttestationError, "allowedPaths"):
            self.verify(token, allowed_paths=["src/a.py"])

    def test_budget_rebinding_is_rejected(self):
        token = self.issue()
        with self.assertRaisesRegex(GovernedLaunchAttestationError, "budgetUsd"):
            self.verify(token, budget_usd=2.0)

    def test_expired_attestation_is_rejected(self):
        token = self.issue()
        with self.assertRaisesRegex(GovernedLaunchAttestationError, "expired"):
            verify_governed_launch_attestation(
                token,
                **self.kw,
                secret=self.secret,
                now=1061,
            )

    def test_extra_field_is_rejected_even_if_unsigned_copy(self):
        token = self.issue()
        bad = copy.deepcopy(token)
        bad["surprise"] = True
        with self.assertRaisesRegex(GovernedLaunchAttestationError, "fields"):
            self.verify(bad)

    def test_signature_tamper_is_rejected(self):
        token = self.issue()
        token["taskId"] = "OTHER"
        with self.assertRaisesRegex(GovernedLaunchAttestationError, "signature mismatch"):
            self.verify(token)

    def test_symlinked_runner_is_rejected(self):
        target = self.root / "real_runner.py"
        target.write_text("print('real')\n", encoding="utf-8")
        self.runner.unlink()
        try:
            self.runner.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(GovernedLaunchAttestationError, "symlink"):
            self.issue()


if __name__ == "__main__":
    unittest.main()
