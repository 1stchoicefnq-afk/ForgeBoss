from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from forgeboss.control.governed_launch import (
    GovernedLaunchError,
    issue_governed_launch_attestation,
    verify_governed_launch_attestation,
)


SECRET = b"l" * 32


class GovernedLaunchTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.repo = self.root / "repo"
        self.worktrees = self.root / "worktrees"
        self.workspace = self.worktrees / "w1"
        (self.repo / "forgeboss" / "executors").mkdir(parents=True)
        self.workspace.mkdir(parents=True)
        self.runner = self.repo / "forgeboss" / "executors" / "mini_swe_runner.py"
        self.runner.write_text("#!/usr/bin/env python3\nprint('runner')\n", encoding="utf-8")
        self.runner.chmod(0o700)

    def args(self):
        return {
            "task_id": "T1",
            "repository": "Owner/Repo",
            "base_sha": "a" * 40,
            "run_id": "RUN-1",
            "adapter": "mini-swe",
            "repo_root": self.repo,
            "workspace_path": self.workspace,
            "worktree_root": self.worktrees,
            "allowed_paths": ["SRC/A.PY.", "tests/a.test.py"],
            "allowed_tools": ["python", "git"],
            "budget_usd": "0.50",
        }

    def issue(self, **overrides):
        args = self.args()
        args.update(overrides)
        return issue_governed_launch_attestation(
            **args,
            secret=SECRET,
            ttl_seconds=300,
            now=1000.0,
        )

    def verify(self, value, **overrides):
        args = self.args()
        args.update(overrides)
        return verify_governed_launch_attestation(
            value,
            **args,
            secret=SECRET,
            now=1100.0,
        )

    def test_exact_launch_identity_verifies(self):
        token = self.issue()
        verified = self.verify(token)
        self.assertEqual(verified.task_id, "T1")
        self.assertEqual(verified.identity.adapter, "mini-swe")
        self.assertEqual(
            verified.identity.runner_sha256,
            hashlib.sha256(self.runner.read_bytes()).hexdigest(),
        )
        self.assertEqual(verified.allowed_paths, ("src/a.py", "tests/a.test.py"))
        self.assertEqual(verified.allowed_tools, ("git", "python"))
        self.assertEqual(verified.budget_usd, "0.5")

    def test_task_run_repo_head_workspace_scope_tools_budget_adapter_are_bound(self):
        token = self.issue()
        cases = {
            "task_id": "T2",
            "run_id": "RUN-2",
            "repository": "owner/other",
            "base_sha": "b" * 40,
            "workspace_path": self.worktrees / "other",
            "allowed_paths": ["src/b.py"],
            "allowed_tools": ["python"],
            "budget_usd": "0.51",
        }
        (self.worktrees / "other").mkdir()
        for key, value in cases.items():
            with self.subTest(key=key):
                with self.assertRaises(GovernedLaunchError):
                    self.verify(token, **{key: value})

    def test_runner_change_invalidates_existing_attestation(self):
        token = self.issue()
        self.runner.write_text("#!/usr/bin/env python3\nprint('changed')\n", encoding="utf-8")
        with self.assertRaisesRegex(GovernedLaunchError, "binding mismatch"):
            self.verify(token)

    def test_signature_tamper_wrong_secret_and_expiry_fail_closed(self):
        token = self.issue()
        token["budgetUsd"] = "0.6"
        with self.assertRaisesRegex(GovernedLaunchError, "signature mismatch"):
            self.verify(token)

        good = self.issue()
        with self.assertRaisesRegex(GovernedLaunchError, "signature mismatch"):
            verify_governed_launch_attestation(
                good,
                **self.args(),
                secret=b"x" * 32,
                now=1100.0,
            )
        with self.assertRaisesRegex(GovernedLaunchError, "expired"):
            verify_governed_launch_attestation(
                good,
                **self.args(),
                secret=SECRET,
                now=1400.0,
            )

    def test_unknown_fields_and_unsupported_adapter_fail_closed(self):
        token = self.issue()
        token["authority"] = "WRITE"
        with self.assertRaisesRegex(GovernedLaunchError, "fields mismatch"):
            self.verify(token)
        with self.assertRaisesRegex(GovernedLaunchError, "unsupported governed adapter"):
            self.issue(adapter="made-up")

    def test_relative_or_escaping_workspace_and_scope_fail_closed(self):
        with self.assertRaises(Exception):
            self.issue(workspace_path="../escape")
        with self.assertRaises(GovernedLaunchError):
            self.issue(allowed_paths=["../src/a.py"])

    def test_empty_or_unapproved_tool_set_is_bounded(self):
        token = self.issue(allowed_tools=[])
        verified = self.verify(token, allowed_tools=[])
        self.assertEqual(verified.allowed_tools, ())
        with self.assertRaisesRegex(GovernedLaunchError, "unapproved tool"):
            self.issue(allowed_tools=["powershell-unrestricted"])

    def test_budget_canonicalization_prevents_string_alias_mismatch(self):
        token = self.issue(budget_usd="0.5000")
        verified = self.verify(token, budget_usd=0.5)
        self.assertEqual(verified.budget_usd, "0.5")

    def test_zero_or_negative_budget_is_rejected_for_paid_governed_launch(self):
        for value in (0, "0", -0.01):
            with self.subTest(value=value):
                with self.assertRaisesRegex(GovernedLaunchError, "positive"):
                    self.issue(budget_usd=value)


if __name__ == "__main__":
    unittest.main()