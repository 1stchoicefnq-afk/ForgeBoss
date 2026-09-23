from __future__ import annotations

import copy
import unittest

from forgeboss.policy.small_repair_authority import (
    SmallRepairAuthorityError,
    classify_work_kind,
    evaluate_task_reuse_readiness,
    issue_small_repair_exemption,
    verify_small_repair_exemption,
)


SECRET = b"s" * 32
TASK = {
    "task_id": "TASK-123",
    "repository": "Owner/Repo",
    "base_sha": "a" * 40,
    "objective": "Fix the exact null check without changing the subsystem.",
    "allowed_paths": ["src/a.py", "tests/a.test.py"],
}


def token(**overrides):
    args = dict(TASK)
    args.update(overrides)
    return issue_small_repair_exemption(
        **args,
        secret=SECRET,
        ttl_seconds=300,
        now=1000.0,
    )


class SmallRepairAuthorityTests(unittest.TestCase):
    def verify(self, value, **overrides):
        args = dict(TASK)
        args.update(overrides)
        return verify_small_repair_exemption(
            value,
            **args,
            secret=SECRET,
            now=1100.0,
        )

    def test_missing_exemption_defaults_to_substantial(self):
        self.assertEqual(
            classify_work_kind(
                **TASK,
                secret=SECRET,
                exemption=None,
                now=1100.0,
            ),
            "substantial-subsystem",
        )

    def test_valid_exact_bound_exemption_is_small_repair(self):
        value = token()
        verified = self.verify(value)
        self.assertEqual(verified.task_id, TASK["task_id"])
        self.assertEqual(
            classify_work_kind(
                **TASK,
                secret=SECRET,
                exemption=value,
                now=1100.0,
            ),
            "small-repair",
        )

    def test_signature_tampering_fails_closed(self):
        value = token()
        value["expiresAt"] = 1201.0
        with self.assertRaisesRegex(SmallRepairAuthorityError, "signature mismatch"):
            self.verify(value)

    def test_expired_future_or_excessive_ttl_fails_closed(self):
        value = token()
        with self.assertRaisesRegex(SmallRepairAuthorityError, "expired"):
            verify_small_repair_exemption(
                value,
                **TASK,
                secret=SECRET,
                now=1400.0,
            )

        with self.assertRaisesRegex(SmallRepairAuthorityError, "not yet valid"):
            verify_small_repair_exemption(
                value,
                **TASK,
                secret=SECRET,
                now=900.0,
            )

        with self.assertRaisesRegex(SmallRepairAuthorityError, "ttl_seconds"):
            issue_small_repair_exemption(
                **TASK,
                secret=SECRET,
                ttl_seconds=3601,
                now=1000.0,
            )

    def test_token_cannot_be_reused_for_different_task_repo_head_objective_or_scope(self):
        value = token()
        mutations = {
            "task_id": "TASK-OTHER",
            "repository": "owner/other",
            "base_sha": "b" * 40,
            "objective": "Different objective",
            "allowed_paths": ["src/a.py", "src/b.py"],
        }
        for key, changed in mutations.items():
            with self.subTest(key=key):
                with self.assertRaisesRegex(SmallRepairAuthorityError, "binding mismatch"):
                    self.verify(value, **{key: changed})

    def test_scope_order_and_slashes_are_canonical(self):
        value = issue_small_repair_exemption(
            task_id=TASK["task_id"],
            repository=TASK["repository"],
            base_sha=TASK["base_sha"],
            objective=TASK["objective"],
            allowed_paths=["tests\\a.test.py", "./src/a.py", "src/a.py"],
            secret=SECRET,
            ttl_seconds=300,
            now=1000.0,
        )
        verified = verify_small_repair_exemption(
            value,
            task_id=TASK["task_id"],
            repository="owner/repo",
            base_sha=TASK["base_sha"].upper(),
            objective=TASK["objective"],
            allowed_paths=["src/a.py", "tests/a.test.py"],
            secret=SECRET,
            now=1100.0,
        )
        self.assertEqual(verified.allowed_paths, ("src/a.py", "tests/a.test.py"))

    def test_absolute_parent_and_empty_scope_paths_fail_closed(self):
        for path in ("/etc/passwd", "../src/a.py", "C:/Windows/system32", "."):
            with self.subTest(path=path):
                with self.assertRaises(SmallRepairAuthorityError):
                    issue_small_repair_exemption(
                        **{**TASK, "allowed_paths": [path]},
                        secret=SECRET,
                        ttl_seconds=300,
                        now=1000.0,
                    )

    def test_unknown_token_fields_fail_closed(self):
        value = token()
        value["authority"] = "WRITE"
        with self.assertRaisesRegex(SmallRepairAuthorityError, "fields mismatch"):
            self.verify(value)

    def test_wrong_secret_fails_closed(self):
        value = token()
        with self.assertRaisesRegex(SmallRepairAuthorityError, "signature mismatch"):
            verify_small_repair_exemption(
                value,
                **TASK,
                secret=b"x" * 32,
                now=1100.0,
            )

    def test_reuse_gate_requires_review_without_exemption(self):
        result = evaluate_task_reuse_readiness(
            **TASK,
            secret=SECRET,
            exemption=None,
            subsystem="terminal-execution",
            reuse_review=None,
            now=1100.0,
        )
        self.assertFalse(result.ready)
        self.assertEqual(result.blocker, "UPSTREAM_REUSE_REVIEW_REQUIRED")

    def test_valid_exemption_allows_small_repair_without_broad_reuse_review(self):
        result = evaluate_task_reuse_readiness(
            **TASK,
            secret=SECRET,
            exemption=token(),
            subsystem="terminal-execution",
            reuse_review=None,
            now=1100.0,
        )
        self.assertTrue(result.ready)
        self.assertEqual(result.work_kind, "small-repair")

    def test_invalid_exemption_does_not_fall_back_to_small_or_substantial_silently(self):
        value = token()
        value["taskId"] = "OTHER"
        with self.assertRaises(SmallRepairAuthorityError):
            evaluate_task_reuse_readiness(
                **TASK,
                secret=SECRET,
                exemption=value,
                subsystem="terminal-execution",
                reuse_review=None,
                now=1100.0,
            )


if __name__ == "__main__":
    unittest.main()
