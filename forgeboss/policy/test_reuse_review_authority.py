from __future__ import annotations

import copy
import unittest

from forgeboss.policy.reuse_review_authority import (
    ReuseReviewAuthorityError,
    evaluate_authorized_reuse_readiness,
    issue_reuse_review_receipt,
    verify_reuse_review_receipt,
)
from forgeboss.policy.small_repair_authority import issue_small_repair_exemption


SECRET = b"r" * 32
TASK = {
    "task_id": "TASK-900",
    "repository": "Owner/Repo",
    "base_sha": "a" * 40,
    "objective": "Build the new terminal execution subsystem.",
    "allowed_paths": ["src/terminal.py", "tests/test_terminal.py"],
}
SUBSYSTEM = "terminal-execution"


def candidate():
    return {
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


def review():
    return {
        "schema": 1,
        "subsystem": SUBSYSTEM,
        "search_performed": ["GitHub terminal process broker", "existing ForgeBoss executors"],
        "candidates": [candidate()],
        "decision": "adapt",
        "custom_build_reason": "",
    }


def receipt(reuse_review=None):
    return issue_reuse_review_receipt(
        **TASK,
        subsystem=SUBSYSTEM,
        reuse_review=review() if reuse_review is None else reuse_review,
        secret=SECRET,
        ttl_seconds=600,
        now=1000.0,
    )


class ReuseReviewAuthorityTests(unittest.TestCase):
    def verify(self, value, *, reuse_review=None, **overrides):
        args = dict(TASK)
        args.update(overrides)
        return verify_reuse_review_receipt(
            value,
            **args,
            subsystem=SUBSYSTEM,
            reuse_review=review() if reuse_review is None else reuse_review,
            secret=SECRET,
            now=1100.0,
        )

    def test_substantial_review_without_signed_receipt_is_blocked(self):
        result = evaluate_authorized_reuse_readiness(
            **TASK,
            secret=SECRET,
            small_repair_exemption=None,
            subsystem=SUBSYSTEM,
            reuse_review=review(),
            reuse_review_receipt=None,
            now=1100.0,
        )
        self.assertFalse(result.ready)
        self.assertEqual(result.blocker, "UPSTREAM_REUSE_REVIEW_RECEIPT_REQUIRED")

    def test_valid_signed_review_receipt_authorizes_exact_review(self):
        reuse_review = review()
        signed = receipt(reuse_review)
        verified = self.verify(signed, reuse_review=reuse_review)
        self.assertEqual(verified.task_id, TASK["task_id"])

        result = evaluate_authorized_reuse_readiness(
            **TASK,
            secret=SECRET,
            small_repair_exemption=None,
            subsystem=SUBSYSTEM,
            reuse_review=reuse_review,
            reuse_review_receipt=signed,
            now=1100.0,
        )
        self.assertTrue(result.ready)
        self.assertEqual(result.work_kind, "substantial-subsystem")
        self.assertEqual(result.review.decision, "adapt")

    def test_review_cannot_be_modified_after_receipt_is_signed(self):
        original = review()
        signed = receipt(original)
        changed = copy.deepcopy(original)
        changed["candidates"][0]["exact_identity"] = "different-commit"
        with self.assertRaisesRegex(ReuseReviewAuthorityError, "binding mismatch"):
            self.verify(signed, reuse_review=changed)

    def test_receipt_cannot_rebind_task_repository_head_objective_or_scope(self):
        signed = receipt()
        mutations = {
            "task_id": "TASK-OTHER",
            "repository": "owner/other",
            "base_sha": "b" * 40,
            "objective": "Different objective",
            "allowed_paths": ["src/other.py"],
        }
        for key, changed in mutations.items():
            with self.subTest(key=key):
                with self.assertRaisesRegex(ReuseReviewAuthorityError, "binding mismatch"):
                    self.verify(signed, **{key: changed})

    def test_receipt_cannot_rebind_subsystem(self):
        signed = receipt()
        with self.assertRaises(ReuseReviewAuthorityError):
            verify_reuse_review_receipt(
                signed,
                **TASK,
                subsystem="database",
                reuse_review=review(),
                secret=SECRET,
                now=1100.0,
            )

    def test_signature_tamper_wrong_secret_and_expiry_fail_closed(self):
        signed = receipt()
        signed["expiresAt"] = 1300.0
        with self.assertRaisesRegex(ReuseReviewAuthorityError, "signature mismatch"):
            self.verify(signed)

        good = receipt()
        with self.assertRaisesRegex(ReuseReviewAuthorityError, "signature mismatch"):
            verify_reuse_review_receipt(
                good,
                **TASK,
                subsystem=SUBSYSTEM,
                reuse_review=review(),
                secret=b"x" * 32,
                now=1100.0,
            )
        with self.assertRaisesRegex(ReuseReviewAuthorityError, "expired"):
            verify_reuse_review_receipt(
                good,
                **TASK,
                subsystem=SUBSYSTEM,
                reuse_review=review(),
                secret=SECRET,
                now=1700.0,
            )

    def test_unknown_receipt_fields_fail_closed(self):
        signed = receipt()
        signed["authority"] = "WRITE"
        with self.assertRaisesRegex(ReuseReviewAuthorityError, "fields mismatch"):
            self.verify(signed)

    def test_invalid_review_cannot_be_signed(self):
        bad = review()
        bad["decision"] = "ship-it"
        with self.assertRaisesRegex(ReuseReviewAuthorityError, "not valid for signing"):
            receipt(bad)

    def test_small_repair_signed_exemption_does_not_require_reuse_review_receipt(self):
        exemption = issue_small_repair_exemption(
            **TASK,
            secret=SECRET,
            ttl_seconds=600,
            now=1000.0,
        )
        result = evaluate_authorized_reuse_readiness(
            **TASK,
            secret=SECRET,
            small_repair_exemption=exemption,
            subsystem=SUBSYSTEM,
            reuse_review=None,
            reuse_review_receipt=None,
            now=1100.0,
        )
        self.assertTrue(result.ready)
        self.assertEqual(result.work_kind, "small-repair")


if __name__ == "__main__":
    unittest.main()
