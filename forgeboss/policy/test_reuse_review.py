from __future__ import annotations

import unittest

from forgeboss.policy.reuse_review import (
    ReuseReviewError,
    evaluate_build_readiness,
    review_summary,
    validate_reuse_review,
)


def candidate(
    name="example/lib",
    *,
    selected=True,
    exact_identity="v1.2.3",
    license_status="permissive",
    platform_fit="fit",
    security_fit="fit",
):
    return {
        "name": name,
        "source": f"https://example.invalid/{name}",
        "exact_identity": exact_identity,
        "license": "MIT",
        "license_status": license_status,
        "maintenance_status": "active",
        "platform_fit": platform_fit,
        "security_fit": security_fit,
        "disposition": "selected" if selected else "rejected",
        "notes": "",
    }


def review(*, decision="reuse", candidates=None, reason=""):
    return {
        "schema": 1,
        "subsystem": "terminal-execution",
        "search_performed": ["GitHub MIT terminal process broker", "existing ForgeBoss executors"],
        "candidates": candidates if candidates is not None else [candidate()],
        "decision": decision,
        "custom_build_reason": reason,
    }


class ReuseReviewTests(unittest.TestCase):
    def test_substantial_work_without_review_is_blocked(self):
        result = evaluate_build_readiness(
            work_kind="substantial-subsystem",
            subsystem="terminal-execution",
            reuse_review=None,
        )
        self.assertFalse(result.ready)
        self.assertEqual(result.blocker, "UPSTREAM_REUSE_REVIEW_REQUIRED")

    def test_small_repair_without_review_is_allowed(self):
        result = evaluate_build_readiness(
            work_kind="small-repair",
            subsystem="terminal-execution",
            reuse_review=None,
        )
        self.assertTrue(result.ready)
        self.assertIsNone(result.review)

    def test_reuse_requires_selected_pinned_compatible_candidate(self):
        parsed = validate_reuse_review(review())
        self.assertEqual(parsed.decision, "reuse")
        self.assertEqual(parsed.selected[0].exact_identity, "v1.2.3")

        for bad in (
            candidate(exact_identity=""),
            candidate(license_status="incompatible"),
            candidate(platform_fit="unfit"),
            candidate(security_fit="unfit"),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ReuseReviewError):
                    validate_reuse_review(review(candidates=[bad]))

    def test_custom_build_requires_candidates_and_explicit_reason(self):
        parsed = validate_reuse_review(
            review(
                decision="custom",
                candidates=[candidate(selected=False)],
                reason="Existing candidates cannot satisfy Windows process-tree ownership.",
            )
        )
        self.assertEqual(parsed.decision, "custom")

        with self.assertRaises(ReuseReviewError):
            validate_reuse_review(review(decision="custom", candidates=[], reason="needed"))
        with self.assertRaises(ReuseReviewError):
            validate_reuse_review(
                review(decision="custom", candidates=[candidate(selected=False)], reason="")
            )

    def test_custom_build_cannot_smuggle_selected_component(self):
        with self.assertRaises(ReuseReviewError):
            validate_reuse_review(
                review(decision="custom", candidates=[candidate()], reason="build ourselves")
            )

    def test_subsystem_binding_blocks_review_reuse_for_different_work(self):
        result = evaluate_build_readiness(
            work_kind="substantial-subsystem",
            subsystem="database-migrations",
            reuse_review=review(),
        )
        self.assertFalse(result.ready)
        self.assertIn("subsystem mismatch", result.blocker)

    def test_unknown_fields_and_vocab_fail_closed(self):
        doc = review()
        doc["authority"] = "WRITE"
        with self.assertRaises(ReuseReviewError):
            validate_reuse_review(doc)

        doc = review()
        doc["candidates"][0]["disposition"] = "auto-install"
        with self.assertRaises(ReuseReviewError):
            validate_reuse_review(doc)

    def test_duplicate_searches_or_candidate_names_fail_closed(self):
        doc = review(candidates=[candidate("x"), candidate("x", selected=False)])
        with self.assertRaises(ReuseReviewError):
            validate_reuse_review(doc)

        doc = review()
        doc["search_performed"].append(doc["search_performed"][0])
        with self.assertRaises(ReuseReviewError):
            validate_reuse_review(doc)

    def test_invalid_review_is_blocked_not_raised_at_readiness_boundary(self):
        doc = review()
        doc["decision"] = "ship-it"
        result = evaluate_build_readiness(
            work_kind="substantial-subsystem",
            subsystem="terminal-execution",
            reuse_review=doc,
        )
        self.assertFalse(result.ready)
        self.assertTrue(result.blocker.startswith("UPSTREAM_REUSE_REVIEW_INVALID:"))

    def test_summary_is_read_only_and_contains_only_decision_evidence(self):
        parsed = validate_reuse_review(review())
        summary = review_summary(parsed)
        self.assertEqual(summary["decision"], "reuse")
        self.assertEqual(summary["selected"][0]["name"], "example/lib")
        with self.assertRaises(TypeError):
            summary["decision"] = "custom"
        with self.assertRaises(TypeError):
            summary["selected"][0]["name"] = "changed"


if __name__ == "__main__":
    unittest.main()
