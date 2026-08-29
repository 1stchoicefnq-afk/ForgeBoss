from __future__ import annotations

import copy
import math
import unittest

from forgeboss.control.receipts import (
    ReceiptValidationError,
    canonical_sha256,
    receipt_sha256,
    receipt_matches_identity,
    require_acceptance_bundle,
    validate_receipt,
)

BASE = "a" * 40
CAND = "b" * 40
CONTRACT = "c" * 64
EVIDENCE = "d" * 64


def identity():
    return {
        "taskId": "task-1",
        "runId": "run-1",
        "ownerEpoch": 2,
        "baseSha": BASE,
        "candidateSha": CAND,
        "contractSha256": CONTRACT,
    }


def receipt(kind, evidence):
    return {"version": 1, "kind": kind, "identity": identity(), "evidence": evidence}


class ReceiptTests(unittest.TestCase):
    def test_canonical_digest_is_order_independent(self):
        a = {"b": 2, "a": {"y": 2, "x": 1}}
        b = {"a": {"x": 1, "y": 2}, "b": 2}
        self.assertEqual(canonical_sha256(a), canonical_sha256(b))

    def test_required_test_binds_immutable_oracle(self):
        r = receipt("required-test", {
            "command": "python -m unittest tests.hidden",
            "oracleSha256": EVIDENCE,
            "exitCode": 0,
            "passed": True,
            "changedOraclePaths": [],
        })
        self.assertEqual(validate_receipt(r)["evidence"]["oracleSha256"], EVIDENCE)
        bad = copy.deepcopy(r)
        bad["evidence"]["changedOraclePaths"] = ["tests/hidden.py"]
        with self.assertRaisesRegex(ReceiptValidationError, "changed oracle"):
            validate_receipt(bad)

    def test_required_test_pass_flag_cannot_lie(self):
        r = receipt("required-test", {
            "command": "pytest",
            "oracleSha256": EVIDENCE,
            "exitCode": 1,
            "passed": True,
            "changedOraclePaths": [],
        })
        with self.assertRaisesRegex(ReceiptValidationError, "exactly match"):
            validate_receipt(r)

    def test_scope_diff_derives_and_enforces_ceiling_shape(self):
        r = receipt("scope-diff", {
            "changedPaths": ["a.py", "z.py"],
            "changedFileCount": 2,
            "additions": 5,
            "deletions": 3,
            "totalChurn": 8,
            "maxChangedFiles": 2,
            "maxChurnLines": 8,
            "diffSha256": EVIDENCE,
        })
        self.assertEqual(validate_receipt(r)["evidence"]["totalChurn"], 8)
        for field, value in (("changedFileCount", 1), ("totalChurn", 7), ("maxChangedFiles", 1), ("maxChurnLines", 7)):
            bad = copy.deepcopy(r)
            bad["evidence"][field] = value
            with self.assertRaises(ReceiptValidationError):
                validate_receipt(bad)

    def test_scope_paths_must_be_canonical_sorted_and_noncolliding(self):
        base = {
            "changedFileCount": 2, "additions": 0, "deletions": 0, "totalChurn": 0,
            "maxChangedFiles": 2, "maxChurnLines": 0, "diffSha256": EVIDENCE,
        }
        for paths in (["z.py", "a.py"], ["A.py", "a.py"], ["../x.py", "a.py"], ["C:/x.py", "a.py"]):
            e = dict(base, changedPaths=paths)
            with self.assertRaises(ReceiptValidationError):
                validate_receipt(receipt("scope-diff", e))

    def test_independent_review_rejects_self_review_and_bad_verdict(self):
        good = receipt("independent-review", {
            "builderPrincipal": "worker-a",
            "reviewerPrincipal": "worker-b",
            "reviewedCandidateSha": CAND,
            "verdict": "PASS",
            "reviewEvidenceSha256": EVIDENCE,
        })
        validate_receipt(good)
        bad = copy.deepcopy(good)
        bad["evidence"]["reviewerPrincipal"] = "WORKER-A"
        with self.assertRaisesRegex(ReceiptValidationError, "independent"):
            validate_receipt(bad)
        bad = copy.deepcopy(good)
        bad["evidence"]["verdict"] = "approved"
        with self.assertRaisesRegex(ReceiptValidationError, "verdict"):
            validate_receipt(bad)

    def test_measured_cost_unknown_is_not_fabricated_zero(self):
        unknown = receipt("measured-cost", {
            "reservedUsd": 1.0,
            "measuredUsd": None,
            "settlementState": "unknown",
            "measurementSha256": EVIDENCE,
        })
        self.assertIsNone(validate_receipt(unknown)["evidence"]["measuredUsd"])
        fake = copy.deepcopy(unknown)
        fake["evidence"]["measuredUsd"] = 0.0
        with self.assertRaisesRegex(ReceiptValidationError, "measuredUsd=null"):
            validate_receipt(fake)

    def test_measured_cost_rejects_nonfinite_negative_and_over_reservation(self):
        template = {
            "reservedUsd": 1.0,
            "measuredUsd": 0.5,
            "settlementState": "settled",
            "measurementSha256": EVIDENCE,
        }
        for field, value in (("reservedUsd", math.inf), ("reservedUsd", -1), ("measuredUsd", math.nan), ("measuredUsd", -1), ("measuredUsd", 1.01)):
            e = dict(template)
            e[field] = value
            with self.assertRaises(ReceiptValidationError):
                validate_receipt(receipt("measured-cost", e))

    def test_freeze_binds_observed_candidate_and_requires_writer_revocation(self):
        good = receipt("candidate-freeze", {
            "observedCandidateSha": CAND,
            "writerRevoked": True,
            "frozenAtUnixMs": 123,
            "scopeDiffReceiptSha256": EVIDENCE,
        })
        validate_receipt(good)
        for field, value in (("observedCandidateSha", BASE), ("writerRevoked", False)):
            bad = copy.deepcopy(good)
            bad["evidence"][field] = value
            with self.assertRaises(ReceiptValidationError):
                validate_receipt(bad)

    def test_receipt_identity_binding_invalidates_candidate_or_contract_change(self):
        r = receipt("candidate-freeze", {
            "observedCandidateSha": CAND,
            "writerRevoked": True,
            "frozenAtUnixMs": 123,
            "scopeDiffReceiptSha256": EVIDENCE,
        })
        digest = receipt_sha256(r)
        self.assertEqual(len(digest), 64)
        self.assertTrue(receipt_matches_identity(
            r, task_id="task-1", run_id="run-1", owner_epoch=2,
            base_sha=BASE, candidate_sha=CAND, contract_sha256=CONTRACT,
        ))
        self.assertFalse(receipt_matches_identity(
            r, task_id="task-1", run_id="run-1", owner_epoch=2,
            base_sha=BASE, candidate_sha=CAND, contract_sha256="e" * 64,
        ))

    def test_exact_key_schema_rejects_ambiguous_extra_fields(self):
        r = receipt("candidate-freeze", {
            "observedCandidateSha": CAND,
            "writerRevoked": True,
            "frozenAtUnixMs": 123,
            "scopeDiffReceiptSha256": EVIDENCE,
        })
        r["evidence"]["candidateShaMaybe"] = CAND
        with self.assertRaisesRegex(ReceiptValidationError, "keys invalid"):
            validate_receipt(r)

    def test_acceptance_bundle_requires_all_receipts_same_identity_and_review_pass(self):
        bundle = [
            receipt("required-test", {
                "command": "pytest", "oracleSha256": EVIDENCE, "exitCode": 0, "passed": True, "changedOraclePaths": [],
            }),
            receipt("scope-diff", {
                "changedPaths": ["a.py"], "changedFileCount": 1, "additions": 1, "deletions": 0, "totalChurn": 1,
                "maxChangedFiles": 1, "maxChurnLines": 1, "diffSha256": EVIDENCE,
            }),
            receipt("independent-review", {
                "builderPrincipal": "worker-a", "reviewerPrincipal": "worker-b", "reviewedCandidateSha": CAND,
                "verdict": "PASS", "reviewEvidenceSha256": EVIDENCE,
            }),
            receipt("measured-cost", {
                "reservedUsd": 1.0, "measuredUsd": 0.4, "settlementState": "settled", "measurementSha256": EVIDENCE,
            }),
            receipt("candidate-freeze", {
                "observedCandidateSha": CAND, "writerRevoked": True, "frozenAtUnixMs": 123,
                "scopeDiffReceiptSha256": EVIDENCE,
            }),
        ]
        accepted = require_acceptance_bundle(bundle)
        self.assertEqual(set(accepted), {
            "required-test", "scope-diff", "independent-review", "measured-cost", "candidate-freeze",
        })

        bad = copy.deepcopy(bundle)
        bad[2]["evidence"]["verdict"] = "FAIL"
        with self.assertRaisesRegex(ReceiptValidationError, "REVIEW PASS"):
            require_acceptance_bundle(bad)

        bad = copy.deepcopy(bundle)
        bad[0]["identity"]["candidateSha"] = BASE
        with self.assertRaisesRegex(ReceiptValidationError, "identity mismatch"):
            require_acceptance_bundle(bad)

        with self.assertRaisesRegex(ReceiptValidationError, "missing acceptance receipts"):
            require_acceptance_bundle(bundle[:-1])

    def test_review_receipt_must_target_bundle_candidate(self):
        bundle = [
            receipt("required-test", {
                "command": "pytest", "oracleSha256": EVIDENCE, "exitCode": 0, "passed": True, "changedOraclePaths": [],
            }),
            receipt("scope-diff", {
                "changedPaths": ["a.py"], "changedFileCount": 1, "additions": 1, "deletions": 0, "totalChurn": 1,
                "maxChangedFiles": 1, "maxChurnLines": 1, "diffSha256": EVIDENCE,
            }),
            receipt("independent-review", {
                "builderPrincipal": "worker-a", "reviewerPrincipal": "worker-b", "reviewedCandidateSha": BASE,
                "verdict": "PASS", "reviewEvidenceSha256": EVIDENCE,
            }),
            receipt("measured-cost", {
                "reservedUsd": 1.0, "measuredUsd": None, "settlementState": "unknown", "measurementSha256": EVIDENCE,
            }),
            receipt("candidate-freeze", {
                "observedCandidateSha": CAND, "writerRevoked": True, "frozenAtUnixMs": 123,
                "scopeDiffReceiptSha256": EVIDENCE,
            }),
        ]
        with self.assertRaisesRegex(ReceiptValidationError, "exact candidate SHA"):
            require_acceptance_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
