from __future__ import annotations

import base64
import copy
import hashlib
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forgeboss.policy.protected_policy_receipt import (
    ProtectedPolicyReceiptError,
    verify_protected_policy_approval,
)
from forgeboss.protected_authority.protocol import canonical_digest
from forgeboss.protected_authority.signing import ReceiptSigner


TASK = {
    "task_id": "task-a",
    "repository": "Owner/Repo",
    "base_sha": "a" * 40,
    "objective": "Build the terminal execution subsystem.",
    "allowed_paths": ["SRC/A.py.", "tests\\A.test.py"],
}
PEER = "controller-a"
CONTROL = 129
SERVICE = "machine:svc"


class ProtectedPolicyVerifierTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.signer = ReceiptSigner.from_private_key(self.key)
        raw = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_b64 = base64.b64encode(raw).decode("ascii")
        self.now = int(time.time())

    def response(self, *, reuse=False, ttl=300):
        result = {
            "schema": 1,
            "approved": True,
            "policy": "reuse-review-v1" if reuse else "small-repair-v1",
            "taskId": TASK["task_id"],
            "repository": "owner/repo",
            "baseSha": TASK["base_sha"],
            "objectiveSha256": hashlib.sha256(TASK["objective"].encode()).hexdigest(),
            "allowedPaths": ["src/a.py", "tests/a.test.py"],
            "issuedAt": self.now,
            "expiresAt": self.now + ttl,
        }
        if reuse:
            result["subsystem"] = "terminal-execution"
            result["reviewSha256"] = "b" * 64
        receipt = {
            "schema": 3,
            "operation": "approve_reuse_review" if reuse else "approve_small_repair",
            "requestId": "00000000-0000-4000-8000-000000000001",
            "peerId": PEER,
            "peerPrincipal": "principal-a",
            "repository": "owner/repo",
            "controlRevision": CONTROL,
            "requestDigest": "c" * 64,
            "resultDigest": canonical_digest(result),
            "servicePrincipal": SERVICE,
        }
        return {**self.signer.sign(receipt), "result": result}

    def verify(self, response, *, reuse=False, **overrides):
        args = dict(
            pinned_public_key_b64=self.public_b64,
            expected_operation="approve_reuse_review" if reuse else "approve_small_repair",
            expected_control_revision=CONTROL,
            expected_service_principal=SERVICE,
            allowed_peer_ids=[PEER],
            subsystem="terminal-execution" if reuse else None,
            review_sha256="b" * 64 if reuse else None,
            now=self.now + 10,
            **TASK,
        )
        args.update(overrides)
        return verify_protected_policy_approval(response, **args)

    def test_small_repair_receipt_verifies_with_public_key_only(self):
        out = self.verify(self.response())
        self.assertEqual(out.policy, "small-repair-v1")
        self.assertEqual(out.repository, "owner/repo")
        self.assertEqual(out.allowed_paths, ("src/a.py", "tests/a.test.py"))
        self.assertEqual(out.peer_id, PEER)

    def test_reuse_receipt_binds_subsystem_and_review_digest(self):
        out = self.verify(self.response(reuse=True), reuse=True)
        self.assertEqual(out.policy, "reuse-review-v1")
        self.assertEqual(out.subsystem, "terminal-execution")
        self.assertEqual(out.review_sha256, "b" * 64)

    def test_wrong_public_key_or_result_mutation_fails_signature_verification(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        with self.assertRaisesRegex(ProtectedPolicyReceiptError, "signature/result"):
            self.verify(
                self.response(),
                pinned_public_key_b64=base64.b64encode(other).decode("ascii"),
            )

        changed = copy.deepcopy(self.response())
        changed["result"]["taskId"] = "other"
        with self.assertRaisesRegex(ProtectedPolicyReceiptError, "signature/result"):
            self.verify(changed)

    def test_wrong_peer_control_service_or_operation_fails_closed(self):
        cases = [
            {"allowed_peer_ids": ["other"]},
            {"expected_control_revision": CONTROL + 1},
            {"expected_service_principal": "machine:other"},
            {"expected_operation": "approve_reuse_review"},
        ]
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(ProtectedPolicyReceiptError):
                    self.verify(self.response(), **change)

    def test_exact_task_repository_base_objective_and_scope_are_bound(self):
        changes = [
            {"task_id": "task-b"},
            {"repository": "owner/other"},
            {"base_sha": "d" * 40},
            {"objective": "Different objective"},
            {"allowed_paths": ["src/a.py", "tests/other.py"]},
        ]
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(ProtectedPolicyReceiptError):
                    self.verify(self.response(), **change)

    def test_scope_uses_control_store_identity(self):
        out = self.verify(
            self.response(),
            allowed_paths=["src/a.py", "TESTS/A.TEST.PY."],
            repository="OWNER/REPO",
            base_sha="A" * 40,
        )
        self.assertEqual(out.allowed_paths, ("src/a.py", "tests/a.test.py"))

    def test_expired_future_and_excess_ttl_fail_closed(self):
        with self.assertRaisesRegex(ProtectedPolicyReceiptError, "expired"):
            self.verify(self.response(ttl=5), now=self.now + 6)

        future = self.response()
        future["result"]["issuedAt"] = self.now + 60
        future["result"]["expiresAt"] = self.now + 120
        receipt = dict(future["receipt"])
        receipt["resultDigest"] = canonical_digest(future["result"])
        future = {**self.signer.sign(receipt), "result": future["result"]}
        with self.assertRaisesRegex(ProtectedPolicyReceiptError, "not yet valid"):
            self.verify(future, now=self.now)

        with self.assertRaisesRegex(ProtectedPolicyReceiptError, "TTL"):
            self.verify(self.response(ttl=3601))

    def test_reuse_expectations_cannot_be_supplied_to_small_repair(self):
        with self.assertRaisesRegex(ProtectedPolicyReceiptError, "must not carry"):
            self.verify(self.response(), subsystem="terminal-execution", review_sha256="b" * 64)

    def test_duplicate_or_escape_scope_fails_closed(self):
        duplicate = self.response()
        duplicate["result"]["allowedPaths"] = ["SRC/A.py", "src/a.py."]
        receipt = dict(duplicate["receipt"])
        receipt["resultDigest"] = canonical_digest(duplicate["result"])
        duplicate = {**self.signer.sign(receipt), "result": duplicate["result"]}
        with self.assertRaisesRegex(ProtectedPolicyReceiptError, "duplicate"):
            self.verify(duplicate)

        escape = self.response()
        escape["result"]["allowedPaths"] = ["../escape.py"]
        receipt = dict(escape["receipt"])
        receipt["resultDigest"] = canonical_digest(escape["result"])
        escape = {**self.signer.sign(receipt), "result": escape["result"]}
        with self.assertRaisesRegex(ProtectedPolicyReceiptError, "parent traversal"):
            self.verify(escape)


if __name__ == "__main__":
    unittest.main()
