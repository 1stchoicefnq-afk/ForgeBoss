from __future__ import annotations
import base64
import math
import unittest
from forgeboss.control.authority import (
    AUTHORITY_VERSION,
    PROTOCOL_VERSION,
    AuthorityKey,
    ControllerAuthoritySignerClient,
    ControllerAuthorityVerifier,
    PinnedAuthorityTrust,
    validate_authority,
)
from forgeboss.control.envelope import canonical

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception:
    Ed25519PrivateKey = None


def sample(key_id="k1"):
    return {
        "authorityVersion": AUTHORITY_VERSION,
        "protocolVersion": PROTOCOL_VERSION,
        "algorithm": "ed25519",
        "keyId": key_id,
        "purpose": "worker-launch",
        "authorityId": "a1",
        "assignmentId": "as1",
        "taskId": "t1",
        "runId": "r1",
        "ownerEpoch": 1,
        "attempt": 1,
        "repository": "Owner/Repo",
        "baseSha": "a" * 40,
        "branch": "forgeboss/task-1",
        "worktreePath": "C:/work/one",
        "runtime": {"adapter": "mini-swe", "provider": "openai", "model": "gpt-5.6-luna"},
        "allowedPaths": ["src/a.py"],
        "deniedPaths": ["secrets"],
        "allowedTools": ["python"],
        "contextBundleHash": "c" * 64,
        "budgetUsd": 1.0,
        "issuedAt": 100.0,
        "expiresAt": 200.0,
        "controllerKnownGood": {
            "revision": 1,
            "manifestSha256": "d" * 64,
            "identitySha256": "e" * 64,
        },
        "reviewPolicy": {"independentReviewRequired": True, "reviewerId": "worker-b"},
    }


class StrictAuthoritySchemaTests(unittest.TestCase):
    def test_accepts_current_git_sha1_identity(self):
        self.assertEqual(validate_authority(sample())["baseSha"], "a" * 40)

    def test_rejects_type_coercion(self):
        fields = {"taskId": 7, "repository": ["Owner", "Repo"], "branch": 9, "worktreePath": {"p": "x"}, "contextBundleHash": 1}
        for field, bad in fields.items():
            with self.subTest(field=field):
                authority = sample()
                authority[field] = bad
                with self.assertRaises(ValueError):
                    validate_authority(authority)

    def test_rejects_bool_epoch_attempt_and_known_good_revision(self):
        for field in ("ownerEpoch", "attempt"):
            authority = sample()
            authority[field] = True
            with self.assertRaises(ValueError):
                validate_authority(authority)
        authority = sample()
        authority["controllerKnownGood"]["revision"] = True
        with self.assertRaises(ValueError):
            validate_authority(authority)

    def test_rejects_nonfinite_time_and_budget(self):
        for field, value in (("budgetUsd", math.nan), ("budgetUsd", math.inf), ("issuedAt", math.nan), ("expiresAt", math.inf)):
            authority = sample()
            authority[field] = value
            with self.assertRaises(ValueError):
                validate_authority(authority)

    def test_rejects_runtime_shape_and_values(self):
        authority = sample()
        authority["runtime"]["provider"] = []
        with self.assertRaises(ValueError):
            validate_authority(authority)
        authority = sample()
        authority["runtime"]["extra"] = "x"
        with self.assertRaises(ValueError):
            validate_authority(authority)

    def test_rejects_path_aliases_reserved_names_and_allow_deny_ancestry(self):
        authority = sample()
        authority["allowedPaths"] = ["SRC/a.py", "src/a.py"]
        with self.assertRaises(ValueError):
            validate_authority(authority)
        for bad in ("src/a.py.", "src/a.py ", "src/a.py:stream", "NUL.txt"):
            authority = sample()
            authority["allowedPaths"] = [bad]
            with self.subTest(path=bad), self.assertRaises(ValueError):
                validate_authority(authority)
        authority = sample()
        authority["allowedPaths"] = ["src/a.py"]
        authority["deniedPaths"] = ["SRC"]
        with self.assertRaises(ValueError):
            validate_authority(authority)
        authority = sample()
        authority["allowedTools"] = ["Python", "python"]
        with self.assertRaises(ValueError):
            validate_authority(authority)

    def test_rejects_relative_worktree_and_bad_review_policy(self):
        authority = sample()
        authority["worktreePath"] = "relative/work"
        with self.assertRaises(ValueError):
            validate_authority(authority)
        authority = sample()
        authority["reviewPolicy"]["independentReviewRequired"] = "true"
        with self.assertRaises(ValueError):
            validate_authority(authority)

    def test_rejects_extra_or_missing_fields(self):
        authority = sample()
        authority["extra"] = 1
        with self.assertRaises(ValueError):
            validate_authority(authority)
        authority = sample()
        authority.pop("attempt")
        with self.assertRaises(ValueError):
            validate_authority(authority)


@unittest.skipIf(Ed25519PrivateKey is None, "cryptography unavailable")
class AuthorityCryptoTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_b64 = base64.b64encode(public).decode()
        self.trust = PinnedAuthorityTrust(2, (AuthorityKey("k1", self.public_b64, 90.0, 150.0, 180.0),), minimum_generation=2)

    def packet(self, authority):
        return {"authority": authority, "signature": "ed25519:" + base64.b64encode(self.private.sign(canonical(authority))).decode()}

    def test_valid_and_tamper(self):
        authority = sample()
        verifier = ControllerAuthorityVerifier(self.trust)
        self.assertEqual(verifier.verify(self.packet(authority), 110)["attempt"], 1)
        packet = self.packet(authority)
        packet["authority"] = dict(authority, attempt=2)
        with self.assertRaises(PermissionError):
            verifier.verify(packet, 110)

    def test_legacy_hmac_is_never_protected_authority(self):
        packet = self.packet(sample())
        packet["signature"] = "hmac-sha256:" + "0" * 64
        with self.assertRaises(PermissionError):
            ControllerAuthorityVerifier(self.trust).verify(packet, 110)

    def test_activation_and_cutoff(self):
        packet = self.packet(sample())
        verifier = ControllerAuthorityVerifier(self.trust)
        with self.assertRaises(PermissionError):
            verifier.verify(packet, 80)
        with self.assertRaises(PermissionError):
            verifier.verify(packet, 181)

    def test_stale_generation_and_duplicate_keys_rejected(self):
        with self.assertRaises(PermissionError):
            PinnedAuthorityTrust(1, self.trust.keys, minimum_generation=2)
        key = AuthorityKey("k1", self.public_b64, 90.0, 150.0, 180.0)
        with self.assertRaises(ValueError):
            PinnedAuthorityTrust(2, (key, key), minimum_generation=2)

    def test_bad_key_encoding_length_and_time_order_rejected(self):
        with self.assertRaises(ValueError):
            AuthorityKey("bad", "not-base64", 1.0)
        with self.assertRaises(ValueError):
            AuthorityKey("bad", base64.b64encode(b"x").decode(), 1.0)
        with self.assertRaises(ValueError):
            AuthorityKey("bad", self.public_b64, 10.0, 9.0, 20.0)
        with self.assertRaises(ValueError):
            AuthorityKey("bad", self.public_b64, 10.0, 15.0, 14.0)

    def test_signer_rejects_top_level_and_nested_mutation(self):
        authority = sample()
        top = ControllerAuthoritySignerClient(
            lambda request: {"authority": dict(request["authority"], attempt=2), "signature": "ed25519:x"},
            "controller-1",
        )
        with self.assertRaises(PermissionError):
            top.sign_worker_launch(authority)

        def nested_transport(request):
            request["authority"]["runtime"]["model"] = "evil-model"
            return {"authority": request["authority"], "signature": "ed25519:x"}
        nested = ControllerAuthoritySignerClient(nested_transport, "controller-1")
        with self.assertRaises(PermissionError):
            nested.sign_worker_launch(authority)
        self.assertEqual(authority["runtime"]["model"], "gpt-5.6-luna")

    def test_signer_request_binds_controller_identity(self):
        seen = {}
        def transport(request):
            seen.update(request)
            authority = request["authority"]
            return {"authority": authority, "signature": "ed25519:" + base64.b64encode(self.private.sign(canonical(authority))).decode()}
        ControllerAuthoritySignerClient(transport, "controller-1").sign_worker_launch(sample())
        self.assertEqual(seen["type"], "sign-worker-launch")
        self.assertEqual(seen["controllerIdentity"], "controller-1")


if __name__ == "__main__":
    unittest.main()
