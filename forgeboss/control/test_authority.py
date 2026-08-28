from __future__ import annotations
import base64
import math
import tempfile
import unittest
from pathlib import Path
from forgeboss.control.authority import (
    AUTHORITY_VERSION,
    PROTOCOL_VERSION,
    AuthorityKey,
    ControllerAuthoritySignerClient,
    ControllerAuthorityVerifier,
    PinnedAuthorityTrust,
    load_pinned_trust,
    validate_authority,
    write_pinned_trust,
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
        "reviewPolicy": {
            "independentReviewRequired": True,
            "authorMayReview": False,
            "reviewerId": "worker-b",
        },
    }


def dummy_key(key_id, activation=90.0, retirement=None, cutoff=None, byte=b"k"):
    return AuthorityKey(key_id, base64.b64encode(byte * 32).decode(), activation, retirement, cutoff)


class StrictAuthoritySchemaTests(unittest.TestCase):
    def test_accepts_current_git_sha1_identity(self):
        self.assertEqual(validate_authority(sample())["baseSha"], "a" * 40)

    def test_rejects_type_coercion_and_bool_versions(self):
        for field, bad in {"taskId": 7, "repository": ["Owner", "Repo"], "branch": 9, "worktreePath": {"p": "x"}, "contextBundleHash": 1}.items():
            authority = sample(); authority[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_authority(authority)
        for field in ("authorityVersion", "protocolVersion", "ownerEpoch", "attempt"):
            authority = sample(); authority[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_authority(authority)

    def test_rejects_nonfinite_time_and_budget(self):
        for field, value in (("budgetUsd", math.nan), ("budgetUsd", math.inf), ("issuedAt", math.nan), ("expiresAt", math.inf)):
            authority = sample(); authority[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_authority(authority)

    def test_rejects_noncanonical_paths_and_contradictory_scope(self):
        for bad in ("src\\a.py", " src/a.py", "src/a.py ", "src/a.py.", "src/a.py:stream", "NUL.txt", "src//a.py"):
            authority = sample(); authority["allowedPaths"] = [bad]
            with self.subTest(path=bad), self.assertRaises(ValueError):
                validate_authority(authority)
        authority = sample(); authority["allowedPaths"] = ["SRC/a.py", "src/a.py"]
        with self.assertRaises(ValueError): validate_authority(authority)
        authority = sample(); authority["allowedPaths"] = ["src/a.py"]; authority["deniedPaths"] = ["SRC"]
        with self.assertRaises(ValueError): validate_authority(authority)

    def test_rejects_noncanonical_worktree_and_bad_review_policy(self):
        for bad in ("relative/work", "C:\\work\\one", "c:/work/one", "C:/work/../one"):
            authority = sample(); authority["worktreePath"] = bad
            with self.subTest(path=bad), self.assertRaises(ValueError): validate_authority(authority)
        authority = sample(); authority["reviewPolicy"]["authorMayReview"] = True
        with self.assertRaises(ValueError): validate_authority(authority)

    def test_trust_record_requires_domain_generation_and_explicit_overlap(self):
        current = dummy_key("k1", 90, 150, 180, b"a")
        nxt = dummy_key("k2", 160, None, 300, b"b")
        trust = PinnedAuthorityTrust(2, (current, nxt), "k1", "k2", minimum_generation=2)
        self.assertEqual(trust.current_key_id, "k1")
        with self.assertRaises(PermissionError):
            PinnedAuthorityTrust(1, (current,), "k1", minimum_generation=2)
        with self.assertRaises(ValueError):
            PinnedAuthorityTrust(2, (current, dummy_key("k2", 181, None, 300, b"b")), "k1", "k2")
        with self.assertRaises(ValueError):
            PinnedAuthorityTrust(2, (current,), "k1", authority_version=2)

    def test_trust_roundtrip_is_durable_and_stale_floor_fails(self):
        trust = PinnedAuthorityTrust(2, (dummy_key("k1", 1, None, 100, b"a"),), "k1", minimum_generation=2)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trust.json"
            write_pinned_trust(path, trust)
            loaded = load_pinned_trust(path, minimum_generation=2)
            self.assertEqual(loaded.to_record(), trust.to_record())
            with self.assertRaises(PermissionError):
                load_pinned_trust(path, minimum_generation=3)


@unittest.skipIf(Ed25519PrivateKey is None, "cryptography unavailable")
class AuthorityCryptoTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_b64 = base64.b64encode(public).decode()
        key = AuthorityKey("k1", self.public_b64, 90.0, 150.0, 180.0)
        self.trust = PinnedAuthorityTrust(2, (key,), "k1", minimum_generation=2)

    def packet(self, authority):
        return {"authority": authority, "signature": "ed25519:" + base64.b64encode(self.private.sign(canonical(authority))).decode()}

    def test_valid_tamper_legacy_and_time_boundaries(self):
        authority = sample(); verifier = ControllerAuthorityVerifier(self.trust)
        self.assertEqual(verifier.verify(self.packet(authority), 110)["attempt"], 1)
        packet = self.packet(authority); packet["authority"] = dict(authority, attempt=2)
        with self.assertRaises(PermissionError): verifier.verify(packet, 110)
        packet = self.packet(authority); packet["signature"] = "hmac-sha256:" + "0" * 64
        with self.assertRaises(PermissionError): verifier.verify(packet, 110)
        with self.assertRaises(PermissionError): verifier.verify(self.packet(authority), 80)
        with self.assertRaises(PermissionError): verifier.verify(self.packet(authority), 181)

    def test_signer_rejects_nested_mutation_and_preserves_input(self):
        authority = sample()
        def nested(request):
            request["authority"]["runtime"]["model"] = "evil-model"
            return {"authority": request["authority"], "signature": "ed25519:x"}
        with self.assertRaises(PermissionError):
            ControllerAuthoritySignerClient(nested, "controller-1").sign_worker_launch(authority)
        self.assertEqual(authority["runtime"]["model"], "gpt-5.6-luna")

    def test_signer_request_binds_controller_identity(self):
        seen = {}
        def transport(request):
            seen.update(request); authority = request["authority"]
            return {"authority": authority, "signature": "ed25519:" + base64.b64encode(self.private.sign(canonical(authority))).decode()}
        ControllerAuthoritySignerClient(transport, "controller-1").sign_worker_launch(sample())
        self.assertEqual(seen["type"], "sign-worker-launch")
        self.assertEqual(seen["controllerIdentity"], "controller-1")


if __name__ == "__main__":
    unittest.main()
