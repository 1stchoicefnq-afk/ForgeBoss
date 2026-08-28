from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from forgeboss.control.auth import (
    CLIENT_AUTH_PREFIX,
    client_auth_file,
    derive_client_auth_key,
    make_connect_proof,
    verify_connect_proof,
)
from forgeboss.control.envelope import secret_file


class ClientAuthMigrationTests(unittest.TestCase):
    def params(self):
        return {
            "protocolVersion": 1,
            "client": "forgeboss-cli",
            "capabilities": ["tasks", "leases"],
            "timestamp": 100,
            "nonce": "a" * 32,
        }

    def test_phase_a_same_source_secret_connects_with_separate_domain(self):
        source = b"s" * 32
        params = self.params()
        proof = make_connect_proof(params, source)
        self.assertTrue(proof.startswith(CLIENT_AUTH_PREFIX))
        self.assertNotEqual(derive_client_auth_key(source), source)
        params["authProof"] = proof
        self.assertTrue(verify_connect_proof(params, source, now=100))

    def test_wrong_or_legacy_proof_rejected(self):
        params = self.params()
        params["authProof"] = make_connect_proof(params, b"a" * 32)
        with self.assertRaises(PermissionError):
            verify_connect_proof(params, b"b" * 32, now=100)
        params = self.params()
        params["authProof"] = "hmac-sha256:" + "0" * 64
        with self.assertRaises(PermissionError):
            verify_connect_proof(params, b"a" * 32, now=100)

    def test_nonce_and_capabilities_are_strict(self):
        params = self.params()
        params["nonce"] = "A" * 32
        with self.assertRaises(PermissionError):
            make_connect_proof(params, b"a" * 32)
        params = self.params()
        params["capabilities"] = ["tasks", "TASKS"]
        with self.assertRaises(ValueError):
            make_connect_proof(params, b"a" * 32)

    def test_future_dedicated_client_credential_is_separate_storage(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch("forgeboss.control.auth.harden_private_dir"), patch(
                "forgeboss.control.auth.harden_private_path"
            ), patch("forgeboss.control.envelope.harden_private_dir"), patch(
                "forgeboss.control.envelope.harden_private_path"
            ):
                daemon_path, daemon_secret = secret_file(root)
                client_path, client_secret = client_auth_file(root)
            self.assertNotEqual(daemon_path, client_path)
            self.assertNotEqual(daemon_secret, client_secret)


if __name__ == "__main__":
    unittest.main()
