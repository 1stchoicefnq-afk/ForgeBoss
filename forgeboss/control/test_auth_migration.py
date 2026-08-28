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

    def test_dedicated_client_credential_is_separate_from_legacy_launch_secret(self):
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
            self.assertNotEqual(derive_client_auth_key(client_secret), daemon_secret)

    def test_unchanged_daemon_call_signature_uses_dedicated_credential(self):
        client_secret = b"c" * 32
        params = self.params()
        params["authProof"] = make_connect_proof(params, client_secret)
        with patch("forgeboss.control.auth.client_auth_file", return_value=(Path("client-auth-secret.bin"), client_secret)):
            self.assertTrue(verify_connect_proof(params, b"legacy-daemon-secret" * 2, now=100))
        self.assertTrue(params["authProof"].startswith(CLIENT_AUTH_PREFIX))

    def test_launch_secret_cannot_authenticate_client_session(self):
        params = self.params()
        params["authProof"] = make_connect_proof(params, b"l" * 32)
        with patch("forgeboss.control.auth.client_auth_file", return_value=(Path("client-auth-secret.bin"), b"c" * 32)):
            with self.assertRaises(PermissionError):
                verify_connect_proof(params, b"l" * 32, now=100)

    def test_old_connect_prefix_nonce_alias_and_duplicate_caps_rejected(self):
        params = self.params(); params["authProof"] = "hmac-sha256:" + "0" * 64
        with patch("forgeboss.control.auth.client_auth_file", return_value=(Path("client-auth-secret.bin"), b"c" * 32)):
            with self.assertRaises(PermissionError): verify_connect_proof(params, None, now=100)
        params = self.params(); params["nonce"] = "A" * 32
        with self.assertRaises(PermissionError): make_connect_proof(params, b"c" * 32)
        params = self.params(); params["capabilities"] = ["tasks", "TASKS"]
        with self.assertRaises(ValueError): make_connect_proof(params, b"c" * 32)


if __name__ == "__main__":
    unittest.main()
