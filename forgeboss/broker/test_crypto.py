from __future__ import annotations
import inspect,unittest
from unittest import mock
from forgeboss.broker import crypto
class CryptoAuthorityTests(unittest.TestCase):
    def base(self):return {"envelopeSha256":"e"*64,"taskId":"t","runId":"r","ownerEpoch":7,"baseSha":"a"*40,"worktreePath":r"C:\repo","budgetUsd":0.25,"expiresAt":9999999999.0,"allowedPaths":["x.py"],"runtime":{"adapter":"mini-swe","provider":"openai","model":"openai/gpt-test"},"resultRef":"refs/forgeboss/results/a/b"}
    def test_protected_authority_binds_worktree_runtime_ref_and_all_launch_fields(self):
        req=self.base();signed={**req,"attestationId":"att-1","protected":True};env={"signedAuthority":signed,"authoritySignature":"unused"}
        with mock.patch.object(crypto,"_verify_attestation",return_value=signed):got=crypto.ProtectedAuthorityVerifier(exchange=lambda q:env,public_key=b"k"*32).verify(req)
        self.assertEqual(got.worktree_path,req["worktreePath"]);self.assertEqual(got.base_sha,req["baseSha"]);self.assertEqual(got.allowed_paths,("x.py",));self.assertEqual(got.runtime,req["runtime"]);self.assertEqual(got.result_ref,req["resultRef"])
    def test_protected_authority_rejects_any_signed_binding_mismatch(self):
        for field,value in (("worktreePath",r"C:\other"),("resultRef","refs/evil"),("runtime",{"adapter":"mini-swe","model":"other"})):
            req=self.base();signed={**req,field:value,"attestationId":"att-1","protected":True}
            with self.subTest(field=field),mock.patch.object(crypto,"_verify_attestation",return_value=signed),self.assertRaisesRegex(crypto.BrokerCryptoError,field):crypto.ProtectedAuthorityVerifier(exchange=lambda q:{},public_key=b"k"*32).verify(req)
    def test_legacy_or_unprotected_attestation_fails_closed(self):
        req=self.base();signed={**req,"attestationId":"att-1","protected":False}
        with mock.patch.object(crypto,"_verify_attestation",return_value=signed),self.assertRaisesRegex(crypto.BrokerCryptoError,"prerequisite"):crypto.ProtectedAuthorityVerifier(exchange=lambda q:{},public_key=b"k"*32).verify(req)
    def test_production_trust_has_no_env_or_path_override(self):
        src=inspect.getsource(crypto);self.assertNotIn("os.environ",src);self.assertNotIn("shutil.which",src);self.assertIn("HKEY_LOCAL_MACHINE",src);self.assertIn("ControllerEd25519PublicKeyBase64",src);self.assertIn("ForgeBossControllerAuthority.v1",src)
    def test_linux_service_gid_comes_only_from_fixed_root_owned_trust(self):
        src=inspect.getsource(crypto.load_service_gid);self.assertIn("LINUX_BROKER_TRUST",src);self.assertNotIn("environ",src)
    def test_receipt_signer_requires_ed25519_private_material(self):
        with self.assertRaises(crypto.BrokerCryptoError):crypto.ReceiptSigner(private_key=b"short").sign({"schema":3})
if __name__=="__main__":unittest.main()
