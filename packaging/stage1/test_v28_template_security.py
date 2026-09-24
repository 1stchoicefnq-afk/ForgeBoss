from __future__ import annotations
import unittest
from pathlib import Path
TEMPLATE=Path(__file__).resolve().parent/"v28-template"
def text(rel):return (TEMPLATE/rel).read_text(encoding="utf-8-sig")
class V28TemplateSecurityTests(unittest.TestCase):
    def test_host_variable(self):
        s=text("Start-ForgeBoss.ps1");self.assertIn("$authorityHost=",s);self.assertNotIn("$host=",s.lower())
    def test_acl_identity_bound(self):
        s=text("Authority/Prepare-MachineAuthorityRoot.ps1");self.assertIn("PackageManifest",s);self.assertIn("PROTECTED_ROOT_IDENTITY_MISMATCH",s);self.assertIn("PROTECTED_ROOT_SYSTEM_DIRECTORY_DENIED",s)
    def test_wheel_only(self):
        self.assertIn("--only-binary :all:",text("Install-Stage1.ps1"));self.assertIn("--only-binary :all:",text("README-FIRST.txt"))
    def test_exact_blob_readback(self):
        s=text("Install-Stage1.ps1");self.assertIn("hash-object --no-filters",s);self.assertIn("ENGINE_BLOB_BYTES_MISMATCH",s)
    def test_engine_proofs(self):
        self.assertIn("prove_budget_policy.py",text("Verify-Stage1.ps1"));self.assertIn("mini_swe_runner._hidden_run",text("Tools/prove_no_console.py"))
    def test_exact_signer_names(self):
        s=text("Tools/Resolve-Tools.ps1");self.assertIn("GetNameInfo",s);self.assertIn("Python Software Foundation",s);self.assertIn("Docker Inc",s);self.assertNotIn("-notmatch '(?i)Docker'",s)
    def test_api_presence_not_validity(self):
        s=text("Verify-Stage1.ps1");self.assertNotIn("[PASS] OpenAI API credential present",s);self.assertIn("does not claim provider validity",s)
if __name__=="__main__":unittest.main()
