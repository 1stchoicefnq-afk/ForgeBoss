from __future__ import annotations
import ast,unittest
from pathlib import Path
TEMPLATE=Path(__file__).resolve().parent/"v28-template"
def text(rel):return (TEMPLATE/rel).read_text(encoding="utf-8-sig")
class V28TemplateSecurityTests(unittest.TestCase):
    def test_host_variable(self):
        s=text("Start-ForgeBoss.ps1");self.assertIn("$authorityHost=",s);self.assertNotIn("$host=",s.lower())
    def test_acl_identity_bound(self):
        s=text("Authority/Prepare-MachineAuthorityRoot.ps1");self.assertIn("PackageManifest",s);self.assertIn("PROTECTED_ROOT_IDENTITY_MISMATCH",s);self.assertIn("PROTECTED_ROOT_SYSTEM_DIRECTORY_DENIED",s)
    def test_acl_validate_only_and_exact_compare(self):
        s=text("Authority/Prepare-MachineAuthorityRoot.ps1")
        self.assertIn("[switch]$ValidateOnly",s)
        self.assertIn(".Equals($expected,[StringComparison]::OrdinalIgnoreCase)",s)
        self.assertIn("PROTECTED_ROOT_SYSTEM_DIRECTORY_DENIED",s)
        self.assertLess(s.index("PROTECTED_ROOT_IDENTITY_MISMATCH"),s.index("/setowner"))
        self.assertLess(s.index("PROTECTED_ROOT_SYSTEM_DIRECTORY_DENIED"),s.index("/setowner"))

    def test_installed_state_rebinds_engine_env_before_gate(self):
        for rel in ("Install-Stage1.ps1","Start-ForgeBoss.ps1","Verify-Stage1.ps1"):
            with self.subTest(rel=rel):
                s=text(rel)
                self.assertIn("FORGEBOSS_ENGINE_ROOT",s)
                self.assertLess(s.index("FORGEBOSS_ENGINE_ROOT"),s.index("stage1_gate.py"))

    def test_authority_host_matches_current_engine_service_contract(self):
        repo=TEMPLATE.parents[2]
        service_ast=ast.parse((repo/"forgeboss/protected_authority/service.py").read_text(encoding="utf-8"))
        fn=next(n for n in service_ast.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="create_production_service")
        params=[a.arg for a in fn.args.kwonlyargs]
        required={a.arg for a,d in zip(fn.args.kwonlyargs,fn.args.kw_defaults) if d is None}
        host_ast=ast.parse(text("Authority/authority_user_host.py"))
        call=next(n for n in ast.walk(host_ast) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="create_production_service")
        supplied={k.arg for k in call.keywords if k.arg}
        self.assertTrue(required.issubset(supplied))
        self.assertTrue(supplied.issubset(set(params)))
        self.assertFalse(any(p.startswith("stage1_") for p in params))
        protocol=(repo/"forgeboss/protected_authority/protocol.py").read_text(encoding="utf-8")
        self.assertIn("self_build_current_known_good",protocol)
        self.assertNotIn("issue_stage1_",protocol)

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
