from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify_package import PackageVerificationError, verify_package


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Stage1PackageVerifierTests(unittest.TestCase):
    def make_pack(self, files: dict[str, bytes]) -> Path:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        baseline = {
            "TURN-ON-FORGEBOSS.cmd": b'@echo off\r\nset "ROOT=%~dp0"\r\nif "%ROOT:~-1%"=="\\" set "ROOT=%ROOT:~0,-1%"\r\n',
            "VERIFY-FORGEBOSS.cmd": b'@echo off\r\nset "ROOT=%~dp0"\r\nif "%ROOT:~-1%"=="\\" set "ROOT=%ROOT:~0,-1%"\r\n',
            "Start-ForgeBoss.ps1": b"$authorityHost='x'\n",
            "Authority/Prepare-MachineAuthorityRoot.ps1": b"param([string]$Root,[string]$PackageManifest)\n# PROTECTED_ROOT_IDENTITY_MISMATCH\n",
        }
        baseline.update(files)
        files = baseline
        for rel, data in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        manifest = {
            "schema": 1,
            "files": {
                rel: {"sha256": sha(root / rel), "sizeBytes": len(data)}
                for rel, data in sorted(files.items())
            },
        }
        (root / "PACKAGE-MANIFEST.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        return root

    def test_clean_pack_passes(self):
        root = self.make_pack({
            "README.txt": b"ok\n",
            "Tools/x.py": b"import os\nprint(os.name)\n",
        })
        out = verify_package(root)
        self.assertTrue(out["ok"])
        self.assertGreaterEqual(out["filesVerified"], 5)

    def test_every_manifest_file_hash_is_enforced(self):
        root = self.make_pack({
            "a.txt": b"a",
            "b.txt": b"b",
            "Tools/x.py": b"pass\n",
        })
        for rel in ("a.txt", "b.txt", "Tools/x.py"):
            original = (root / rel).read_bytes()
            (root / rel).write_bytes(original + b"X")
            with self.subTest(rel=rel), self.assertRaises(PackageVerificationError) as cm:
                verify_package(root)
            self.assertIn("PACKAGE_HASH_MISMATCH", str(cm.exception))
            (root / rel).write_bytes(original)

    def test_extra_file_is_rejected(self):
        root = self.make_pack({"a.txt": b"a"})
        (root / "unexpected.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertIn("PACKAGE_FILESET_MISMATCH", str(cm.exception))

    def test_missing_file_is_rejected(self):
        root = self.make_pack({"a.txt": b"a"})
        (root / "a.txt").unlink()
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertIn("PACKAGE_FILESET_MISMATCH", str(cm.exception))

    def test_static_package_verification_claim_is_rejected(self):
        root = self.make_pack({"a.txt": b"a"})
        (root / "PACKAGE-VERIFICATION.json").write_text('{"ok":true}', encoding="utf-8")
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertEqual(str(cm.exception), "STATIC_VERIFICATION_FILE_DENIED")

    def test_os_mkdir_monkeypatch_detected_under_renamed_alias(self):
        root = self.make_pack({
            "Tools/x.py": b"import os as banana\nbanana.mkdir = lambda *a, **k: None\n"
        })
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertIn("PROCESSWIDE_MONKEYPATCH_DENIED", str(cm.exception))
        self.assertIn("os.mkdir", str(cm.exception))

    def test_subprocess_popen_monkeypatch_detected_under_renamed_alias(self):
        root = self.make_pack({
            "UI/x.py": b"import subprocess as forge\nforge.Popen = object\n"
        })
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertIn("PROCESSWIDE_MONKEYPATCH_DENIED", str(cm.exception))
        self.assertIn("subprocess.Popen", str(cm.exception))

    def test_setattr_monkeypatch_detected(self):
        root = self.make_pack({
            "UI/x.py": b"import subprocess as s\nsetattr(s, 'Popen', object)\n"
        })
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertIn("PROCESSWIDE_MONKEYPATCH_DENIED", str(cm.exception))

    def test_indirect_subprocess_module_alias_monkeypatch_detected(self):
        root = self.make_pack({
            "UI/x.py": b"import subprocess\n_m=subprocess\n_n=_m\n_n.Popen=object\n"
        })
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertIn("PROCESSWIDE_MONKEYPATCH_DENIED", str(cm.exception))
        self.assertIn("subprocess.Popen", str(cm.exception))

    def test_indirect_os_module_alias_setattr_detected(self):
        root = self.make_pack({
            "UI/x.py": b"import os\n_m=os\nsetattr(_m, 'mkdir', object)\n"
        })
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertIn("PROCESSWIDE_MONKEYPATCH_DENIED", str(cm.exception))
        self.assertIn("os.mkdir", str(cm.exception))

    def test_reserved_powershell_host_assignment_rejected(self):
        root = self.make_pack({"Start-ForgeBoss.ps1": b"$host='bad'\n"})
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertEqual(str(cm.exception), "POWERSHELL_RESERVED_HOST_ASSIGNMENT")

    def test_hardcoded_authority_root_version_rejected(self):
        root = self.make_pack({
            "Authority/Prepare-MachineAuthorityRoot.ps1":
                b"$Expected='C:\\\\ForgeBossAuthorityStage1-v27'\n"
        })
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertIn("HARDCODED_AUTHORITY_ROOT_VERSION", str(cm.exception))

    def test_cmd_trailing_root_normalization_required(self):
        root = self.make_pack({"VERIFY-FORGEBOSS.cmd": b"@echo off\r\nset \"ROOT=%~dp0\"\r\n"})
        with self.assertRaises(PackageVerificationError) as cm:
            verify_package(root)
        self.assertIn("CMD_ROOT_NORMALIZATION_MISSING", str(cm.exception))

    def test_symbol_name_alone_does_not_fail(self):
        root = self.make_pack({
            "UI/x.py": b"def _stage1_finish_line_one_plan():\n    return 1\n"
        })
        out = verify_package(root)
        self.assertTrue(out["ok"])


    def test_computed_setattr_name_is_detected(self):
        root=self.make_pack({"Tools/x.py":b"import subprocess\nsetattr(subprocess,'Po'+'pen',object)\n"})
        with self.assertRaises(PackageVerificationError) as cm:verify_package(root)
        self.assertIn("PROCESSWIDE_MONKEYPATCH_DENIED",str(cm.exception))

    def test_importlib_module_monkeypatch_is_detected(self):
        root=self.make_pack({"Tools/x.py":b"import importlib\nimportlib.import_module('subprocess').Popen=object\n"})
        with self.assertRaises(PackageVerificationError) as cm:verify_package(root)
        self.assertIn("PROCESSWIDE_MONKEYPATCH_DENIED",str(cm.exception))

    def test_vars_module_monkeypatch_is_detected(self):
        root=self.make_pack({"Tools/x.py":b"import subprocess\nvars(subprocess)['Popen']=object\n"})
        with self.assertRaises(PackageVerificationError) as cm:verify_package(root)
        self.assertIn("PROCESSWIDE_MONKEYPATCH_DENIED",str(cm.exception))

    def test_subprocess_run_monkeypatch_is_detected(self):
        root=self.make_pack({"Tools/x.py":b"import subprocess\nsubprocess.run=object\n"})
        with self.assertRaises(PackageVerificationError) as cm:verify_package(root)
        self.assertIn("subprocess.run",str(cm.exception))

    def test_builtins_open_monkeypatch_is_detected(self):
        root=self.make_pack({"Tools/x.py":b"import builtins\nbuiltins.open=object\n"})
        with self.assertRaises(PackageVerificationError) as cm:verify_package(root)
        self.assertIn("builtins.open",str(cm.exception))

    def test_dynamic_setattr_fails_closed(self):
        root=self.make_pack({"Tools/x.py":b"import subprocess\nname='Popen'\nsetattr(subprocess,name,object)\n"})
        with self.assertRaises(PackageVerificationError) as cm:verify_package(root)
        self.assertIn("DYNAMIC_PROCESSWIDE_MONKEYPATCH_DENIED",str(cm.exception))

    def test_powershell_automatic_variables_are_case_insensitive(self):
        for name in ("host","args","input","error","psitem","true","false","null","pwd","pid","home"):
            with self.subTest(name=name):
                root=self.make_pack({"Extra.ps1":("$"+name.upper()+" = 'bad'\n").encode()})
                with self.assertRaises(PackageVerificationError) as cm:verify_package(root)
                self.assertIn("POWERSHELL_AUTOMATIC_VARIABLE_ASSIGNMENT",str(cm.exception))

if __name__ == "__main__":
    unittest.main()
