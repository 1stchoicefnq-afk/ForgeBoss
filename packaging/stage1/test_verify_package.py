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
            "TURN-ON-FORGEBOSS.cmd": b"@echo off\r\n",
            "Tools/x.py": b"import os\nprint(os.name)\n",
        })
        out = verify_package(root)
        self.assertTrue(out["ok"])
        self.assertEqual(out["filesVerified"], 2)

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

    def test_symbol_name_alone_does_not_fail(self):
        root = self.make_pack({
            "UI/x.py": b"def _stage1_finish_line_one_plan():\n    return 1\n"
        })
        out = verify_package(root)
        self.assertTrue(out["ok"])


if __name__ == "__main__":
    unittest.main()
