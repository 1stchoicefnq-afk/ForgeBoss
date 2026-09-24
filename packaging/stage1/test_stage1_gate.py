from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packaging.stage1.stage1_gate import Stage1GateError, installed_engine, verify_engine


class CP:
    def __init__(self, out="", rc=0, err=""):
        self.stdout=out;self.returncode=rc;self.stderr=err


class Stage1GateTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.addCleanup(self.td.cleanup)
        self.root=Path(self.td.name)/"engine";self.root.mkdir()
        self.state=Path(self.td.name)/"stage1-installed.json"
        self.sha="a"*40
        self.state.write_text(json.dumps({"engineRoot":str(self.root),"engineSha":self.sha}),encoding="utf-8")

    def test_env_cannot_override_installed_engine(self):
        other=Path(self.td.name)/"other";other.mkdir()
        with self.assertRaises(Stage1GateError) as cm:
            installed_engine(self.state,{"FORGEBOSS_ENGINE_ROOT":str(other)})
        self.assertEqual(str(cm.exception),"ENGINE_ROOT_ENV_MISMATCH")

    def test_same_env_root_is_allowed(self):
        root,sha=installed_engine(self.state,{"FORGEBOSS_ENGINE_ROOT":str(self.root)})
        self.assertEqual(root,self.root.resolve());self.assertEqual(sha,self.sha)

    def test_verify_uses_resolved_absolute_git_and_is_read_only(self):
        git=Path(self.td.name)/"trusted"/"git.exe";git.parent.mkdir();git.write_bytes(b"git")
        before={p.relative_to(self.root).as_posix():p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        calls=[]
        def run(argv,**kw):
            calls.append(list(argv))
            args=argv[3:]
            if args[:2]==["rev-parse","--verify"]:return CP(self.sha+"\n")
            if args and args[0]=="status":return CP("")
            if args[:2]==["rev-parse","--show-toplevel"]:return CP(str(self.root.resolve())+"\n")
            raise AssertionError(argv)
        with patch("packaging.stage1.stage1_gate._resolve_git_executable",return_value=git.resolve()), \
             patch("packaging.stage1.stage1_gate.subprocess.run",side_effect=run):
            out=verify_engine(self.state,{})
        self.assertTrue(out["ok"]);self.assertTrue(out["readOnly"])
        self.assertTrue(all(row[0]==str(git.resolve()) for row in calls))
        after={p.relative_to(self.root).as_posix():p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before,after)

    def test_sha_mismatch_fails(self):
        git=Path(self.td.name)/"git.exe";git.write_bytes(b"git")
        def run(argv,**kw):
            return CP("b"*40+"\n")
        with patch("packaging.stage1.stage1_gate._resolve_git_executable",return_value=git.resolve()), \
             patch("packaging.stage1.stage1_gate.subprocess.run",side_effect=run):
            with self.assertRaises(Stage1GateError) as cm:
                verify_engine(self.state,{})
        self.assertEqual(str(cm.exception),"ENGINE_SHA_MISMATCH")


if __name__=="__main__":
    unittest.main()
