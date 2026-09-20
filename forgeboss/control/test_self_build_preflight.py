from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeboss.control.self_build_preflight import concise_blockers, self_build_preflight


class SelfBuildPreflightTests(unittest.TestCase):
    def test_missing_source_fails_closed(self):
        out=self_build_preflight("/definitely/not/forgeboss",running_root=Path.cwd(),requested_budget_usd=2,env={})
        self.assertFalse(out["ready"])
        self.assertEqual(out["blockers"][0]["name"],"source-folder")

    def _tree(self,td):
        root=Path(td)/"ForgeBoss";root.mkdir()
        for rel in ("forgeboss/control/activation.py","forgeboss/control/known_good.py","dashboard/pro_shell.py","START-FORGEBOSS.vbs"):
            p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text("x",encoding="utf-8")
        (root/".git").mkdir()
        fake_git=Path(td)/("git.exe" if os.name=="nt" else "git");fake_git.write_text("x")
        return root,fake_git

    def test_preflight_reports_missing_production_authority_without_inventing_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root,fake_git=self._tree(td)
            env={"FORGEBOSS_STATE_ROOT":str(Path(td)/"state")}
            with patch("forgeboss.control.self_build_preflight._resolve_git_executable",return_value=fake_git), \
                 patch("forgeboss.control.self_build_preflight._git_head",return_value="a"*40), \
                 patch("forgeboss.control.self_build_preflight.shutil.which",return_value=None), \
                 patch("forgeboss.control.self_build_preflight.importlib.util.find_spec",return_value=None):
                out=self_build_preflight(root,running_root=root,requested_budget_usd=2,env=env)
            self.assertFalse(out["ready"])
            names={x["name"] for x in out["blockers"]}
            self.assertIn("known-good-manifest",names)
            self.assertIn("docker",names)
            self.assertIn("mini-swe",names)
            self.assertIn("authority-peer-key",names)

    def test_protected_known_good_allows_successor_source_different_from_old_orchestrator_head(self):
        with tempfile.TemporaryDirectory() as td:
            root,fake_git=self._tree(td);manifest=root/"manifest.json";manifest.write_text("{}",encoding="utf-8")
            peer=Path(td)/"peer.key";peer.write_text("x");pin=Path(td)/"pin";pin.write_text("x")
            env={"FORGEBOSS_STATE_ROOT":str(Path(td)/"state"),"OPENAI_API_KEY":"test",
                 "FORGEBOSS_AUTHORITY_PEER_KEY":str(peer),"FORGEBOSS_AUTHORITY_RECEIPT_PUBLIC_KEY":str(pin)}
            authoritative={"code_root":str(root.resolve()),"revision":"b"*40,"manifest_path":str(manifest.resolve()),
                           "manifest_sha256":"c"*64,"identity_sha256":"d"*64}
            identity={"verified":True,"revision":"b"*40,"identitySha256":"d"*64}
            with patch("forgeboss.control.self_build_preflight._resolve_git_executable",return_value=fake_git), \
                 patch("forgeboss.control.self_build_preflight._git_head",side_effect=["b"*40,"a"*40]), \
                 patch("forgeboss.control.self_build_preflight.verify_build_manifest",return_value=identity), \
                 patch("forgeboss.control.self_build_preflight.shutil.which",return_value="/usr/bin/docker"), \
                 patch("forgeboss.control.self_build_preflight.importlib.util.find_spec",return_value=object()):
                out=self_build_preflight(root,running_root=root,requested_budget_usd=2,env=env,authoritative_known_good=authoritative)
            rows={x["name"]:x for x in out["checks"]}
            self.assertTrue(rows["self-target"]["ok"]);self.assertTrue(rows["protected-known-good-root"]["ok"])
            self.assertTrue(rows["known-good-manifest"]["ok"]);self.assertEqual(out["known_good_sha"],"b"*40)

    def test_runtime_state_inside_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root,fake_git=self._tree(td)
            env={"FORGEBOSS_STATE_ROOT":str(root/"state")}
            with patch("forgeboss.control.self_build_preflight._resolve_git_executable",return_value=fake_git), \
                 patch("forgeboss.control.self_build_preflight._git_head",return_value="a"*40), \
                 patch("forgeboss.control.self_build_preflight.shutil.which",return_value=None), \
                 patch("forgeboss.control.self_build_preflight.importlib.util.find_spec",return_value=None):
                out=self_build_preflight(root,running_root=root,requested_budget_usd=2,env=env)
            row=next(x for x in out["checks"] if x["name"]=="external-runtime-state")
            self.assertFalse(row["ok"])

    def test_concise_blockers_is_owner_readable(self):
        text=concise_blockers({"blockers":[{"name":"docker","detail":"missing"},{"name":"authority","detail":"offline"}]})
        self.assertIn("docker: missing",text)
        self.assertIn("authority: offline",text)


if __name__=="__main__":
    unittest.main()
