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
