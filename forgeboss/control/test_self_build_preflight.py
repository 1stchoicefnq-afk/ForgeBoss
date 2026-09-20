from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeboss.control.self_build_preflight import concise_blockers, self_build_preflight, self_build_session_plan
from forgeboss.control.self_build_session_evidence import evaluate_p0_session


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

    def test_session_plan_reserves_full_two_dollar_cap_per_cycle(self):
        one=self_build_session_plan(3.0);self.assertEqual(one["cycle_target"],1);self.assertEqual(one["reserved_cap_usd"],"2.00");self.assertEqual(one["unreserved_usd"],"1.00")
        three=self_build_session_plan(6.0);self.assertEqual(three["cycle_target"],3);self.assertEqual(three["reserved_cap_usd"],"6.00");self.assertEqual(three["unreserved_usd"],"0.00")
        capped=self_build_session_plan(99.0);self.assertEqual(capped["cycle_target"],3)
        with self.assertRaises(ValueError):self_build_session_plan(1.99)
        with self.assertRaises(ValueError):self_build_session_plan(float("nan"))

    def _p0_evidence(self):
        runs=[];base="a"*40
        for i,succ in enumerate(("b"*40,"c"*40,"d"*40),1):
            runs.append({
                "cycle_index":i,"run_id":f"fl1-c{i}","base_revision":base,"successor_sha":succ,
                "phase":"SUCCESSOR_ACTIVATED","error":None,
                "activation":{"status":"ACTIVATED_KNOWN_GOOD","successor_sha":succ,"generation":i+1,
                              "probe_evidence_sha256":str(i)*64,"health_evidence_sha256":str(i+3)*64},
            });base=succ
        proof={"status":"ROLLBACK_PROVEN","run_id":"fl1-c1","known_good_revision":"b"*40,
               "pointer_revision":"b"*40,"final_phase":"ROLLED_BACK","candidate_process_dead":True,
               "workspace_cleaned":True,"broken_candidate_sha":"e"*40,"evidence_digest":"f"*64}
        return {"schema":1,"session_id":"fl1s-proof","proof_mode":True,"cycle_target":3,"completed_cycles":3,
                "session_budget_usd":"6.00","reserved_cap_usd":"6.00","stop_requested":False,"error":None,
                "runs":runs,"rollback_proof":proof,
                "final_known_good":{"phase":"READY","generation":5,"revision":"d"*40,
                                    "manifest_sha256":"a"*64,"identity_sha256":"b"*64}}

    def test_p0_session_evaluator_requires_exact_three_cycle_lineage_and_rollback(self):
        evidence=self._p0_evidence();out=evaluate_p0_session(evidence)
        self.assertEqual(out["status"],"PASS");self.assertEqual(out["cycle_count"],3)
        self.assertEqual(out["accepted_revisions"],["b"*40,"c"*40,"d"*40]);self.assertEqual(len(out["evidence_digest"]),64)

    def test_p0_session_evaluator_fails_closed_on_lineage_stop_budget_or_rollback_gaps(self):
        cases=[]
        x=self._p0_evidence();x["runs"][1]["base_revision"]="9"*40;cases.append(("cycle-2-lineage",x))
        x=self._p0_evidence();x["stop_requested"]=True;cases.append(("stop-gate",x))
        x=self._p0_evidence();x["reserved_cap_usd"]="4.00";cases.append(("budget-reservation",x))
        x=self._p0_evidence();x["rollback_proof"]["candidate_process_dead"]=False;cases.append(("rollback-process",x))
        x=self._p0_evidence();x["final_known_good"]["revision"]="9"*40;cases.append(("final-revision",x))
        for expected,evidence in cases:
            with self.subTest(expected=expected):
                out=evaluate_p0_session(evidence);self.assertEqual(out["status"],"FAIL")
                self.assertIn(expected,{b["name"] for b in out["blockers"]})

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
