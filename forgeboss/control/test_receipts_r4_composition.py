from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from forgeboss.control.receipts import CandidateHandoff, ReceiptError, policy_path_key, POLICY_PATH_KEY_VERSION
from forgeboss.control.run_budget import GlobalRunBudget, RunBudgetError, STATE_PAID_STARTED
from forgeboss.control.store import ControlStore

A40 = "a" * 40
B40 = "b" * 40
C40 = "c" * 40
AUTH_KEY = b"receipts-r4-run-budget-auth-key-32b"


def _task():
    return {
        "taskId": "task-r4",
        "repository": "owner/repo",
        "purpose": "receipts-r4",
        "baseSha": A40,
        "branch": "fb/task-r4",
        "allowedPaths": ["src/a.py"],
        "requiredTests": ["receipts"],
        "budgetUsd": "5",
    }


def _path(path="src/a.py"):
    return {"gitPath": path, "policyPathKey": policy_path_key(path), "policyVersion": POLICY_PATH_KEY_VERSION}


def _handoff(packet):
    return {
        "assignment": packet,
        "candidateSha": B40,
        "candidateTreeSha": C40,
        "changedPaths": [_path()],
        "requiredTestReceipts": ["2" * 64],
        "scopeDiffSha256": "3" * 64,
        "additions": 1,
        "deletions": 0,
        "measuredCostUsd": "1.25",
        "reservedCostUsd": "1",
        "contributors": ["worker-a"],
        "knownUncertainty": [],
    }


class ReceiptsR4CompositionTests(unittest.TestCase):
    def _live_store(self, root: Path):
        db = root / "state.db"
        st = ControlStore(db)
        st.create_budget_run("budget-r4", "20")
        st.create_task(_task())
        assignment = st.assign_builder("task-r4", "worker-a", "budget-r4")
        worktrees = root / "worktrees"
        worktrees.mkdir(exist_ok=True)
        wt = worktrees / "task-r4"
        wt.mkdir(exist_ok=True)
        lease = st.claim_workspace(
            "task-r4",
            "run-r4",
            wt,
            "fb/task-r4",
            A40,
            worktree_root=worktrees,
            budget_reserved="1",
            builder_id="worker-a",
            assignment_token=assignment["assignmentToken"],
            assignment_generation=assignment["assignmentGeneration"],
            assignment_sha256=assignment["assignmentSha256"],
            budget_run_revision=assignment["budgetRunRevision"],
        )
        return st, db, assignment, lease

    def test_exact_store_identity_survives_restart_while_writer_is_live(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            st, db, _, lease = self._live_store(root)
            packet = st.assignment_identity("task-r4", "run-r4", lease["owner_epoch"])
            h1 = CandidateHandoff.from_dict(_handoff(packet), store=st)
            st.db.close()

            st2 = ControlStore(db)
            try:
                packet2 = st2.assignment_identity("task-r4", "run-r4", lease["owner_epoch"])
                self.assertEqual(packet2, packet)
                h2 = CandidateHandoff.from_dict(_handoff(packet), store=st2)
                self.assertEqual(h2.assignment.identity_sha256, h1.assignment.identity_sha256)
            finally:
                st2.db.close()

    def test_stale_assignment_identity_is_denied_after_release_and_restart(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            st, db, _, lease = self._live_store(root)
            packet = st.assignment_identity("task-r4", "run-r4", lease["owner_epoch"])
            st.release("task-r4", "run-r4", lease["owner_epoch"], A40)
            with self.assertRaises(Exception):
                CandidateHandoff.from_dict(_handoff(packet), store=st)
            st.db.close()

            st2 = ControlStore(db)
            try:
                with self.assertRaises(Exception):
                    CandidateHandoff.from_dict(_handoff(packet), store=st2)
            finally:
                st2.db.close()

    def test_self_hashed_caller_substitution_cannot_replace_store_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            st, _, _, lease = self._live_store(root)
            try:
                packet = st.assignment_identity("task-r4", "run-r4", lease["owner_epoch"])
                forged = copy.deepcopy(packet)
                forged["identity"]["builderPrincipal"] = "attacker"
                import hashlib, json
                forged["assignmentIdentitySha256"] = hashlib.sha256(
                    json.dumps(forged["identity"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                ).hexdigest()
                with self.assertRaises(ReceiptError):
                    CandidateHandoff.from_dict(_handoff(forged), store=st)
            finally:
                st.db.close()

    def test_receipts_do_not_refund_paid_run_budget_and_restore_requires_auth(self):
        budget = GlobalRunBudget("5")
        budget.reserve("receipt-work", "1", worker_id="worker-a")
        _, token = budget.start_paid("receipt-work")
        self.assertEqual(budget.get("receipt-work").state, STATE_PAID_STARTED)

        with self.assertRaises(RunBudgetError) as release_error:
            budget.release("receipt-work")
        self.assertEqual(release_error.exception.code, "PAID_WORK_STARTED")

        with self.assertRaises(RunBudgetError) as plain_restore:
            GlobalRunBudget.from_snapshot(budget.snapshot())
        self.assertEqual(plain_restore.exception.code, "SNAPSHOT_AUTH_REQUIRED")

        wrapped = budget.authenticated_snapshot(AUTH_KEY)
        restored = GlobalRunBudget.from_snapshot(wrapped, authentication_key=AUTH_KEY)
        self.assertEqual(restored.get("receipt-work").state, STATE_PAID_STARTED)
        with self.assertRaises(RunBudgetError) as wrong_token:
            restored.settle("receipt-work", ".75", authority_token="wrong")
        self.assertEqual(wrong_token.exception.code, "AUTHORITY_TOKEN_INVALID")
        restored.settle("receipt-work", ".75", authority_token=token)
        self.assertEqual(str(restored.committed), "0.75")

class SuccessorCompositionTests(unittest.TestCase):
    def _g(self,root,*args,binary=False):
        import subprocess
        p=subprocess.run([str(self.git),"-C",str(root),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=not binary,check=False)
        self.assertEqual(p.returncode,0,msg=(p.stderr if not binary else p.stderr.decode("utf-8","replace")))
        return p.stdout if binary else p.stdout.strip()

    def setUp(self):
        import shutil
        git=shutil.which("git")
        if not git:self.skipTest("git required")
        self.git=Path(git).resolve();self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name)
        self.source=self.root/"source";self.workspaces=self.root/"workspaces";self.state=self.root/"state"
        self.source.mkdir();self.workspaces.mkdir();self.state.mkdir();self._g(self.source,"init","-q")
        self._g(self.source,"config","user.email","test@example.invalid");self._g(self.source,"config","user.name","ForgeBoss Test")
        for rel,body in {
            "forgeboss/__init__.py":"","forgeboss/control/__init__.py":"",
            "forgeboss/control/daemon.py":"def main():\n    return None\n",
            "forgeboss/learning/__init__.py":"","forgeboss/security/__init__.py":"",
        }.items():
            p=self.source/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body,encoding="utf-8")
        self._g(self.source,"add",".");self._g(self.source,"commit","-qm","base");self.base=self._g(self.source,"rev-parse","HEAD")

    def tearDown(self):self.td.cleanup()

    def _worker(self,name,rel,body):
        import hashlib,subprocess
        work=self.workspaces/name
        subprocess.run([str(self.git),"clone","-q","--no-local",str(self.source),str(work)],check=True)
        self._g(work,"remote","remove","origin");self._g(work,"checkout","-q","--detach",self.base)
        p=work/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body,encoding="utf-8");self._g(work,"add","--",rel)
        self._g(work,"-c","user.email=test@example.invalid","-c","user.name=Worker","commit","-qm",name)
        candidate=self._g(work,"rev-parse","HEAD");tree=self._g(work,"rev-parse",f"{candidate}^{{tree}}")
        diff=hashlib.sha256(bytes(self._g(work,"diff","--binary",self.base,candidate,"--",binary=True))).hexdigest()
        return work,candidate,tree,diff

    def _item(self,task,builder,work,run,budget,rel,test,epoch=1,replacement_for=None):
        packet={"allowed_files":[rel],"required_tests":[test]}
        if replacement_for:packet["replacement_for"]=replacement_for
        out={"task_id":task,"builder_id":builder,"worktree":str(work.resolve()),"owner_epoch":epoch,"authority":{"run_id":run,"budget_usd":budget},"packet":packet}
        if replacement_for:out["replacement_for"]=replacement_for
        return out

    def _chain(self,item,candidate,tree,diff,rel):
        import hashlib,json
        from forgeboss.control.receipts import receipt_digest
        ident={"taskId":item["task_id"],"runId":item["authority"]["run_id"],"attempt":1,"ownerEpoch":item["owner_epoch"],"builderPrincipal":item["builder_id"],"assignmentGeneration":1,"assignmentPolicySha256":"3"*64,"repository":"1stchoicefnq-afk/forgeboss","baseSha":self.base,"branch":"forgeboss/fl1-fixture","worktreePath":item["worktree"],"workspaceGeneration":1,"workspaceContentIdentity":self.base,"budgetRunId":"fl1-fixture"}
        assignment={"identity":ident,"assignmentIdentitySha256":hashlib.sha256(json.dumps(ident,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()}
        handoff={"assignment":assignment,"candidateSha":candidate,"candidateTreeSha":tree,"changedPaths":[{"gitPath":rel,"policyPathKey":policy_path_key(rel),"policyVersion":POLICY_PATH_KEY_VERSION}],"requiredTestReceipts":["4"*64],"scopeDiffSha256":diff,"additions":4,"deletions":0,"measuredCostUsd":"0.10","reservedCostUsd":item["authority"]["budget_usd"],"contributors":[item["builder_id"]],"knownUncertainty":[]}
        hd=receipt_digest({"type":"candidate-handoff","schemaVersion":3,**handoff})
        review={"assignment":assignment,"handoffSha256":hd,"candidateSha":candidate,"candidateTreeSha":tree,"reviewerId":"reviewer-independent","verdict":"pass","evidenceSha256":"5"*64,"reviewerTestReceipts":["6"*64]}
        rd=receipt_digest({"type":"reviewer-receipt","schemaVersion":3,**review})
        acceptance={"assignment":assignment,"handoffSha256":hd,"reviewSha256":rd,"candidateSha":candidate,"candidateTreeSha":tree,"controllerId":"controller-fixture","accepted":True}
        ad=receipt_digest({"type":"controller-acceptance","schemaVersion":3,**acceptance})
        return ({"taskId":item["task_id"],"handoff":handoff,"handoffDigest":hd},{"taskId":item["task_id"],"review":review,"reviewDigest":rd,"status":"PASS"},{"taskId":item["task_id"],"workerRunId":item["authority"]["run_id"],"ownerEpoch":item["owner_epoch"],"candidateSha":candidate,"candidateTreeSha":tree,"acceptance":acceptance,"acceptanceDigest":ad,"handoffDigest":hd,"reviewDigest":rd,"status":"ACCEPTED"})

    def _fixture(self):
        a_rel="forgeboss/learning/test_fl1_reuse_regression.py";b_rel="forgeboss/security/test_fl1_packet_validation.py"
        aw,ac,at,ad=self._worker("a",a_rel,"import unittest\nclass T(unittest.TestCase):\n    def test_a(self): self.assertTrue(True)\n")
        bw,bc,bt,bd=self._worker("b2",b_rel,"import unittest\nclass T(unittest.TestCase):\n    def test_b(self): self.assertEqual(1,1)\n")
        a=self._item("task-a","builder-a",aw,"run-a","1.00",a_rel,"python -m unittest forgeboss.learning.test_fl1_reuse_regression -v")
        old=self._item("task-b","builder-b",self.workspaces/"unused-b","run-b","0.50",b_rel,"python -m unittest forgeboss.security.test_fl1_packet_validation -v")
        b2=self._item("task-b2","builder-b2",bw,"run-b2","0.50",b_rel,"python -m unittest forgeboss.security.test_fl1_packet_validation -v",2,"task-b")
        ah,ar,aa=self._chain(a,ac,at,ad,a_rel);bh,br,ba=self._chain(b2,bc,bt,bd,b_rel)
        return {"schema":1,"phase":"REPLACEMENT_PREPARED","prepared":{"run_id":"fl1-fixture","base_sha":self.base,"source_root":str(self.source.resolve()),"builders":[a,old]},"replacement":b2,"revocations":[{"taskId":"task-b","workerRunId":"run-b","ownerEpoch":1,"reason":"fixture"}],"handoffs":[ah,bh],"reviews":[ar,br],"accepted":[aa,ba]},a_rel,b_rel

    def _provision(self,source,target,workspace_root,base,branch,git,protected_state=None):
        import subprocess
        subprocess.run([str(git),"clone","-q","--no-local",str(source),str(target)],check=True)
        self._g(target,"remote","remove","origin");self._g(target,"checkout","-q","--detach",base);self._g(target,"branch","-f",branch,base);self._g(target,"checkout","-q",branch)

    def test_successor_composes_only_accepted_a_and_b2_and_verifies_manifest(self):
        from forgeboss.control.self_build_compose import compose_successor
        record,a_rel,b_rel=self._fixture()
        out=compose_successor(record=record,run_id="fl1-fixture",source_root=self.source,workspace_root=self.workspaces,protected_state=object(),git_executable=self.git,manifest_path=self.state/"manifest.json",provision_workspace_fn=self._provision)
        self.assertEqual(set(out["changed_files"]),{a_rel,b_rel});self.assertEqual(self._g(Path(out["workspace"]),"rev-parse",f"{out['successor_sha']}^"),self.base)
        self.assertEqual(self._g(Path(out["workspace"]),"remote"),"");self.assertEqual(len(out["focused_tests"]),2);self.assertTrue(Path(out["manifest_path"]).is_file())

    def test_post_acceptance_handoff_tamper_fails_closed(self):
        from forgeboss.control.self_build_compose import SelfBuildComposeError,compose_successor
        record,_,_=self._fixture();record["handoffs"][0]["handoff"]["knownUncertainty"]=["tampered"]
        with self.assertRaises(SelfBuildComposeError) as cm:compose_successor(record=record,run_id="fl1-fixture",source_root=self.source,workspace_root=self.workspaces,protected_state=object(),git_executable=self.git,manifest_path=self.state/"bad.json",provision_workspace_fn=self._provision)
        self.assertEqual(cm.exception.code,"HANDOFF_DIGEST_MISMATCH")


if __name__ == "__main__":
    unittest.main()
