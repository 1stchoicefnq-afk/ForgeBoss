from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from forgeboss.control.self_build_runtime import SelfBuildRuntime,SelfBuildRuntimeError


class Boundary:
    def __init__(self):self.deny=False;self.service_checks=0;self.path_checks=0
    def assert_service_principal(self,root):
        self.service_checks+=1
        if self.deny:raise RuntimeError("service denied")
        return "fixture-service"
    def assert_protected_path(self,path,*,protected_root=None,secret=False):
        self.path_checks+=1
        if self.deny:raise RuntimeError("path denied")


class Coordinator:
    def __init__(self):self.prepare_calls=[];self.replace_calls=[]
    def prepare_initial_run(self,**kw):
        self.prepare_calls.append(kw)
        return {
            "schema":1,"run_id":kw["run_id"],"base_sha":kw["base_sha"],
            "source_root":str(Path(kw["source_root"]).resolve()),
            "global_budget_cap_usd":"2.00","global_budget_reserved_usd":"1.50",
            "reassignment_headroom_usd":"0.50","builders":[],
            "replacement_plan":{"task_id":"b2"},
        }
    def prepare_replacement(self,**kw):
        self.replace_calls.append(kw)
        return {"task_id":"b2","replacement_for":"b","builder_id":"builder-b2"}


class RuntimeTests(unittest.TestCase):
    @unittest.skipUnless(__import__("shutil").which("git"),"git required")
    def test_record_handoff_uses_live_store_identity_and_does_not_release_writer(self):
        import hashlib,shutil,subprocess
        from forgeboss.control.receipts import receipt_digest
        git=Path(shutil.which("git")).resolve()
        work=self.runtime.workspace_root/"fl1-handoff-worker-a";work.mkdir()
        def g(*args,binary=False):
            p=subprocess.run([str(git),"-C",str(work),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                             text=not binary,check=False)
            self.assertEqual(p.returncode,0,msg=(p.stderr if not binary else p.stderr.decode("utf-8","replace")))
            return p.stdout
        g("init","-q");g("config","user.email","test@example.invalid");g("config","user.name","Test")
        (work/"base.txt").write_text("base\n",encoding="utf-8");g("add",".");g("commit","-qm","base")
        base=str(g("rev-parse","HEAD")).strip()
        (work/"candidate.txt").write_text("candidate\n",encoding="utf-8");g("add","candidate.txt");g("commit","-qm","candidate")
        candidate=str(g("rev-parse","HEAD")).strip();tree=str(g("rev-parse",f"{candidate}^{{tree}}")).strip()
        patch=bytes(g("diff","--binary",base,candidate,"--",binary=True));scope=hashlib.sha256(patch).hexdigest()
        test_core={"command":"python -m unittest x -v","exit_code":0,"output_sha256":"2"*64}
        test_row={**test_core,"receipt_digest":receipt_digest(test_core)}
        ident={"taskId":"task-a","runId":"worker-a","attempt":1,"ownerEpoch":1,"builderPrincipal":"builder-a",
               "assignmentGeneration":1,"assignmentPolicySha256":"3"*64,"repository":"1stchoicefnq-afk/ForgeBoss",
               "baseSha":base,"branch":"forgeboss/fl1-selfbuild-a","worktreePath":str(work.resolve()),
               "workspaceGeneration":1,"workspaceContentIdentity":base,"budgetRunId":"fl1-run"}
        packet={"identity":ident,"assignmentIdentitySha256":hashlib.sha256(json.dumps(ident,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()}
        class Store:
            def __init__(self):self.released=False;self.status="running";self.result_head=None
            def assignment_identity(self,task_id,run_id,owner_epoch):
                self.last=(task_id,run_id,owner_epoch);return packet
            def get_task(self,task_id):
                return {"task_id":task_id,"status":self.status,"result_head":self.result_head}
            def release(self,task_id,run_id,owner_epoch,result_head=None,outcome="released",expected_head=None):
                self.released=True;self.status="released";self.result_head=result_head
        store=Store();self.runtime.store=store;self.runtime.git_resolver=lambda:git
        item={"task_id":"task-a","builder_id":"builder-a","worktree":str(work),"owner_epoch":1,
              "packet":{"allowed_files":["candidate.txt"]},
              "authority":{"run_id":"worker-a","budget_usd":"1.00"}}
        run=self.runtime._run_path("fl1-handoff")
        run.write_text(json.dumps({"schema":1,"phase":"PREPARED","prepared":{"base_sha":base,"builders":[item]},"replacement":None}),encoding="utf-8")
        evidence={"schema":1,"task_id":"task-a","builder_id":"builder-a","base_sha":base,"candidate_sha":candidate,
                  "candidate_tree_sha":tree,"changed_files":["candidate.txt"],"additions":1,"deletions":0,"changed_lines":1,
                  "focused_tests":[test_row],"measured_cost_usd":"0.25","reserved_cost_usd":"1.00",
                  "postflight_changed_paths":["candidate.txt"],"runner_result_digest":"4"*64,
                  "process_evidence_digest":"5"*64,"known_uncertainty":[],"scope_diff_sha256":scope,"evidence_digest":"6"*64}
        out=self.runtime.record_handoff({"runId":"fl1-handoff","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1,"evidence":evidence})
        self.assertEqual(out["handoff"]["candidateSha"],candidate)
        self.assertEqual(out["status"],"FROZEN_AWAITING_INDEPENDENT_REVIEW")
        self.assertFalse(store.released)
        again=self.runtime.record_handoff({"runId":"fl1-handoff","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1,"evidence":evidence})
        self.assertEqual(again,out)
        with self.assertRaises(SelfBuildRuntimeError) as self_review:
            self.runtime.record_review({"runId":"fl1-handoff","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1,
                                        "review":{"reviewerId":"builder-a","verdict":"pass","evidenceSha256":"7"*64,
                                                  "reviewerTestReceipts":[test_row["receipt_digest"]]}})
        self.assertEqual(self_review.exception.code,"REVIEW_RECEIPT_INVALID")
        review=self.runtime.record_review({"runId":"fl1-handoff","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1,
                                           "review":{"reviewerId":"reviewer-independent","verdict":"pass","evidenceSha256":"7"*64,
                                                     "reviewerTestReceipts":[test_row["receipt_digest"]]}})
        self.assertEqual(review["status"],"PASS")
        accepted=self.runtime.accept_candidate({"runId":"fl1-handoff","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1},controller_id="controller-a")
        self.assertEqual(accepted["status"],"ACCEPTED")
        self.assertTrue(store.released)
        self.assertEqual(store.result_head,candidate)
        self.assertEqual(self.runtime.accept_candidate({"runId":"fl1-handoff","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1},controller_id="controller-a"),accepted)

    def setUp(self):
        self.td=tempfile.TemporaryDirectory()
        self.root=Path(self.td.name)/"protected";self.root.mkdir()
        self.source=Path(self.td.name)/"ForgeBoss";self.source.mkdir()
        self.boundary=Boundary()
        self.runtime=SelfBuildRuntime(
            protected_root=self.root,boundary=self.boundary,
            receipt_public_key_b64="c"*44,
            git_resolver=lambda:Path("/trusted/git"),
        )
        self.coordinator=Coordinator()
        self.runtime.coordinator=self.coordinator
        self.base="a"*40

    def tearDown(self):
        self.runtime.close()
        self.td.cleanup()

    def pointer(self):
        p=self.runtime.activation_root/"known-good.json"
        p.write_text(json.dumps({
            "schema":2,"generation":1,
            "current":{"verified":True,"revision":self.base,"codeRoot":str(self.source)},
            "previous":None,
        }),encoding="utf-8")
        return p

    def test_missing_known_good_pointer_blocks_prepare_before_coordinator(self):
        with self.assertRaises(SelfBuildRuntimeError) as cm:
            self.runtime.prepare({"sourceRoot":str(self.source),"baseSha":self.base,"runId":"fl1-one"})
        self.assertEqual(cm.exception.code,"KNOWN_GOOD_POINTER_MISSING")
        self.assertEqual(self.coordinator.prepare_calls,[])

    def test_prepare_persists_protected_run_state_and_status_reads_it(self):
        self.pointer()
        out=self.runtime.prepare({"sourceRoot":str(self.source),"baseSha":self.base,"runId":"fl1-one"})
        self.assertEqual(out["run_id"],"fl1-one")
        state=self.runtime.status({"runId":"fl1-one"})
        self.assertEqual(state["phase"],"PREPARED")
        self.assertEqual(state["prepared"]["base_sha"],self.base)
        run_path=self.runtime.run_root/"fl1-one.json"
        self.assertTrue(run_path.is_file())
        self.assertTrue(run_path.resolve().is_relative_to(self.root.resolve()))

    def test_duplicate_run_id_is_denied_without_second_prepare(self):
        self.pointer()
        payload={"sourceRoot":str(self.source),"baseSha":self.base,"runId":"fl1-dup"}
        self.runtime.prepare(payload)
        with self.assertRaises(SelfBuildRuntimeError) as cm:self.runtime.prepare(payload)
        self.assertEqual(cm.exception.code,"RUN_ALREADY_EXISTS")
        self.assertEqual(len(self.coordinator.prepare_calls),1)

    def test_replacement_updates_durable_phase_once(self):
        self.pointer()
        payload={"sourceRoot":str(self.source),"baseSha":self.base,"runId":"fl1-r"}
        self.runtime.prepare(payload)
        out=self.runtime.prepare_replacement({"runId":"fl1-r"})
        self.assertEqual(out["builder_id"],"builder-b2")
        state=self.runtime.status({"runId":"fl1-r"})
        self.assertEqual(state["phase"],"REPLACEMENT_PREPARED")
        with self.assertRaises(SelfBuildRuntimeError) as cm:self.runtime.prepare_replacement({"runId":"fl1-r"})
        self.assertIn(cm.exception.code,{"RUN_STATE_INVALID","REPLACEMENT_ALREADY_PREPARED"})

    def test_service_principal_revocation_denies_status(self):
        self.pointer()
        self.runtime.prepare({"sourceRoot":str(self.source),"baseSha":self.base,"runId":"fl1-deny"})
        self.boundary.deny=True
        with self.assertRaises(SelfBuildRuntimeError) as cm:self.runtime.status({"runId":"fl1-deny"})
        self.assertEqual(cm.exception.code,"SERVICE_PRINCIPAL_DENIED")


if __name__=="__main__":
    unittest.main()
