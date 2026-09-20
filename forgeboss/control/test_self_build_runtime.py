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
               "assignmentGeneration":1,"assignmentPolicySha256":"3"*64,"repository":"1stchoicefnq-afk/forgeboss",
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
        review_core={"schema":1,"reviewer_id":"reviewer-independent","task_id":"task-a","builder_id":"builder-a",
                     "base_sha":base,"candidate_sha":candidate,"candidate_tree_sha":tree,
                     "handoff_sha256":out["handoffDigest"],"changed_files":["candidate.txt"],
                     "scope_diff_sha256":scope,"tests":[test_row],"verdict":"pass",
                     "workspace_pristine":True,"workspace_cleanup_proven":True}
        self.runtime.review_fn=lambda **kw:{**review_core,"evidence_digest":receipt_digest(review_core)}
        review=self.runtime.record_review({"runId":"fl1-handoff","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1})
        self.assertEqual(review["status"],"PASS")
        accepted=self.runtime.accept_candidate({"runId":"fl1-handoff","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1},controller_id="controller-a")
        self.assertEqual(accepted["status"],"ACCEPTED")
        self.assertTrue(store.released)
        self.assertEqual(store.result_head,candidate)
        self.assertEqual(self.runtime.accept_candidate({"runId":"fl1-handoff","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1},controller_id="controller-a"),accepted)

    @unittest.skipUnless(__import__("shutil").which("git"),"git required")
    def test_real_independent_reviewer_retests_exact_candidate_and_cleans_workspace(self):
        import hashlib,shutil,subprocess
        from types import SimpleNamespace
        from forgeboss.control.self_build_review import review_frozen_candidate
        git=Path(shutil.which("git")).resolve();work=self.runtime.workspace_root/"review-source";work.mkdir()
        def g(*args,binary=False):
            p=subprocess.run([str(git),"-C",str(work),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=not binary,check=False)
            self.assertEqual(p.returncode,0,msg=(p.stderr if not binary else p.stderr.decode("utf-8","replace")))
            return p.stdout if binary else p.stdout.strip()
        g("init","-q");g("config","user.email","test@example.invalid");g("config","user.name","Review Test")
        for rel,body in {"forgeboss/__init__.py":"","forgeboss/tests/__init__.py":""}.items():
            p=work/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body,encoding="utf-8")
        g("add",".");g("commit","-qm","base");base=g("rev-parse","HEAD")
        rel="forgeboss/tests/test_reviewed.py";p=work/rel
        p.write_text("import unittest\nclass T(unittest.TestCase):\n    def test_ok(self): self.assertEqual(2+2,4)\n",encoding="utf-8")
        g("add","--",rel);g("commit","-qm","candidate");candidate=g("rev-parse","HEAD");tree=g("rev-parse",f"{candidate}^{{tree}}")
        scope=hashlib.sha256(bytes(g("diff","--no-ext-diff","--binary",base,candidate,"--",binary=True))).hexdigest()
        handoff=SimpleNamespace(
            assignment=SimpleNamespace(base_sha=base,worktree_path=str(work.resolve()),task_id="task-review",builder_principal="builder-a"),
            candidate_sha=candidate,candidate_tree_sha=tree,contributors=("builder-a",),
            changed_paths=((rel,"unused"),),scope_diff_sha256=scope,digest="d"*64,
        )
        item={"task_id":"task-review","builder_id":"builder-a","worktree":str(work.resolve()),
              "packet":{"required_tests":["python -m unittest forgeboss.tests.test_reviewed -v"]}}
        evidence=review_frozen_candidate(item=item,handoff=handoff,workspace_root=self.runtime.workspace_root,
                                         protected_state=self.runtime.workspace_state,git_executable=git)
        self.assertEqual(evidence["verdict"],"pass");self.assertEqual(len(evidence["tests"]),1)
        tag=hashlib.sha256(("task-review"+"\0"+candidate).encode("utf-8")).hexdigest()[:16]
        self.assertFalse((self.runtime.workspace_root/f"review-{tag}").exists())

    @unittest.skipUnless(__import__("shutil").which("git"),"git required")
    def test_independent_reviewer_rejects_test_that_mutates_review_checkout(self):
        import hashlib,shutil,subprocess
        from types import SimpleNamespace
        from forgeboss.control.self_build_review import SelfBuildReviewError,review_frozen_candidate
        git=Path(shutil.which("git")).resolve();work=self.runtime.workspace_root/"review-mutator";work.mkdir()
        def g(*args,binary=False):
            p=subprocess.run([str(git),"-C",str(work),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=not binary,check=False)
            self.assertEqual(p.returncode,0,msg=(p.stderr if not binary else p.stderr.decode("utf-8","replace")))
            return p.stdout if binary else p.stdout.strip()
        g("init","-q");g("config","user.email","test@example.invalid");g("config","user.name","Review Test")
        for rel,body in {"forgeboss/__init__.py":"","forgeboss/tests/__init__.py":""}.items():
            p=work/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body,encoding="utf-8")
        g("add",".");g("commit","-qm","base");base=g("rev-parse","HEAD")
        rel="forgeboss/tests/test_mutator.py";p=work/rel
        p.write_text("import pathlib,unittest\nclass T(unittest.TestCase):\n    def test_mutates(self): pathlib.Path('review-mutation.txt').write_text('x'); self.assertTrue(True)\n",encoding="utf-8")
        g("add","--",rel);g("commit","-qm","candidate");candidate=g("rev-parse","HEAD");tree=g("rev-parse",f"{candidate}^{{tree}}")
        scope=hashlib.sha256(bytes(g("diff","--no-ext-diff","--binary",base,candidate,"--",binary=True))).hexdigest()
        handoff=SimpleNamespace(
            assignment=SimpleNamespace(base_sha=base,worktree_path=str(work.resolve()),task_id="task-mutator",builder_principal="builder-a"),
            candidate_sha=candidate,candidate_tree_sha=tree,contributors=("builder-a",),
            changed_paths=((rel,"unused"),),scope_diff_sha256=scope,digest="e"*64,
        )
        item={"task_id":"task-mutator","builder_id":"builder-a","worktree":str(work.resolve()),
              "packet":{"required_tests":["python -m unittest forgeboss.tests.test_mutator -v"]}}
        with self.assertRaises(SelfBuildReviewError) as cm:
            review_frozen_candidate(item=item,handoff=handoff,workspace_root=self.runtime.workspace_root,
                                    protected_state=self.runtime.workspace_state,git_executable=git)
        self.assertEqual(cm.exception.code,"REVIEW_WORKSPACE_MUTATED")

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

    def test_compose_successor_persists_once_and_reverifies_on_reentry(self):
        self.pointer();self.runtime.prepare({"sourceRoot":str(self.source),"baseSha":self.base,"runId":"fl1-compose"});self.runtime.prepare_replacement({"runId":"fl1-compose"})
        calls={"compose":0,"verify":0}
        def compose(**kw):
            calls["compose"]+=1;work=self.runtime.workspace_root/"fl1-compose-successor";work.mkdir();manifest=Path(kw["manifest_path"]);manifest.write_text("{}",encoding="utf-8")
            return {"schema":1,"run_id":"fl1-compose","workspace":str(work.resolve()),"manifest_path":str(manifest.resolve()),"composition_digest":"a"*64}
        def verify(**kw):
            calls["verify"]+=1;self.assertEqual(kw["expected"]["status"],"COMPOSED_AWAITING_ACTIVATION");return {"verified":True}
        self.runtime.compose_fn=compose;self.runtime.verify_compose_fn=verify
        first=self.runtime.compose_successor({"runId":"fl1-compose"});self.assertEqual(first["status"],"COMPOSED_AWAITING_ACTIVATION")
        state=self.runtime.status({"runId":"fl1-compose"});self.assertEqual(state["phase"],"SUCCESSOR_COMPOSED");self.assertEqual(state["successor"],first)
        second=self.runtime.compose_successor({"runId":"fl1-compose"});self.assertEqual(second,first);self.assertEqual(calls,{"compose":1,"verify":2})

    def test_compose_successor_fails_closed_on_unrecorded_artifacts(self):
        self.pointer();self.runtime.prepare({"sourceRoot":str(self.source),"baseSha":self.base,"runId":"fl1-orphan"});self.runtime.prepare_replacement({"runId":"fl1-orphan"})
        (self.runtime.workspace_root/"fl1-orphan-successor").mkdir()
        self.runtime.compose_fn=lambda **kw:self.fail("orphaned successor must not be silently reused")
        with self.assertRaises(SelfBuildRuntimeError) as cm:self.runtime.compose_successor({"runId":"fl1-orphan"})
        self.assertEqual(cm.exception.code,"SUCCESSOR_RECOVERY_REQUIRED")

    def test_compose_successor_reverify_failure_is_runtime_failure(self):
        from forgeboss.control.self_build_compose import SelfBuildComposeError
        self.pointer();self.runtime.prepare({"sourceRoot":str(self.source),"baseSha":self.base,"runId":"fl1-reverify"});self.runtime.prepare_replacement({"runId":"fl1-reverify"})
        def compose(**kw):
            work=self.runtime.workspace_root/"fl1-reverify-successor";work.mkdir();manifest=Path(kw["manifest_path"]);manifest.write_text("{}",encoding="utf-8")
            return {"schema":1,"workspace":str(work.resolve()),"manifest_path":str(manifest.resolve()),"composition_digest":"b"*64}
        self.runtime.compose_fn=compose;self.runtime.verify_compose_fn=lambda **kw:({"verified":True})
        self.runtime.compose_successor({"runId":"fl1-reverify"})
        def denied(**kw):raise SelfBuildComposeError("SUCCESSOR_RECORD_MISMATCH","tampered")
        self.runtime.verify_compose_fn=denied
        with self.assertRaises(SelfBuildRuntimeError) as cm:self.runtime.compose_successor({"runId":"fl1-reverify"})
        self.assertEqual(cm.exception.code,"SUCCESSOR_RECORD_MISMATCH")

    def test_activate_successor_proves_promotes_health_and_persists_final_state(self):
        from forgeboss.control.activation import ActivationError
        run_id="fl1-activate";work=self.runtime.workspace_root/f"{run_id}-successor";work.mkdir()
        manifest=self.runtime.run_root/f"{run_id}-successor-manifest.json";manifest.write_text("{}",encoding="utf-8")
        successor={"schema":1,"run_id":run_id,"workspace":str(work.resolve()),"manifest_path":str(manifest.resolve()),
                   "successor_sha":"b"*40,"manifest_sha256":"c"*64,"status":"COMPOSED_AWAITING_ACTIVATION","composition_digest":"d"*64}
        record={"schema":1,"phase":"SUCCESSOR_COMPOSED","prepared":{"source_root":str(self.source)},"successor":successor}
        self.runtime._run_path(run_id).write_text(json.dumps(record),encoding="utf-8")
        self.runtime.verify_compose_fn=lambda **kw:({"verified":True})
        running={"verified":True,"revision":"a"*40,"codeRoot":str(self.source.resolve()),"manifestPath":str(self.source/"manifest.json"),
                 "manifestSha256":"1"*64,"identitySha256":"2"*64,"treeSha256":"3"*64}
        self.runtime._verified_running_identity=lambda:dict(running)
        self.runtime.identity_verifier=lambda *a,**kw:{"verified":True,"revision":"b"*40,"manifestSha256":"c"*64}
        events=[]
        class Manager:
            def __init__(self,*args):self.state={"schema":2,"phase":"IDLE","generation":1};self.pointer={"schema":2,"generation":1,"current":running,"previous":None}
            def initialize_known_good(self):events.append("init");return self.pointer
            def status(self):return dict(self.state)
            def stage(self,root,manifest_path,revision,manifest_sha,expected_generation=None):
                events.append("stage");self.state={"schema":2,"phase":"STAGED","generation":2,"candidate":{"revision":revision,"manifestSha256":manifest_sha}};return dict(self.state)
            def start_candidate(self,expected_generation=None):
                events.append("start");self.state.update({"phase":"STARTING","candidateStateRoot":str(self.runtime_state if hasattr(self,"runtime_state") else Path(self_ref.runtime.activation_root)/"candidate-runtime-2")});return object()
            def authoritative_probe(self,expected_generation=None,timeout=0):
                events.append("probe");self.state.update({"phase":"PROBED","probe":{"evidenceSha256":"4"*64}});return dict(self.state)
            def promote(self,expected_generation=None):
                events.append("promote");self.state["phase"]="PROMOTED";self.pointer={"schema":2,"generation":2,"current":{"revision":"b"*40,"manifestSha256":"c"*64},"previous":running};return self.pointer
            def authoritative_health_check(self,expected_generation=None,timeout=0):
                events.append("health");self.state["activationHealth"]={"evidenceSha256":"5"*64};self.state["phase"]="READY";self.state["running"]={"revision":"b"*40};return self.pointer
            def known_good_pointer(self):return self.pointer
        self_ref=self
        manager=Manager()
        self.runtime.activation_manager_factory=lambda *_:manager
        out=self.runtime.activate_successor({"runId":run_id})
        self.assertEqual(out["status"],"ACTIVATED_KNOWN_GOOD")
        self.assertEqual(events,["init","stage","start","probe","promote","health"])
        saved=self.runtime.status({"runId":run_id})
        self.assertEqual(saved["phase"],"SUCCESSOR_ACTIVATED")
        self.assertEqual(saved["activation"]["probe_evidence_sha256"],"4"*64)
        self.assertEqual(saved["activation"]["health_evidence_sha256"],"5"*64)

    def test_activate_successor_health_failure_records_failure_and_does_not_mark_activated(self):
        from forgeboss.control.activation import ActivationError
        run_id="fl1-activate-fail";work=self.runtime.workspace_root/f"{run_id}-successor";work.mkdir()
        manifest=self.runtime.run_root/f"{run_id}-successor-manifest.json";manifest.write_text("{}",encoding="utf-8")
        successor={"schema":1,"run_id":run_id,"workspace":str(work.resolve()),"manifest_path":str(manifest.resolve()),
                   "successor_sha":"b"*40,"manifest_sha256":"c"*64,"status":"COMPOSED_AWAITING_ACTIVATION","composition_digest":"d"*64}
        self.runtime._run_path(run_id).write_text(json.dumps({"schema":1,"phase":"SUCCESSOR_COMPOSED","prepared":{"source_root":str(self.source)},"successor":successor}),encoding="utf-8")
        self.runtime.verify_compose_fn=lambda **kw:({"verified":True})
        running={"verified":True,"revision":"a"*40,"codeRoot":str(self.source.resolve()),"manifestPath":str(self.source/"manifest.json"),
                 "manifestSha256":"1"*64,"identitySha256":"2"*64,"treeSha256":"3"*64}
        self.runtime._verified_running_identity=lambda:dict(running)
        class Manager:
            def __init__(self):self.state={"schema":2,"phase":"IDLE","generation":1};self.pointer={"schema":2,"generation":1,"current":running}
            def initialize_known_good(self):return self.pointer
            def status(self):return dict(self.state)
            def stage(self,*a,**kw):self.state={"schema":2,"phase":"STAGED","generation":2,"candidate":{"revision":"b"*40,"manifestSha256":"c"*64}};return dict(self.state)
            def start_candidate(self,**kw):self.state.update({"phase":"STARTING","candidateStateRoot":str(self_ref.runtime.activation_root/"candidate-runtime-2")});return object()
            def authoritative_probe(self,**kw):self.state.update({"phase":"PROBED","probe":{"evidenceSha256":"4"*64}});return dict(self.state)
            def promote(self,**kw):self.state["phase"]="PROMOTED";self.pointer={"schema":2,"generation":2,"current":{"revision":"b"*40,"manifestSha256":"c"*64}};return self.pointer
            def authoritative_health_check(self,**kw):self.state["phase"]="ROLLED_BACK";raise ActivationError("health failed")
            def known_good_pointer(self):return self.pointer
        self_ref=self;manager=Manager();self.runtime.activation_manager_factory=lambda *_:manager
        with self.assertRaises(SelfBuildRuntimeError) as cm:self.runtime.activate_successor({"runId":run_id})
        self.assertEqual(cm.exception.code,"ACTIVATION_FAILED")
        saved=self.runtime.status({"runId":run_id})
        self.assertEqual(saved["phase"],"SUCCESSOR_COMPOSED")
        self.assertEqual(saved["activation"]["status"],"ACTIVATION_FAILED")
        self.assertEqual(saved["activation"]["activation_phase"],"ROLLED_BACK")

    @unittest.skipUnless(__import__("shutil").which("git"),"git required")
    def test_real_rollback_proof_builds_broken_candidate_and_cleans_workspace(self):
        import shutil,subprocess
        from forgeboss.control.activation import ActivationError
        from forgeboss.control.self_build_compose import build_manifest
        from forgeboss.control.self_build_rollback_proof import run_rollback_proof
        git=Path(shutil.which("git")).resolve()
        source=Path(self.td.name)/"rollback-source";source.mkdir()
        def g(*args):
            p=subprocess.run([str(git),"-C",str(source),*args],capture_output=True,text=True,check=False)
            self.assertEqual(p.returncode,0,msg=p.stderr);return p.stdout.strip()
        g("init","-q");g("config","user.email","test@example.invalid");g("config","user.name","Rollback Test")
        for rel,body in {
            "forgeboss/__init__.py":"",
            "forgeboss/control/__init__.py":"",
            "forgeboss/control/daemon.py":"from forgeboss.control.known_good import runtime_identity_from_env\nROOT=None\nRUNTIME_IDENTITY=runtime_identity_from_env(ROOT)\n",
            "forgeboss/control/known_good.py":"def runtime_identity_from_env(root): return {}\n",
        }.items():
            p=source/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body,encoding="utf-8")
        g("add",".");g("commit","-qm","known-good");base=g("rev-parse","HEAD")
        current_manifest=self.runtime.run_root/"rollback-current-manifest.json"
        md,identity=build_manifest(git=git,root=source,revision=base,manifest_path=current_manifest)
        current={**identity,"verified":True}
        class Manager:
            def __init__(self):self.state={"schema":2,"phase":"READY","generation":2,"running":current};self.pointer={"schema":2,"generation":2,"current":current}
            def initialize_known_good(self):return self.pointer
            def status(self):return dict(self.state)
            def stage(self,root,manifest,revision,manifest_sha,expected_generation=None):
                self.assertions=(root,manifest,revision,manifest_sha,expected_generation)
                self.state={"schema":2,"phase":"STAGED","generation":3,"candidate":{"revision":revision,"manifestSha256":manifest_sha}}
                return dict(self.state)
            def start_candidate(self,expected_generation=None):self.state["phase"]="STARTING";self.state["processIdentity"]={"pid":123};return object()
            def authoritative_probe(self,expected_generation=None,timeout=0):
                self.state={"schema":2,"phase":"ROLLED_BACK","generation":3,"processIdentity":None,"running":current}
                raise ActivationError("deliberate runtime identity mismatch")
            def known_good_pointer(self):return self.pointer
        manager=Manager()
        proof_manifest=self.runtime.run_root/"fl1-proof-rollback-proof-manifest.json"
        evidence=run_rollback_proof(
            run_id="fl1-proof",current_identity=current,activation_root=self.runtime.activation_root,
            workspace_root=self.runtime.workspace_root,protected_state=self.runtime.workspace_state,
            git_executable=git,manifest_path=proof_manifest,activation_manager_factory=lambda *_:manager,
        )
        self.assertEqual(evidence["status"],"ROLLBACK_PROVEN");self.assertEqual(evidence["known_good_revision"],base)
        self.assertNotEqual(evidence["broken_candidate_sha"],base);self.assertEqual(evidence["changed_files"],["forgeboss/control/daemon.py"])
        self.assertEqual(evidence["final_phase"],"ROLLED_BACK");self.assertTrue(evidence["candidate_process_dead"]);self.assertTrue(evidence["workspace_cleaned"])
        self.assertFalse((self.runtime.workspace_root/"fl1-proof-rollback-drill").exists())

    def test_runtime_persists_rollback_proof_and_returns_it_idempotently(self):
        from forgeboss.control.receipts import receipt_digest
        run_id="fl1-proof-runtime"
        current={"verified":True,"revision":"b"*40,"codeRoot":str(self.source.resolve()),"manifestPath":str((self.source/"manifest.json").resolve()),
                 "manifestSha256":"c"*64,"identitySha256":"d"*64,"treeSha256":"e"*64}
        (self.source/"manifest.json").write_text("{}",encoding="utf-8")
        activation={"status":"ACTIVATED_KNOWN_GOOD","successor_sha":"b"*40,"manifest_sha256":"c"*64}
        self.runtime._run_path(run_id).write_text(json.dumps({"schema":1,"phase":"SUCCESSOR_ACTIVATED","activation":activation}),encoding="utf-8")
        self.runtime._verified_running_identity=lambda:dict(current)
        core={"schema":1,"status":"ROLLBACK_PROVEN","run_id":run_id,"known_good_revision":"b"*40,"broken_candidate_sha":"f"*40,
              "changed_files":["forgeboss/control/daemon.py"],"manifest_sha256":"1"*64,"activation_generation":3,
              "final_phase":"ROLLED_BACK","pointer_revision":"b"*40,"expected_probe_failure":"expected",
              "candidate_process_dead":True,"workspace_cleaned":True}
        calls=[]
        self.runtime.rollback_proof_fn=lambda **kw:(calls.append(kw) or {**core,"evidence_digest":receipt_digest(core)})
        first=self.runtime.prove_activation_rollback({"runId":run_id});second=self.runtime.prove_activation_rollback({"runId":run_id})
        self.assertEqual(first,second);self.assertEqual(len(calls),1)
        saved=self.runtime.status({"runId":run_id});self.assertEqual(saved["rollbackProof"]["status"],"ROLLBACK_PROVEN")

    def test_current_known_good_requires_ready_activation_and_returns_verified_source(self):
        identity={"verified":True,"revision":"b"*40,"codeRoot":str(self.source.resolve()),
                  "manifestPath":str((self.source/"manifest.json").resolve()),"manifestSha256":"c"*64,
                  "identitySha256":"d"*64,"treeSha256":"e"*64}
        (self.source/"manifest.json").write_text("{}",encoding="utf-8")
        (self.runtime.activation_root/"known-good.json").write_text(json.dumps({"schema":2,"generation":2,"current":identity,"previous":None}),encoding="utf-8")
        self.runtime._verified_running_identity=lambda:dict(identity)
        class Manager:
            def recover(self):return {"schema":2}
            def status(self):return {"schema":2,"phase":"READY","generation":2,"running":{"revision":"b"*40,"manifestSha256":"c"*64}}
        self.runtime.activation_manager_factory=lambda *_:Manager()
        out=self.runtime.current_known_good({})
        self.assertEqual(out["phase"],"READY");self.assertEqual(out["generation"],2)
        self.assertEqual(out["revision"],"b"*40);self.assertEqual(out["code_root"],str(self.source.resolve()))
        class RolledManager:
            def recover(self):return {"schema":2}
            def status(self):return {"schema":2,"phase":"ROLLED_BACK","generation":3,"running":{"revision":"b"*40,"manifestSha256":"c"*64}}
        self.runtime.activation_manager_factory=lambda *_:RolledManager()
        rolled=self.runtime.current_known_good({});self.assertEqual(rolled["phase"],"ROLLED_BACK_READY")
        with self.assertRaises(SelfBuildRuntimeError) as cm:self.runtime.current_known_good({"extra":True})
        self.assertEqual(cm.exception.code,"SELF_BUILD_PAYLOAD_INVALID")

    def test_service_principal_revocation_denies_status(self):
        self.pointer()
        self.runtime.prepare({"sourceRoot":str(self.source),"baseSha":self.base,"runId":"fl1-deny"})
        self.boundary.deny=True
        with self.assertRaises(SelfBuildRuntimeError) as cm:self.runtime.status({"runId":"fl1-deny"})
        self.assertEqual(cm.exception.code,"SERVICE_PRINCIPAL_DENIED")


if __name__=="__main__":
    unittest.main()
