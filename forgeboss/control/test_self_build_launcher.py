from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from forgeboss.control.self_build_launcher import SelfBuildLauncher,SelfBuildLaunchError
from forgeboss.control.self_build_freeze import SelfBuildFreezeError,freeze_candidate
from forgeboss.control.process_supervisor import ProcessSupervisor,SupervisorError
from forgeboss.protected_authority.client import ProtectedAuthorityClient


@dataclass(frozen=True)
class A:
    worker_id:str
    generation:int
    state:str
    pid:int
    exit_code:int|None=None
    started_at:float=1.0
    containment_id:str="fake-containment"


@dataclass(frozen=True)
class E:
    state:str="STOPPED"
    containment_empty:bool=True
    def as_dict(self):return {"operationId":"op","workerId":"w","generation":1,"state":self.state,"reason":"verified-complete","exitCode":0,"containmentEmpty":self.containment_empty,"startedAt":1.0,"finishedAt":2.0}


class Client(ProtectedAuthorityClient):
    def __init__(self):
        self.attested=[];self.revoked=[];self.handoffs=[];self.reviews=[];self.accepted=[];self.composed=[];self.activated=[]
    def attest_launch_payload(self,signed):
        self.attested.append(dict(signed))
        return {"schema":1,"envelope":{"signed":dict(signed),"signature":"sig"},"authorityResponse":{"receipt":"public"}}
    def revoke_self_build_worker(self,**kw):
        self.revoked.append(dict(kw));return {"result":{"revoked":True}}
    def record_self_build_handoff(self,**kw):
        self.handoffs.append(dict(kw));return {"result":{"status":"FROZEN_AWAITING_INDEPENDENT_REVIEW"},"receipt":{"operation":"record_self_build_handoff"}}
    def review_self_build_candidate(self,**kw):
        self.reviews.append(dict(kw));return {"result":{"status":"PASS"},"receipt":{"operation":"review_self_build_candidate"}}
    def accept_self_build_candidate(self,**kw):
        self.accepted.append(dict(kw));return {"result":{"status":"ACCEPTED"},"receipt":{"operation":"accept_self_build_candidate"}}
    def compose_self_build_successor(self,**kw):
        self.composed.append(dict(kw));return {"result":{"status":"COMPOSED_AWAITING_ACTIVATION","run_id":kw["run_id"]},"receipt":{"operation":"compose_self_build_successor"}}
    def activate_self_build_successor(self,**kw):
        self.activated.append(dict(kw));return {"result":{"status":"ACTIVATED_KNOWN_GOOD","successor_sha":"f"*40},"receipt":{"operation":"activate_self_build_successor"}}



class Supervisor(ProcessSupervisor):
    def __init__(self,fail_on=None):
        self.launched=[];self.stopped=[];self.fail_on=fail_on
    def launch(self,worker_id,argv,*,cwd=None,env=None):
        if worker_id==self.fail_on:raise RuntimeError("launch boom")
        row=A(worker_id,len(self.launched)+1,"RUNNING",100+len(self.launched))
        self.launched.append({"row":row,"argv":list(argv),"cwd":cwd,"env":dict(env or {})});return row
    def stop(self,worker_id,expected_generation,*,timeout=10.0):
        self.stopped.append((worker_id,expected_generation,timeout));return E()
    def get(self,worker_id,*,refresh=False):
        row=next(x["row"] for x in self.launched if x["row"].worker_id==worker_id)
        return row
    def complete(self,worker_id,expected_generation,*,timeout=5.0):
        return E()



class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name)
        self.state=self.root/"state";self.state.mkdir()
        self.worka=self.root/"wa";self.worka.mkdir()
        self.workb=self.root/"wb";self.workb.mkdir()
        self.runner=self.root/"runner.py";self.runner.write_text("pass\n",encoding="utf-8")
        self.python=Path(__import__("sys").executable).resolve()
        self.client=Client();self.supervisor=Supervisor()
        self.leases=[]
        def issue(packet,workspace,executor,ttl):
            row={"ok":True,"lease":str(self.state/f"lease-{len(self.leases)}.json"),"token":f"TOKEN-{len(self.leases)}"}
            self.leases.append({"row":row,"packet":packet,"workspace":workspace,"executor":executor,"ttl":ttl})
            return row
        self.issue=issue
        self.prepared=self._prepared()

    def tearDown(self):self.td.cleanup()

    def _item(self,builder,task,work,budget):
        return {
            "task_id":task,"builder_id":builder,"worktree":str(work),"owner_epoch":1,
            "packet":{
                "schema":1,"product":"ForgeBoss","project_id":"forgeboss",
                "allowed_files":[f"forgeboss/tests/test_{builder}.py"],"context_files":[],
                "expected_head_revision":"a"*40,"objective":"test","acceptance_criteria":["test"],
                "self_build_authority":{
                    "repository":"1stchoicefnq-afk/ForgeBoss","control_revision":1,
                    "task_id":task,"run_id":f"worker-{builder}","owner_epoch":1,
                    "builder_id":builder,"assignment_generation":1,"assignment_sha256":"b"*64,
                    "branch":f"forgeboss/fl1-selfbuild-{builder}","budget_usd":budget,
                    "global_budget_run_id":"fl1-run","global_budget_reservation_id":task,
                    "receipt_public_key_b64":"pin",
                },
            },
            "authority":{
                "repository":"1stchoicefnq-afk/ForgeBoss","control_revision":1,
                "task_id":task,"run_id":f"worker-{builder}","owner_epoch":1,
                "builder_id":builder,"assignment_generation":1,"assignment_sha256":"b"*64,
                "branch":f"forgeboss/fl1-selfbuild-{builder}","budget_usd":budget,
                "global_budget_run_id":"fl1-run","global_budget_reservation_id":task,
                "receipt_public_key_b64":"pin",
            },
        }

    def _prepared(self):
        return {
            "schema":1,"run_id":"fl1-run","base_sha":"a"*40,"global_budget_cap_usd":"2.00",
            "builders":[
                self._item("builder-a","task-a",self.worka,"1.00"),
                self._item("builder-b","task-b",self.workb,"0.50"),
            ],
        }

    def launcher(self,supervisor=None,freeze_fn=freeze_candidate):
        return SelfBuildLauncher(
            client=self.client,supervisor=supervisor or self.supervisor,state_root=self.state,
            python_executable=self.python,runner_path=self.runner,issue_lease_fn=self.issue,freeze_fn=freeze_fn,
            container_cleanup_fn=lambda **kw:{"container_empty":True,"observed_container_ids":[]},clock=lambda:1000.0,
        )

    def test_launch_initial_binds_two_workers_to_exact_packet_and_service_attestation(self):
        with patch.dict(os.environ,{
            "OPENAI_API_KEY":"MODEL-KEY",
            "GH_TOKEN":"GITHUB-SECRET",
            "FORGEBOSS_AUTHORITY_PEER_KEY":"C:/secret-peer.key",
        },clear=False):
            out=self.launcher().launch_initial(self.prepared)
        self.assertEqual(len(out["workers"]),2)
        self.assertEqual(len(self.supervisor.launched),2)
        self.assertEqual(len(self.client.attested),2)
        for launched,public,attested in zip(self.supervisor.launched,out["workers"],self.client.attested):
            env=launched["env"]
            self.assertEqual(env["FORGEBOSS_ALLOW_PAID_EXECUTOR"],"YES")
            self.assertEqual(env["FORGEBOSS_SELF_BUILD_MODE"],"YES")
            self.assertEqual(env["OPENAI_API_KEY"],"MODEL-KEY")
            self.assertNotIn("GH_TOKEN",env)
            self.assertNotIn("FORGEBOSS_AUTHORITY_PEER_KEY",env)
            self.assertNotIn("TOKEN-",json.dumps(public))
            packet=Path(public["packet_file"])
            self.assertEqual(__import__("hashlib").sha256(packet.read_bytes()).hexdigest(),public["packet_sha256"])
            self.assertEqual(attested["packetSha256"],public["packet_sha256"])
            self.assertEqual(attested["worktreePath"],str(Path(public["worktree"]).resolve()))

    def test_launch_initial_records_simultaneous_running_proof(self):
        out=self.launcher().launch_initial(self.prepared)
        self.assertEqual(out["concurrent_proof"]["states"],["RUNNING","RUNNING"])
        self.assertEqual(out["concurrent_proof"]["builders"],["builder-a","builder-b"])

    def test_initial_workers_are_fully_staged_before_either_process_starts(self):
        launcher=self.launcher()
        events=[]
        original_prepare=launcher._prepare_worker_launch
        original_start=launcher._start_prepared_worker
        def prepare(prepared_run,item):
            events.append("prepare-"+item["builder_id"])
            return original_prepare(prepared_run,item)
        def start(staged):
            events.append("start-"+staged["builder_id"])
            return original_start(staged)
        with patch.object(launcher,"_prepare_worker_launch",side_effect=prepare), \
             patch.object(launcher,"_start_prepared_worker",side_effect=start):
            launcher.launch_initial(self.prepared)
        self.assertEqual(events,[
            "prepare-builder-a","prepare-builder-b",
            "start-builder-a","start-builder-b",
        ])

    def test_concurrency_failure_persists_worker_exit_diagnostic(self):
        class FailedB(Supervisor):
            def get(self,worker_id,*,refresh=False):
                row=super().get(worker_id,refresh=refresh)
                if worker_id=="builder-b":
                    return A(row.worker_id,row.generation,"FAILED",row.pid,exit_code=13,started_at=row.started_at,containment_id=row.containment_id)
                return row
        launcher=self.launcher(FailedB())
        with self.assertRaises(SelfBuildLaunchError) as cm:
            launcher.launch_initial(self.prepared)
        self.assertEqual(cm.exception.code,"CONCURRENCY_NOT_PROVEN")
        report=self.state/"self-build-launch"/"fl1-run"/"initial-launch-failure.json"
        self.assertTrue(report.is_file())
        data=json.loads(report.read_text(encoding="utf-8"))
        rows={x["builder_id"]:x for x in data["workers"]}
        self.assertEqual(rows["builder-b"]["state"],"FAILED")
        self.assertEqual(rows["builder-b"]["exit_code"],13)

    def test_fresh_replacement_is_appended_without_erasing_initial_evidence(self):
        out=self.launcher().launch_initial(self.prepared)
        replacement=self._item("builder-b2","task-b2",self.root/"wb2","0.50")
        Path(replacement["worktree"]).mkdir()
        replacement["replacement_for"]="task-b"
        out2=self.launcher().launch_replacement(self.prepared,replacement,out)
        self.assertEqual(len(out2["workers"]),3)
        self.assertEqual(out2["replacement_proof"]["replacement_for"],"task-b")
        self.assertEqual(out2["workers"][-1]["builder_id"],"builder-b2")
        self.assertIn("concurrent_proof",out2)

    def test_second_launch_failure_stops_and_revokes_first(self):
        sup=Supervisor(fail_on="builder-b")
        launcher=self.launcher(sup)
        with self.assertRaises(SelfBuildLaunchError) as cm:
            launcher.launch_initial(self.prepared)
        self.assertEqual(cm.exception.code,"WORKER_LAUNCH_FAILED")
        self.assertEqual(sup.stopped[0][0],"builder-a")
        revoked={x["task_id"] for x in self.client.revoked}
        self.assertIn("task-a",revoked)
        self.assertIn("task-b",revoked)

    def test_second_prelaunch_failure_revokes_both_unstarted_authorities_and_reports(self):
        calls=[]
        def issue(packet,workspace,executor,ttl):
            calls.append(packet)
            if len(calls)==2:
                raise RuntimeError("lease preparation boom")
            return {"ok":True,"lease":str(self.state/"lease-prep.json"),"token":"TOKEN-PREP"}
        launcher=SelfBuildLauncher(
            client=self.client,supervisor=self.supervisor,state_root=self.state,
            python_executable=self.python,runner_path=self.runner,issue_lease_fn=issue,
            freeze_fn=freeze_candidate,
            container_cleanup_fn=lambda **kw:{"container_empty":True,"observed_container_ids":[]},
            clock=lambda:1000.0,
        )
        with self.assertRaises(RuntimeError):
            launcher.launch_initial(self.prepared)
        self.assertEqual(self.supervisor.launched,[])
        revoked={x["task_id"] for x in self.client.revoked}
        self.assertEqual(revoked,{"task-a","task-b"})
        report=self.state/"self-build-launch"/"fl1-run"/"initial-launch-failure.json"
        self.assertTrue(report.is_file())
        data=json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(data["error_code"],"RuntimeError")
        self.assertIn("lease preparation boom",data["message"])

    def test_public_launch_record_never_contains_executor_lease_token(self):
        out=self.launcher().launch_initial(self.prepared)
        raw=json.dumps(out,sort_keys=True)
        self.assertNotIn("TOKEN-0",raw);self.assertNotIn("TOKEN-1",raw)
        self.assertNotIn("EXECUTOR_LEASE_TOKEN",raw)

    def test_status_uses_external_result_evidence_not_exit_zero_as_acceptance(self):
        out=self.launcher().launch_initial(self.prepared)
        first=out["workers"][0]
        Path(first["result_file"]).parent.mkdir(parents=True,exist_ok=True)
        Path(first["result_file"]).write_text(json.dumps({"completed":True,"cost_usd":0.2,"error":None}),encoding="utf-8")
        status=self.launcher().status(out)
        self.assertTrue(status["workers"][0]["result"]["completed"])
        self.assertEqual(status["workers"][0]["state"],"RUNNING")
        self.assertIsNone(status["workers"][1]["result"])

    def test_stop_requires_containment_empty_before_protected_revoke(self):
        out=self.launcher().launch_initial(self.prepared)
        result=self.launcher().stop_worker(
            prepared_run=self.prepared,launched_run=out,builder_id="builder-b",reason="mandatory proof"
        )
        self.assertTrue(result["stopped"])
        self.assertEqual(self.client.revoked[-1]["task_id"],"task-b")
        self.assertTrue(result["docker_evidence"]["container_empty"])

    def test_complete_worker_surfaces_persisted_worker_error(self):
        class FailedComplete(Supervisor):
            def complete(self,worker_id,expected_generation,*,timeout=5.0):
                raise SupervisorError("WORKER_COMPLETION_UNPROVEN","worker-exit-nonzero")
        sup=FailedComplete()
        launcher=self.launcher(sup)
        out=launcher.launch_initial(self.prepared)
        first=out["workers"][0]
        Path(first["result_file"]).parent.mkdir(parents=True,exist_ok=True)
        Path(first["result_file"]).write_text(json.dumps({
            "schema":1,"executor":"mini-swe","model":"test","cost_usd":0.0,"calls":0,
            "completed":False,"error":"protected paid-start guard denied: fixture",
            "task_id":"task-a","builder_id":"builder-a","run_id":"fl1-run",
            "expected_head_revision":"a"*40,"workspace":str(self.worka.resolve()),
            "packet_sha256":first["packet_sha256"],"postflight":None,
        }),encoding="utf-8")
        with self.assertRaises(SelfBuildLaunchError) as cm:
            launcher.complete_worker(prepared_run=self.prepared,launched_run=out,builder_id="builder-a")
        self.assertEqual(cm.exception.code,"WORKER_COMPLETION_UNPROVEN")
        self.assertIn("builder-a",str(cm.exception))
        self.assertIn("protected paid-start guard denied",str(cm.exception))

    def test_complete_worker_freezes_then_records_protected_handoff(self):
        out=self.launcher(freeze_fn=lambda **kw:{
            "schema":1,"task_id":"task-a","builder_id":"builder-a",
            "base_sha":"a"*40,"candidate_sha":"c"*40,
            "changed_files":["forgeboss/tests/test_builder-a.py"],"changed_lines":5,
            "focused_tests":[],"measured_cost_usd":"0.20",
            "postflight_changed_paths":["forgeboss/tests/test_builder-a.py"],
            "runner_result_digest":"d"*64,"evidence_digest":"e"*64,
        }).launch_initial(self.prepared)
        first=out["workers"][0]
        Path(first["result_file"]).parent.mkdir(parents=True,exist_ok=True)
        Path(first["result_file"]).write_text(json.dumps({"schema":1}),encoding="utf-8")
        handoff=self.launcher(freeze_fn=lambda **kw:{
            "schema":1,"task_id":"task-a","builder_id":"builder-a",
            "base_sha":"a"*40,"candidate_sha":"c"*40,
            "changed_files":["forgeboss/tests/test_builder-a.py"],"changed_lines":5,
            "focused_tests":[],"measured_cost_usd":"0.20",
            "postflight_changed_paths":["forgeboss/tests/test_builder-a.py"],
            "runner_result_digest":"d"*64,"evidence_digest":"e"*64,
        })
        # Use the same supervisor/client and external state as the launched run.
        handoff.supervisor=self.supervisor;handoff.client=self.client
        result=handoff.complete_worker(prepared_run=self.prepared,launched_run=out,builder_id="builder-a")
        self.assertEqual(result["candidate_sha"],"c"*40)
        self.assertEqual(result["review_status"],"FROZEN_AWAITING_INDEPENDENT_REVIEW")
        self.assertEqual(self.client.handoffs[-1]["evidence"]["candidate_sha"],"c"*40)
        self.assertEqual(self.client.handoffs[-1]["evidence"]["measured_cost_usd"],"0.20")
        self.assertTrue(Path(first["result_file"]).parent.joinpath("candidate-evidence.json").is_file())
        review_response=handoff.review_candidate(prepared_run=self.prepared,launched_run=out,builder_id="builder-a")
        self.assertEqual(review_response["result"]["status"],"PASS")
        self.assertEqual(self.client.reviews[-1]["task_id"],"task-a")
        self.assertNotIn("review",self.client.reviews[-1])
        accepted=handoff.accept_reviewed_candidate(prepared_run=self.prepared,launched_run=out,builder_id="builder-a")
        self.assertEqual(accepted["result"]["status"],"ACCEPTED")
        self.assertEqual(self.client.accepted[-1]["task_id"],"task-a")

    def test_finish_review_accept_compose_uses_only_a_and_b2(self):
        launcher=self.launcher()
        replacement=self._item("builder-b2","task-b2",self.root/"wb2","0.50")
        replacement["replacement_for"]="task-b";self.prepared["replacement"]=replacement
        launched={"run_id":"fl1-run","workers":[{"builder_id":"builder-a"},{"builder_id":"builder-b2"}]}
        completed=[];reviewed=[];accepted=[]
        def complete(**kw):completed.append(kw["builder_id"]);return {"candidate_sha":"c"*40}
        def review(**kw):reviewed.append(kw["builder_id"]);return {"result":{"status":"PASS"}}
        def accept(**kw):accepted.append(kw["builder_id"]);return {"result":{"status":"ACCEPTED"}}
        with patch.object(launcher,"complete_worker",side_effect=complete),patch.object(launcher,"review_candidate",side_effect=review),patch.object(launcher,"accept_reviewed_candidate",side_effect=accept):
            out=launcher.finish_review_accept_compose(prepared_run=self.prepared,launched_run=launched,timeout=1,poll_seconds=0.01)
        self.assertEqual(completed,["builder-a","builder-b2"]);self.assertEqual(reviewed,completed);self.assertEqual(accepted,completed)
        self.assertEqual(out["successor"]["status"],"COMPOSED_AWAITING_ACTIVATION")
        self.assertEqual(self.client.composed,[{"run_id":"fl1-run"}])

    def test_activate_composed_successor_requires_protected_final_status_and_persists_receipt(self):
        launcher=self.launcher()
        out=launcher.activate_composed_successor(run_id="fl1-run")
        self.assertEqual(out["result"]["status"],"ACTIVATED_KNOWN_GOOD")
        self.assertEqual(self.client.activated,[{"run_id":"fl1-run"}])
        self.assertTrue((launcher.run_root/"fl1-run"/"activation.json").is_file())

    def test_finish_review_failure_revokes_unaccepted_writers_and_never_composes(self):
        launcher=self.launcher()
        replacement=self._item("builder-b2","task-b2",self.root/"wb2","0.50")
        replacement["replacement_for"]="task-b";self.prepared["replacement"]=replacement
        launched={"run_id":"fl1-run","workers":[{"builder_id":"builder-a"},{"builder_id":"builder-b2"}]}
        stops=[]
        def review(**kw):
            return {"result":{"status":"PASS" if kw["builder_id"]=="builder-a" else "FAIL"}}
        def stop(**kw):stops.append(kw["builder_id"]);return {"stopped":True}
        with patch.object(launcher,"complete_worker",return_value={"candidate_sha":"c"*40}),patch.object(launcher,"review_candidate",side_effect=review),patch.object(launcher,"stop_worker",side_effect=stop):
            with self.assertRaises(SelfBuildLaunchError) as cm:
                launcher.finish_review_accept_compose(prepared_run=self.prepared,launched_run=launched,timeout=1,poll_seconds=0.01)
        self.assertEqual(cm.exception.code,"INDEPENDENT_REVIEW_FAILED")
        self.assertEqual(stops,["builder-a","builder-b2"]);self.assertEqual(self.client.composed,[])

    @unittest.skipUnless(__import__("shutil").which("git"),"git required")
    def test_freeze_candidate_real_git_scope_test_and_exact_sha(self):
        import subprocess,sys,shutil
        repo=self.root/"freeze-repo";repo.mkdir()
        git=Path(shutil.which("git")).resolve()
        def g(*args):
            p=subprocess.run([str(git),"-C",str(repo),*args],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,msg=p.stderr);return p.stdout.strip()
        g("init","-q");g("config","user.email","test@example.invalid");g("config","user.name","Test")
        (repo/"pkg").mkdir();(repo/"pkg"/"__init__.py").write_text("",encoding="utf-8")
        g("add",".");g("commit","-qm","base");base=g("rev-parse","HEAD")
        candidate=repo/"pkg"/"test_candidate.py"
        candidate.write_text("import unittest\nclass T(unittest.TestCase):\n    def test_ok(self): self.assertEqual(2+2,4)\n",encoding="utf-8")
        item={
            "task_id":"task-a","builder_id":"builder-a","worktree":str(repo),
            "authority":{"budget_usd":"1.00"},
            "packet":{
                "run_id":"fl1-run","expected_head_revision":base,
                "allowed_files":["pkg/test_candidate.py"],
                "required_tests":["python -m unittest pkg.test_candidate -v"],
                "max_changed_files":1,"max_changed_lines":20,
            },
        }
        public={"packet_sha256":"f"*64}
        result={
            "schema":1,"executor":"mini-swe","model":"test","cost_usd":0.2,"calls":1,
            "completed":True,"error":None,"task_id":"task-a","builder_id":"builder-a",
            "run_id":"fl1-run","expected_head_revision":base,"workspace":str(repo.resolve()),
            "packet_sha256":"f"*64,
            "postflight":{"ok":True,"scope_ok":True,"paid_consumed":True,"changed_paths":["pkg/test_candidate.py"]},
        }
        process={"state":"STOPPED","containmentEmpty":True,"exitCode":0,"reason":"verified-complete"}
        frozen=freeze_candidate(item=item,public=public,result=result,process_evidence=process,git_executable=git,python_executable=Path(sys.executable))
        self.assertNotEqual(frozen["candidate_sha"],base)
        self.assertEqual(frozen["changed_files"],["pkg/test_candidate.py"])
        self.assertEqual(g("status","--porcelain=v1"),"")
        self.assertEqual(g("diff","--name-only",base,frozen["candidate_sha"]),"pkg/test_candidate.py")

    def test_state_root_inside_forgeboss_source_is_rejected(self):
        source=Path(__file__).resolve().parents[2]
        with self.assertRaises(SelfBuildLaunchError) as cm:
            SelfBuildLauncher(
                client=self.client,supervisor=self.supervisor,state_root=source/"state",
                python_executable=self.python,runner_path=self.runner,issue_lease_fn=self.issue,
            )
        self.assertEqual(cm.exception.code,"STATE_ROOT_INSIDE_SOURCE")


if __name__=="__main__":unittest.main()