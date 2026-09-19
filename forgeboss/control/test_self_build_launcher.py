from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from forgeboss.control.self_build_launcher import SelfBuildLauncher,SelfBuildLaunchError
from forgeboss.control.process_supervisor import ProcessSupervisor
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
    def as_dict(self):return {"state":self.state,"containment_empty":self.containment_empty}


class Client(ProtectedAuthorityClient):
    def __init__(self):
        self.attested=[];self.revoked=[]
    def attest_launch_payload(self,signed):
        self.attested.append(dict(signed))
        return {"schema":1,"envelope":{"signed":dict(signed),"signature":"sig"},"authorityResponse":{"receipt":"public"}}
    def revoke_self_build_worker(self,**kw):
        self.revoked.append(dict(kw));return {"result":{"revoked":True}}


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

    def launcher(self,supervisor=None):
        return SelfBuildLauncher(
            client=self.client,supervisor=supervisor or self.supervisor,state_root=self.state,
            python_executable=self.python,runner_path=self.runner,issue_lease_fn=self.issue,clock=lambda:1000.0,
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

    def test_state_root_inside_forgeboss_source_is_rejected(self):
        source=Path(__file__).resolve().parents[2]
        with self.assertRaises(SelfBuildLaunchError) as cm:
            SelfBuildLauncher(
                client=self.client,supervisor=self.supervisor,state_root=source/"state",
                python_executable=self.python,runner_path=self.runner,issue_lease_fn=self.issue,
            )
        self.assertEqual(cm.exception.code,"STATE_ROOT_INSIDE_SOURCE")


if __name__=="__main__":unittest.main()
