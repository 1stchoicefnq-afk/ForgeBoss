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
    def test_complete_worker_releases_exact_authority_and_is_idempotent(self):
        class Store:
            def __init__(self):self.calls=[]
            def release(self,*args,**kw):self.calls.append((args,kw))
        self.runtime.store=Store()
        path=self.runtime._run_path("fl1-c")
        item={
            "task_id":"task-a","owner_epoch":3,
            "authority":{"run_id":"worker-a","budget_usd":"1.00"},
        }
        path.write_text(json.dumps({
            "schema":1,"phase":"PREPARED",
            "prepared":{"run_id":"fl1-c","base_sha":self.base,"builders":[item]},
            "replacement":None,
        }),encoding="utf-8")
        payload={"runId":"fl1-c","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":3,
                 "resultHead":"b"*40,"measuredCostUsd":"0.25","resultDigest":"c"*64}
        out=self.runtime.complete_worker(payload)
        self.assertTrue(out["completed"])
        self.assertEqual(len(self.runtime.store.calls),1)
        args,kw=self.runtime.store.calls[0]
        self.assertEqual(args[:3],("task-a","worker-a",3))
        self.assertEqual(kw["result_head"],"b"*40)
        self.assertEqual(kw["expected_head"],self.base)
        again=self.runtime.complete_worker(payload)
        self.assertEqual(again,out)
        self.assertEqual(len(self.runtime.store.calls),1)

    def test_complete_worker_rejects_cost_over_cap_before_release(self):
        class Store:
            def release(self,*args,**kw):raise AssertionError("release must not run")
        self.runtime.store=Store()
        path=self.runtime._run_path("fl1-over")
        item={"task_id":"task-a","owner_epoch":1,"authority":{"run_id":"worker-a","budget_usd":"0.50"}}
        path.write_text(json.dumps({"schema":1,"phase":"PREPARED","prepared":{"base_sha":self.base,"builders":[item]},"replacement":None}),encoding="utf-8")
        with self.assertRaises(SelfBuildRuntimeError) as cm:
            self.runtime.complete_worker({"runId":"fl1-over","taskId":"task-a","workerRunId":"worker-a","ownerEpoch":1,
                                          "resultHead":"b"*40,"measuredCostUsd":"0.500001","resultDigest":"c"*64})
        self.assertEqual(cm.exception.code,"MEASURED_COST_EXCEEDS_AUTHORITY")

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
