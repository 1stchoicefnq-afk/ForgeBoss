from __future__ import annotations
import sqlite3,tempfile,time,unittest
from pathlib import Path
from forgeboss.control.store import ControlStore,AssignmentAuthorityError,BudgetReservationError,WorkspaceCollisionError

BASE="a"*40;CONTENT="b"*64
class StoreAuthorityV3Tests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name);self.wsroot=self.root/"workspaces";self.wsroot.mkdir();self.db=self.root/"control.db";self.store=ControlStore(self.db)
    def tearDown(self):
        try:self.store.db.close()
        except Exception:pass
        self.td.cleanup()
    def task(self,tid="t1",budget=10,paths=None):
        return self.store.create_task({"taskId":tid,"repository":"Owner/Repo","purpose":"x","baseSha":BASE,"allowedPaths":paths or ["src/a"],"requiredTests":[],"budgetUsd":budget})
    def legacy(self,tid="t1",run="r1",head=BASE,budget=0):
        return self.store.claim_workspace(tid,run,self.wsroot/tid,None,head,worktree_root=self.wsroot,budget_reserved=budget)
    def bound(self,tid="t1",run="r1",head=BASE,generation=1,budget=0,principal="worker-a",wsgen="1",content=CONTENT):
        return self.store.claim_workspace(tid,run,self.wsroot/tid,None,head,worktree_root=self.wsroot,budget_reserved=budget,builder_principal=principal,assignment_generation=generation,workspace_generation=wsgen,workspace_content_identity=content)
    def test_legacy_never_bound_reclaim_remains_compatible(self):
        self.task();lease=self.legacy();self.assertIsNone(lease["assignment_digest"]);self.store.release("t1","r1",1,result_head=BASE);lease2=self.legacy(run="r2");self.assertEqual(lease2["owner_epoch"],2);self.assertEqual(self.store.get_task("t1")["assignment_bound_ever"],0)
    def test_first_bound_claim_sets_permanent_history_and_digest(self):
        self.task();lease=self.bound();task=self.store.get_task("t1");self.assertEqual((task["assignment_bound_ever"],task["assignment_generation"]),(1,1));auth=self.store.get_assignment_authority("t1");self.assertEqual(auth["digest"],lease["assignment_digest"]);ident=auth["identity"];self.assertEqual(ident["builderPrincipal"],"worker-a");self.assertEqual((ident["assignmentGeneration"],ident["attempt"],ident["ownerEpoch"]),(1,1,1));self.assertEqual(ident["repository"],"owner/repo");self.assertEqual(ident["baseSha"],BASE);self.assertEqual(ident["workspaceGeneration"],"1");self.assertEqual(ident["workspaceContentIdentity"],CONTENT)
    def test_bound_task_cannot_downgrade_to_legacy_after_release(self):
        self.task();lease=self.bound();digest=lease["assignment_digest"];self.store.release("t1","r1",1,result_head=BASE,assignment_digest=digest)
        with self.assertRaises(AssignmentAuthorityError) as cm:self.legacy(run="r2")
        self.assertEqual(cm.exception.code,"ASSIGNMENT_DOWNGRADE_DENIED");self.assertEqual(self.store.get_task("t1")["assignment_bound_ever"],1)
    def test_retry_requires_exact_next_assignment_generation(self):
        self.task();first=self.bound();self.store.release("t1","r1",1,result_head=BASE,assignment_digest=first["assignment_digest"])
        for bad in (1,3,True,0):
            with self.subTest(bad=bad),self.assertRaises(AssignmentAuthorityError):self.bound(run=f"bad{bad}",generation=bad)
        second=self.bound(run="r2",generation=2,wsgen="2",content="c"*64);self.assertEqual(second["assignment_generation"],2);self.assertNotEqual(first["assignment_digest"],second["assignment_digest"])
    def test_stale_digest_denied_after_release_and_retry(self):
        self.task();first=self.bound();d1=first["assignment_digest"];self.store.release("t1","r1",1,result_head=BASE,assignment_digest=d1)
        with self.assertRaises(AssignmentAuthorityError) as cm:self.store.assert_assignment_authority("t1",d1)
        self.assertEqual(cm.exception.code,"ASSIGNMENT_INACTIVE");second=self.bound(run="r2",generation=2,wsgen="2",content="c"*64);d2=second["assignment_digest"]
        with self.assertRaises(AssignmentAuthorityError) as cm:self.store.assert_assignment_authority("t1",d1)
        self.assertEqual(cm.exception.code,"ASSIGNMENT_STALE");self.store.assert_assignment_authority("t1",d2,runId="r2",ownerEpoch=2,assignmentGeneration=2)
    def test_bound_writer_operations_require_digest(self):
        self.task();lease=self.bound();d=lease["assignment_digest"]
        with self.assertRaises(AssignmentAuthorityError):self.store.assert_writer("t1","r1",1)
        with self.assertRaises(AssignmentAuthorityError):self.store.heartbeat("t1","r1",1)
        with self.assertRaises(AssignmentAuthorityError):self.store.release("t1","r1",1)
        self.store.assert_writer("t1","r1",1,assignment_digest=d);self.store.heartbeat("t1","r1",1,assignment_digest=d);self.store.release("t1","r1",1,assignment_digest=d)
    def test_partial_bound_fields_fail_without_mutation(self):
        self.task();before=self.store.get_task("t1")
        with self.assertRaises(AssignmentAuthorityError):self.store.claim_workspace("t1","r1",self.wsroot/"t1",None,BASE,worktree_root=self.wsroot,builder_principal="w")
        after=self.store.get_task("t1");self.assertEqual(after["budget_spent"],before["budget_spent"]);self.assertIsNone(self.store.get_lease("t1"))
    def test_tampered_durable_identity_or_digest_fails_closed(self):
        self.task();lease=self.bound();d=lease["assignment_digest"];self.store.db.execute("UPDATE workspace_leases SET builder_principal='attacker' WHERE task_id='t1'")
        with self.assertRaises(AssignmentAuthorityError) as cm:self.store.assert_assignment_authority("t1",d)
        self.assertEqual(cm.exception.code,"ASSIGNMENT_STATE_INVALID")
    def test_restart_preserves_bound_history_and_stale_fencing(self):
        self.task();first=self.bound();d1=first["assignment_digest"];self.store.release("t1","r1",1,result_head=BASE,assignment_digest=d1);self.store.db.close();self.store=ControlStore(self.db);self.assertEqual(self.store.get_task("t1")["assignment_bound_ever"],1)
        with self.assertRaises(AssignmentAuthorityError):self.legacy(run="r2")
        second=self.bound(run="r2",generation=2,wsgen="2",content="c"*64)
        with self.assertRaises(AssignmentAuthorityError):self.store.assert_assignment_authority("t1",d1)
        self.store.assert_assignment_authority("t1",second["assignment_digest"])
    def test_budget_reservation_semantics_preserved(self):
        self.task(budget=1);lease=self.bound(budget=.6);self.assertAlmostEqual(self.store.get_task("t1")["budget_spent"],.6);self.store.release("t1","r1",1,result_head=BASE,assignment_digest=lease["assignment_digest"])
        with self.assertRaises(BudgetReservationError):self.bound(run="r2",generation=2,budget=.5,wsgen="2",content="c"*64)
        self.assertAlmostEqual(self.store.get_task("t1")["budget_spent"],.6)
    def test_collision_semantics_preserved(self):
        self.task("t1",paths=["src"]);self.task("t2",paths=["src/a"]);self.bound("t1","r1")
        with self.assertRaises(WorkspaceCollisionError) as cm:self.store.claim_workspace("t2","r2",self.wsroot/"t2",None,BASE,worktree_root=self.wsroot,builder_principal="worker-b",assignment_generation=1,workspace_generation="1",workspace_content_identity="c"*64)
        self.assertEqual(cm.exception.code,"WRITABLE_SCOPE_COLLISION")
    def test_migration_from_schema3_adds_columns_without_marking_legacy_bound(self):
        other=self.root/"old.db";db=sqlite3.connect(other);db.executescript("""CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);CREATE TABLE tasks(task_id TEXT PRIMARY KEY,repository TEXT NOT NULL,purpose TEXT NOT NULL,base_sha TEXT NOT NULL,branch TEXT,status TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,current_step TEXT,assigned_runtime TEXT,allowed_paths_json TEXT NOT NULL DEFAULT '[]',required_tests_json TEXT NOT NULL DEFAULT '[]',budget_allocated REAL NOT NULL DEFAULT 0,budget_spent REAL NOT NULL DEFAULT 0,cancel_requested_at REAL,result_head TEXT,terminal_outcome TEXT,created_at REAL NOT NULL,updated_at REAL NOT NULL);CREATE TABLE task_runs(run_id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(task_id),attempt INTEGER NOT NULL,owner_epoch INTEGER NOT NULL,runtime_id TEXT,status TEXT NOT NULL,started_at REAL NOT NULL,finished_at REAL);CREATE TABLE task_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT,run_id TEXT,event_type TEXT NOT NULL,payload_json TEXT NOT NULL,state_version INTEGER NOT NULL,created_at REAL NOT NULL);CREATE TABLE workspace_leases(task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),worktree_path TEXT NOT NULL,branch TEXT,owner_run_id TEXT NOT NULL,owner_epoch INTEGER NOT NULL,claimed_at REAL NOT NULL,heartbeat_at REAL NOT NULL,expires_at REAL NOT NULL,released_at REAL,current_head TEXT NOT NULL,budget_reserved REAL NOT NULL DEFAULT 0);CREATE TABLE worker_instances(worker_id TEXT PRIMARY KEY,task_id TEXT,run_id TEXT,owner_epoch INTEGER,runtime_id TEXT NOT NULL,envelope_hash TEXT NOT NULL,status TEXT NOT NULL,last_seen_at REAL NOT NULL);CREATE TABLE validation_receipts(receipt_id TEXT PRIMARY KEY,task_id TEXT NOT NULL,run_id TEXT,result_json TEXT NOT NULL,created_at REAL NOT NULL);CREATE TABLE artefacts(artefact_id TEXT PRIMARY KEY,task_id TEXT,type TEXT NOT NULL,path TEXT NOT NULL,sha256 TEXT NOT NULL,size INTEGER NOT NULL,created_at REAL NOT NULL);CREATE TABLE provider_usage(id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT,run_id TEXT,provider TEXT,model TEXT,input_tokens INTEGER,output_tokens INTEGER,cost_usd REAL NOT NULL DEFAULT 0,created_at REAL NOT NULL);""");now=time.time();db.execute("INSERT INTO tasks(task_id,repository,purpose,base_sha,branch,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",("legacy","owner/repo","x",BASE,None,"queued",now,now));db.commit();db.close();migrated=ControlStore(other)
        try:task=migrated.get_task("legacy");self.assertEqual((task["assignment_bound_ever"],task["assignment_generation"]),(0,0));cols={r[1] for r in migrated.db.execute("PRAGMA table_info(workspace_leases)")};self.assertIn("assignment_digest",cols)
        finally:migrated.db.close()
if __name__=="__main__":unittest.main()