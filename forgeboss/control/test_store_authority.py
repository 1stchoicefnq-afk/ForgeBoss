from __future__ import annotations
import concurrent.futures,sqlite3,tempfile,threading,time,unittest
from decimal import Decimal
from pathlib import Path
from forgeboss.control.store import BudgetReservationError,ControlStore,StoreAuthorityError

class StoreAuthorityV2Tests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.base=Path(self.td.name);self.root=self.base/"worktrees";self.root.mkdir();self.db=self.base/"state"/"control.sqlite3";self.store=ControlStore(self.db)
    def tearDown(self):
        try:self.store.db.close()
        except Exception:pass
        self.td.cleanup()
    def task(self,tid,budget=10,paths=None):
        self.store.create_task({"taskId":tid,"repository":"owner/repo","purpose":"fl1","baseSha":"a"*40,"branch":"b-"+tid,"allowedPaths":paths or [f"src/{tid}.py"],"requiredTests":["python -m unittest"],"budgetUsd":budget})
    def bind(self,tid,builder="builder-a",budget_run="GLOBAL"):
        if not self.store.get_budget_run(budget_run):self.store.create_budget_run(budget_run,10)
        return self.store.assign_builder(tid,builder,budget_run)
    def claim(self,tid,run,assignment,amount,store=None,global_revision=None,branch=None):
        s=store or self.store
        if global_revision is None:global_revision=int(s.get_budget_run(assignment["budgetRunId"])["revision"])
        return s.claim_workspace(tid,run,self.root/tid,branch or "b-"+tid,"a"*40,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=amount,
            builder_id=assignment["builderId"],assignment_token=assignment["assignmentToken"],assignment_generation=assignment["assignmentGeneration"],
            assignment_sha256=assignment["assignmentSha256"],budget_run_revision=global_revision)
    def counts(self,tid):
        return (self.store.get_task(tid)["budget_spent"],self.store.db.execute("SELECT COUNT(*) FROM task_runs WHERE task_id=?",(tid,)).fetchone()[0],
                self.store.db.execute("SELECT COUNT(*) FROM task_events WHERE task_id=? AND event_type='workspace.claimed'",(tid,)).fetchone()[0])
    def rolled_back_read(self,sql,params,reader):
        started=threading.Event();pool=concurrent.futures.ThreadPoolExecutor(max_workers=1);future=None
        self.store._lock.acquire()
        try:
            self.store.db.execute("BEGIN IMMEDIATE");self.store.db.execute(sql,params)
            def run():started.set();return reader()
            future=pool.submit(run);self.assertTrue(started.wait(1));time.sleep(0.05);self.assertFalse(future.done(),"authoritative read exposed in-flight same-connection transaction")
            self.store.db.execute("ROLLBACK")
        finally:
            self.store._lock.release()
        try:return future.result(timeout=2)
        finally:pool.shutdown(wait=True)

    def test_global_budget_6_then_5_denied_without_leak(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");self.task("B");a=self.bind("A");b=self.bind("B")
        self.claim("A","ra",a,6)
        before=self.counts("B")
        with self.assertRaises(BudgetReservationError) as cm:self.claim("B","rb",b,5)
        self.assertEqual(cm.exception.code,"GLOBAL_BUDGET_EXCEEDED");self.assertEqual(self.counts("B"),before)
        self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],"6")

    def test_exact_global_boundary_6_plus_4(self):
        self.store.create_budget_run("GLOBAL","10.00");self.task("A");self.task("B");a=self.bind("A");b=self.bind("B")
        self.claim("A","ra",a,"6.00");self.claim("B","rb",b,"4.00")
        self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],"10")
        self.assertEqual(self.store.get_budget_run("GLOBAL")["remaining_exact"],"0")

    def test_task_and_global_caps_are_independent(self):
        self.store.create_budget_run("GLOBAL",20);self.task("A",3);a=self.bind("A")
        with self.assertRaises(BudgetReservationError) as cm:self.claim("A","ra",a,4)
        self.assertEqual(cm.exception.code,"BUDGET_EXCEEDED");self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],"0")

    def test_wrong_builder_token_generation_digest_and_revision_fail_before_mutation(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");before=self.counts("A")
        kwargs=dict(task_id="A",run_id="r",worktree=self.root/"A",branch="b-A",current_head="a"*40,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=1,
                    builder_id=a["builderId"],assignment_token=a["assignmentToken"],assignment_generation=a["assignmentGeneration"],assignment_sha256=a["assignmentSha256"],budget_run_revision=a["budgetRunRevision"])
        for field,bad in (("builder_id","other"),("assignment_token","bad"),("assignment_generation",999),("assignment_sha256","0"*64),("budget_run_revision",999)):
            with self.subTest(field=field):
                x=dict(kwargs);x[field]=bad
                with self.assertRaises(StoreAuthorityError):self.store.claim_workspace(**x)
                self.assertEqual(self.counts("A"),before);self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],"0")

    def test_wrong_branch_rejected_before_any_claim_or_budget_mutation(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");before=self.counts("A");gbefore=self.store.get_budget_run("GLOBAL")["reserved_exact"]
        with self.assertRaises(StoreAuthorityError) as cm:self.claim("A","bad-branch",a,2,branch="attacker-branch")
        self.assertEqual(cm.exception.code,"ASSIGNMENT_BRANCH_MISMATCH");self.assertEqual(self.counts("A"),before)
        self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],gbefore);self.assertIsNone(self.store.get_lease("A"))

    def test_invalid_assigned_branch_is_rejected_before_assignment(self):
        with self.assertRaises(StoreAuthorityError) as cm:self.store.create_task({"taskId":"A","repository":"owner/repo","purpose":"fl1","baseSha":"a"*40,"branch":"bad..branch","allowedPaths":["src/a.py"],"requiredTests":[],"budgetUsd":1})
        self.assertEqual(cm.exception.code,"BRANCH_INVALID")

    def test_reassign_rotates_token_generation_and_old_authority_fails_after_restart(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A","builder-a");b=self.store.assign_builder("A","builder-b","GLOBAL")
        self.assertGreater(b["assignmentGeneration"],a["assignmentGeneration"]);self.assertNotEqual(a["assignmentToken"],b["assignmentToken"]);self.assertNotEqual(a["assignmentSha256"],b["assignmentSha256"])
        self.store.db.close();self.store=ControlStore(self.db)
        with self.assertRaises(StoreAuthorityError):self.claim("A","old",a,1)
        self.claim("A","new",b,1)

    def test_assignment_digest_is_stable_and_binds_exact_assignment(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A")
        row=self.store.get_task("A");self.assertEqual(row["assignment_sha256"],a["assignmentSha256"]);self.assertEqual(len(a["assignmentSha256"]),64)
        self.store.db.close();self.store=ControlStore(self.db);self.assertEqual(self.store.get_task("A")["assignment_sha256"],a["assignmentSha256"])

    def test_duplicate_run_failure_rolls_back_task_and_global_reservation(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");self.task("B");a=self.bind("A");b=self.bind("B")
        self.claim("A","same",a,2);self.store.release("A","same",1)
        gbefore=self.store.get_budget_run("GLOBAL")["reserved_exact"];before=self.counts("B")
        with self.assertRaises(sqlite3.IntegrityError):self.claim("B","same",b,3)
        self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],gbefore);self.assertEqual(self.counts("B"),before)

    def test_release_invalidates_assignment_and_does_not_refund(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");lease=self.claim("A","ra",a,3)
        self.store.release("A","ra",lease["owner_epoch"],outcome="released");self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],"3")
        row=self.store.get_task("A");self.assertIsNone(row["assigned_builder_id"]);self.assertIsNone(row["assignment_token_hash"]);self.assertIsNone(row["assignment_sha256"]);self.assertGreater(row["assignment_generation"],a["assignmentGeneration"])
        before=self.counts("A");gbefore=self.store.get_budget_run("GLOBAL")["reserved_exact"]
        with self.assertRaises(StoreAuthorityError):self.claim("A","reclaim",a,2)
        self.assertEqual(self.counts("A"),before);self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],gbefore)
        self.store.retry_task("A","continue after review");b=self.store.assign_builder("A","builder-a","GLOBAL");lease2=self.claim("A","rb",b,2);self.store.revoke_writer("A","rb",lease2["owner_epoch"],"stop")
        self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],"5");self.assertEqual(self.store.get_task("A")["budget_spent"],5.0)

    def test_revoke_is_idempotent_and_fences_writer(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");lease=self.claim("A","ra",a,1);epoch=lease["owner_epoch"]
        first=self.store.revoke_writer("A","ra",epoch,"stop");second=self.store.revoke_writer("A","ra",epoch,"stop")
        self.assertIsNotNone(first["revoked_at"]);self.assertEqual(first["revoked_at"],second["revoked_at"])
        with self.assertRaises(PermissionError):self.store.heartbeat("A","ra",epoch)
        with self.assertRaises(PermissionError):self.store.release("A","ra",epoch)

    def test_retry_invalidates_revoked_assignment_before_reassignment_and_restart(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");lease=self.claim("A","ra",a,1);self.store.revoke_writer("A","ra",lease["owner_epoch"],"stop")
        revoked=self.store.get_task("A");self.assertIsNone(revoked["assigned_builder_id"]);self.assertIsNone(revoked["assignment_token_hash"]);self.assertIsNone(revoked["assignment_sha256"]);self.assertGreater(revoked["assignment_generation"],a["assignmentGeneration"])
        self.store.retry_task("A","replacement");row=self.store.get_task("A");self.assertGreater(row["assignment_generation"],revoked["assignment_generation"])
        before=self.counts("A");gbefore=self.store.get_budget_run("GLOBAL")["reserved_exact"]
        with self.assertRaises(StoreAuthorityError) as cm:self.claim("A","stale",a,2)
        self.assertEqual(cm.exception.code,"ASSIGNMENT_REQUIRED");self.assertEqual(self.counts("A"),before);self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],gbefore)
        self.store.db.close();self.store=ControlStore(self.db)
        with self.assertRaises(StoreAuthorityError):self.claim("A","stale-after-restart",a,2)
        b=self.store.assign_builder("A","builder-b","GLOBAL");self.assertGreater(b["assignmentGeneration"],row["assignment_generation"]);self.claim("A","replacement",b,1)

    def test_retry_required_for_revoked_and_cancelled(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");lease=self.claim("A","ra",a,1);self.store.revoke_writer("A","ra",lease["owner_epoch"],"stop")
        with self.assertRaises(StoreAuthorityError) as cm:self.claim("A","rb",a,1)
        self.assertEqual(cm.exception.code,"TASK_RETRY_REQUIRED")
        self.store.retry_task("A","replacement")
        with self.assertRaises(StoreAuthorityError):self.claim("A","old-after-retry",a,1)
        b=self.store.assign_builder("A","builder-b","GLOBAL");self.claim("A","rb",b,1)

    def test_stale_epoch_cannot_revoke_newer_owner(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");l1=self.claim("A","r1",a,1);self.store.release("A","r1",l1["owner_epoch"])
        self.store.retry_task("A","continue after release");b=self.store.assign_builder("A","builder-b","GLOBAL");l2=self.claim("A","r2",b,1)
        with self.assertRaises(StoreAuthorityError) as cm:self.store.revoke_writer("A","r1",l1["owner_epoch"],"stale")
        self.assertEqual(cm.exception.code,"REVOKE_STALE_AUTHORITY");self.store.assert_writer("A","r2",l2["owner_epoch"])

    def test_worker_success_like_outcomes_rejected_pre_mutation(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");lease=self.claim("A","ra",a,1);before=dict(self.store.get_lease("A"))
        for outcome in ("accepted","completed","approved","reviewed","validated","review-rejected","anything"):
            with self.subTest(outcome=outcome):
                with self.assertRaises(StoreAuthorityError):self.store.release("A","ra",lease["owner_epoch"],outcome=outcome)
                self.assertEqual(self.store.get_lease("A")["released_at"],before["released_at"])
        self.store.release("A","ra",lease["owner_epoch"],outcome="failed")
        with self.assertRaises(StoreAuthorityError):self.claim("A","rb",a,1)
        self.store.retry_task("A","retry after failure")

    def test_concurrent_claims_serialize_under_global_cap(self):
        self.store.create_budget_run("GLOBAL",10)
        assignments={}
        for i in range(4):
            tid=f"T{i}";self.task(tid,budget=10);assignments[tid]=self.bind(tid,builder=f"b{i}")
        stores=[ControlStore(self.db) for _ in range(4)];barrier=threading.Barrier(4)
        def attempt(i):
            tid=f"T{i}";s=stores[i];barrier.wait()
            rev=int(s.get_budget_run("GLOBAL")["revision"])
            try:self.claim(tid,f"r{i}",assignments[tid],3,store=s,global_revision=rev);return "ok"
            except (StoreAuthorityError,BudgetReservationError):return "denied"
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(attempt,range(4)))
        finally:
            for s in stores:s.db.close()
        reserved=Decimal(self.store.get_budget_run("GLOBAL")["reserved_exact"]);self.assertLessEqual(reserved,Decimal("10"));self.assertGreaterEqual(results.count("ok"),1)

    def test_restart_preserves_budget_assignment_revoke_and_attempt(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");l=self.claim("A","r1",a,2);self.store.revoke_writer("A","r1",l["owner_epoch"],"stop")
        self.store.db.close();self.store=ControlStore(self.db)
        self.assertEqual(self.store.get_budget_run("GLOBAL")["reserved_exact"],"2");self.assertIsNone(self.store.get_task("A")["assignment_sha256"])
        run=self.store.db.execute("SELECT * FROM task_runs WHERE run_id='r1'").fetchone();self.assertIsNotNone(run["revoked_at"]);self.assertEqual(run["attempt"],1)
        self.store.retry_task("A","replacement");b=self.store.assign_builder("A","builder-b","GLOBAL");l2=self.claim("A","r2",b,1)
        self.assertEqual(l2["attempt"],2);self.assertGreater(l2["owner_epoch"],l["owner_epoch"])

    def test_authoritative_reads_hide_same_connection_rolled_back_ghosts(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");a=self.bind("A");self.claim("A","ra",a,1)
        task=self.rolled_back_read("UPDATE tasks SET purpose='ghost' WHERE task_id='A'",(),lambda:self.store.get_task("A"));self.assertEqual(task["purpose"],"fl1")
        budget=self.rolled_back_read("UPDATE budget_runs SET reserved_exact='9' WHERE run_id='GLOBAL'",(),lambda:self.store.get_budget_run("GLOBAL"));self.assertEqual(budget["reserved_exact"],"1")
        lease=self.rolled_back_read("UPDATE workspace_leases SET current_head=? WHERE task_id='A'",("b"*40,),lambda:self.store.get_lease("A"));self.assertEqual(lease["current_head"],"a"*40)
        snap=self.rolled_back_read("UPDATE tasks SET purpose='ghost2' WHERE task_id='A'",(),self.store.snapshot);self.assertEqual(next(t for t in snap["tasks"] if t["task_id"]=="A")["purpose"],"fl1")

    def test_closed_unknown_nonfinite_and_bool_global_budget_fail_closed(self):
        for cap in (True,-1,float("nan"),float("inf"),"bad"):
            with self.subTest(cap=cap):
                with self.assertRaises(BudgetReservationError):self.store.create_budget_run("X"+str(cap),cap)
        self.store.create_budget_run("GLOBAL",5);self.task("A");a=self.bind("A");self.store.close_budget_run("GLOBAL")
        with self.assertRaises(StoreAuthorityError):self.claim("A","r",a,1)

    def test_migration_preserves_legacy_spent_into_exact_authority(self):
        legacy=self.base/"legacy.sqlite3";raw=sqlite3.connect(legacy)
        raw.execute("""CREATE TABLE tasks(task_id TEXT PRIMARY KEY,repository TEXT NOT NULL,purpose TEXT NOT NULL,base_sha TEXT NOT NULL,branch TEXT,status TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,current_step TEXT,assigned_runtime TEXT,allowed_paths_json TEXT NOT NULL DEFAULT '[]',required_tests_json TEXT NOT NULL DEFAULT '[]',budget_allocated REAL NOT NULL DEFAULT 0,budget_spent REAL NOT NULL DEFAULT 0,cancel_requested_at REAL,result_head TEXT,terminal_outcome TEXT,created_at REAL NOT NULL,updated_at REAL NOT NULL)""")
        raw.execute("INSERT INTO tasks(task_id,repository,purpose,base_sha,branch,status,allowed_paths_json,required_tests_json,budget_allocated,budget_spent,created_at,updated_at) VALUES('L','owner/repo','x',?,'b','released','[]','[]',1.0,0.6,1,1)",("a"*40,))
        raw.commit();raw.close()
        s=ControlStore(legacy)
        try:self.assertEqual(s.get_task("L")["budget_cap_exact"],"1");self.assertEqual(s.get_task("L")["budget_reserved_exact"],"0.6")
        finally:s.db.close()

    def test_snapshot_does_not_expose_assignment_token_hash(self):
        self.store.create_budget_run("GLOBAL",10);self.task("A");self.bind("A")
        task=self.store.snapshot()["tasks"][0];self.assertNotIn("assignment_token_hash",task);self.assertNotIn("budget_spent",task);self.assertIn("budgetReservedExact",task);self.assertIn("assignment_sha256",task)

if __name__=="__main__":unittest.main()
