from __future__ import annotations
import importlib,json,os,sqlite3,sys,tempfile,threading,time,unittest,uuid
from pathlib import Path
from unittest import mock
import forgeboss.control.store as store_module
import forgeboss.control.envelope as envelope_module

class BootstrapStore:
    def __init__(self,path):self.path=path

class WorkspaceClaimBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name);cls.worktrees=cls.root/"worktrees";cls.worktrees.mkdir()
        fake_secret=lambda root:(cls.root/"secret.bin",b"s"*32)
        with mock.patch.object(store_module,"ControlStore",BootstrapStore),mock.patch.object(envelope_module,"secret_file",fake_secret),mock.patch.dict(os.environ,{"FORGEBOSS_WORKTREE_ROOT":str(cls.worktrees)}):
            sys.modules.pop("forgeboss.control.daemon",None)
            cls.mod=importlib.import_module("forgeboss.control.daemon")
    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("forgeboss.control.daemon",None);cls.temp.cleanup()

    def daemon(self,allocated=1.0,spent=0.0,db_path=None,store=None):
        if store is None:
            db_path=db_path or self.root/(uuid.uuid4().hex+".sqlite")
            store=store_module.ControlStore(db_path)
            store.create_task({"taskId":"T1","repository":"owner/repo","purpose":"budget-test","baseSha":"a"*40,"allowedPaths":["src/a.js"],"requiredTests":[],"budgetUsd":allocated})
            store.db.execute("UPDATE tasks SET budget_spent=? WHERE task_id='T1'",(spent,))
        d=self.mod.ForgeBossDaemon.__new__(self.mod.ForgeBossDaemon)
        d.store=store;d.secret=b"k"*32;d.idempotency={};d.lock=threading.RLock();d.started=time.time()
        return d

    def request(self,budget="__missing__",run_id=None):
        work=self.worktrees/uuid.uuid4().hex;work.mkdir()
        p={"taskId":"T1","repository":"owner/repo","baseSha":"a"*40,"allowedPaths":["src/a.js"],"allowedTools":["python"],"worktreePath":str(work),"runId":run_id or uuid.uuid4().hex,"currentHead":"a"*40,"ttlSeconds":60,"runtimeId":"mini-swe"}
        if budget!="__missing__":p["budgetUsd"]=budget
        return {"method":"workspace.claim","idempotencyKey":uuid.uuid4().hex,"params":p}

    def assert_code(self,code,fn):
        with self.assertRaises(self.mod.ProtocolError) as ctx:fn()
        self.assertEqual(ctx.exception.code,code)

    def assert_clean_failure(self,d,spent):
        self.assertIsNone(d.store.get_lease("T1"))
        self.assertEqual(float(d.store.get_task("T1")["budget_spent"]),spent)
        self.assertEqual(d.store.db.execute("SELECT COUNT(*) FROM task_runs").fetchone()[0],0)

    def test_boundary_lower_and_missing_request_reserve_and_sign_same_amount(self):
        for requested,expected in ((0.6,0.6),(0.25,0.25),("0.10",0.10),("__missing__",0.0)):
            with self.subTest(requested=requested):
                d=self.daemon(1.0,0.4);self.addCleanup(d.store.db.close)
                out=d.dispatch(self.request(requested),True);lease=out["lease"]
                unsigned=self.mod.verify_envelope(out["launchEnvelope"],d.secret,now=time.time())
                self.assertEqual(float(lease["budget_reserved"]),expected)
                self.assertEqual(unsigned["budgetUsd"],expected)
                self.assertAlmostEqual(float(d.store.get_task("T1")["budget_spent"]),0.4+expected)
                tampered=dict(out["launchEnvelope"]);tampered["budgetUsd"]=expected+0.01
                with self.assertRaises(PermissionError):self.mod.verify_envelope(tampered,d.secret,now=time.time())

    def test_decimal_exact_boundary_does_not_false_reject(self):
        d=self.daemon(0.30,0.10);self.addCleanup(d.store.db.close)
        out=d.dispatch(self.request(0.20,"DECIMAL"),True)
        self.assertEqual(float(out["lease"]["budget_reserved"]),0.20)
        self.assertEqual(self.mod.verify_envelope(out["launchEnvelope"],d.secret,now=time.time())["budgetUsd"],0.20)
        self.assertEqual(float(d.store.get_task("T1")["budget_spent"]),0.30)

    def test_invalid_requested_budget_rejects_without_reservation_or_lease(self):
        cases=(float("nan"),float("inf"),float("-inf"),"NaN","Infinity","-Infinity","not-a-number",None,-0.01,True,False)
        for requested in cases:
            with self.subTest(requested=requested):
                d=self.daemon(1.0,0.4);self.addCleanup(d.store.db.close)
                self.assert_code("BUDGET_INVALID",lambda:d.dispatch(self.request(requested),True));self.assert_clean_failure(d,0.4)

    def test_over_remaining_budget_rejects_without_reservation_or_lease(self):
        d=self.daemon(1.0,0.4);self.addCleanup(d.store.db.close)
        self.assert_code("BUDGET_EXCEEDED",lambda:d.dispatch(self.request(0.6001),True));self.assert_clean_failure(d,0.4)

    def test_invalid_or_missing_task_budget_state_fails_closed(self):
        missing_alloc={"budget_spent":0.0};missing_spent={"budget_allocated":1.0}
        for task in (missing_alloc,missing_spent,{"budget_allocated":"bad","budget_spent":0.0},{"budget_allocated":1.0,"budget_spent":"bad"},{"budget_allocated":-1.0,"budget_spent":0.0},{"budget_allocated":1.0,"budget_spent":-0.1},{"budget_allocated":1.0,"budget_spent":1.01}):
            with self.subTest(task=task):
                with self.assertRaises(store_module.BudgetReservationError) as ctx:store_module._validated_budget_request(task,0.1)
                self.assertEqual(ctx.exception.code,"BUDGET_STATE_INVALID")
        d=self.daemon(1.0,0.0);self.addCleanup(d.store.db.close);d.store.db.execute("UPDATE tasks SET budget_spent='bad' WHERE task_id='T1'")
        self.assert_code("BUDGET_STATE_INVALID",lambda:d.dispatch(self.request(0.1),True));self.assertIsNone(d.store.get_lease("T1"))

    def test_release_does_not_refund_and_sequential_claim_cannot_reuse_budget(self):
        d=self.daemon(1.0,0.0);self.addCleanup(d.store.db.close)
        r1="R1";first=d.dispatch(self.request(0.6,r1),True);self.assertAlmostEqual(float(d.store.get_task("T1")["budget_spent"]),0.6)
        d.store.release("T1",r1,int(first["lease"]["owner_epoch"]),outcome="released")
        self.assertAlmostEqual(float(d.store.get_task("T1")["budget_spent"]),0.6)
        self.assert_code("BUDGET_EXCEEDED",lambda:d.dispatch(self.request(0.5,"R2"),True))
        second=d.dispatch(self.request(0.4,"R3"),True)
        self.assertEqual(self.mod.verify_envelope(second["launchEnvelope"],d.secret,now=time.time())["budgetUsd"],0.4)
        self.assertAlmostEqual(float(d.store.get_task("T1")["budget_spent"]),1.0)

    def test_mid_claim_failure_rolls_back_budget_and_lease_replacement(self):
        d=self.daemon(1.0,0.0);self.addCleanup(d.store.db.close)
        first=d.dispatch(self.request(0.1,"DUP"),True);d.store.release("T1","DUP",int(first["lease"]["owner_epoch"]),outcome="released")
        before=d.store.get_lease("T1");self.assertAlmostEqual(float(d.store.get_task("T1")["budget_spent"]),0.1)
        with self.assertRaises(sqlite3.IntegrityError):d.dispatch(self.request(0.2,"DUP"),True)
        after=d.store.get_lease("T1")
        self.assertAlmostEqual(float(d.store.get_task("T1")["budget_spent"]),0.1)
        self.assertEqual(after["owner_epoch"],before["owner_epoch"]);self.assertEqual(float(after["budget_reserved"]),0.1);self.assertIsNotNone(after["released_at"])
        self.assertEqual(d.store.db.execute("SELECT COUNT(*) FROM task_runs").fetchone()[0],1)

    def test_concurrent_claims_cannot_double_reserve(self):
        db=self.root/(uuid.uuid4().hex+".sqlite");s1=store_module.ControlStore(db);self.addCleanup(s1.db.close)
        s1.create_task({"taskId":"T1","repository":"owner/repo","purpose":"concurrent","baseSha":"a"*40,"allowedPaths":["src/a.js"],"requiredTests":[],"budgetUsd":1.0})
        s2=store_module.ControlStore(db);self.addCleanup(s2.db.close);d1=self.daemon(store=s1);d2=self.daemon(store=s2)
        barrier=threading.Barrier(2);results=[];errors=[]
        def claim(d,run_id):
            barrier.wait()
            try:results.append(d.dispatch(self.request(0.6,run_id),True))
            except Exception as ex:errors.append(ex)
        t1=threading.Thread(target=claim,args=(d1,"C1"));t2=threading.Thread(target=claim,args=(d2,"C2"));t1.start();t2.start();t1.join(10);t2.join(10)
        self.assertFalse(t1.is_alive() or t2.is_alive());self.assertEqual(len(results),1);self.assertEqual(len(errors),1)
        self.assertAlmostEqual(float(s1.get_task("T1")["budget_spent"]),0.6)
        self.assertEqual(s1.db.execute("SELECT COUNT(*) FROM task_runs").fetchone()[0],1)
        lease=s1.get_lease("T1");self.assertAlmostEqual(float(lease["budget_reserved"]),0.6);self.assertIsNone(lease["released_at"])

    def test_existing_v2_workspace_lease_schema_migrates_budget_reserved(self):
        db=self.root/(uuid.uuid4().hex+"-v2.sqlite");raw=sqlite3.connect(db)
        raw.execute("""CREATE TABLE workspace_leases(task_id TEXT PRIMARY KEY,worktree_path TEXT NOT NULL,branch TEXT,owner_run_id TEXT NOT NULL,owner_epoch INTEGER NOT NULL,claimed_at REAL NOT NULL,heartbeat_at REAL NOT NULL,expires_at REAL NOT NULL,released_at REAL,current_head TEXT NOT NULL)""")
        raw.commit();raw.close()
        store=store_module.ControlStore(db);self.addCleanup(store.db.close)
        cols={r[1] for r in store.db.execute("PRAGMA table_info(workspace_leases)")}
        self.assertIn("budget_reserved",cols)
        self.assertEqual(store.db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0],str(store_module.SCHEMA_VERSION))

if __name__=="__main__":unittest.main()
