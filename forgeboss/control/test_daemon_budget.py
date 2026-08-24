from __future__ import annotations
import importlib,os,sys,tempfile,threading,time,unittest,uuid
from pathlib import Path
from unittest import mock
import forgeboss.control.store as store_module
import forgeboss.control.envelope as envelope_module

class BootstrapStore:
    def __init__(self,path):self.path=path

class SpendAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name);cls.worktrees=cls.root/"worktrees";cls.worktrees.mkdir()
        fake_secret=lambda root:(cls.root/"secret.bin",b"s"*32)
        with mock.patch.object(store_module,"ControlStore",BootstrapStore),mock.patch.object(envelope_module,"secret_file",fake_secret),mock.patch.dict(os.environ,{"FORGEBOSS_WORKTREE_ROOT":str(cls.worktrees)}):
            sys.modules.pop("forgeboss.control.daemon",None);cls.mod=importlib.import_module("forgeboss.control.daemon")
    @classmethod
    def tearDownClass(cls):sys.modules.pop("forgeboss.control.daemon",None);cls.temp.cleanup()

    def add_task(self,s,task_id="T1",allocated=1.0,run="BUILD-1",global_cap=1.5):
        return s.create_task({"taskId":task_id,"repository":"owner/repo","purpose":"budget-test","baseSha":"a"*40,"allowedPaths":[f"src/{task_id}.js"],"requiredTests":[],"budgetUsd":allocated,"budgetRunId":run,"globalBudgetUsd":global_cap})
    def daemon(self,store):
        d=self.mod.ForgeBossDaemon.__new__(self.mod.ForgeBossDaemon);d.store=store;d.secret=b"k"*32;d.idempotency={};d.lock=threading.RLock();d.started=time.time();return d
    def request(self,task_id,budget,run_id):
        work=self.worktrees/uuid.uuid4().hex;work.mkdir();return {"method":"workspace.claim","idempotencyKey":uuid.uuid4().hex,"params":{"taskId":task_id,"repository":"owner/repo","baseSha":"a"*40,"allowedPaths":[f"src/{task_id}.js"],"allowedTools":["python"],"worktreePath":str(work),"runId":run_id,"currentHead":"a"*40,"ttlSeconds":60,"runtimeId":"mini-swe","budgetUsd":budget}}

    def test_paid_task_requires_finite_global_authority(self):
        for payload in ({"budgetUsd":1.0},{"budgetUsd":1.0,"budgetRunId":"R"},{"budgetUsd":1.0,"budgetRunId":"R","globalBudgetUsd":float("nan")},{"budgetUsd":-1.0,"budgetRunId":"R","globalBudgetUsd":1.0}):
            s=store_module.ControlStore(self.root/(uuid.uuid4().hex+".sqlite"));self.addCleanup(s.db.close)
            base={"taskId":"T","repository":"owner/repo","purpose":"x","baseSha":"a"*40,"allowedPaths":["x"],"requiredTests":[]};base.update(payload)
            with self.assertRaises(store_module.BudgetReservationError):s.create_task(base)
            self.assertIsNone(s.get_task("T"))

    def test_task_allocation_cannot_exceed_global_cap(self):
        s=store_module.ControlStore(self.root/(uuid.uuid4().hex+".sqlite"));self.addCleanup(s.db.close)
        with self.assertRaises(store_module.BudgetReservationError) as ctx:self.add_task(s,allocated=2.0,global_cap=1.0)
        self.assertEqual(ctx.exception.code,"GLOBAL_BUDGET_EXCEEDED")

    def test_claim_reserves_task_and_global_and_signed_budget_matches(self):
        s=store_module.ControlStore(self.root/(uuid.uuid4().hex+".sqlite"));self.addCleanup(s.db.close);self.add_task(s,global_cap=2.0);d=self.daemon(s)
        out=d.dispatch(self.request("T1",0.6,"R1"),True);unsigned=self.mod.verify_envelope(out["launchEnvelope"],d.secret,now=time.time())
        self.assertEqual(unsigned["budgetUsd"],0.6);self.assertAlmostEqual(float(s.get_task("T1")["budget_spent"]),0.6);self.assertAlmostEqual(float(s.get_budget_run("BUILD-1")["reserved_usd"]),0.6)

    def test_release_does_not_refund_task_or_global_budget(self):
        s=store_module.ControlStore(self.root/(uuid.uuid4().hex+".sqlite"));self.addCleanup(s.db.close);self.add_task(s,global_cap=1.0);d=self.daemon(s)
        first=d.dispatch(self.request("T1",0.6,"R1"),True);s.release("T1","R1",int(first["lease"]["owner_epoch"]))
        self.assertAlmostEqual(float(s.get_task("T1")["budget_spent"]),0.6);self.assertAlmostEqual(float(s.get_budget_run("BUILD-1")["reserved_usd"]),0.6)
        with self.assertRaises(store_module.BudgetReservationError):d.dispatch(self.request("T1",0.5,"R2"),True)

    def test_two_tasks_cannot_collectively_exceed_global_cap(self):
        db=self.root/(uuid.uuid4().hex+".sqlite");s1=store_module.ControlStore(db);self.addCleanup(s1.db.close);self.add_task(s1,"T1",1.0,"BUILD-1",1.0);self.add_task(s1,"T2",1.0,"BUILD-1",1.0)
        s2=store_module.ControlStore(db);self.addCleanup(s2.db.close);d1=self.daemon(s1);d2=self.daemon(s2);barrier=threading.Barrier(2);ok=[];err=[]
        def claim(d,tid,rid):
            barrier.wait()
            try:ok.append(d.dispatch(self.request(tid,0.6,rid),True))
            except Exception as ex:err.append(ex)
        a=threading.Thread(target=claim,args=(d1,"T1","R1"));b=threading.Thread(target=claim,args=(d2,"T2","R2"));a.start();b.start();a.join(10);b.join(10)
        self.assertEqual(len(ok),1);self.assertEqual(len(err),1);self.assertAlmostEqual(float(s1.get_budget_run("BUILD-1")["reserved_usd"]),0.6)

    def test_global_reservation_survives_restart(self):
        db=self.root/(uuid.uuid4().hex+".sqlite");s=store_module.ControlStore(db);self.add_task(s,"T1",1.0,"BUILD-1",1.0);d=self.daemon(s);d.dispatch(self.request("T1",0.7,"R1"),True);s.db.close()
        reopened=store_module.ControlStore(db);self.addCleanup(reopened.db.close);self.assertAlmostEqual(float(reopened.get_budget_run("BUILD-1")["reserved_usd"]),0.7)

if __name__=="__main__":unittest.main()
