from __future__ import annotations
import tempfile, threading, time, unittest
from pathlib import Path
from forgeboss.control.store import ControlStore,BudgetReservationError

class StoreTransactionTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory()
        self.root=Path(self.td.name)/"worktrees";self.root.mkdir()
        self.db=Path(self.td.name)/"control.db"
        self.s=ControlStore(self.db)
        self.task={"taskId":"t1","repository":"r","purpose":"p","baseSha":"abc","budgetUsd":1.0}
        self.s.create_task(self.task)

    def tearDown(self):
        self.td.cleanup()

    def claim(self,store=None,run="r1",budget=.2,ttl=1200,head="abc"):
        store=store or self.s
        wt=self.root/run;wt.mkdir(exist_ok=True)
        return store.claim_workspace("t1",run,str(wt),"b",head,ttl_seconds=ttl,worktree_root=self.root,budget_reserved=budget)

    def events(self,typ=None):
        q="SELECT * FROM task_events";args=()
        if typ:q+=" WHERE event_type=?";args=(typ,)
        return [dict(r) for r in self.s.db.execute(q,args)]

    def test_create_task_rolls_back_if_event_fails(self):
        s=ControlStore(Path(self.td.name)/"other.db")
        s._event=lambda *a,**k: (_ for _ in ()).throw(RuntimeError("event fail"))
        with self.assertRaises(RuntimeError):
            s.create_task({"taskId":"x","repository":"r","purpose":"p","baseSha":"a"})
        self.assertIsNone(s.get_task("x"))
        self.assertEqual([],list(s.db.execute("SELECT * FROM task_events")))

    def test_heartbeat_rejects_expired_lease_without_revival_or_event(self):
        lease=self.claim(ttl=1)
        self.s.db.execute("UPDATE workspace_leases SET expires_at=? WHERE task_id='t1'",(time.time()-1,))
        before=len(self.events("workspace.heartbeat"))
        with self.assertRaises(PermissionError):self.s.heartbeat("t1","r1",lease["owner_epoch"])
        row=self.s.get_lease("t1")
        self.assertLess(row["expires_at"],time.time())
        self.assertEqual(before,len(self.events("workspace.heartbeat")))

    def test_heartbeat_rolls_back_update_if_event_fails(self):
        lease=self.claim();before=self.s.get_lease("t1")
        self.s._event=lambda *a,**k: (_ for _ in ()).throw(RuntimeError("boom"))
        with self.assertRaises(RuntimeError):self.s.heartbeat("t1","r1",lease["owner_epoch"],current_head="new")
        after=self.s.get_lease("t1")
        self.assertEqual(before["current_head"],after["current_head"])
        self.assertEqual(before["expires_at"],after["expires_at"])

    def test_release_rolls_back_every_state_if_event_fails(self):
        lease=self.claim();self.s._event=lambda *a,**k: (_ for _ in ()).throw(RuntimeError("boom"))
        with self.assertRaises(RuntimeError):self.s.release("t1","r1",lease["owner_epoch"],result_head="new",outcome="succeeded")
        l=self.s.get_lease("t1");run=dict(self.s.db.execute("SELECT * FROM task_runs WHERE run_id='r1'").fetchone());task=self.s.get_task("t1")
        self.assertIsNone(l["released_at"]);self.assertEqual("abc",l["current_head"])
        self.assertEqual("running",run["status"]);self.assertIsNone(run["finished_at"])
        self.assertEqual("running",task["status"]);self.assertIsNone(task["result_head"])
        self.assertEqual([],self.events("workspace.released"))

    def test_stale_releaser_cannot_terminalize_after_takeover(self):
        first=self.claim(run="r1",budget=.2)
        self.s.db.execute("UPDATE workspace_leases SET expires_at=? WHERE task_id='t1'",(time.time()-1,))
        second=self.claim(run="r2",budget=.2,head="def");before=len(self.events("workspace.released"))
        with self.assertRaises(PermissionError):self.s.release("t1","r1",first["owner_epoch"],outcome="succeeded")
        self.assertEqual("r2",self.s.get_lease("t1")["owner_run_id"])
        self.assertEqual(second["owner_epoch"],self.s.get_lease("t1")["owner_epoch"])
        self.assertEqual("running",self.s.get_task("t1")["status"])
        r2=dict(self.s.db.execute("SELECT * FROM task_runs WHERE run_id='r2'").fetchone())
        self.assertEqual("running",r2["status"]);self.assertEqual(before,len(self.events("workspace.released")))

    def test_concurrent_claim_only_one_active_owner(self):
        s2=ControlStore(self.db);barrier=threading.Barrier(2);out=[]
        def go(store,run):
            wt=self.root/run;wt.mkdir(exist_ok=True);barrier.wait()
            try:
                lease=store.claim_workspace("t1",run,str(wt),"b","abc",worktree_root=self.root,budget_reserved=.6)
                out.append(("ok",run,lease["owner_epoch"]))
            except Exception as e:out.append(("err",run,type(e).__name__))
        a=threading.Thread(target=go,args=(self.s,"a"));b=threading.Thread(target=go,args=(s2,"b"));a.start();b.start();a.join();b.join()
        self.assertEqual(1,sum(x[0]=="ok" for x in out));self.assertEqual(.6,self.s.get_task("t1")["budget_spent"])

    def test_budget_reservation_semantics_preserved_across_release(self):
        lease=self.claim(budget=.6);self.s.release("t1","r1",lease["owner_epoch"])
        self.assertEqual(.6,self.s.get_task("t1")["budget_spent"])
        with self.assertRaises(BudgetReservationError):self.claim(run="r2",budget=.5)

    def test_event_versions_are_unique_under_two_connections(self):
        s2=ControlStore(self.db);barrier=threading.Barrier(2);errs=[]
        def go(store,n):
            try:
                barrier.wait()
                for i in range(10):store.event("probe",{"i":i,"n":n})
            except Exception as e:errs.append(e)
        a=threading.Thread(target=go,args=(self.s,1));b=threading.Thread(target=go,args=(s2,2));a.start();b.start();a.join();b.join()
        self.assertFalse(errs,errs)
        versions=[r["state_version"] for r in self.s.db.execute("SELECT state_version FROM task_events WHERE event_type='probe'")]
        self.assertEqual(20,len(versions));self.assertEqual(20,len(set(versions)))

    def test_concurrent_expired_heartbeat_and_takeover_claim(self):
        first=self.claim(run="r1",budget=.2)
        self.s.db.execute("UPDATE workspace_leases SET expires_at=? WHERE task_id='t1'",(time.time()-1,))
        s2=ControlStore(self.db);barrier=threading.Barrier(2);out=[]
        wt=self.root/"r2";wt.mkdir(exist_ok=True)
        def beat():
            barrier.wait()
            try:self.s.heartbeat("t1","r1",first["owner_epoch"]);out.append("heartbeat-ok")
            except PermissionError:out.append("heartbeat-denied")
        def takeover():
            barrier.wait()
            try:s2.claim_workspace("t1","r2",str(wt),"b","def",worktree_root=self.root,budget_reserved=.2);out.append("claim-ok")
            except Exception as e:out.append(type(e).__name__)
        a=threading.Thread(target=beat);b=threading.Thread(target=takeover);a.start();b.start();a.join();b.join()
        self.assertIn("heartbeat-denied",out);self.assertIn("claim-ok",out)
        self.assertEqual("r2",self.s.get_lease("t1")["owner_run_id"])

    def test_concurrent_heartbeat_and_release_remain_consistent(self):
        lease=self.claim();s2=ControlStore(self.db);barrier=threading.Barrier(2);out=[]
        def beat():
            barrier.wait()
            try:self.s.heartbeat("t1","r1",lease["owner_epoch"],current_head="beat");out.append("heartbeat-ok")
            except PermissionError:out.append("heartbeat-denied")
        def rel():
            barrier.wait()
            try:s2.release("t1","r1",lease["owner_epoch"],result_head="done");out.append("release-ok")
            except Exception as e:out.append(type(e).__name__)
        a=threading.Thread(target=beat);b=threading.Thread(target=rel);a.start();b.start();a.join();b.join()
        self.assertIn("release-ok",out)
        final=self.s.get_lease("t1");self.assertIsNotNone(final["released_at"]);self.assertEqual("done",final["current_head"])
        self.assertEqual("released",self.s.get_task("t1")["status"])
        self.assertEqual(1,len(self.events("workspace.released")))

if __name__=="__main__":unittest.main()
