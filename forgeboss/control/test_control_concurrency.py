"""Control-plane concurrency regressions.

Every race here is forced deterministically instead of being raced-for-luck:
a second, independent ``ControlStore`` (its own SQLite connection, its own
process-local lock) opens ``BEGIN IMMEDIATE`` and therefore owns the database
write lock. Any other connection that wants to write must queue behind it,
which pins the victim thread inside the exact window under test. Nothing in
``store.py`` is monkey-patched, so the tests keep proving the same property if
the implementation is restructured.
"""
from __future__ import annotations
import tempfile,threading,time,unittest,uuid
from pathlib import Path
import forgeboss.control.store as store_module

TASK="T1"
SHA="a"*40


class ControlConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.worktrees=self.root/"worktrees";self.worktrees.mkdir()
        self.db_path=self.root/(uuid.uuid4().hex+".sqlite")

    def store(self):
        s=store_module.ControlStore(self.db_path);self.addCleanup(s.db.close);return s

    def new_task(self,s,task_id=TASK):
        s.create_task({"taskId":task_id,"repository":"owner/repo","purpose":"concurrency","baseSha":SHA,
                       "allowedPaths":["src/a.js"],"requiredTests":[],"budgetUsd":1.0})

    def claim(self,s,run_id="R1",ttl=1200,task_id=TASK):
        work=self.worktrees/uuid.uuid4().hex;work.mkdir()
        return s.claim_workspace(task_id,run_id,str(work),None,SHA,ttl,"mini-swe",self.worktrees,budget_reserved=0.0)

    def counts(self,s,event_type,task_id=TASK):
        return int(s.db.execute("SELECT COUNT(*) FROM task_events WHERE task_id=? AND event_type=?",
                                (task_id,event_type)).fetchone()[0])

    def run_blocked(self,fn):
        """Start ``fn`` in a thread and let it reach the DB write lock it will queue on."""
        box={}
        entered=threading.Event()
        def body():
            entered.set()
            try:box["value"]=fn()
            except BaseException as ex:box["error"]=ex
        t=threading.Thread(target=body,daemon=True);t.start()
        self.assertTrue(entered.wait(5))
        time.sleep(.35)
        self.assertTrue(t.is_alive(),"victim thread was expected to be queued on the DB write lock")
        return t,box

    # --- double completion -------------------------------------------------

    def test_concurrent_release_cannot_double_complete(self):
        """Two callers holding the same run/epoch must not both terminalize the run."""
        writer=self.store();self.new_task(writer)
        lease=self.claim(writer,"R1")
        epoch=int(lease["owner_epoch"])
        before=writer.get_task(TASK)

        loser=self.store()
        writer.db.execute("BEGIN IMMEDIATE")
        t,box=self.run_blocked(lambda:loser.release(TASK,"R1",epoch,result_head="b"*40,outcome="failed"))
        # Winner commits a real completion while the loser is pinned mid-flight.
        writer.release(TASK,"R1",epoch,result_head="c"*40,outcome="success")
        writer.db.execute("COMMIT")
        t.join(10);self.assertFalse(t.is_alive())

        self.assertIsInstance(box.get("error"),PermissionError,f"loser unexpectedly succeeded: {box}")
        task=writer.get_task(TASK)
        self.assertEqual(task["status"],"success")
        self.assertEqual(task["result_head"],"c"*40)
        self.assertEqual(int(task["revision"]),int(before["revision"])+1)
        self.assertEqual(self.counts(writer,"workspace.released"),1)
        self.assertEqual(writer.db.execute("SELECT status FROM task_runs WHERE run_id='R1'").fetchone()[0],"success")

    # --- stale-clock TOCTOU ------------------------------------------------

    def test_release_blocked_past_expiry_fails_closed(self):
        """A release that samples the clock before waiting must not act on a lease
        that expired while it waited."""
        writer=self.store();self.new_task(writer)
        lease=self.claim(writer,"R1",ttl=1)
        epoch=int(lease["owner_epoch"])
        before=writer.get_task(TASK)

        caller=self.store()
        writer.db.execute("BEGIN IMMEDIATE")
        t,box=self.run_blocked(lambda:caller.release(TASK,"R1",epoch,result_head="b"*40,outcome="success"))
        while time.time()<=float(lease["expires_at"]):time.sleep(.05)
        writer.db.execute("COMMIT")
        t.join(10);self.assertFalse(t.is_alive())

        self.assertIsInstance(box.get("error"),PermissionError,f"expired lease was allowed to release: {box}")
        self.assertIsNone(writer.get_lease(TASK)["released_at"])
        task=writer.get_task(TASK)
        self.assertEqual(task["status"],before["status"])
        self.assertEqual(int(task["revision"]),int(before["revision"]))
        self.assertIsNone(task["result_head"])
        self.assertEqual(self.counts(writer,"workspace.released"),0)
        self.assertEqual(writer.db.execute("SELECT status FROM task_runs WHERE run_id='R1'").fetchone()[0],"running")

    def test_heartbeat_blocked_past_expiry_cannot_resurrect_lease(self):
        """An expired lease must not be extended by a heartbeat that was admitted
        before the expiry and only reached the database after it."""
        writer=self.store();self.new_task(writer)
        lease=self.claim(writer,"R1",ttl=1)
        epoch=int(lease["owner_epoch"])

        caller=self.store()
        writer.db.execute("BEGIN IMMEDIATE")
        t,box=self.run_blocked(lambda:caller.heartbeat(TASK,"R1",epoch,1200))
        while time.time()<=float(lease["expires_at"]):time.sleep(.05)
        writer.db.execute("COMMIT")
        t.join(10);self.assertFalse(t.is_alive())

        self.assertIsInstance(box.get("error"),PermissionError,f"expired lease was extended: {box}")
        after=writer.get_lease(TASK)
        self.assertEqual(float(after["expires_at"]),float(lease["expires_at"]))
        self.assertEqual(float(after["heartbeat_at"]),float(lease["heartbeat_at"]))
        self.assertEqual(self.counts(writer,"workspace.heartbeat"),0)
        # The lease is genuinely expired, so a fresh claim is still able to take over.
        self.claim(writer,"R2")

    # --- partial state updates ---------------------------------------------

    def test_failed_task_creation_leaves_no_orphan_row(self):
        s=self.store()
        boom=RuntimeError("event sink down")
        def explode(*a,**k):raise boom
        s.event=explode
        with self.assertRaises(RuntimeError):self.new_task(s)
        self.assertIsNone(s.get_task(TASK))
        self.assertEqual(int(s.db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]),0)

    def test_release_cannot_park_task_in_a_non_terminal_status(self):
        """`outcome` is caller-supplied and lands in tasks.status, so releasing must
        not be able to leave a lease-less task claiming it is still live."""
        s=self.store();self.new_task(s)
        lease=self.claim(s,"R1");epoch=int(lease["owner_epoch"])
        for bad in ("running","queued","RUNNING"," running ",""):
            with self.subTest(outcome=bad):
                with self.assertRaises(ValueError):s.release(TASK,"R1",epoch,outcome=bad)
                self.assertIsNone(s.get_lease(TASK)["released_at"])
                self.assertEqual(s.get_task(TASK)["status"],"running")
                self.assertEqual(self.counts(s,"workspace.released"),0)
        s.release(TASK,"R1",epoch,outcome="success")
        self.assertEqual(s.get_task(TASK)["status"],"success")

    def test_concurrent_events_do_not_share_a_state_version(self):
        writer=self.store();self.new_task(writer)
        other=self.store()
        writer.db.execute("BEGIN IMMEDIATE")
        t,box=self.run_blocked(lambda:other.event("probe.b",{},TASK))
        first=writer.event("probe.a",{},TASK)
        writer.db.execute("COMMIT")
        t.join(10);self.assertFalse(t.is_alive())
        self.assertNotIn("error",box,f"queued event failed: {box.get('error')!r}")
        self.assertNotEqual(int(first["stateVersion"]),int(box["value"]["stateVersion"]))
        versions=[r[0] for r in writer.db.execute("SELECT state_version FROM task_events")]
        self.assertEqual(len(versions),len(set(versions)))

    def test_snapshot_is_a_consistent_read(self):
        """snapshot() must not mix pre-write and post-write rows from different tables."""
        s=self.store();self.new_task(s)
        other=self.store()
        original=s.db
        fired=[]
        test=self
        class Hooked:
            def __getattr__(self,name):return getattr(original,name)
            def execute(self,sql,*a,**k):
                cur=original.execute(sql,*a,**k)
                if "FROM workspace_leases" in sql and not fired:
                    fired.append(1)
                    test.new_task(other,"T2")
                return cur
        s.db=Hooked()
        try:snap=s.snapshot()
        finally:s.db=original
        self.assertTrue(fired)
        task_ids={t["task_id"] for t in snap["tasks"]}
        seq_of_t2=int(s.db.execute("SELECT MAX(seq) FROM task_events WHERE task_id='T2'").fetchone()[0])
        if "T2" in task_ids:self.assertGreaterEqual(snap["lastEventSeq"],seq_of_t2)
        else:self.assertLess(snap["lastEventSeq"],seq_of_t2,"snapshot mixed pre-write tasks with post-write event sequence")


if __name__=="__main__":unittest.main()
