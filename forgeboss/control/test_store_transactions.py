from __future__ import annotations
import concurrent.futures,tempfile,threading,time,unittest
from pathlib import Path
from forgeboss.control.store import ControlStore,WorkspaceCollisionError

class StoreTransactionCollisionTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name)/"worktrees";self.root.mkdir();self.db=Path(self.td.name)/"state"/"control.sqlite3";self.store=ControlStore(self.db)
    def tearDown(self):
        try:self.store.db.close()
        except Exception:pass
        self.td.cleanup()
    def task(self,task_id,paths,budget=2.0,repository="1stchoicefnq-afk/ForgeBoss",base_sha="a"*40):
        return self.store.create_task({"taskId":task_id,"repository":repository,"purpose":"test","baseSha":base_sha,"branch":"b-"+task_id,"allowedPaths":list(paths),"requiredTests":[],"budgetUsd":budget})
    def claim(self,store,task,run,worktree,head="a"*40,budget=.25,ttl=1200):
        return store.claim_workspace(task,run,worktree,"b-"+task,head,ttl_seconds=ttl,runtime_id="mini-swe",worktree_root=self.root,budget_reserved=budget)
    def counts(self,task):
        return {
            "runs":self.store.db.execute("SELECT COUNT(*) n FROM task_runs WHERE task_id=?",(task,)).fetchone()["n"],
            "claims":self.store.db.execute("SELECT COUNT(*) n FROM task_events WHERE task_id=? AND event_type='workspace.claimed'",(task,)).fetchone()["n"],
            "lease":self.store.get_lease(task),
            "spent":self.store.get_task(task)["budget_spent"],
        }

    def test_create_task_and_created_event_are_atomic(self):
        self.store.db.execute("CREATE TRIGGER reject_task_created BEFORE INSERT ON task_events WHEN NEW.event_type='task.created' BEGIN SELECT RAISE(ABORT,'event rejected'); END")
        with self.assertRaises(Exception):self.task("A",["src/a.py"])
        self.assertIsNone(self.store.get_task("A"));self.assertEqual(self.store.db.execute("SELECT COUNT(*) n FROM task_events WHERE task_id='A'").fetchone()["n"],0)
        self.store.db.execute("DROP TRIGGER reject_task_created")

    def test_same_physical_worktree_different_tasks_is_rejected_before_budget_or_run_mutation(self):
        self.task("A",["src/a.py"]);self.task("B",["src/b.py"]);path=self.root/"Worker"
        self.claim(self.store,"A","run-a",path);before=self.counts("B")
        with self.assertRaisesRegex(WorkspaceCollisionError,"physical worktree") as cm:self.claim(self.store,"B","run-b",path)
        self.assertEqual(cm.exception.code,"WORKTREE_COLLISION");self.assertEqual(self.counts("B"),before)

    def test_windows_equivalent_worktree_case_and_trailing_dot_collide(self):
        self.task("A",["src/a.py"]);self.task("B",["src/b.py"]);self.claim(self.store,"A","run-a",self.root/"Worker")
        with self.assertRaises(WorkspaceCollisionError):self.claim(self.store,"B","run-b",self.root/"worker.")

    def test_overlapping_scope_across_distinct_worktrees_is_rejected(self):
        self.task("A",["src/"]);self.task("B",["SRC/child/file.py"]);self.claim(self.store,"A","run-a",self.root/"wa")
        with self.assertRaisesRegex(WorkspaceCollisionError,"writable scope") as cm:self.claim(self.store,"B","run-b",self.root/"wb")
        self.assertEqual(cm.exception.code,"WRITABLE_SCOPE_COLLISION");self.assertEqual(self.counts("B")["spent"],0.0)

    def test_windows_equivalent_scope_spelling_collides(self):
        self.task("A",[r"Src\Child. \file.py"]);self.task("B",["src/child/file.py"]);self.claim(self.store,"A","run-a",self.root/"wa")
        with self.assertRaises(WorkspaceCollisionError):self.claim(self.store,"B","run-b",self.root/"wb")

    def test_repository_case_aliases_share_collision_domain(self):
        self.task("A",["src/shared.py"],repository="1stChoiceFNQ-AFK/ForgeBoss")
        self.task("B",["SRC/shared.py"],repository="1stchoicefnq-afk/forgeboss")
        self.claim(self.store,"A","run-a",self.root/"wa")
        with self.assertRaisesRegex(WorkspaceCollisionError,"writable scope"):self.claim(self.store,"B","run-b",self.root/"wb")
        self.assertEqual(self.counts("B")["spent"],0.0)

    def test_same_repository_different_base_lineage_same_scope_remains_independent(self):
        base_b="b"*40
        self.task("A",["src/shared.py"],base_sha="a"*40);self.task("B",["SRC/shared.py"],base_sha=base_b)
        a=self.claim(self.store,"A","run-a",self.root/"wa");b=self.claim(self.store,"B","run-b",self.root/"wb",head=base_b)
        self.assertEqual(a["owner_epoch"],1);self.assertEqual(b["owner_epoch"],1)

    def test_same_repository_same_lineage_file_root_and_root_root_overlap_fail_closed(self):
        cases=[(["pkg/file.py"],["PKG/"]),(["pkg/"],["pkg/child/"]),([r"Pkg\Child. \file.py"],["pkg/child/file.py"])]
        for index,(left,right) in enumerate(cases):
            with self.subTest(index=index):
                a=f"A{index}";b=f"B{index}";self.task(a,left);self.task(b,right);self.claim(self.store,a,f"run-{a}",self.root/f"wa{index}")
                with self.assertRaises(WorkspaceCollisionError):self.claim(self.store,b,f"run-{b}",self.root/f"wb{index}")
                self.store.release(a,f"run-{a}",1)

    def test_different_repositories_with_same_scope_remain_independent(self):
        self.task("A",["src/shared.py"],repository="owner/repo-a");self.task("B",["SRC/shared.py"],repository="owner/repo-b")
        a=self.claim(self.store,"A","run-a",self.root/"wa");b=self.claim(self.store,"B","run-b",self.root/"wb")
        self.assertEqual(a["owner_epoch"],1);self.assertEqual(b["owner_epoch"],1)

    def test_disjoint_sibling_files_and_worktrees_can_both_claim(self):
        self.task("A",["src/a.py"]);self.task("B",["src/b.py"])
        a=self.claim(self.store,"A","run-a",self.root/"wa");b=self.claim(self.store,"B","run-b",self.root/"wb")
        self.assertEqual(a["owner_epoch"],1);self.assertEqual(b["owner_epoch"],1)

    def test_concurrent_same_physical_worktree_has_exactly_one_winner_and_loser_leaks_nothing(self):
        self.task("A",["src/a.py"]);self.task("B",["src/b.py"]);path=self.root/"shared";barrier=threading.Barrier(2);s1=ControlStore(self.db);s2=ControlStore(self.db)
        def attempt(store,task,run):
            barrier.wait()
            try:return (task,"ok",self.claim(store,task,run,path))
            except Exception as ex:return (task,"err",ex)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda args:attempt(*args),[(s1,"A","run-a"),(s2,"B","run-b")]))
        finally:s1.db.close();s2.db.close()
        winners=[x for x in results if x[1]=="ok"];losers=[x for x in results if x[1]=="err"]
        self.assertEqual(len(winners),1);self.assertEqual(len(losers),1);self.assertIsInstance(losers[0][2],WorkspaceCollisionError)
        loser=losers[0][0];state=self.counts(loser);self.assertEqual(state["runs"],0);self.assertEqual(state["claims"],0);self.assertIsNone(state["lease"]);self.assertEqual(state["spent"],0.0)

    def test_concurrent_overlapping_scope_has_exactly_one_winner(self):
        self.task("A",["pkg/"]);self.task("B",["pkg/file.py"]);barrier=threading.Barrier(2);s1=ControlStore(self.db);s2=ControlStore(self.db)
        def attempt(store,task,run,path):
            barrier.wait()
            try:return (task,"ok",self.claim(store,task,run,path))
            except Exception as ex:return (task,"err",ex)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda args:attempt(*args),[(s1,"A","run-a",self.root/"wa"),(s2,"B","run-b",self.root/"wb")]))
        finally:s1.db.close();s2.db.close()
        self.assertEqual(sum(x[1]=="ok" for x in results),1);self.assertEqual(sum(x[1]=="err" for x in results),1)

    def test_expired_same_task_takeover_increments_epoch_and_stale_owner_is_fenced(self):
        self.task("A",["src/a.py"],budget=1.0);first=self.claim(self.store,"A","run-1",self.root/"wa",ttl=.02);self.assertEqual(first["owner_epoch"],1);time.sleep(.04)
        second=self.claim(self.store,"A","run-2",self.root/"wa",budget=.25);self.assertEqual(second["owner_epoch"],2)
        with self.assertRaises(PermissionError):self.store.heartbeat("A","run-1",1)
        with self.assertRaises(PermissionError):self.store.release("A","run-1",1)
        self.assertEqual(self.store.get_lease("A")["owner_run_id"],"run-2")

    def _assert_blocked_until_expired_fails(self,operation):
        self.task("A",["src/a.py"]);self.claim(self.store,"A","run-a",self.root/"wa",ttl=.15)
        blocker=ControlStore(self.db);worker=ControlStore(self.db);blocker.db.execute("BEGIN IMMEDIATE")
        started=threading.Event();box={}
        def call():
            started.set()
            try:operation(worker)
            except Exception as ex:box["error"]=ex
            else:box["ok"]=True
        t=threading.Thread(target=call);t.start();started.wait(1);time.sleep(.25);blocker.db.execute("ROLLBACK");t.join(2)
        blocker.db.close();worker.db.close();self.assertFalse(t.is_alive());self.assertNotIn("ok",box);self.assertIsInstance(box.get("error"),PermissionError);self.assertIn("expired",str(box["error"]))

    def test_heartbeat_samples_clock_after_sqlite_write_lock(self):
        self._assert_blocked_until_expired_fails(lambda s:s.heartbeat("A","run-a",1,ttl_seconds=1))

    def test_release_samples_clock_after_sqlite_write_lock(self):
        self._assert_blocked_until_expired_fails(lambda s:s.release("A","run-a",1))

    def test_heartbeat_expected_head_mismatch_rolls_back_without_extending_lease(self):
        self.task("A",["src/a.py"]);lease=self.claim(self.store,"A","run-a",self.root/"wa");before=dict(lease)
        with self.assertRaisesRegex(PermissionError,"expected head mismatch"):self.store.heartbeat("A","run-a",1,current_head="b"*40,expected_head="c"*40)
        after=self.store.get_lease("A");self.assertEqual(after["current_head"],before["current_head"]);self.assertEqual(after["expires_at"],before["expires_at"]);self.assertEqual(after["heartbeat_at"],before["heartbeat_at"])

    def test_release_run_rowcount_failure_rolls_back_lease_release(self):
        self.task("A",["src/a.py"]);self.claim(self.store,"A","run-a",self.root/"wa");self.store.db.execute("UPDATE task_runs SET status='broken' WHERE run_id='run-a'")
        with self.assertRaisesRegex(PermissionError,"run authority lost"):self.store.release("A","run-a",1)
        lease=self.store.get_lease("A");self.assertIsNone(lease["released_at"]);self.assertEqual(self.store.get_task("A")["status"],"running")

    def test_duplicate_run_id_failure_rolls_back_budget_lease_and_claim_event(self):
        self.task("A",["src/a.py"]);self.task("B",["src/b.py"]);self.claim(self.store,"A","same-run",self.root/"wa");before=self.counts("B")
        with self.assertRaises(Exception):self.claim(self.store,"B","same-run",self.root/"wb")
        self.assertEqual(self.counts("B"),before)

    def test_released_worktree_and_scope_can_be_reused_by_other_task(self):
        self.task("A",["src/a.py"]);self.task("B",["src/a.py"]);path=self.root/"wa";self.claim(self.store,"A","run-a",path);self.store.release("A","run-a",1)
        lease=self.claim(self.store,"B","run-b",path);self.assertEqual(lease["owner_run_id"],"run-b")

if __name__=="__main__":unittest.main()