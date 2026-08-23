from __future__ import annotations
import math, tempfile, threading, unittest
from pathlib import Path
from .store import BudgetReservationError,ControlStore


class ClaimBudgetReservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)/"worktrees"
        self.root.mkdir()
        self.db=Path(self.tmp.name)/"control.db"
        self.store=ControlStore(self.db)

    def tearDown(self):
        try:self.store.db.close()
        finally:self.tmp.cleanup()

    def task(self,task_id="t",budget=1.0):
        return self.store.create_task({
            "taskId":task_id,"repository":"repo","purpose":"test","baseSha":"abc",
            "allowedPaths":[],"requiredTests":[],"budgetUsd":budget,
        })

    def claim(self,run_id,budget,ttl=1200,store=None):
        store=store or self.store
        worktree=self.root/run_id
        return store.claim_workspace("t",run_id,str(worktree),None,"abc",ttl,None,self.root,budget)

    def test_successful_claim_consumes_budget_and_release_does_not_refund(self):
        self.task(budget=1.0)
        lease=self.claim("a",0.6)
        self.assertAlmostEqual(0.6,lease["budget_reserved_usd"])
        self.assertAlmostEqual(0.6,self.store.get_task("t")["budget_spent"])
        self.store.release("t","a",lease["owner_epoch"],outcome="released")
        self.assertAlmostEqual(0.6,self.store.get_task("t")["budget_spent"])
        lease2=self.claim("b",0.4)
        self.assertAlmostEqual(0.4,lease2["budget_reserved_usd"])
        self.assertAlmostEqual(1.0,self.store.get_task("t")["budget_spent"])

    def test_sequential_claim_cannot_reuse_consumed_allocation(self):
        self.task(budget=1.0)
        lease=self.claim("a",1.0)
        self.store.release("t","a",lease["owner_epoch"])
        with self.assertRaises(BudgetReservationError):self.claim("b",0.01)
        self.assertAlmostEqual(1.0,self.store.get_task("t")["budget_spent"])
        self.assertIsNotNone(self.store.get_lease("t"))
        self.assertEqual("a",self.store.get_lease("t")["owner_run_id"])

    def test_exact_boundary_and_lower_claims_are_valid(self):
        self.task(budget=1.0)
        lease=self.claim("a",0.25)
        self.store.release("t","a",lease["owner_epoch"])
        lease2=self.claim("b",0.75)
        self.assertAlmostEqual(0.75,lease2["budget_reserved_usd"])
        self.assertAlmostEqual(1.0,self.store.get_task("t")["budget_spent"])

    def test_nonfinite_negative_and_over_remaining_fail_without_leak(self):
        for value in (math.nan,math.inf,-math.inf,-0.01,1.01):
            with self.subTest(value=value):
                self.db.unlink(missing_ok=True) if False else None
        self.task(budget=1.0)
        for i,value in enumerate((math.nan,math.inf,-math.inf,-0.01,1.01)):
            with self.subTest(value=value):
                with self.assertRaises(BudgetReservationError):self.claim(f"bad{i}",value)
                self.assertAlmostEqual(0.0,self.store.get_task("t")["budget_spent"])
                self.assertIsNone(self.store.get_lease("t"))

    def test_invalid_persisted_task_budget_state_fails_closed_without_lease(self):
        self.task(budget=1.0)
        self.store.db.execute("UPDATE tasks SET budget_spent=2.0 WHERE task_id='t'")
        with self.assertRaises(BudgetReservationError):self.claim("a",0.1)
        self.assertEqual(2.0,self.store.get_task("t")["budget_spent"])
        self.assertIsNone(self.store.get_lease("t"))

    def test_failed_claim_after_budget_check_rolls_back_reservation(self):
        self.task(budget=1.0)
        lease=self.claim("same-run",0.25)
        self.store.release("t","same-run",lease["owner_epoch"])
        before=self.store.get_task("t")["budget_spent"]
        with self.assertRaises(Exception):self.claim("same-run",0.25)
        self.assertAlmostEqual(before,self.store.get_task("t")["budget_spent"])
        self.assertEqual("same-run",self.store.get_lease("t")["owner_run_id"])

    def test_two_connections_cannot_double_reserve(self):
        self.task(budget=1.0)
        other=ControlStore(self.db)
        barrier=threading.Barrier(2)
        results=[]
        lock=threading.Lock()
        def worker(store,run_id):
            barrier.wait()
            try:
                lease=self.claim(run_id,0.75,ttl=-1,store=store)
                result=("ok",lease["budget_reserved_usd"])
            except Exception as ex:
                result=(type(ex).__name__,str(ex))
            with lock:results.append(result)
        try:
            a=threading.Thread(target=worker,args=(self.store,"a"));b=threading.Thread(target=worker,args=(other,"b"))
            a.start();b.start();a.join();b.join()
            self.assertEqual(1,sum(1 for x in results if x[0]=="ok"),results)
            self.assertEqual(1,sum(1 for x in results if x[0]=="BudgetReservationError"),results)
            self.assertAlmostEqual(0.75,self.store.get_task("t")["budget_spent"])
        finally:
            other.db.close()


if __name__=="__main__":unittest.main()
