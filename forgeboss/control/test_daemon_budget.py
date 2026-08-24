from __future__ import annotations
import importlib, os, sqlite3, sys, tempfile, threading, time, unittest, uuid
from pathlib import Path
from unittest import mock
import forgeboss.control.store as store_module
import forgeboss.control.envelope as envelope_module


class BootstrapStore:
    def __init__(self, path):
        self.path = path


class SpendAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.worktrees = cls.root / "worktrees"
        cls.worktrees.mkdir()
        fake_secret = lambda root: (cls.root / "secret.bin", b"s" * 32)
        with mock.patch.object(store_module, "ControlStore", BootstrapStore), mock.patch.object(envelope_module, "secret_file", fake_secret), mock.patch.dict(os.environ, {"FORGEBOSS_WORKTREE_ROOT": str(cls.worktrees)}):
            sys.modules.pop("forgeboss.control.daemon", None)
            cls.mod = importlib.import_module("forgeboss.control.daemon")

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("forgeboss.control.daemon", None)
        cls.temp.cleanup()

    def add_task(self, store, task_id="T1", allocated=1.0, run="BUILD-1", global_cap=1.5):
        return store.create_task({
            "taskId": task_id,
            "repository": "owner/repo",
            "purpose": "budget-test",
            "baseSha": "a" * 40,
            "allowedPaths": [f"src/{task_id}.js"],
            "requiredTests": [],
            "budgetUsd": allocated,
            "budgetRunId": run,
            "globalBudgetUsd": global_cap,
        })

    def daemon(self, store):
        d = self.mod.ForgeBossDaemon.__new__(self.mod.ForgeBossDaemon)
        d.store = store
        d.secret = b"k" * 32
        d.idempotency = {}
        d.lock = threading.RLock()
        d.started = time.time()
        return d

    def request(self, task_id, budget, run_id):
        work = self.worktrees / uuid.uuid4().hex
        work.mkdir()
        return {
            "method": "workspace.claim",
            "idempotencyKey": uuid.uuid4().hex,
            "params": {
                "taskId": task_id,
                "repository": "owner/repo",
                "baseSha": "a" * 40,
                "allowedPaths": [f"src/{task_id}.js"],
                "allowedTools": ["python"],
                "worktreePath": str(work),
                "runId": run_id,
                "currentHead": "a" * 40,
                "ttlSeconds": 60,
                "runtimeId": "mini-swe",
                "budgetUsd": budget,
            },
        }

    def test_paid_task_requires_finite_global_authority(self):
        cases = (
            {"budgetUsd": 1.0},
            {"budgetUsd": 1.0, "budgetRunId": "R"},
            {"budgetUsd": 1.0, "budgetRunId": "R", "globalBudgetUsd": float("nan")},
            {"budgetUsd": -1.0, "budgetRunId": "R", "globalBudgetUsd": 1.0},
        )
        for payload in cases:
            with self.subTest(payload=payload):
                store = store_module.ControlStore(self.root / (uuid.uuid4().hex + ".sqlite"))
                self.addCleanup(store.db.close)
                task = {"taskId": "T", "repository": "owner/repo", "purpose": "x", "baseSha": "a" * 40, "allowedPaths": ["x"], "requiredTests": []}
                task.update(payload)
                with self.assertRaises(store_module.BudgetReservationError):
                    store.create_task(task)
                self.assertIsNone(store.get_task("T"))

    def test_task_allocation_cannot_exceed_global_cap(self):
        store = store_module.ControlStore(self.root / (uuid.uuid4().hex + ".sqlite"))
        self.addCleanup(store.db.close)
        with self.assertRaises(store_module.BudgetReservationError) as ctx:
            self.add_task(store, allocated=2.0, global_cap=1.0)
        self.assertEqual(ctx.exception.code, "GLOBAL_BUDGET_EXCEEDED")
        self.assertIsNone(store.get_task("T1"))

    def test_aggregate_task_authority_is_reserved_at_create(self):
        store = store_module.ControlStore(self.root / (uuid.uuid4().hex + ".sqlite"))
        self.addCleanup(store.db.close)
        self.add_task(store, "T1", 0.6, "BUILD-1", 1.0)
        self.assertAlmostEqual(float(store.get_budget_run("BUILD-1")["reserved_usd"]), 0.6)
        with self.assertRaises(store_module.BudgetReservationError) as ctx:
            self.add_task(store, "T2", 0.5, "BUILD-1", 1.0)
        self.assertEqual(ctx.exception.code, "GLOBAL_BUDGET_EXCEEDED")
        self.assertIsNone(store.get_task("T2"))
        self.assertAlmostEqual(float(store.get_budget_run("BUILD-1")["reserved_usd"]), 0.6)

    def test_conflicting_global_cap_rejects_without_mutation(self):
        store = store_module.ControlStore(self.root / (uuid.uuid4().hex + ".sqlite"))
        self.addCleanup(store.db.close)
        self.add_task(store, "T1", 0.4, "BUILD-1", 1.0)
        with self.assertRaises(store_module.BudgetReservationError) as ctx:
            self.add_task(store, "T2", 0.1, "BUILD-1", 2.0)
        self.assertEqual(ctx.exception.code, "GLOBAL_BUDGET_MISMATCH")
        self.assertIsNone(store.get_task("T2"))
        run = store.get_budget_run("BUILD-1")
        self.assertAlmostEqual(float(run["cap_usd"]), 1.0)
        self.assertAlmostEqual(float(run["reserved_usd"]), 0.4)

    def test_task_insert_failure_rolls_back_global_authority(self):
        store = store_module.ControlStore(self.root / (uuid.uuid4().hex + ".sqlite"))
        self.addCleanup(store.db.close)
        self.add_task(store, "T1", 0.4, "BUILD-1", 1.0)
        with self.assertRaises(sqlite3.IntegrityError):
            self.add_task(store, "T1", 0.2, "BUILD-1", 1.0)
        self.assertAlmostEqual(float(store.get_budget_run("BUILD-1")["reserved_usd"]), 0.4)

    def test_concurrent_task_creation_cannot_overallocate_global_authority(self):
        db = self.root / (uuid.uuid4().hex + ".sqlite")
        store1 = store_module.ControlStore(db)
        store2 = store_module.ControlStore(db)
        self.addCleanup(store1.db.close)
        self.addCleanup(store2.db.close)
        barrier = threading.Barrier(2)
        ok = []
        err = []

        def create(store, task_id):
            barrier.wait()
            try:
                ok.append(self.add_task(store, task_id, 0.6, "BUILD-1", 1.0))
            except Exception as ex:
                err.append(ex)

        a = threading.Thread(target=create, args=(store1, "T1"))
        b = threading.Thread(target=create, args=(store2, "T2"))
        a.start()
        b.start()
        a.join(10)
        b.join(10)
        self.assertFalse(a.is_alive() or b.is_alive())
        self.assertEqual(len(ok), 1)
        self.assertEqual(len(err), 1)
        self.assertIsInstance(err[0], store_module.BudgetReservationError)
        self.assertEqual(err[0].code, "GLOBAL_BUDGET_EXCEEDED")
        self.assertAlmostEqual(float(store1.get_budget_run("BUILD-1")["reserved_usd"]), 0.6)
        self.assertEqual(store1.db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 1)

    def test_task_authority_reservation_survives_restart(self):
        db = self.root / (uuid.uuid4().hex + ".sqlite")
        store = store_module.ControlStore(db)
        self.add_task(store, "T1", 0.7, "BUILD-1", 1.0)
        store.db.close()
        reopened = store_module.ControlStore(db)
        self.addCleanup(reopened.db.close)
        self.assertAlmostEqual(float(reopened.get_budget_run("BUILD-1")["reserved_usd"]), 0.7)
        with self.assertRaises(store_module.BudgetReservationError):
            self.add_task(reopened, "T2", 0.4, "BUILD-1", 1.0)

    def test_claim_consumes_task_budget_but_does_not_double_reserve_global_authority(self):
        store = store_module.ControlStore(self.root / (uuid.uuid4().hex + ".sqlite"))
        self.addCleanup(store.db.close)
        self.add_task(store, "T1", 1.0, "BUILD-1", 1.0)
        daemon = self.daemon(store)
        self.assertAlmostEqual(float(store.get_budget_run("BUILD-1")["reserved_usd"]), 1.0)
        out = daemon.dispatch(self.request("T1", 0.6, "R1"), True)
        unsigned = self.mod.verify_envelope(out["launchEnvelope"], daemon.secret, now=time.time())
        self.assertEqual(unsigned["budgetUsd"], 0.6)
        self.assertAlmostEqual(float(store.get_task("T1")["budget_spent"]), 0.6)
        self.assertAlmostEqual(float(store.get_budget_run("BUILD-1")["reserved_usd"]), 1.0)

    def test_release_does_not_refund_task_or_global_authority(self):
        store = store_module.ControlStore(self.root / (uuid.uuid4().hex + ".sqlite"))
        self.addCleanup(store.db.close)
        self.add_task(store, "T1", 1.0, "BUILD-1", 1.0)
        daemon = self.daemon(store)
        first = daemon.dispatch(self.request("T1", 0.6, "R1"), True)
        store.release("T1", "R1", int(first["lease"]["owner_epoch"]))
        self.assertAlmostEqual(float(store.get_task("T1")["budget_spent"]), 0.6)
        self.assertAlmostEqual(float(store.get_budget_run("BUILD-1")["reserved_usd"]), 1.0)
        with self.assertRaises(store_module.BudgetReservationError):
            daemon.dispatch(self.request("T1", 0.5, "R2"), True)

    def test_multiple_preallocated_tasks_can_claim_within_their_own_authority(self):
        store = store_module.ControlStore(self.root / (uuid.uuid4().hex + ".sqlite"))
        self.addCleanup(store.db.close)
        self.add_task(store, "T1", 0.5, "BUILD-1", 1.0)
        self.add_task(store, "T2", 0.5, "BUILD-1", 1.0)
        daemon = self.daemon(store)
        daemon.dispatch(self.request("T1", 0.4, "R1"), True)
        daemon.dispatch(self.request("T2", 0.4, "R2"), True)
        self.assertAlmostEqual(float(store.get_budget_run("BUILD-1")["reserved_usd"]), 1.0)
        self.assertAlmostEqual(float(store.get_task("T1")["budget_spent"]), 0.4)
        self.assertAlmostEqual(float(store.get_task("T2")["budget_spent"]), 0.4)


if __name__ == "__main__":
    unittest.main()
