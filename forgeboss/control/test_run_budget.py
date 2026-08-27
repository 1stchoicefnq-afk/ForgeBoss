from __future__ import annotations

import concurrent.futures
import math
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from forgeboss.control.run_budget import (
    RunBudgetConflict,
    RunBudgetExceeded,
    RunBudgetInputError,
    RunBudgetStateError,
    create_run_budget,
    install_schema,
    reserve,
    snapshot,
)


class RunBudgetPrimitiveTests(unittest.TestCase):
    def _db(self, path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(str(path), isolation_level=None, timeout=5)
        conn.execute("PRAGMA foreign_keys=ON")
        install_schema(conn)
        return conn

    def _create(self, conn, cap="10"):
        conn.execute("BEGIN IMMEDIATE")
        out = create_run_budget(conn, "selfbuild-1", "kg-main", cap, now=1)
        conn.execute("COMMIT")
        return out

    def test_requires_caller_transaction_for_mutations(self):
        with tempfile.TemporaryDirectory() as td:
            conn = self._db(Path(td) / "db.sqlite")
            with self.assertRaises(RunBudgetStateError):
                create_run_budget(conn, "run-1", "kg-main", 10)
            self._create(conn)
            with self.assertRaises(RunBudgetStateError):
                reserve(conn, "selfbuild-1", "kg-main", "r1", "task-1", "worker-a", 1)
            conn.close()

    def test_exact_cap_and_lower_reservations(self):
        with tempfile.TemporaryDirectory() as td:
            conn = self._db(Path(td) / "db.sqlite")
            self._create(conn)
            conn.execute("BEGIN IMMEDIATE")
            self.assertEqual(
                reserve(conn, "selfbuild-1", "kg-main", "r1", "task-1", "worker-a", "6").reserved_usd,
                "6",
            )
            self.assertEqual(
                reserve(conn, "selfbuild-1", "kg-main", "r2", "task-2", "worker-b", "4").reserved_usd,
                "10",
            )
            conn.execute("COMMIT")
            self.assertEqual(snapshot(conn, "selfbuild-1").reserved_usd, "10")
            conn.close()

    def test_second_reservation_over_global_cap_is_denied_without_leak(self):
        with tempfile.TemporaryDirectory() as td:
            conn = self._db(Path(td) / "db.sqlite")
            self._create(conn)
            conn.execute("BEGIN IMMEDIATE")
            reserve(conn, "selfbuild-1", "kg-main", "r1", "task-1", "worker-a", 6)
            conn.execute("COMMIT")
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(RunBudgetExceeded):
                reserve(conn, "selfbuild-1", "kg-main", "r2", "task-2", "worker-b", 5)
            conn.execute("ROLLBACK")
            self.assertEqual(snapshot(conn, "selfbuild-1").reserved_usd, "6")
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM run_budget_reservations").fetchone()[0], 1
            )
            conn.close()

    def test_concurrent_workers_cannot_both_cross_cap(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "db.sqlite"
            root = self._db(db)
            self._create(root)
            root.close()
            barrier = threading.Barrier(2)

            def attempt(name):
                conn = self._db(db)
                barrier.wait()
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    reserve(
                        conn,
                        "selfbuild-1",
                        "kg-main",
                        f"r-{name}",
                        f"task-{name}",
                        f"worker-{name}",
                        6,
                    )
                    conn.execute("COMMIT")
                    return "ok"
                except RunBudgetExceeded:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    return "denied"
                finally:
                    conn.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(attempt, ("a", "b")))
            self.assertEqual(sorted(results), ["denied", "ok"])
            check = self._db(db)
            self.assertEqual(snapshot(check, "selfbuild-1").reserved_usd, "6")
            self.assertEqual(
                check.execute("SELECT COUNT(*) FROM run_budget_reservations").fetchone()[0], 1
            )
            check.close()

    def test_restart_preserves_consumed_global_authority(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "db.sqlite"
            first = self._db(db)
            self._create(first)
            first.execute("BEGIN IMMEDIATE")
            reserve(first, "selfbuild-1", "kg-main", "r1", "task-1", "worker-a", "7.25")
            first.execute("COMMIT")
            first.close()

            second = self._db(db)
            self.assertEqual(snapshot(second, "selfbuild-1").reserved_usd, "7.25")
            second.execute("BEGIN IMMEDIATE")
            with self.assertRaises(RunBudgetExceeded):
                reserve(second, "selfbuild-1", "kg-main", "r2", "task-2", "worker-b", 3)
            second.execute("ROLLBACK")
            second.close()

    def test_rollback_removes_reservation_and_counter_change(self):
        with tempfile.TemporaryDirectory() as td:
            conn = self._db(Path(td) / "db.sqlite")
            self._create(conn)
            conn.execute("BEGIN IMMEDIATE")
            reserve(conn, "selfbuild-1", "kg-main", "r1", "task-1", "worker-a", 4)
            conn.execute("ROLLBACK")
            self.assertEqual(snapshot(conn, "selfbuild-1").reserved_usd, "0")
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM run_budget_reservations").fetchone()[0], 0
            )
            conn.close()

    def test_reservation_id_is_idempotent_but_conflicting_reuse_fails(self):
        with tempfile.TemporaryDirectory() as td:
            conn = self._db(Path(td) / "db.sqlite")
            self._create(conn)
            conn.execute("BEGIN IMMEDIATE")
            first = reserve(conn, "selfbuild-1", "kg-main", "r1", "task-1", "worker-a", 2)
            again = reserve(conn, "selfbuild-1", "kg-main", "r1", "task-1", "worker-a", 2)
            self.assertEqual(first.reserved_usd, again.reserved_usd)
            with self.assertRaises(RunBudgetConflict):
                reserve(conn, "selfbuild-1", "kg-main", "r1", "task-1", "worker-a", 3)
            conn.execute("COMMIT")
            conn.close()

    def test_controller_identity_is_bound(self):
        with tempfile.TemporaryDirectory() as td:
            conn = self._db(Path(td) / "db.sqlite")
            self._create(conn)
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(RunBudgetConflict):
                reserve(conn, "selfbuild-1", "other-controller", "r1", "task-1", "worker-a", 1)
            conn.execute("ROLLBACK")
            conn.close()

    def test_invalid_nonfinite_negative_and_boolean_amounts_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            conn = self._db(Path(td) / "db.sqlite")
            for bad in (math.nan, math.inf, -math.inf, -1, True):
                conn.execute("BEGIN IMMEDIATE")
                with self.assertRaises(RunBudgetInputError):
                    create_run_budget(conn, f"bad-{str(bad).replace('.', '-')}", "kg-main", bad)
                conn.execute("ROLLBACK")
            self._create(conn)
            for bad in (math.nan, math.inf, -math.inf, -1, True):
                conn.execute("BEGIN IMMEDIATE")
                with self.assertRaises(RunBudgetInputError):
                    reserve(
                        conn,
                        "selfbuild-1",
                        "kg-main",
                        "r-bad",
                        "task-1",
                        "worker-a",
                        bad,
                    )
                conn.execute("ROLLBACK")
            conn.close()

    def test_conflicting_recreate_of_run_budget_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            conn = self._db(Path(td) / "db.sqlite")
            self._create(conn)
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaises(RunBudgetConflict):
                create_run_budget(conn, "selfbuild-1", "kg-other", 10)
            with self.assertRaises(RunBudgetConflict):
                create_run_budget(conn, "selfbuild-1", "kg-main", 11)
            conn.execute("ROLLBACK")
            conn.close()


if __name__ == "__main__":
    unittest.main()
