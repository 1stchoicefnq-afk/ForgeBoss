from __future__ import annotations

import math
import sqlite3
import tempfile
import unittest
from pathlib import Path

from forgeboss.control.idempotency import (
    IdempotencyConflict,
    IdempotencyInProgress,
    IdempotencyKeyError,
    IdempotencyStateError,
    complete,
    install_schema,
    request_digest,
    reserve,
    validate_idempotency_key,
)


class IdempotencyPrimitiveTests(unittest.TestCase):
    def _db(self, path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(str(path), isolation_level=None, timeout=5)
        install_schema(conn)
        return conn

    def test_key_validation_rejects_empty_whitespace_controls_and_oversize(self):
        for value in ("", " ", " bad", "bad ", "bad\nkey", "bad/key", "x" * 129, None):
            with self.subTest(value=value):
                with self.assertRaises(IdempotencyKeyError):
                    validate_idempotency_key(value)
        self.assertEqual(validate_idempotency_key("run-1:claim.A"), "run-1:claim.A")

    def test_request_digest_is_deterministic_and_rejects_nonfinite_json(self):
        a = request_digest("task.create", {"b": 2, "a": 1})
        b = request_digest("task.create", {"a": 1, "b": 2})
        self.assertEqual(a, b)
        self.assertNotEqual(a, request_digest("task.create", {"a": 1, "b": 3}))
        for bad in (math.nan, math.inf, -math.inf):
            with self.assertRaises(IdempotencyStateError):
                request_digest("task.create", {"budgetUsd": bad})

    def test_completed_result_replays_after_connection_restart(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "control.sqlite3"
            digest = request_digest("task.create", {"taskId": "T1"})
            c1 = self._db(db)
            c1.execute("BEGIN IMMEDIATE")
            first = reserve(c1, "key-1", digest, now=1)
            self.assertFalse(first.replay)
            complete(c1, "key-1", digest, {"taskId": "T1", "status": "queued"}, now=2)
            c1.execute("COMMIT")
            c1.close()

            c2 = self._db(db)
            replay = reserve(c2, "key-1", digest, now=3)
            self.assertTrue(replay.replay)
            self.assertEqual(replay.result, {"status": "queued", "taskId": "T1"})
            c2.close()

    def test_same_key_different_digest_conflicts(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "control.sqlite3"
            conn = self._db(db)
            one = request_digest("task.create", {"taskId": "T1"})
            two = request_digest("task.create", {"taskId": "T2"})
            conn.execute("BEGIN IMMEDIATE")
            reserve(conn, "key-1", one)
            complete(conn, "key-1", one, {"ok": True})
            conn.execute("COMMIT")
            with self.assertRaises(IdempotencyConflict):
                reserve(conn, "key-1", two)
            conn.close()

    def test_in_progress_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "control.sqlite3"
            conn = self._db(db)
            digest = request_digest("workspace.claim", {"taskId": "T1"})
            conn.execute("BEGIN IMMEDIATE")
            reserve(conn, "claim-1", digest)
            conn.execute("COMMIT")
            with self.assertRaises(IdempotencyInProgress):
                reserve(conn, "claim-1", digest)
            conn.close()

    def test_transaction_rollback_leaves_no_reservation_ghost(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "control.sqlite3"
            conn = self._db(db)
            digest = request_digest("workspace.release", {"taskId": "T1"})
            conn.execute("BEGIN IMMEDIATE")
            reserve(conn, "release-1", digest)
            conn.execute("ROLLBACK")
            row = conn.execute(
                "SELECT 1 FROM idempotency_operations WHERE idempotency_key='release-1'"
            ).fetchone()
            self.assertIsNone(row)
            conn.close()

    def test_completion_is_digest_and_state_cas(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "control.sqlite3"
            conn = self._db(db)
            digest = request_digest("task.create", {"taskId": "T1"})
            other = request_digest("task.create", {"taskId": "T2"})
            conn.execute("BEGIN IMMEDIATE")
            reserve(conn, "key-1", digest)
            with self.assertRaises(IdempotencyConflict):
                complete(conn, "key-1", other, {"ok": True})
            complete(conn, "key-1", digest, {"ok": True})
            with self.assertRaises(IdempotencyStateError):
                complete(conn, "key-1", digest, {"ok": True})
            conn.execute("COMMIT")
            conn.close()

    def test_unknown_persisted_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "control.sqlite3"
            conn = self._db(db)
            digest = request_digest("task.create", {"taskId": "T1"})
            conn.execute(
                """
                INSERT INTO idempotency_operations(
                  idempotency_key,request_digest,state,result_json,created_at,updated_at
                ) VALUES(?,?,'mystery',NULL,1,1)
                """,
                ("key-1", digest),
            )
            with self.assertRaises(IdempotencyStateError):
                reserve(conn, "key-1", digest)
            conn.close()


if __name__ == "__main__":
    unittest.main()
