from __future__ import annotations

import importlib
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

import forgeboss.control.envelope as envelope_module
import forgeboss.control.store as store_module


class BootstrapStore:
    def __init__(self, path):
        self.path = path


class TaskCancelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.worktrees = cls.root / "worktrees"
        cls.worktrees.mkdir()
        fake_secret = lambda root: (cls.root / "secret.bin", b"s" * 32)
        fake_policy = lambda root: (cls.root / "policy.bin", b"p" * 32)
        fake_launch = lambda root: (cls.root / "launch.bin", b"l" * 32)
        with (
            mock.patch.object(store_module, "ControlStore", BootstrapStore),
            mock.patch.object(envelope_module, "secret_file", fake_secret),
            mock.patch.object(envelope_module, "policy_secret_file", fake_policy),
            mock.patch.object(envelope_module, "launch_secret_file", fake_launch),
            mock.patch.dict(os.environ, {"FORGEBOSS_WORKTREE_ROOT": str(cls.worktrees)}),
        ):
            sys.modules.pop("forgeboss.control.daemon", None)
            cls.mod = importlib.import_module("forgeboss.control.daemon")

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("forgeboss.control.daemon", None)
        cls.temp.cleanup()

    def setUp(self):
        self.store = store_module.ControlStore(self.root / f"{uuid.uuid4().hex}.sqlite")
        self.addCleanup(self.store.db.close)
        self.daemon = self.mod.ForgeBossDaemon.__new__(self.mod.ForgeBossDaemon)
        self.daemon.store = self.store
        self.daemon.secret = b"k" * 32
        self.daemon.policy_secret = b"p" * 32
        self.daemon.launch_secret = b"l" * 32
        self.daemon.idempotency = {}
        self.daemon.lock = threading.RLock()
        self.daemon.started = time.time()
        self.store.create_task({
            "taskId":"T1",
            "repository":"owner/repo",
            "purpose":"test",
            "baseSha":"a"*40,
            "allowedPaths":["src/a.py"],
            "requiredTests":[],
            "budgetUsd":1.0,
        })

    def req(self, task_id="T1", key=None):
        return {
            "method":"task.cancel",
            "idempotencyKey":key or uuid.uuid4().hex,
            "params":{"taskId":task_id},
        }

    def event_count(self):
        return self.store.db.execute(
            "SELECT COUNT(*) FROM task_events WHERE task_id='T1' AND event_type='task.cancel_requested'"
        ).fetchone()[0]

    def test_first_cancel_sets_timestamp_and_one_event(self):
        out=self.daemon.dispatch(self.req(),True)
        self.assertFalse(out["alreadyRequested"])
        self.assertGreater(out["cancelRequestedAt"],0)
        self.assertEqual(self.event_count(),1)
        self.assertIsNotNone(self.store.get_task("T1")["cancel_requested_at"])

    def test_repeated_cancel_is_idempotent_and_does_not_duplicate_event(self):
        first=self.daemon.dispatch(self.req(key="same"),True)
        second=self.daemon.dispatch(self.req(key="same"),True)
        self.assertEqual(first,second)
        self.assertEqual(self.event_count(),1)

        third=self.daemon.dispatch(self.req(key="different"),True)
        self.assertTrue(third["alreadyRequested"])
        self.assertEqual(first["cancelRequestedAt"],third["cancelRequestedAt"])
        self.assertEqual(self.event_count(),1)

    def test_unknown_task_fails_closed(self):
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(self.req("NOPE"),True)
        self.assertEqual(ctx.exception.code,"TASK_NOT_FOUND")

    def test_cancelled_task_cannot_claim_workspace(self):
        self.daemon.dispatch(self.req(),True)
        work=self.worktrees/"w"
        work.mkdir()
        with self.assertRaisesRegex(PermissionError,"cancellation requested"):
            self.store.claim_workspace(
                "T1","RUN1",str(work),None,"a"*40,60,"mini-swe",
                self.worktrees,budget_reserved=0.1
            )
        self.assertIsNone(self.store.get_lease("T1"))

    def test_cancel_wins_if_requested_before_supervised_release(self):
        work=self.worktrees/"cancel-wins"
        work.mkdir()
        lease=self.store.claim_workspace(
            "T1","RUN-CANCEL",str(work),None,"a"*40,60,"mini-swe",
            self.worktrees,budget_reserved=0.1
        )
        self.store.request_cancel("T1")
        out=self.store.release(
            "T1","RUN-CANCEL",int(lease["owner_epoch"]),
            result_head=lease["current_head"],outcome="completed",respect_cancel=True
        )
        self.assertEqual(out["outcome"],"cancelled")
        self.assertEqual(self.store.get_task("T1")["status"],"cancelled")

    def test_completion_wins_if_committed_before_cancel_request(self):
        work=self.worktrees/"complete-wins"
        work.mkdir()
        lease=self.store.claim_workspace(
            "T1","RUN-DONE",str(work),None,"a"*40,60,"mini-swe",
            self.worktrees,budget_reserved=0.1
        )
        out=self.store.release(
            "T1","RUN-DONE",int(lease["owner_epoch"]),
            result_head=lease["current_head"],outcome="completed",respect_cancel=True
        )
        self.assertEqual(out["outcome"],"completed")
        with self.assertRaises(self.mod.ProtocolError) as ctx:
            self.daemon.dispatch(self.req(),True)
        self.assertEqual(ctx.exception.code,"TASK_TERMINAL")
        self.assertIsNone(self.store.get_task("T1")["cancel_requested_at"])

    def test_client_uses_shared_mutation_set_for_cancel(self):
        from forgeboss.control.client import Client
        self.assertIn("task.cancel",Client.call.__globals__["MUTATIONS"])


if __name__=="__main__":
    unittest.main()