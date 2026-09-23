from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from forgeboss.control.project_admission import (
    ProjectAdmissionError,
    issue_project_build_admission,
    verify_project_build_admission,
)
from forgeboss.control.store import (
    BudgetReservationError,
    ControlStore,
    ProjectAdmissionReplayError,
)


@unittest.skipUnless(shutil.which("git"), "git is required")
class ProjectAdmissionConsumptionTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self._git("init", "-q")
        self._git("config", "user.email", "forgeboss-test@example.invalid")
        self._git("config", "user.name", "ForgeBoss Test")
        (self.project / "a.py").write_text("print('a')\n", encoding="utf-8")
        (self.project / "b.py").write_text("print('b')\n", encoding="utf-8")
        self._git("add", "a.py", "b.py")
        self._git("commit", "-qm", "base")
        self.base = self._git("rev-parse", "HEAD").strip().lower()
        self.db = self.root / "state" / "control.sqlite"
        self.store = ControlStore(self.db)
        self.addCleanup(self.store.db.close)
        self.secret = b"z" * 32
        self.rules = hashlib.sha256(b"rules-v1").hexdigest()
        self.reuse = hashlib.sha256(b"reuse-v1").hexdigest()
        self.scope = ["a.py", "b.py"]
        self.now = int(time.time())

    def _git(self, *args):
        p = subprocess.run(
            [shutil.which("git"), "-C", str(self.project), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if p.returncode:
            self.fail(f"git {' '.join(args)} failed: {p.stderr}")
        return p.stdout

    def admission(self):
        receipt = issue_project_build_admission(
            project_root=self.project,
            base_sha=self.base,
            subsystem="project-builder",
            allowed_paths=self.scope,
            rules_canonical_sha256=self.rules,
            reuse_review_sha256=self.reuse,
            secret=self.secret,
            now=self.now,
        )
        return verify_project_build_admission(
            receipt,
            secret=self.secret,
            expected_project_root=self.project,
            expected_base_sha=self.base,
            expected_subsystem="project-builder",
            expected_allowed_paths=self.scope,
            expected_rules_canonical_sha256=self.rules,
            expected_reuse_review_sha256=self.reuse,
            now=self.now + 1,
        )

    def task(self, task_id, *, paths=None, base_sha=None):
        return {
            "taskId": task_id,
            "repository": "1stchoicefnq-afk/ForgeBoss",
            "purpose": "P0 project build",
            "baseSha": base_sha or self.base,
            "branch": "forgeboss/project/" + task_id,
            "allowedPaths": list(paths or self.scope),
            "requiredTests": ["python -m unittest"],
            "budgetUsd": 1.0,
        }

    def test_create_project_task_consumes_verified_admission_atomically(self):
        admission = self.admission()
        task = self.store.create_project_task(self.task("P1"), admission, self.secret)
        self.assertEqual(task["status"], "queued")
        self.assertEqual(task["base_sha"], self.base)

        row = self.store.get_project_admission_consumption(admission["admissionId"])
        self.assertIsNotNone(row)
        self.assertEqual(row["task_id"], "P1")
        expected_json = json.dumps(
            admission,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        self.assertEqual(row["receipt_json"], expected_json)
        self.assertEqual(
            row["receipt_sha256"],
            hashlib.sha256(expected_json.encode("utf-8")).hexdigest(),
        )

        event = self.store.db.execute(
            "SELECT event_type,payload_json FROM task_events WHERE task_id='P1'"
        ).fetchone()
        self.assertEqual(event["event_type"], "project.task.created")
        payload = json.loads(event["payload_json"])
        self.assertEqual(payload["admissionId"], admission["admissionId"])

    def test_same_admission_cannot_create_second_task(self):
        admission = self.admission()
        self.store.create_project_task(self.task("P1"), admission, self.secret)
        with self.assertRaises(ProjectAdmissionReplayError) as cm:
            self.store.create_project_task(self.task("P2"), admission, self.secret)
        self.assertEqual(cm.exception.code, "PROJECT_ADMISSION_REPLAY")
        self.assertIsNone(self.store.get_task("P2"))

    def test_base_or_scope_mismatch_does_not_consume_admission(self):
        admission = self.admission()
        with self.assertRaises(ProjectAdmissionError):
            self.store.create_project_task(
                self.task("P1", base_sha="f" * 40),
                admission,
                self.secret,
            )
        self.assertIsNone(
            self.store.get_project_admission_consumption(admission["admissionId"])
        )
        self.assertIsNone(self.store.get_task("P1"))

        with self.assertRaises(ProjectAdmissionError):
            self.store.create_project_task(
                self.task("P2", paths=["a.py"]),
                admission,
                self.secret,
            )
        self.assertIsNone(
            self.store.get_project_admission_consumption(admission["admissionId"])
        )
        self.assertIsNone(self.store.get_task("P2"))

    def test_wrong_secret_expiry_or_workspace_change_fails_before_consumption(self):
        admission = self.admission()
        with self.assertRaisesRegex(ProjectAdmissionError, "signature mismatch"):
            self.store.create_project_task(
                self.task("BADSECRET"),
                admission,
                b"x" * 32,
            )
        self.assertIsNone(self.store.get_task("BADSECRET"))
        self.assertIsNone(
            self.store.get_project_admission_consumption(admission["admissionId"])
        )

        expired = issue_project_build_admission(
            project_root=self.project,
            base_sha=self.base,
            subsystem="project-builder",
            allowed_paths=self.scope,
            rules_canonical_sha256=self.rules,
            reuse_review_sha256=self.reuse,
            secret=self.secret,
            ttl_seconds=1,
            now=self.now - 2,
        )
        with self.assertRaisesRegex(ProjectAdmissionError, "expired"):
            self.store.create_project_task(
                self.task("EXPIRED"),
                expired,
                self.secret,
            )
        self.assertIsNone(self.store.get_task("EXPIRED"))
        self.assertIsNone(
            self.store.get_project_admission_consumption(expired["admissionId"])
        )

        (self.project / "a.py").write_text("DIRTY\n", encoding="utf-8")
        with self.assertRaisesRegex(ProjectAdmissionError, "workspace baseline changed"):
            self.store.create_project_task(
                self.task("DIRTY"),
                admission,
                self.secret,
            )
        self.assertIsNone(self.store.get_task("DIRTY"))
        self.assertIsNone(
            self.store.get_project_admission_consumption(admission["admissionId"])
        )
        self._git("checkout", "--", "a.py")

    def test_nonfinite_budget_fails_without_consuming_admission(self):
        admission = self.admission()
        task = self.task("NAN")
        task["budgetUsd"] = float("nan")
        with self.assertRaises(BudgetReservationError):
            self.store.create_project_task(
                task,
                admission,
                self.secret,
            )
        self.assertIsNone(self.store.get_task("NAN"))
        self.assertIsNone(
            self.store.get_project_admission_consumption(admission["admissionId"])
        )

    def test_event_failure_rolls_back_task_and_admission_consumption(self):
        admission = self.admission()
        self.store.db.execute(
            """CREATE TRIGGER reject_project_event
            BEFORE INSERT ON task_events
            WHEN NEW.event_type='project.task.created'
            BEGIN SELECT RAISE(ABORT,'event rejected'); END"""
        )
        with self.assertRaises(Exception):
            self.store.create_project_task(self.task("P1"), admission, self.secret)
        self.assertIsNone(self.store.get_task("P1"))
        self.assertIsNone(
            self.store.get_project_admission_consumption(admission["admissionId"])
        )

    def test_legacy_create_task_does_not_consume_project_admission(self):
        admission = self.admission()
        self.store.create_task(self.task("LEGACY"))
        self.assertIsNotNone(self.store.get_task("LEGACY"))
        self.assertIsNone(
            self.store.get_project_admission_consumption(admission["admissionId"])
        )

    def test_concurrent_replay_has_exactly_one_winner(self):
        admission = self.admission()
        second = ControlStore(self.db)
        self.addCleanup(second.db.close)
        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()

        def worker(store, task_id):
            barrier.wait()
            try:
                store.create_project_task(
                    self.task(task_id),
                    admission,
                    self.secret,
                )
                result = ("ok", task_id)
            except ProjectAdmissionReplayError:
                result = ("replay", task_id)
            with lock:
                outcomes.append(result)

        threads = [
            threading.Thread(target=worker, args=(self.store, "P1")),
            threading.Thread(target=worker, args=(second, "P2")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())

        self.assertEqual(sum(1 for kind, _ in outcomes if kind == "ok"), 1)
        self.assertEqual(sum(1 for kind, _ in outcomes if kind == "replay"), 1)
        tasks = [
            self.store.get_task("P1"),
            self.store.get_task("P2"),
        ]
        self.assertEqual(sum(task is not None for task in tasks), 1)


if __name__ == "__main__":
    unittest.main()