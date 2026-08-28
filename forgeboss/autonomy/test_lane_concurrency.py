"""End-to-end multi-process tests for the autonomy CLIs themselves.

``test_state_store`` pins the primitives; this pins the modules the orchestrator
actually invokes. Each worker is a real process running the module's own
``main()``/``record()`` against an isolated state path, so a lost update or a
fail-open on corrupt history shows up exactly as it would in a parallel repair
loop.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from forgeboss.autonomy import state_store  # noqa: E402

WORKERS = 8
GATE_TIMEOUT = 30.0

PRELUDE = """
import json, os, pathlib, sys, time
sys.path.insert(0, {root!r})
ready = pathlib.Path(sys.argv[1]); gate = pathlib.Path(sys.argv[2]); me = sys.argv[3]
args = sys.argv[4:]
ready.write_text("1")
deadline = time.monotonic() + {gate_timeout}
while not gate.exists():
    if time.monotonic() > deadline:
        raise SystemExit("gate never opened")
    time.sleep(0.001)
"""


class LaneHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fb-lane-"))
        self.gate = self.tmp / "GATE"

    def write(self, name, obj):
        p = self.tmp / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def spawn(self, body, count=WORKERS, extra=()):
        code = PRELUDE.format(root=str(ROOT), gate_timeout=GATE_TIMEOUT) + body
        procs = []
        for i in range(count):
            ready = self.tmp / f"ready-{i}"
            procs.append((i, ready, subprocess.Popen(
                [sys.executable, "-c", code, str(ready), str(self.gate), str(i), *[str(x) for x in extra]],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )))
        deadline = time.monotonic() + GATE_TIMEOUT
        for _, ready, proc in procs:
            while not ready.exists():
                if proc.poll() is not None:
                    self.fail(f"worker died before the barrier: {proc.communicate()[1]}")
                if time.monotonic() > deadline:
                    self.fail("workers never reached the barrier")
                time.sleep(0.005)
        self.gate.write_text("go")
        return procs

    def collect(self, procs, expect_rc=0):
        out = []
        for i, _, proc in procs:
            stdout, stderr = proc.communicate(timeout=120)
            if expect_rc is not None:
                self.assertEqual(proc.returncode, expect_rc,
                                 f"worker {i} exited {proc.returncode}\nstdout={stdout}\nstderr={stderr}")
            out.append((i, proc.returncode, stdout.strip(), stderr.strip()))
        return out

    def assertNoTempDebris(self):
        debris = [p.name for p in self.tmp.iterdir() if ".tmp" in p.name]
        self.assertEqual(debris, [], f"temp files left behind: {debris}")


REPAIR_MEMORY_WORKER = """
from forgeboss.autonomy import repair_memory
repair_memory.MEM = pathlib.Path(args[0])
sys.argv = ["repair_memory.py", "--feedback", args[1] + me + ".json"]
raise SystemExit(repair_memory.main())
"""

REPAIR_MEMORY_SAME_SIG_WORKER = """
from forgeboss.autonomy import repair_memory
repair_memory.MEM = pathlib.Path(args[0])
sys.argv = ["repair_memory.py", "--feedback", args[1]]
raise SystemExit(repair_memory.main())
"""


class RepairMemoryConcurrencyTests(LaneHarness):
    def feedback(self, name, signature):
        return self.write(name, {"signature": signature, "category": "database",
                                 "acceptance": {"failed_steps": ["step_" + signature]}})

    def test_concurrent_feedback_records_every_signature(self):
        mem = self.tmp / "repair-memory.json"
        for i in range(WORKERS):
            self.feedback(f"fb-{i}.json", f"sig-{i}")
        self.collect(self.spawn(REPAIR_MEMORY_WORKER, extra=[mem, str(self.tmp / "fb-")]))
        entries = state_store.load_db(mem, default={"entries": []})["entries"]
        self.assertEqual(sorted(e["signature"] for e in entries), sorted(f"sig-{i}" for i in range(WORKERS)))
        self.assertNoTempDebris()

    def test_concurrent_same_signature_accumulates_seen_count(self):
        """The upsert path is a read-modify-write; unserialised it loses counts.

        ``seen_count`` is what tells the orchestrator a strategy is a repeated
        dead end, so an undercount re-authorises paid repairs already known to fail.
        """
        mem = self.tmp / "repair-memory.json"
        fb = self.feedback("shared.json", "sig-shared")
        self.collect(self.spawn(REPAIR_MEMORY_SAME_SIG_WORKER, extra=[mem, fb]))
        entries = state_store.load_db(mem, default={"entries": []})["entries"]
        self.assertEqual(len(entries), 1, "upsert must not duplicate the signature")
        self.assertEqual(entries[0]["seen_count"], WORKERS, "concurrent observations were lost")

    def test_fails_closed_on_corrupt_history_instead_of_reporting_no_history(self):
        mem = self.tmp / "repair-memory.json"
        mem.write_text("{truncated", encoding="utf-8")
        query = self.write("query.json", {"category": "database", "failure_signature": "sig-shared"})
        code = (
            f"import sys, pathlib; sys.path.insert(0, {str(ROOT)!r})\n"
            "from forgeboss.autonomy import repair_memory\n"
            f"repair_memory.MEM = pathlib.Path({str(mem)!r})\n"
            f"sys.argv = ['repair_memory.py', '--query', {str(query)!r}]\n"
            "raise SystemExit(repair_memory.main())\n"
        )
        first = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(first.returncode, 9, f"corrupt history did not fail closed: {first.stderr}")
        payload = json.loads(first.stdout.strip())
        self.assertTrue(payload["fail_closed"])
        self.assertIsNone(payload["failed_history"], "must not present an empty history as fact")
        self.assertIsNone(payload["proven_history"])

        # A second, independent process must stay closed even though the corrupt
        # file has been quarantined and the canonical path now looks like a fresh run.
        second = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(second.returncode, 9, "history silently reset to empty after quarantine")
        self.assertFalse(mem.exists())

    def test_query_only_does_not_bump_the_generation(self):
        mem = self.tmp / "repair-memory.json"
        state_store.update_db(mem, lambda d: d, default={"schema": 1, "entries": []})
        before = state_store.generation(state_store.load_db(mem))
        query = self.write("query.json", {"category": "database", "failure_signature": "x"})
        code = (
            f"import sys, pathlib; sys.path.insert(0, {str(ROOT)!r})\n"
            "from forgeboss.autonomy import repair_memory\n"
            f"repair_memory.MEM = pathlib.Path({str(mem)!r})\n"
            f"sys.argv = ['repair_memory.py', '--query', {str(query)!r}]\n"
            "raise SystemExit(repair_memory.main())\n"
        )
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout.strip()), {"failed_history": [], "proven_history": []})
        self.assertEqual(state_store.generation(state_store.load_db(mem)), before,
                         "a read-only query must not rewrite shared history")


REPAIR_PLAYBOOK_WORKER = """
from forgeboss.autonomy import repair_playbook
repair_playbook.DB = pathlib.Path(args[0])
repair_playbook.record(args[1] + me + ".json", args[2] + me + ".json")
"""


class RepairPlaybookConcurrencyTests(LaneHarness):
    def report(self, name, path):
        return self.write(name, {"exact_head": None, "local_workspace": None, "local_commit": None,
                                 "builder_specialists": [],
                                 "attempts": [{"acceptance_passed": False, "changed_paths": [path], "runs": []}]})

    def test_concurrent_record_keeps_every_workers_entry(self):
        db = self.tmp / "repair-playbook.json"
        for i in range(WORKERS):
            self.report(f"report-{i}.json", f"src/worker{i}.js")
            self.write(f"feedback-{i}.json", {"signature": f"sig-{i}", "category": "backend"})
        self.collect(self.spawn(REPAIR_PLAYBOOK_WORKER,
                                extra=[db, str(self.tmp / "report-"), str(self.tmp / "feedback-")]))
        entries = state_store.load_db(db, default={"entries": []})["entries"]
        self.assertEqual(sorted(e["failure_signature"] for e in entries),
                         sorted(f"sig-{i}" for i in range(WORKERS)))
        self.assertEqual(len({e["key"] for e in entries}), WORKERS)
        self.assertNoTempDebris()

    def test_concurrent_record_of_the_same_key_accumulates_seen_count(self):
        db = self.tmp / "repair-playbook.json"
        for i in range(WORKERS):
            self.report(f"report-{i}.json", "src/same.js")
            self.write(f"feedback-{i}.json", {"signature": "sig-shared", "category": "backend"})
        self.collect(self.spawn(REPAIR_PLAYBOOK_WORKER,
                                extra=[db, str(self.tmp / "report-"), str(self.tmp / "feedback-")]))
        entries = state_store.load_db(db, default={"entries": []})["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["seen_count"], WORKERS)

    def test_find_fails_closed_on_corrupt_playbook(self):
        db = self.tmp / "repair-playbook.json"
        db.write_text("[]", encoding="utf-8")  # valid JSON, wrong root type
        funnel = self.write("funnel.json", {"target_sha": "abc", "failure_signature": "s", "category": "backend"})
        code = (
            f"import sys, pathlib; sys.path.insert(0, {str(ROOT)!r})\n"
            "from forgeboss.autonomy import repair_playbook\n"
            f"repair_playbook.DB = pathlib.Path({str(db)!r})\n"
            f"sys.argv = ['repair_playbook.py', 'query', '--funnel', {str(funnel)!r}, '--repo', {str(self.tmp)!r}]\n"
            "raise SystemExit(repair_playbook.main())\n"
        )
        first = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(first.returncode, 9, f"corrupt playbook did not fail closed: {first.stderr}")
        self.assertTrue(json.loads(first.stdout.strip())["fail_closed"])
        second = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(second.returncode, 9, "playbook silently reset to empty after quarantine")


FEEDBACK_WORKER = """
from forgeboss.autonomy import failure_feedback
failure_feedback.STATE = pathlib.Path(args[0])
failure_feedback.make(pathlib.Path(args[1] + me + ".json"), "repair-rat")
"""


class ArtifactPublicationConcurrencyTests(LaneHarness):
    def test_concurrent_feedback_publishers_never_mix_payloads(self):
        state = self.tmp / "state"
        state.mkdir()
        for i in range(WORKERS):
            self.write(f"src-{i}.json", {
                "exact_head": f"head{i}",
                "attempts": [{"runs": [{"name": f"suite_{i}", "exit_code": 1}]}],
            })
        self.collect(self.spawn(FEEDBACK_WORKER, extra=[state, str(self.tmp / "src-")]))

        published = json.loads((state / "failure-feedback-last.json").read_text(encoding="utf-8"))
        self.assertIn(state_store.WRITER_KEY, published, "artefact is not writer-stamped")
        head = published["target_sha"]
        self.assertIn(head, [f"head{i}" for i in range(WORKERS)])
        # The whole document must come from one run, not be spliced from two.
        self.assertEqual(published["acceptance"]["failed_steps"], [f"suite_{head[len('head'):]}"])
        debris = [p.name for p in state.iterdir() if ".tmp" in p.name]
        self.assertEqual(debris, [], f"temp files left behind: {debris}")


if __name__ == "__main__":
    unittest.main()
