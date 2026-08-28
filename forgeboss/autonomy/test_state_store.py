"""Multi-process regression tests for autonomy shared-state safety.

These deliberately spawn *real independent processes* rather than threads. The
defects being pinned -- shared temp-path collisions, lost read-modify-write
updates, a corruption latch that only fails closed once, a stale lock wedging the
lane after a worker dies -- are all cross-process defects that in-process threads
cannot demonstrate.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from forgeboss.autonomy import state_store  # noqa: E402

WORKERS = 8
GATE_TIMEOUT = 30.0

PRELUDE = """
import json, os, pathlib, sys, time
sys.path.insert(0, {root!r})
from forgeboss.autonomy import state_store
ready = pathlib.Path(sys.argv[1]); gate = pathlib.Path(sys.argv[2]); me = sys.argv[3]
args = sys.argv[4:]
ready.write_text("1")
deadline = time.monotonic() + {gate_timeout}
while not gate.exists():
    if time.monotonic() > deadline:
        raise SystemExit("gate never opened")
    time.sleep(0.001)
"""


class ConcurrencyHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fb-autonomy-"))
        self.gate = self.tmp / "GATE"

    def spawn(self, body, count=WORKERS, extra=()):
        """Start ``count`` processes and release them all at the same instant."""
        code = PRELUDE.format(root=str(ROOT), gate_timeout=GATE_TIMEOUT) + body
        procs = []
        for i in range(count):
            ready = self.tmp / f"ready-{i}"
            procs.append((
                i,
                ready,
                subprocess.Popen(
                    [sys.executable, "-c", code, str(ready), str(self.gate), str(i), *[str(x) for x in extra]],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                ),
            ))
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
                self.assertEqual(
                    proc.returncode, expect_rc,
                    f"worker {i} exited {proc.returncode}\nstdout={stdout}\nstderr={stderr}",
                )
            out.append((i, proc.returncode, stdout.strip(), stderr.strip()))
        return out


class ConcurrentUpdateTests(ConcurrencyHarness):
    def test_concurrent_read_modify_write_loses_no_update(self):
        """Eight processes appending at once must all survive in the final DB.

        Without an inter-process lock each worker reads the same snapshot and the
        last replace() wins, so the DB ends up with a single entry.
        """
        db = self.tmp / "history.json"
        self.collect(self.spawn("""
def mutate(doc):
    doc.setdefault("entries", []).append({"worker": me})
    return doc
state_store.update_db(pathlib.Path(args[0]), mutate, default={"entries": []})
""", extra=[db]))

        final = state_store.load_db(db, default={"entries": []})
        self.assertEqual(
            sorted(e["worker"] for e in final["entries"]),
            sorted(str(i) for i in range(WORKERS)),
        )
        self.assertEqual(state_store.generation(final), WORKERS)

    def test_concurrent_counter_increments_are_all_applied(self):
        db = self.tmp / "counter.json"
        self.collect(self.spawn("""
def mutate(doc):
    doc["count"] = int(doc.get("count", 0)) + 1
    return doc
for _ in range(5):
    state_store.update_db(pathlib.Path(args[0]), mutate, default={"count": 0})
""", extra=[db]))
        self.assertEqual(state_store.load_db(db, default={"count": 0})["count"], WORKERS * 5)


class ConcurrentPublishTests(ConcurrencyHarness):
    def test_concurrent_publishers_never_share_a_temp_path(self):
        """The exact defect reported against a fixed ``<file>.tmp`` sibling.

        With one deterministic temp name, worker A can publish worker B's bytes
        and still return success, and B's own replace() then fails. Unique O_EXCL
        temps make both impossible: every worker succeeds, and the destination is
        always byte-identical to exactly one worker's own payload.
        """
        target = self.tmp / "artifact.json"
        results = self.collect(self.spawn("""
payload = {"worker": me, "filler": "x" * 200000}
published = state_store.publish_artifact(pathlib.Path(args[0]), payload)
print(json.dumps({"worker": me, "run_id": published[state_store.WRITER_KEY]["run_id"]}))
""", extra=[target]))

        claims = {json.loads(out)["run_id"]: json.loads(out)["worker"] for _, _, out, _ in results}
        self.assertEqual(len(claims), WORKERS, "run ids must be distinct per process")

        final = json.loads(target.read_text(encoding="utf-8"))
        winner = final[state_store.WRITER_KEY]["run_id"]
        self.assertIn(winner, claims, "destination carries a run id no worker claimed")
        self.assertEqual(
            final["worker"], claims[winner],
            "destination payload belongs to a different worker than the one that published it",
        )
        self.assertEqual(len(final["filler"]), 200000, "published payload is truncated")

        leftovers = [p.name for p in self.tmp.iterdir() if ".tmp" in p.name]
        self.assertEqual(leftovers, [], f"temp files left behind: {leftovers}")

    def test_reader_never_observes_a_partial_file_during_concurrent_publishes(self):
        target = self.tmp / "artifact.json"
        state_store.publish_artifact(target, {"worker": "seed", "filler": "x" * 200000})
        procs = self.spawn("""
payload = {"worker": me, "filler": "x" * 200000}
for _ in range(10):
    state_store.publish_artifact(pathlib.Path(args[0]), payload)
""", extra=[target])

        seen = 0
        deadline = time.monotonic() + 30
        while any(proc.poll() is None for _, _, proc in procs) and time.monotonic() < deadline:
            doc = json.loads(target.read_text(encoding="utf-8"))  # raises on a torn write
            self.assertEqual(len(doc["filler"]), 200000)
            seen += 1
        self.collect(procs)
        self.assertGreater(seen, 0, "reader never sampled the file during the race")

    def test_temp_paths_are_unique_per_write(self):
        target = self.tmp / "unique.json"
        names = []
        real = state_store.tempfile.mkstemp

        def spy(*a, **kw):
            fd, name = real(*a, **kw)
            names.append(Path(name).name)
            return fd, name

        with mock.patch.object(state_store.tempfile, "mkstemp", side_effect=spy):
            for i in range(20):
                state_store.atomic_write_json(target, {"i": i})
        self.assertEqual(len(set(names)), 20, "temp file names must never repeat")
        self.assertNotIn("unique.json.tmp", names, "must not use a deterministic sibling temp name")


class CorruptionLatchTests(ConcurrencyHarness):
    def corrupt(self, name="history.json"):
        db = self.tmp / name
        db.write_text("{not json", encoding="utf-8")
        return db

    def test_corruption_is_quarantined_and_raises(self):
        db = self.corrupt()
        with self.assertRaises(state_store.StateCorruptionError):
            state_store.load_db(db, default={"entries": []})
        self.assertFalse(db.exists(), "corrupt file must be moved out of the canonical path")
        marker = json.loads(state_store.recovery_marker_path(db).read_text())
        self.assertTrue(Path(marker["quarantined_to"]).exists())
        self.assertIsNone(marker["quarantine_error"])
        self.assertEqual(Path(marker["quarantined_to"]).read_text(), "{not json")

    def test_latch_still_fails_closed_when_canonical_file_is_missing(self):
        """The bug called out in review: fail closed once, then silently reset.

        After quarantine the canonical path no longer exists, so a naive
        implementation reads the next call as a legitimate first run and returns
        an empty history -- exactly the fail-open reset this is meant to prevent.
        """
        db = self.corrupt()
        with self.assertRaises(state_store.StateCorruptionError):
            state_store.load_db(db, default={"entries": []})
        self.assertFalse(db.exists())
        for _ in range(3):
            with self.assertRaises(state_store.StateRecoveryRequiredError):
                state_store.load_db(db, default={"entries": []})
            with self.assertRaises(state_store.StateRecoveryRequiredError):
                state_store.update_db(db, lambda d: d, default={"entries": []})

    def test_latch_survives_process_death(self):
        db = self.corrupt()
        with self.assertRaises(state_store.StateCorruptionError):
            state_store.load_db(db, default={"entries": []})
        code = (
            f"import sys; sys.path.insert(0, {str(ROOT)!r})\n"
            "from forgeboss.autonomy import state_store\n"
            "import pathlib\n"
            "try:\n"
            f"    state_store.load_db(pathlib.Path({str(db)!r}), default={{'entries': []}})\n"
            "except state_store.StateRecoveryRequiredError:\n"
            "    raise SystemExit(9)\n"
            "raise SystemExit(0)\n"
        )
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 9, f"a fresh process re-opened the latched state: {proc.stderr}")

    def test_unparseable_marker_still_latches(self):
        db = self.tmp / "history.json"
        db.write_text(json.dumps({"entries": []}), encoding="utf-8")
        state_store.recovery_marker_path(db).write_text("<<corrupt marker>>", encoding="utf-8")
        with self.assertRaises(state_store.StateRecoveryRequiredError):
            state_store.load_db(db, default={"entries": []})

    def test_empty_file_is_corruption_not_first_run(self):
        db = self.tmp / "history.json"
        db.write_text("", encoding="utf-8")
        with self.assertRaises(state_store.StateCorruptionError):
            state_store.load_db(db, default={"entries": []})

    def test_recovery_requires_explicit_confirmation(self):
        db = self.corrupt()
        with self.assertRaises(state_store.StateCorruptionError):
            state_store.load_db(db, default={"entries": []})
        with self.assertRaises(state_store.StateError):
            state_store.clear_recovery(db)
        with self.assertRaises(state_store.StateRecoveryRequiredError):
            state_store.load_db(db, default={"entries": []})
        self.assertEqual(state_store.main(["status", "--path", str(db)]), 9)
        self.assertEqual(state_store.main(["recover", "--path", str(db), "--confirm"]), 0)
        self.assertEqual(state_store.load_db(db, default={"entries": []}), {"entries": []})

    def test_concurrent_corrupt_readers_do_not_collide_on_quarantine_names(self):
        """Two processes can detect the same corruption inside the same second.

        A second-resolution quarantine name would let one overwrite the other's
        evidence; every reader must also fail closed rather than one winning.
        """
        db = self.corrupt()
        results = self.collect(self.spawn("""
target = pathlib.Path(args[0])
try:
    state_store.load_db(target, default={"entries": []})
except state_store.StateCorruptionError:
    print("corruption")
except state_store.StateRecoveryRequiredError:
    print("latched")
else:
    raise SystemExit("state was read as usable")
""", extra=[db]))
        kinds = [out for _, _, out, _ in results]
        self.assertEqual(len(kinds), WORKERS)
        self.assertEqual(kinds.count("corruption") + kinds.count("latched"), WORKERS)
        quarantines = sorted(p.name for p in self.tmp.iterdir() if ".corrupt-" in p.name)
        self.assertEqual(len(quarantines), len(set(quarantines)))
        self.assertGreaterEqual(len(quarantines), 1)
        for q in quarantines:
            self.assertEqual((self.tmp / q).read_text(), "{not json")


class StaleWriterTests(ConcurrencyHarness):
    def test_stale_snapshot_is_rejected_by_compare_and_set(self):
        db = self.tmp / "cas.json"
        snapshot = state_store.update_db(db, lambda d: d, default={"entries": []})
        gen = state_store.generation(snapshot)
        state_store.update_db(db, lambda d: d.__setitem__("entries", ["newer"]) or d, default={"entries": []})
        with self.assertRaises(state_store.StaleWriterError):
            state_store.commit_db(db, {"entries": ["stale"]}, expected_generation=gen)
        self.assertEqual(state_store.load_db(db)["entries"], ["newer"])

    def test_fresh_snapshot_commits(self):
        db = self.tmp / "cas.json"
        current = state_store.update_db(db, lambda d: d, default={"entries": []})
        state_store.commit_db(db, {"entries": ["ok"]}, expected_generation=state_store.generation(current))
        self.assertEqual(state_store.load_db(db)["entries"], ["ok"])


class CrashRecoveryTests(ConcurrencyHarness):
    def test_lock_is_released_when_the_holder_is_killed(self):
        """A worker killed while holding the lock must not wedge the lane.

        The lock is a kernel advisory lock, so process death releases it with no
        stale-lock heuristic and no manual cleanup.
        """
        db = self.tmp / "history.json"
        state_store.update_db(db, lambda d: d, default={"entries": ["before"]})
        holding = self.tmp / "HOLDING"
        code = (
            f"import sys, time, pathlib; sys.path.insert(0, {str(ROOT)!r})\n"
            "from forgeboss.autonomy import state_store\n"
            f"with state_store.file_lock(pathlib.Path({str(db)!r})):\n"
            f"    pathlib.Path({str(holding)!r}).write_text('1')\n"
            "    time.sleep(120)\n"
        )
        proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 30
            while not holding.exists():
                self.assertIsNone(proc.poll(), "lock holder exited early")
                self.assertLess(time.monotonic(), deadline, "lock holder never acquired the lock")
                time.sleep(0.005)
            with self.assertRaises(state_store.StateLockTimeout):
                state_store.update_db(db, lambda d: d, default={"entries": []}, timeout=0.5)
            proc.kill()
            proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
        state_store.update_db(db, lambda d: d.__setitem__("entries", ["after"]) or d, default={"entries": []})
        self.assertEqual(state_store.load_db(db)["entries"], ["after"])

    def test_failure_before_publish_leaves_the_previous_state_intact(self):
        db = self.tmp / "history.json"
        state_store.atomic_write_json(db, {"entries": ["good"]})
        with mock.patch.object(state_store, "_replace_with_retry", side_effect=OSError("simulated crash")):
            with self.assertRaises(OSError):
                state_store.atomic_write_json(db, {"entries": ["never published"]})
        self.assertEqual(json.loads(db.read_text())["entries"], ["good"])
        self.assertEqual([p.name for p in self.tmp.iterdir() if ".tmp" in p.name], [])

    def test_lock_timeout_fails_closed_rather_than_writing(self):
        db = self.tmp / "history.json"
        state_store.atomic_write_json(db, {"entries": ["original"]})
        with state_store.file_lock(db):
            code = (
                f"import sys, pathlib; sys.path.insert(0, {str(ROOT)!r})\n"
                "from forgeboss.autonomy import state_store\n"
                "try:\n"
                f"    state_store.update_db(pathlib.Path({str(db)!r}), lambda d: d.__setitem__('entries', ['stomped']) or d, timeout=0.4)\n"
                "except state_store.StateLockTimeout:\n"
                "    raise SystemExit(8)\n"
                "raise SystemExit(0)\n"
            )
            proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 8, f"a blocked writer did not fail closed: {proc.stderr}")
        self.assertEqual(json.loads(db.read_text())["entries"], ["original"])


class DurabilityTests(ConcurrencyHarness):
    def test_publish_fsyncs_the_payload_before_replacing(self):
        db = self.tmp / "durable.json"
        with mock.patch.object(state_store.os, "fsync", wraps=os.fsync) as fsync:
            state_store.atomic_write_json(db, {"entries": []})
        self.assertGreaterEqual(fsync.call_count, 1, "temp payload must be fsynced before publication")

    def test_published_bytes_match_the_requested_payload(self):
        db = self.tmp / "durable.json"
        payload = {"entries": [{"n": i} for i in range(500)]}
        state_store.atomic_write_json(db, payload)
        self.assertEqual(json.loads(db.read_text()), payload)
        self.assertEqual(
            hashlib.sha256(db.read_bytes()).hexdigest(),
            hashlib.sha256(json.dumps(payload, indent=2).encode("utf-8")).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
