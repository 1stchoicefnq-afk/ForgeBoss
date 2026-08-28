"""Multi-process regressions for the AUTONOMY lane's shared state.

These tests spawn real independent interpreters released together by a
start-gate file. Threads share a GIL, a file table and an flock owner, so they
cannot demonstrate lost updates, temp-path collisions or lock-inode swaps -- the
defects these tests exist to catch.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from forgeboss.autonomy import state_store as ss

ROOT = Path(__file__).resolve().parents[2]
WORKERS = 8
CHILD_TIMEOUT = 120

PRELUDE = f"""
import json,os,sys,time
sys.path.insert(0,{str(ROOT)!r})
from pathlib import Path
from forgeboss.autonomy import state_store as ss

def wait_for_gate(gate):
    for _ in range(20000):
        if Path(gate).exists():
            return
        time.sleep(0.005)
    raise SystemExit('start gate never opened')
"""


def spawn(body, *args, env=None):
    child_env = dict(os.environ)
    child_env.pop(ss.LOCK_TIMEOUT_ENV, None)
    child_env.pop(ss.LOCK_POLL_ENV, None)
    if env:
        child_env.update(env)
    return subprocess.Popen([sys.executable, "-c", PRELUDE + body, *[str(a) for a in args]],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, cwd=str(ROOT), env=child_env)


class ConcurrencyCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.gate = self.tmp / "GO"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def open_gate(self):
        self.gate.write_text("go")

    def collect(self, procs):
        out = []
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=CHILD_TIMEOUT)
            out.append((proc.returncode, stdout.strip(), stderr.strip()))
        return out

    def assert_no_stray_temps(self):
        strays = [p.name for p in self.tmp.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(strays, [], f"temp files left behind: {strays}")


# ---------------------------------------------------------------------------
# Lost updates under concurrent read-modify-write
# ---------------------------------------------------------------------------

APPEND_BODY = """
path, gate, tag = sys.argv[1], sys.argv[2], sys.argv[3]
wait_for_gate(gate)
def mutate(db):
    db.setdefault('entries', []).append({'tag': tag})
    return db
ss.update_db(path, mutate, default={'entries': []})
print('ok')
"""


class LostUpdateTests(ConcurrencyCase):
    def test_every_concurrent_update_survives(self):
        path = self.tmp / "state.json"
        procs = [spawn(APPEND_BODY, path, self.gate, f"w{i}") for i in range(WORKERS)]
        self.open_gate()
        results = self.collect(procs)
        for rc, out, err in results:
            self.assertEqual(rc, 0, err)
        doc = ss.load_db(path, default={"entries": []})
        tags = sorted(e["tag"] for e in doc["entries"])
        self.assertEqual(tags, sorted(f"w{i}" for i in range(WORKERS)),
                         "an unlocked read-modify-write drops all but one writer")
        self.assertEqual(ss.generation(doc), WORKERS)
        self.assert_no_stray_temps()

    def test_document_is_always_valid_json_while_writers_race(self):
        path = self.tmp / "state.json"
        procs = [spawn(APPEND_BODY, path, self.gate, f"w{i}") for i in range(WORKERS)]
        self.open_gate()
        deadline = time.monotonic() + 10
        reads = 0
        while time.monotonic() < deadline and any(p.poll() is None for p in procs):
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                continue
            if not raw:
                continue
            ss.strict_loads(raw.decode("utf-8-sig"))
            reads += 1
        for rc, out, err in self.collect(procs):
            self.assertEqual(rc, 0, err)
        self.assertGreater(reads, 0, "the reader never observed a published document")


# ---------------------------------------------------------------------------
# The lane's real entry points
# ---------------------------------------------------------------------------

MEMORY_BODY = """
path, gate, feedback = sys.argv[1], sys.argv[2], sys.argv[3]
from forgeboss.autonomy import repair_memory as rm
rm.MEM = Path(path)
wait_for_gate(gate)
raise SystemExit(rm.main(['--feedback', feedback]))
"""

PLAYBOOK_BODY = """
path, gate, report = sys.argv[1], sys.argv[2], sys.argv[3]
from forgeboss.autonomy import repair_playbook as rp
rp.DB = Path(path)
rp.build_entries = lambda r, f=None: [json.loads(Path(report).read_text())]
wait_for_gate(gate)
raise SystemExit(rp.main(['record', '--report', report]))
"""


class LaneEntryPointTests(ConcurrencyCase):
    def test_repair_memory_counts_every_concurrent_failure_report(self):
        path = self.tmp / "repair-memory.json"
        feedback = self.tmp / "feedback.json"
        feedback.write_text(json.dumps({
            "signature": "sig-1", "category": "database",
            "acceptance": {"failed_steps": ["a"]}}))
        procs = [spawn(MEMORY_BODY, path, self.gate, feedback) for _ in range(WORKERS)]
        self.open_gate()
        for rc, out, err in self.collect(procs):
            self.assertEqual(rc, 0, err)
        entries = ss.load_db(path, default={"entries": []})["entries"]
        self.assertEqual(len(entries), 1)
        # An undercounted seen_count re-authorises paid repair work already known
        # to be a dead end.
        self.assertEqual(entries[0]["seen_count"], WORKERS)
        self.assert_no_stray_temps()

    def test_repair_playbook_keeps_every_concurrent_record(self):
        path = self.tmp / "repair-playbook.json"
        procs = []
        for i in range(WORKERS):
            report = self.tmp / f"report-{i}.json"
            report.write_text(json.dumps({"key": f"k{i}", "outcome": "failed",
                                          "last_seen": 1.0}))
            procs.append(spawn(PLAYBOOK_BODY, path, self.gate, report))
        self.open_gate()
        for rc, out, err in self.collect(procs):
            self.assertEqual(rc, 0, err)
        entries = ss.load_db(path, default={"entries": []})["entries"]
        self.assertEqual(sorted(e["key"] for e in entries),
                         sorted(f"k{i}" for i in range(WORKERS)))
        self.assert_no_stray_temps()

    def test_repair_memory_query_fails_closed_on_a_latched_database(self):
        path = self.tmp / "repair-memory.json"
        path.write_text("{not json")
        funnel = self.tmp / "funnel.json"
        funnel.write_text(json.dumps({"category": "database", "failure_signature": "s"}))
        body = """
path, funnel = sys.argv[1], sys.argv[2]
from forgeboss.autonomy import repair_memory as rm
rm.MEM = Path(path)
raise SystemExit(rm.main(['--query', funnel]))
"""
        proc = spawn(body, path, funnel)
        rc, out, err = self.collect([proc])[0]
        self.assertEqual(rc, ss.EXIT_RECOVERY)
        payload = json.loads(out)
        self.assertTrue(payload["fail_closed"])
        self.assertIsNone(payload["failed_history"])
        # A fresh process must stay latched rather than reading the now-missing
        # canonical file as a legitimate first run.
        proc = spawn(body, path, funnel)
        rc, out, err = self.collect([proc])[0]
        self.assertEqual(rc, ss.EXIT_RECOVERY)
        self.assertEqual(json.loads(out)["error"], "RecoveryRequired")

    def test_repair_playbook_apply_reports_state_failure_not_a_clean_miss(self):
        path = self.tmp / "repair-playbook.json"
        path.write_text("{not json")
        funnel = self.tmp / "funnel.json"
        funnel.write_text(json.dumps({"target_sha": "x", "category": "database"}))
        body = """
path, funnel = sys.argv[1], sys.argv[2]
from forgeboss.autonomy import repair_playbook as rp
rp.DB = Path(path)
raise SystemExit(rp.main(['apply', '--funnel', funnel, '--repo', '.']))
"""
        rc, out, err = self.collect([spawn(body, path, funnel)])[0]
        self.assertEqual(rc, ss.EXIT_RECOVERY)
        payload = json.loads(out)
        self.assertTrue(payload["fail_closed"])
        self.assertIsNone(payload["hit"], "a state failure must not look like 'no hit'")


# ---------------------------------------------------------------------------
# Lock identity across processes (defect 3)
# ---------------------------------------------------------------------------

HOLDER_BODY = """
path, ready, gate = sys.argv[1], sys.argv[2], sys.argv[3]
with ss.file_lock(path, timeout=60) as lock:
    Path(ready).write_text('held')
    wait_for_gate(gate)
    try:
        ss.publish_json(path, {'entries': ['holder'], 'winner': 'holder'}, lock=lock)
    except ss.LockIdentityError as exc:
        print(json.dumps({'published': False, 'error': type(exc).__name__}))
        raise SystemExit(7)
print(json.dumps({'published': True}))
"""

INTRUDER_BODY = """
path = sys.argv[1]
with ss.file_lock(path, timeout=10) as lock:
    ss.publish_json(path, {'entries': ['intruder'], 'winner': 'intruder'}, lock=lock)
print(json.dumps({'published': True}))
"""


@unittest.skipIf(os.name == "nt", "POSIX unlink-while-open semantics")
class LockIdentityProcessTests(ConcurrencyCase):
    def test_replacing_the_lock_inode_cannot_produce_two_successful_writers(self):
        path = self.tmp / "state.json"
        ready = self.tmp / "READY"
        holder = spawn(HOLDER_BODY, path, ready, self.gate)
        deadline = time.monotonic() + 30
        while not ready.exists() and time.monotonic() < deadline:
            self.assertIsNone(holder.poll(), "holder exited before acquiring the lock")
            time.sleep(0.01)
        self.assertTrue(ready.exists(), "holder never acquired the lock")

        # Hostile sibling swaps the lock inode out from under the holder.
        lock_path = ss.lock_path_for(path)
        os.unlink(str(lock_path))
        os.close(os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600))

        intruder = spawn(INTRUDER_BODY, path)
        rc_i, out_i, err_i = self.collect([intruder])[0]
        self.assertEqual(rc_i, 0, err_i)
        self.assertTrue(json.loads(out_i)["published"])

        self.open_gate()
        rc_h, out_h, err_h = self.collect([holder])[0]
        self.assertEqual(rc_h, ss.EXIT_LOCK_IDENTITY, err_h)
        self.assertFalse(json.loads(out_h)["published"],
                         "a writer whose lock was replaced must not publish")
        self.assertEqual(ss.load_db(path)["winner"], "intruder",
                         "the holder must not have overwritten the intruder's payload")
        self.assert_no_stray_temps()

    def test_second_process_waits_rather_than_entering_a_held_lock(self):
        path = self.tmp / "state.json"
        ready = self.tmp / "READY"
        holder = spawn(HOLDER_BODY, path, ready, self.gate)
        deadline = time.monotonic() + 30
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready.exists())
        body = """
path = sys.argv[1]
try:
    with ss.file_lock(path, timeout=0.5):
        print(json.dumps({'entered': True}))
except ss.LockTimeout:
    print(json.dumps({'entered': False}))
"""
        rc, out, err = self.collect([spawn(body, path)])[0]
        self.assertEqual(rc, 0, err)
        self.assertFalse(json.loads(out)["entered"],
                         "the lock must actually exclude a second process")
        self.open_gate()
        self.collect([holder])


# ---------------------------------------------------------------------------
# Hostile configuration under contention (defect 1)
# ---------------------------------------------------------------------------


@unittest.skipIf(os.name == "nt", "POSIX flock contention")
class HostileTimeoutTests(ConcurrencyCase):
    def _contend(self, timeout_value):
        path = self.tmp / "state.json"
        ready = self.tmp / "READY"
        holder = spawn(HOLDER_BODY, path, ready, self.gate)
        deadline = time.monotonic() + 30
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready.exists(), "holder never acquired the lock")
        body = """
path = sys.argv[1]
try:
    with ss.file_lock(path):
        print(json.dumps({'entered': True}))
except ss.StateStoreError as exc:
    print(json.dumps({'entered': False, 'error': type(exc).__name__}))
    raise SystemExit(ss.exit_code_for(exc))
"""
        contender = spawn(body, path, env={ss.LOCK_TIMEOUT_ENV: timeout_value})
        started = time.monotonic()
        try:
            rc, out, err = self.collect([contender])[0]
        except subprocess.TimeoutExpired:
            contender.kill()
            self.fail(f"contender hung forever with {ss.LOCK_TIMEOUT_ENV}={timeout_value}")
        elapsed = time.monotonic() - started
        self.open_gate()
        self.collect([holder])
        return rc, out, elapsed

    def test_nan_timeout_terminates_bounded_with_a_config_error(self):
        rc, out, elapsed = self._contend("nan")
        self.assertEqual(rc, ss.EXIT_CONFIG)
        self.assertEqual(json.loads(out)["error"], "ConfigError")
        self.assertLess(elapsed, 30, "a NaN deadline must not become an immortal wait")

    def test_infinite_timeout_terminates_bounded_with_a_config_error(self):
        rc, out, elapsed = self._contend("Infinity")
        self.assertEqual(rc, ss.EXIT_CONFIG)
        self.assertLess(elapsed, 30)

    def test_valid_short_timeout_reports_a_lock_timeout(self):
        rc, out, elapsed = self._contend("0.5")
        self.assertEqual(rc, ss.EXIT_LOCK_TIMEOUT)
        self.assertEqual(json.loads(out)["error"], "LockTimeout")


# ---------------------------------------------------------------------------
# Recovery cannot be raced (defect 4)
# ---------------------------------------------------------------------------


class RecoveryRaceTests(ConcurrencyCase):
    def test_a_stale_recovery_process_cannot_erase_a_newer_marker(self):
        path = self.tmp / "state.json"
        good = self.tmp / "reconciled.json"
        good.write_text(json.dumps({"entries": [{"key": "kept"}]}))

        path.write_text("{first corruption")
        with self.assertRaises(ss.StateCorruption):
            ss.load_db(path, default={"entries": []})
        first = json.loads(ss.marker_path_for(path).read_text())
        ss.recover(path, marker_id=first["marker_id"],
                   quarantine_sha256=first["corrupt_sha256"], replacement=good)

        path.write_text("}second corruption")
        with self.assertRaises(ss.StateCorruption):
            ss.load_db(path, default={"entries": []})
        second = json.loads(ss.marker_path_for(path).read_text())

        body = """
path, marker_id, digest, replacement = sys.argv[1:5]
raise SystemExit(ss.main(['recover','--path',path,'--marker-id',marker_id,
                          '--quarantine-sha256',digest,'--from',replacement]))
"""
        rc, out, err = self.collect(
            [spawn(body, path, first["marker_id"], first["corrupt_sha256"], good)])[0]
        self.assertEqual(rc, ss.EXIT_RECOVERY)
        self.assertIn("StaleRecoveryError", err)
        self.assertEqual(json.loads(ss.marker_path_for(path).read_text())["marker_id"],
                         second["marker_id"], "the newer corruption marker must survive")
        with self.assertRaises(ss.RecoveryRequired):
            ss.load_db(path, default={"entries": []})

    def test_concurrent_recoveries_bound_to_one_marker_admit_exactly_one_winner(self):
        path = self.tmp / "state.json"
        good = self.tmp / "reconciled.json"
        good.write_text(json.dumps({"entries": [{"key": "kept"}]}))
        path.write_text("{corrupt")
        with self.assertRaises(ss.StateCorruption):
            ss.load_db(path, default={"entries": []})
        marker = json.loads(ss.marker_path_for(path).read_text())

        body = """
path, gate, marker_id, digest, replacement = sys.argv[1:6]
wait_for_gate(gate)
raise SystemExit(ss.main(['recover','--path',path,'--marker-id',marker_id,
                          '--quarantine-sha256',digest,'--from',replacement]))
"""
        procs = [spawn(body, path, self.gate, marker["marker_id"],
                       marker["corrupt_sha256"], good) for _ in range(4)]
        self.open_gate()
        codes = [rc for rc, _, _ in self.collect(procs)]
        self.assertEqual(codes.count(0), 1, f"exactly one recovery may win, got {codes}")
        self.assertEqual(codes.count(ss.EXIT_RECOVERY), 3)
        doc = ss.load_db(path, default={"entries": []})
        self.assertEqual(doc["entries"], [{"key": "kept"}])
        receipts = ss.recovery_log_for(path).read_text().strip().splitlines()
        self.assertEqual(len(receipts), 1, "recovery must produce exactly one receipt")
        self.assert_no_stray_temps()


if __name__ == "__main__":
    unittest.main()
