"""Unit regressions for forgeboss.autonomy.state_store.

Every test here maps to a specific fail-open defect raised in review of the
prior AUTONOMY candidate. Multi-process behaviour is covered separately in
test_lane_concurrency.py -- threads cannot demonstrate those defects.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from forgeboss.autonomy import state_store as ss


class TempStateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.path = self.tmp / "state.json"
        self._env = {k: os.environ.get(k) for k in
                     (ss.LOCK_TIMEOUT_ENV, ss.LOCK_POLL_ENV, ss.RUN_ID_ENV)}
        for key in self._env:
            os.environ.pop(key, None)

    def tearDown(self):
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_raw(self, text):
        self.path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Defect 1 -- lock timeout configuration must be validated before use.
# ---------------------------------------------------------------------------


class LockTimeoutConfigTests(TempStateCase):
    def test_nan_timeout_is_rejected_instead_of_waiting_forever(self):
        # NaN makes `monotonic() >= deadline` permanently false, so the previous
        # code would block forever on a contended lock instead of failing closed.
        for value in ("nan", "NaN", "-nan"):
            os.environ[ss.LOCK_TIMEOUT_ENV] = value
            with self.assertRaises(ss.ConfigError):
                ss.lock_timeout()

    def test_infinite_timeout_is_rejected(self):
        for value in ("inf", "Infinity", "-Infinity", "-inf"):
            os.environ[ss.LOCK_TIMEOUT_ENV] = value
            with self.assertRaises(ss.ConfigError):
                ss.lock_timeout()

    def test_nonpositive_timeout_is_rejected(self):
        for value in ("0", "-1", "-0.5"):
            os.environ[ss.LOCK_TIMEOUT_ENV] = value
            with self.assertRaises(ss.ConfigError):
                ss.lock_timeout()

    def test_out_of_range_and_malformed_and_oversized_are_rejected(self):
        for value in ("99999", "0.0001", "abc", "1e400", "9" * 64):
            os.environ[ss.LOCK_TIMEOUT_ENV] = value
            with self.assertRaises(ss.ConfigError):
                ss.lock_timeout()

    def test_bool_is_not_a_timeout(self):
        with self.assertRaises(ss.ConfigError):
            ss.parse_seconds(True, name="t", low=0.1, high=10, default=1)

    def test_valid_values_and_default_are_accepted(self):
        os.environ[ss.LOCK_TIMEOUT_ENV] = "2.5"
        self.assertEqual(ss.lock_timeout(), 2.5)
        os.environ[ss.LOCK_TIMEOUT_ENV] = ""
        self.assertEqual(ss.lock_timeout(), ss.LOCK_TIMEOUT_DEFAULT)
        os.environ.pop(ss.LOCK_TIMEOUT_ENV)
        self.assertEqual(ss.lock_timeout(), ss.LOCK_TIMEOUT_DEFAULT)

    def test_hostile_timeout_fails_before_any_lock_attempt(self):
        os.environ[ss.LOCK_TIMEOUT_ENV] = "nan"
        with self.assertRaises(ss.ConfigError):
            ss.file_lock(self.path)
        self.assertFalse(ss.lock_path_for(self.path).exists(),
                         "no lock file should be created for invalid config")

    def test_poll_interval_is_validated_too(self):
        os.environ[ss.LOCK_POLL_ENV] = "inf"
        with self.assertRaises(ss.ConfigError):
            ss.lock_poll()


# ---------------------------------------------------------------------------
# Defect 2 -- generation is authority metadata, never coerced to 0.
# ---------------------------------------------------------------------------


class GenerationStrictnessTests(TempStateCase):
    def assert_latched(self, raw):
        self.write_raw(raw)
        with self.assertRaises(ss.StateStoreError):
            ss.load_db(self.path, default={"entries": []})
        self.assertTrue(ss.marker_path_for(self.path).exists(),
                        "corruption must leave a durable recovery marker")
        # And it must keep failing closed, not reset to an empty first run.
        with self.assertRaises(ss.RecoveryRequired):
            ss.load_db(self.path, default={"entries": []})

    def test_string_generation_is_corruption(self):
        self.assert_latched(json.dumps(
            {"_state_store": {"schema": 1}, "_generation": "corrupt", "entries": []}))

    def test_bool_generation_is_corruption(self):
        self.assert_latched(json.dumps(
            {"_state_store": {"schema": 1}, "_generation": True, "entries": []}))

    def test_negative_generation_is_corruption(self):
        self.assert_latched(json.dumps(
            {"_state_store": {"schema": 1}, "_generation": -1, "entries": []}))

    def test_float_generation_is_corruption(self):
        self.assert_latched(json.dumps(
            {"_state_store": {"schema": 1}, "_generation": 1.5, "entries": []}))

    def test_overflow_generation_is_corruption(self):
        self.assert_latched(json.dumps(
            {"_state_store": {"schema": 1}, "_generation": 2 ** 70, "entries": []}))

    def test_managed_document_missing_generation_is_corruption(self):
        self.assert_latched(json.dumps({"_state_store": {"schema": 1}, "entries": []}))

    def test_duplicate_generation_key_is_corruption(self):
        # Last-wins duplicate keys let a tamperer hide the real authority value.
        self.assert_latched('{"_state_store":{"schema":1},"_generation":1,"_generation":9}')

    def test_non_finite_number_is_corruption(self):
        self.assert_latched('{"entries":[],"score":NaN}')

    def test_root_must_be_an_object(self):
        self.assert_latched('[1,2,3]')

    def test_legacy_document_without_store_marker_migrates_at_generation_zero(self):
        self.write_raw(json.dumps({"schema": 1, "entries": [{"key": "a"}]}))
        doc = ss.load_db(self.path, default={"entries": []})
        self.assertEqual(ss.generation(doc), 0)
        out = ss.update_db(self.path, lambda d: d, default={"entries": []})
        self.assertEqual(out[ss.GENERATION_KEY], 1)
        self.assertEqual(out["entries"], [{"key": "a"}])
        self.assertFalse(ss.marker_path_for(self.path).exists())

    def test_malformed_generation_never_rewrites_the_canonical_document(self):
        raw = json.dumps({"_state_store": {"schema": 1}, "_generation": "x", "entries": [1]})
        self.write_raw(raw)
        with self.assertRaises(ss.StateStoreError):
            ss.update_db(self.path, lambda d: d, default={"entries": []})
        marker = json.loads(ss.marker_path_for(self.path).read_text())
        quarantined = Path(marker["quarantined_to"])
        self.assertEqual(quarantined.read_text(), raw,
                         "the corrupt bytes must be preserved as evidence")


# ---------------------------------------------------------------------------
# Compare-and-set
# ---------------------------------------------------------------------------


class CompareAndSetTests(TempStateCase):
    def test_generation_increments_and_stale_commit_is_rejected(self):
        ss.update_db(self.path, lambda d: d, default={"entries": []})
        doc = ss.load_db(self.path, default={"entries": []})
        self.assertEqual(ss.generation(doc), 1)
        ss.commit_db(self.path, {"entries": ["a"]}, expected_generation=1)
        with self.assertRaises(ss.StaleWriterError):
            ss.commit_db(self.path, {"entries": ["stale"]}, expected_generation=1)
        self.assertEqual(ss.load_db(self.path)["entries"], ["a"])

    def test_expected_generation_must_be_an_integer(self):
        with self.assertRaises(ss.StateStoreError):
            ss.commit_db(self.path, {}, expected_generation=True)


# ---------------------------------------------------------------------------
# Defect 3 -- lock identity
# ---------------------------------------------------------------------------


@unittest.skipIf(os.name == "nt", "POSIX lock-identity semantics")
class LockIdentityTests(TempStateCase):
    def test_symlinked_lock_path_is_refused(self):
        target = self.tmp / "elsewhere.lock"
        target.write_bytes(b"")
        os.symlink(str(target), str(ss.lock_path_for(self.path)))
        with self.assertRaises(ss.LockIdentityError):
            with ss.file_lock(self.path, timeout=1):
                pass

    def test_hard_linked_lock_file_is_refused(self):
        lock = ss.lock_path_for(self.path)
        lock.write_bytes(b"")
        os.chmod(str(lock), 0o600)
        os.link(str(lock), str(self.tmp / "shadow.lock"))
        with self.assertRaises(ss.LockIdentityError):
            with ss.file_lock(self.path, timeout=0.5):
                pass

    def test_group_writable_lock_file_is_refused(self):
        lock = ss.lock_path_for(self.path)
        lock.write_bytes(b"")
        os.chmod(str(lock), 0o660)
        with self.assertRaises(ss.LockIdentityError):
            with ss.file_lock(self.path, timeout=0.5):
                pass

    def test_replacing_the_lock_inode_makes_the_holder_fail_closed(self):
        with ss.file_lock(self.path, timeout=1) as lock:
            lock.assert_held()
            lock_path = ss.lock_path_for(self.path)
            os.unlink(str(lock_path))
            os.close(os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600))
            with self.assertRaises(ss.LockIdentityError):
                lock.assert_held()

    def test_publication_is_refused_after_the_lock_inode_is_replaced(self):
        with ss.file_lock(self.path, timeout=1) as lock:
            lock_path = ss.lock_path_for(self.path)
            os.unlink(str(lock_path))
            os.close(os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600))
            with self.assertRaises(ss.LockIdentityError):
                ss.publish_json(self.path, {"entries": []}, lock=lock)
        self.assertFalse(self.path.exists(), "nothing may be published under a swapped lock")
        leftovers = [p for p in self.tmp.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [], "the temp file must be cleaned up")

    def test_unlinked_lock_path_is_detected(self):
        with ss.file_lock(self.path, timeout=1) as lock:
            os.unlink(str(ss.lock_path_for(self.path)))
            with self.assertRaises(ss.LockIdentityError):
                lock.assert_held()


# ---------------------------------------------------------------------------
# Publication
# ---------------------------------------------------------------------------


class PublicationTests(TempStateCase):
    def test_temp_name_is_unique_per_write(self):
        seen = set()
        real = ss.tempfile.mkstemp

        def spy(*a, **kw):
            fd, name = real(*a, **kw)
            seen.add(name)
            return fd, name

        ss.tempfile.mkstemp = spy
        try:
            for i in range(5):
                ss.publish_json(self.path, {"i": i})
        finally:
            ss.tempfile.mkstemp = real
        self.assertEqual(len(seen), 5, "each write needs its own temp identity")
        self.assertNotIn(str(self.path) + ".tmp", seen,
                         "the fixed sibling temp name must be gone")

    def test_temp_lives_in_the_destination_directory(self):
        names = []
        real = ss.tempfile.mkstemp

        def spy(*a, **kw):
            fd, name = real(*a, **kw)
            names.append(name)
            return fd, name

        ss.tempfile.mkstemp = spy
        try:
            ss.publish_json(self.path, {"a": 1})
        finally:
            ss.tempfile.mkstemp = real
        self.assertEqual(Path(names[0]).parent, self.path.parent)

    def test_artifact_records_its_writer(self):
        os.environ[ss.RUN_ID_ENV] = "run-abc"
        ss.publish_artifact(self.path, {"kind": "x"})
        doc = json.loads(self.path.read_text())
        self.assertEqual(doc["_provenance"]["claimed_run_id"], "run-abc")
        # Environment text is a claim, not proof of identity.
        self.assertFalse(doc["_provenance"]["run_id_authenticated"])

    def test_no_temp_files_remain_after_success(self):
        ss.publish_json(self.path, {"a": 1})
        self.assertEqual([p.name for p in self.tmp.iterdir()], ["state.json"])


# ---------------------------------------------------------------------------
# Defect 4 -- recovery is a CAS-bound state transition
# ---------------------------------------------------------------------------


class RecoveryContractTests(TempStateCase):
    def latch(self):
        self.write_raw("{not json")
        with self.assertRaises(ss.StateCorruption):
            ss.load_db(self.path, default={"entries": []})
        return json.loads(ss.marker_path_for(self.path).read_text())

    def test_corruption_latch_persists_across_calls(self):
        marker = self.latch()
        self.assertTrue(marker["quarantined_to"])
        self.assertIsNone(marker["quarantine_error"])
        self.assertFalse(self.path.exists())
        for _ in range(3):
            with self.assertRaises(ss.RecoveryRequired):
                ss.load_db(self.path, default={"entries": []})

    def test_recovery_without_a_replacement_is_refused_and_marker_survives(self):
        marker = self.latch()
        # This is the previously-committed "recover --confirm" behaviour: it
        # deleted the marker, the canonical file was still absent, and the next
        # load silently returned empty paid-repair history.
        with self.assertRaises(ss.StaleRecoveryError):
            ss.recover(self.path, marker_id=marker["marker_id"])
        self.assertTrue(ss.marker_path_for(self.path).exists())
        with self.assertRaises(ss.RecoveryRequired):
            ss.load_db(self.path, default={"entries": []})

    def test_reset_empty_requires_explicit_history_loss_acknowledgement(self):
        marker = self.latch()
        with self.assertRaises(ss.StaleRecoveryError):
            ss.recover(self.path, marker_id=marker["marker_id"], reset_empty=True)
        self.assertTrue(ss.marker_path_for(self.path).exists())

    def test_reset_empty_marks_history_loss_unacknowledged(self):
        marker = self.latch()
        ss.recover(self.path, marker_id=marker["marker_id"], reset_empty=True,
                   accept_history_loss=True, operator="tester")
        doc = ss.load_db(self.path, default={"entries": []})
        self.assertTrue(doc["_history_reset_unacknowledged"])

    def test_recovery_must_be_bound_to_the_current_marker_id(self):
        marker = self.latch()
        good = self.tmp / "reconciled.json"
        good.write_text(json.dumps({"entries": [{"key": "kept"}]}))
        with self.assertRaises(ss.StaleRecoveryError):
            ss.recover(self.path, marker_id="0" * 32, replacement=good)
        self.assertTrue(ss.marker_path_for(self.path).exists())
        self.assertEqual(
            json.loads(ss.marker_path_for(self.path).read_text())["marker_id"],
            marker["marker_id"])

    def test_recovery_must_be_bound_to_the_quarantined_digest(self):
        marker = self.latch()
        good = self.tmp / "reconciled.json"
        good.write_text(json.dumps({"entries": []}))
        with self.assertRaises(ss.StaleRecoveryError):
            ss.recover(self.path, marker_id=marker["marker_id"],
                       quarantine_sha256="deadbeef", replacement=good)
        self.assertTrue(ss.marker_path_for(self.path).exists())

    def test_stale_recovery_cannot_erase_a_newer_corruption_marker(self):
        first = self.latch()
        good = self.tmp / "reconciled.json"
        good.write_text(json.dumps({"entries": [{"key": "kept"}]}))
        ss.recover(self.path, marker_id=first["marker_id"],
                   quarantine_sha256=first["corrupt_sha256"], replacement=good)
        # A second, newer corruption event.
        self.write_raw("}}also not json")
        with self.assertRaises(ss.StateCorruption):
            ss.load_db(self.path, default={"entries": []})
        second = json.loads(ss.marker_path_for(self.path).read_text())
        self.assertNotEqual(second["marker_id"], first["marker_id"])
        # An operator replaying the older recovery decision must be rejected.
        with self.assertRaises(ss.StaleRecoveryError):
            ss.recover(self.path, marker_id=first["marker_id"],
                       quarantine_sha256=first["corrupt_sha256"], replacement=good)
        self.assertEqual(
            json.loads(ss.marker_path_for(self.path).read_text())["marker_id"],
            second["marker_id"], "the newer marker must survive")
        with self.assertRaises(ss.RecoveryRequired):
            ss.load_db(self.path, default={"entries": []})

    def test_successful_recovery_publishes_reconciled_history_not_empty(self):
        marker = self.latch()
        good = self.tmp / "reconciled.json"
        good.write_text(json.dumps({"entries": [{"key": "kept"}], "_generation": 4}))
        receipt = ss.recover(self.path, marker_id=marker["marker_id"],
                             quarantine_sha256=marker["corrupt_sha256"],
                             replacement=good, operator="tester")
        self.assertFalse(ss.marker_path_for(self.path).exists())
        doc = ss.load_db(self.path, default={"entries": []})
        self.assertEqual(doc["entries"], [{"key": "kept"}])
        self.assertGreater(ss.generation(doc), 4,
                           "recovery must move past any stale in-flight writer")
        self.assertEqual(receipt["marker_id"], marker["marker_id"])
        log = ss.recovery_log_for(self.path).read_text().strip().splitlines()
        self.assertEqual(len(log), 1)
        self.assertEqual(json.loads(log[0])["marker_id"], marker["marker_id"])

    def test_replacement_must_be_strict_valid_json(self):
        marker = self.latch()
        bad = self.tmp / "bad.json"
        bad.write_text('{"entries":[],"entries":[1]}')
        with self.assertRaises(ss.StaleRecoveryError):
            ss.recover(self.path, marker_id=marker["marker_id"], replacement=bad)
        self.assertTrue(ss.marker_path_for(self.path).exists())

    def test_replacement_with_malformed_generation_is_refused(self):
        marker = self.latch()
        bad = self.tmp / "bad.json"
        bad.write_text(json.dumps({"entries": [], "_generation": "x"}))
        with self.assertRaises(ss.StateCorruption):
            ss.recover(self.path, marker_id=marker["marker_id"], replacement=bad)
        self.assertTrue(ss.marker_path_for(self.path).exists())

    def test_missing_canonical_state_after_a_recovery_is_not_a_first_run(self):
        marker = self.latch()
        good = self.tmp / "reconciled.json"
        good.write_text(json.dumps({"entries": [{"key": "kept"}]}))
        ss.recover(self.path, marker_id=marker["marker_id"], replacement=good)
        self.path.unlink()
        with self.assertRaises(ss.StateCorruption):
            ss.load_db(self.path, default={"entries": []})

    def test_unreadable_marker_still_latches_and_cannot_be_recovered_blindly(self):
        ss.marker_path_for(self.path).write_text("<<not json>>")
        with self.assertRaises(ss.RecoveryRequired):
            ss.load_db(self.path, default={"entries": []})
        with self.assertRaises(ss.StaleRecoveryError):
            ss.recover(self.path, marker_id="anything",
                       replacement=self.tmp / "missing.json")
        self.assertTrue(ss.marker_path_for(self.path).exists())

    def test_first_marker_wins_so_evidence_is_not_overwritten(self):
        marker = self.latch()
        with ss.file_lock(self.path, timeout=1) as lock:
            again = ss._latch_corruption(self.path, b"other", "second", lock)
        self.assertEqual(again["marker_id"], marker["marker_id"])

    def test_quarantine_names_are_unique(self):
        names = set()
        for _ in range(3):
            marker = self.latch()
            names.add(marker["quarantined_to"])
            ss.marker_path_for(self.path).unlink()
        self.assertEqual(len(names), 3)

    def test_quarantine_failure_is_reported_truthfully(self):
        self.write_raw("{not json")
        real = ss.os.replace

        def boom(src, dst):
            if str(src) == str(self.path):
                raise OSError(13, "denied")
            return real(src, dst)

        ss.os.replace = boom
        try:
            with self.assertRaises(ss.StateCorruption):
                ss.load_db(self.path, default={"entries": []})
        finally:
            ss.os.replace = real
        marker = json.loads(ss.marker_path_for(self.path).read_text())
        self.assertIsNone(marker["quarantined_to"])
        self.assertIn("denied", marker["quarantine_error"])


class RecoveryCliTests(TempStateCase):
    def test_status_reports_latch_and_exits_nonzero(self):
        self.write_raw("{not json")
        with self.assertRaises(ss.StateCorruption):
            ss.load_db(self.path, default={"entries": []})
        self.assertEqual(ss.main(["status", "--path", str(self.path)]),
                         ss.EXIT_RECOVERY)

    def test_status_on_clean_state_exits_zero(self):
        self.assertEqual(ss.main(["status", "--path", str(self.path)]), ss.EXIT_OK)

    def test_cli_recover_requires_a_replacement(self):
        self.write_raw("{not json")
        with self.assertRaises(ss.StateCorruption):
            ss.load_db(self.path, default={"entries": []})
        marker = json.loads(ss.marker_path_for(self.path).read_text())
        rc = ss.main(["recover", "--path", str(self.path),
                      "--marker-id", marker["marker_id"]])
        self.assertEqual(rc, ss.EXIT_RECOVERY)
        self.assertTrue(ss.marker_path_for(self.path).exists())


if __name__ == "__main__":
    unittest.main()
