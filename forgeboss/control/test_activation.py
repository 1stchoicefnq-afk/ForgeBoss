from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeboss.control.activation import ActivationError, ActivationManager, _same_process, _terminate_posix_pidfd


class ActivationTests(unittest.TestCase):
    def _identity(self, root, revision="1" * 40, verified=True):
        return {"verified": verified, "revision": revision if verified else None, "codeRoot": str(root.resolve()), "entrypoint": "forgeboss/daemon.py", "manifestPath": str(root / "manifest.json"), "manifestSha256": "2" * 64 if verified else None, "identitySha256": "3" * 64 if verified else None, "treeSha256": "4" * 64 if verified else None, "files": {}}

    def _manager(self, base, verified=True):
        running = base / "running"
        running.mkdir()
        return ActivationManager(base / "state", self._identity(running, verified=verified))

    def _stage(self, manager, base, revision="a" * 40, expected_generation=None):
        root = base / ("candidate-" + revision[:4])
        pkg = root / "forgeboss"
        pkg.mkdir(parents=True)
        (pkg / "daemon.py").write_text("print('candidate')\n", encoding="utf-8")
        manifest = base / ("manifest-" + revision[:4] + ".json")
        manifest.write_text("{}", encoding="utf-8")
        candidate = {"verified": True, "revision": revision, "codeRoot": str(root.resolve()), "entrypoint": "forgeboss/daemon.py", "manifestPath": str(manifest.resolve()), "manifestSha256": "5" * 64, "identitySha256": "6" * 64, "treeSha256": "7" * 64, "files": {"forgeboss/daemon.py": "8" * 64}}
        with patch("forgeboss.control.activation.verify_build_manifest", return_value=candidate):
            return manager.stage(root, manifest, revision, "5" * 64, expected_generation=expected_generation)

    def _probe(self, manager, state):
        manager.begin_probe(expected_generation=state["generation"])
        return manager.record_probe({"startup": True, "health": True, "control": True, "selftests": True, "multiAgent": True, "identity": {"revision": state["candidate"]["revision"], "manifestSha256": state["candidate"]["manifestSha256"], "treeSha256": state["candidate"]["treeSha256"], "identitySha256": state["candidate"]["identitySha256"]}}, expected_generation=state["generation"])

    def test_unverified_running_controller_cannot_stage(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base, False)
            root = base / "candidate"
            root.mkdir()
            manifest = base / "m"
            manifest.write_text("{}")
            with self.assertRaisesRegex(ActivationError, "verified running known-good"):
                manager.stage(root, manifest)

    def test_initialize_pointer_is_exact_and_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            p1 = manager.initialize_known_good()
            p2 = manager.initialize_known_good()
            self.assertEqual(p1["current"]["revision"], "1" * 40)
            self.assertEqual(p1, p2)

    def test_stale_generation_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            manager.initialize_known_good()
            state = self._stage(manager, base)
            with self.assertRaisesRegex(ActivationError, "stale activation generation"):
                manager.begin_probe(expected_generation=state["generation"] - 1)

    def test_duplicate_stage_same_candidate_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            manager.initialize_known_good()
            first = self._stage(manager, base)
            root = Path(first["candidate"]["codeRoot"])
            manifest = Path(first["candidate"]["manifestPath"])
            with patch("forgeboss.control.activation.verify_build_manifest", return_value=first["candidate"]):
                second = manager.stage(root, manifest, first["candidate"]["revision"], first["candidate"]["manifestSha256"], expected_generation=first["generation"])
            self.assertEqual(first["generation"], second["generation"])
            self.assertEqual(first["requestId"], second["requestId"])

    def test_probe_then_promote_preserves_previous_known_good(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            prior = manager.initialize_known_good()["current"]
            state = self._stage(manager, base)
            self._probe(manager, state)
            pointer = manager.promote(expected_generation=state["generation"])
            self.assertEqual(pointer["previous"]["revision"], prior["revision"])
            self.assertEqual(pointer["current"]["revision"], state["candidate"]["revision"])
            self.assertEqual(manager.promote(expected_generation=state["generation"]), pointer)

    def test_failed_probe_retains_prior_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            prior = manager.initialize_known_good()["current"]
            state = self._stage(manager, base)
            manager.begin_probe(expected_generation=state["generation"])
            with self.assertRaisesRegex(ActivationError, "candidate probe failed"):
                manager.record_probe({"startup": True, "health": False, "control": True, "selftests": True, "multiAgent": True, "identity": {}}, expected_generation=state["generation"])
            self.assertEqual(manager.known_good_pointer()["current"]["revision"], prior["revision"])
            self.assertEqual(manager.status()["phase"], "ROLLED_BACK")

    def test_forced_rollback_revokes_candidate_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            prior = manager.initialize_known_good()["current"]
            state = self._stage(manager, base)
            self._probe(manager, state)
            manager.promote(expected_generation=state["generation"])
            one = manager.rollback("forced", expected_generation=state["generation"])
            two = manager.rollback("forced", expected_generation=state["generation"])
            self.assertEqual(one["current"]["revision"], prior["revision"])
            self.assertEqual(two["current"]["revision"], prior["revision"])
            self.assertIsNone(manager.status()["processIdentity"])

    def test_recover_completes_pointer_written_promoting_state(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            manager.initialize_known_good()
            state = self._stage(manager, base)
            self._probe(manager, state)
            state = manager.status()
            state["phase"] = "PROMOTING"
            manager.state_path.write_text(json.dumps(state), encoding="utf-8")
            pointer = {"schema": 2, "generation": state["generation"], "current": state["candidate"], "previous": state["prior"], "updatedAt": 1}
            manager.pointer_path.write_text(json.dumps(pointer), encoding="utf-8")
            recovered = ActivationManager(manager.state_dir, manager.running_identity).recover()
            self.assertEqual(recovered["current"]["revision"], state["candidate"]["revision"])
            self.assertEqual(manager.status()["phase"], "PROMOTED")

    def test_newer_pointer_blocks_stale_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            manager.initialize_known_good()
            state = self._stage(manager, base)
            pointer = manager.known_good_pointer()
            pointer["current"] = {**pointer["current"], "revision": "f" * 40}
            manager.pointer_path.write_text(json.dumps(pointer), encoding="utf-8")
            with self.assertRaisesRegex(ActivationError, "newer known-good authority"):
                manager.rollback("stale", expected_generation=state["generation"])

    def test_termination_failure_quarantines_without_pointer_advance(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            prior = manager.initialize_known_good()["current"]
            state = self._stage(manager, base)
            saved = manager.status()
            saved["processIdentity"] = {"pid": 123, "startToken": "t", "exe": "python"}
            saved["pid"] = 123
            manager.state_path.write_text(json.dumps(saved), encoding="utf-8")
            with patch("forgeboss.control.activation.terminate_verified_process", side_effect=ActivationError("no stable authority")):
                with self.assertRaisesRegex(ActivationError, "termination authority unavailable"):
                    manager.rollback("forced", expected_generation=state["generation"])
            self.assertEqual(manager.status()["phase"], "QUARANTINED")
            self.assertEqual(manager.known_good_pointer()["current"]["revision"], prior["revision"])

    def test_pid_reuse_mismatch_is_not_same_process(self):
        self.assertFalse(_same_process({"pid": 10, "startToken": "old", "exe": "python"}, {"pid": 10, "startToken": "new", "exe": "python"}))

    @unittest.skipIf(os.name == "nt", "Linux pidfd regression")
    def test_pidfd_handle_is_acquired_before_identity_and_replacement_not_signaled(self):
        expected = {"pid": 44, "startToken": "old", "exe": "/usr/bin/python"}
        replacement = {"pid": 44, "startToken": "new", "exe": "/usr/bin/python"}
        with patch("forgeboss.control.activation.os.pidfd_open", return_value=91) as opened, patch("forgeboss.control.activation._posix_identity", return_value=replacement) as identity, patch("forgeboss.control.activation.signal.pidfd_send_signal") as sent, patch("forgeboss.control.activation.os.close") as closed:
            self.assertTrue(_terminate_posix_pidfd(expected, 1.0))
        opened.assert_called_once_with(44, 0)
        identity.assert_called_once_with(44)
        sent.assert_not_called()
        closed.assert_called_once_with(91)

    @unittest.skipIf(os.name == "nt", "Linux pidfd regression")
    def test_pidfd_unavailable_fails_closed_without_numeric_pid_fallback(self):
        expected = {"pid": 44, "startToken": "old", "exe": "/usr/bin/python"}
        with patch.object(os, "pidfd_open", None, create=True), patch("forgeboss.control.activation.signal.pidfd_send_signal", None, create=True), patch("forgeboss.control.activation.os.kill") as numeric_kill:
            with self.assertRaisesRegex(ActivationError, "stable POSIX process handle unavailable"):
                _terminate_posix_pidfd(expected, 1.0)
        numeric_kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
