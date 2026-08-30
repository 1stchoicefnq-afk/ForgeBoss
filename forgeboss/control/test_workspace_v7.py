from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from forgeboss.control import workspace as w
from forgeboss.control.workspace_state import ProtectedWorkspaceState, ProtectedWorkspaceStateError


class FakeBoundary:
    def __init__(self):
        self.service_checks = 0
        self.path_checks = 0
        self.deny = False
    def assert_service_principal(self, root):
        self.service_checks += 1
        if self.deny:
            raise RuntimeError("service denied")
        return "fixture-service"
    def assert_protected_path(self, path, *, protected_root=None, secret=False):
        self.path_checks += 1
        if self.deny:
            raise RuntimeError("path denied")


class WorkspaceV7ProtectedStateTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        self.protected = self.base / "protected"; self.protected.mkdir()
        self.workspaces = self.base / "workspaces"; self.workspaces.mkdir()
        self.target = self.workspaces / "worker-a"
        self.boundary = FakeBoundary()
        self.state = ProtectedWorkspaceState(protected_root=self.protected, boundary=self.boundary)

    def tearDown(self):
        self.td.cleanup()

    def _identity(self, path: Path) -> dict:
        return {"resolved": str(path.resolve()), "dev": 1, "ino": 2, "ctimeNs": 3, "mode": 16832, "linuxHandle": {"mountId": 1, "handleType": 1, "handleHex": "aa"}}

    def _record(self, *, generation="a" * 32, oid="1" * 40, state="quarantined"):
        stage = self.workspaces / (w.STAGE_PREFIX + "fixture-" + generation)
        return {"version": w.QUARANTINE_VERSION, "generation": generation, "target": str(self.target), "stage": str(stage), "identity": self._identity(stage), "contentOid": oid, "state": state, "updatedAt": 1.0}

    def test_workspace_operations_require_protected_state(self):
        with self.assertRaises(w.WorkspaceProvisionError) as cm:
            w.quarantine_status(self.target, self.workspaces)
        self.assertEqual(cm.exception.code, "WORKSPACE_PROTECTED_STATE_REQUIRED")
        with self.assertRaises(w.WorkspaceProvisionError):
            w.cleanup_workspace(self.target, self.workspaces)

    def test_state_is_machine_root_anchored_not_workspace_local(self):
        path = self.state.path_for(self.workspaces, self.target)
        self.assertTrue(path.is_relative_to(self.protected.resolve()))
        self.assertFalse(path.is_relative_to(self.workspaces.resolve()))
        self.assertNotIn(".forgeboss-quarantine", str(path))

    def test_restart_readback_uses_same_canonical_key(self):
        record = self._record()
        self.state.write(self.workspaces, self.target, record)
        restarted = ProtectedWorkspaceState(protected_root=self.protected, boundary=self.boundary)
        self.assertEqual(restarted.read(self.workspaces, self.target), record)
        self.assertGreater(self.boundary.service_checks, 2)

    def test_worker_local_forgery_is_not_authority(self):
        local = self.workspaces / ".forgeboss-quarantine"; local.mkdir()
        (local / "forged.json").write_text(json.dumps(self._record()), encoding="utf-8")
        self.assertIsNone(w.quarantine_status(self.target, self.workspaces, protected_state=self.state))

    def test_tampered_protected_target_is_rejected(self):
        record = self._record(); record["target"] = str(self.workspaces / "other")
        self.state.write(self.workspaces, self.target, record)
        with self.assertRaises(w.WorkspaceProvisionError) as cm:
            w.quarantine_status(self.target, self.workspaces, protected_state=self.state)
        self.assertEqual(cm.exception.code, "WORKSPACE_QUARANTINE_INVALID")

    def test_wrong_generation_reconcile_fails_before_mutation(self):
        record = self._record(); self.state.write(self.workspaces, self.target, record)
        with mock.patch.object(w, "_git_executable") as git_check, mock.patch.object(w, "_rmtree_windows_safe") as rm:
            with self.assertRaises(w.WorkspaceProvisionError) as cm:
                w.reconcile_quarantined_workspace(self.target, self.workspaces, "b" * 32, "/definitely/not/a/git/binary", protected_state=self.state)
        self.assertEqual(cm.exception.code, "WORKSPACE_GENERATION_MISMATCH")
        git_check.assert_not_called()
        rm.assert_not_called()

    def test_content_oid_mismatch_blocks_delete_before_mutation(self):
        self.target.mkdir()
        record = self._record(); record["identity"] = self._identity(self.target)
        self.state.write(self.workspaces, self.target, record)
        with mock.patch.object(w, "_git_executable", return_value=Path("/git")), \
             mock.patch.object(w, "_identity_matches", return_value=True), \
             mock.patch.object(w, "_current_content_oid", return_value="2" * 40), \
             mock.patch.object(w, "_rmtree_windows_safe") as rm:
            with self.assertRaises(w.WorkspaceProvisionError) as cm:
                w.reconcile_quarantined_workspace(self.target, self.workspaces, record["generation"], "/git", protected_state=self.state)
        self.assertEqual(cm.exception.code, "WORKSPACE_CONTENT_OID_MISMATCH")
        rm.assert_not_called()
        self.assertTrue(self.target.exists())

    def test_identity_recheck_occurs_immediately_before_delete(self):
        self.target.mkdir()
        record = self._record(); record["identity"] = self._identity(self.target)
        self.state.write(self.workspaces, self.target, record)
        calls = []
        with mock.patch.object(w, "_git_executable", return_value=Path("/git")), \
             mock.patch.object(w, "_identity_matches", return_value=True), \
             mock.patch.object(w, "_current_content_oid", return_value=record["contentOid"]), \
             mock.patch.object(w, "_path_identity", return_value=dict(record["identity"])), \
             mock.patch.object(w, "_stable_generation_equal", return_value=False), \
             mock.patch.object(w, "_rmtree_windows_safe", side_effect=lambda *a: calls.append(a)):
            with self.assertRaises(w.WorkspaceProvisionError) as cm:
                w.reconcile_quarantined_workspace(self.target, self.workspaces, record["generation"], "/git", protected_state=self.state)
        self.assertEqual(cm.exception.code, "WORKSPACE_GENERATION_MISMATCH")
        self.assertEqual(calls, [])

    def test_service_boundary_failure_denies_later_state_operation(self):
        record = self._record(); self.state.write(self.workspaces, self.target, record)
        self.boundary.deny = True
        with self.assertRaises(ProtectedWorkspaceStateError):
            self.state.read(self.workspaces, self.target)

    def test_record_delete_is_idempotent_and_restart_visible(self):
        record = self._record(); self.state.write(self.workspaces, self.target, record)
        self.state.delete(self.workspaces, self.target)
        self.state.delete(self.workspaces, self.target)
        restarted = ProtectedWorkspaceState(protected_root=self.protected, boundary=self.boundary)
        self.assertIsNone(restarted.read(self.workspaces, self.target))

    def test_source_contract_has_no_workspace_local_quarantine_authority(self):
        source = Path(w.__file__).read_text(encoding="utf-8")
        self.assertNotIn('QUARANTINE_DIRNAME = ".forgeboss-quarantine"', source)
        self.assertIn("ProtectedWorkspaceState", source)
        self.assertIn("contentOid", source)


if __name__ == "__main__":
    unittest.main()
