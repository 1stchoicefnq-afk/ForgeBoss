from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from forgeboss.control.workspace import (
    QUARANTINE_DIRNAME,
    STAGE_PREFIX,
    WorkspaceProvisionError,
    cleanup_workspace,
    discover_quarantined_workspaces,
    inspect_source,
    provision_workspace,
    quarantine_status,
    reconcile_quarantined_workspace,
    verify_workspace,
)


class WorkspaceProvisioningV2Tests(unittest.TestCase):
    def setUp(self):
        self.git = Path(shutil.which("git") or "").resolve()
        if not self.git.is_file():
            self.skipTest("git executable unavailable")
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        self.source = self.base / "source"
        self.workspaces = self.base / "workspaces"
        self.workspaces.mkdir()
        self._git(["init", str(self.source)], cwd=self.base)
        self._git(["config", "user.email", "worker-c@example.invalid"], cwd=self.source)
        self._git(["config", "user.name", "Worker C"], cwd=self.source)
        (self.source / "a.txt").write_text("one\n", encoding="utf-8")
        self._git(["add", "a.txt"], cwd=self.source)
        self._git(["commit", "-m", "base"], cwd=self.source)
        self.base_sha = self._git(["rev-parse", "HEAD"], cwd=self.source)
        self.main_branch = self._git(["symbolic-ref", "--short", "HEAD"], cwd=self.source)
        self._git(["branch", "peer-proof", self.base_sha], cwd=self.source)

    def tearDown(self):
        self.td.cleanup()

    def _git(self, args, cwd):
        result = subprocess.run(
            [str(self.git), *args],
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode:
            self.fail(f"git failed: {args}: {result.stderr}")
        return result.stdout.strip()

    def test_provisions_exact_private_git_authority_and_removes_remotes(self):
        target = self.workspaces / "worker-a"
        identity = provision_workspace(self.source, target, self.workspaces, self.base_sha.upper(), "task/one", self.git)
        self.assertEqual(identity.base_sha, self.base_sha)
        self.assertEqual(identity.head_sha, self.base_sha)
        self.assertEqual(identity.branch, "task/one")
        self.assertEqual(identity.remotes, ())
        self.assertEqual(Path(identity.workspace_root), target.resolve())
        self.assertTrue(Path(identity.git_dir).is_relative_to(target.resolve()))
        self.assertTrue(Path(identity.common_dir).is_relative_to(target.resolve()))
        self.assertNotEqual(Path(identity.git_dir), Path(identity.source_git_dir))
        self.assertNotEqual(Path(identity.common_dir), Path(identity.source_common_dir))
        self.assertFalse((Path(identity.common_dir) / "objects" / "info" / "alternates").exists())
        self.assertIsNone(quarantine_status(target, self.workspaces))
        self.assertEqual(list(self.workspaces.glob(f"{STAGE_PREFIX}*")), [])

    def test_hostile_worker_ref_mutation_cannot_change_supervisor_or_peer_refs(self):
        before_main = self._git(["rev-parse", self.main_branch], cwd=self.source)
        before_peer = self._git(["rev-parse", "peer-proof"], cwd=self.source)
        target = self.workspaces / "worker-a"
        provision_workspace(self.source, target, self.workspaces, self.base_sha, "task/one", self.git)
        self._git(["branch", "-f", self.main_branch, "HEAD"], cwd=target)
        self._git(["branch", "-f", "peer-proof", "HEAD"], cwd=target)
        (target / "a.txt").write_text("worker mutation\n", encoding="utf-8")
        self._git(["add", "a.txt"], cwd=target)
        self._git(["config", "user.email", "worker@example.invalid"], cwd=target)
        self._git(["config", "user.name", "Worker"], cwd=target)
        self._git(["commit", "-m", "worker mutation"], cwd=target)
        self._git(["branch", "-f", self.main_branch, "HEAD"], cwd=target)
        self._git(["branch", "-f", "peer-proof", "HEAD"], cwd=target)
        self.assertEqual(self._git(["rev-parse", self.main_branch], cwd=self.source), before_main)
        self.assertEqual(self._git(["rev-parse", "peer-proof"], cwd=self.source), before_peer)

    def test_verify_denies_wrong_head_wrong_branch_and_detached_named_policy(self):
        target = self.workspaces / "worker-a"
        identity = provision_workspace(self.source, target, self.workspaces, self.base_sha, "task/one", self.git)
        source_identity = inspect_source(self.source, self.base_sha, self.git)
        (target / "a.txt").write_text("two\n", encoding="utf-8")
        self._git(["add", "a.txt"], cwd=target)
        self._git(["config", "user.email", "worker@example.invalid"], cwd=target)
        self._git(["config", "user.name", "Worker"], cwd=target)
        self._git(["commit", "-m", "other"], cwd=target)
        with self.assertRaises(WorkspaceProvisionError) as cm:
            verify_workspace(target, self.workspaces, self.base_sha, "task/one", self.git, source_identity=source_identity)
        self.assertEqual(cm.exception.code, "WORKSPACE_HEAD_MISMATCH")
        self._git(["reset", "--hard", self.base_sha], cwd=target)
        self._git(["checkout", "-B", "task/other", self.base_sha], cwd=target)
        with self.assertRaises(WorkspaceProvisionError) as cm:
            verify_workspace(target, self.workspaces, self.base_sha, "task/one", self.git, source_identity=source_identity)
        self.assertEqual(cm.exception.code, "WORKSPACE_BRANCH_MISMATCH")
        self._git(["checkout", "--detach", self.base_sha], cwd=target)
        with self.assertRaises(WorkspaceProvisionError) as cm:
            verify_workspace(target, self.workspaces, self.base_sha, "task/one", self.git, source_identity=source_identity)
        self.assertEqual(cm.exception.code, "WORKSPACE_BRANCH_MISMATCH")
        self.assertEqual(identity.source_identity, source_identity["source_identity"])

    def test_invalid_source_base_branch_and_workspace_escape_fail_closed(self):
        before = set(self.workspaces.iterdir())
        with self.assertRaises(WorkspaceProvisionError):
            provision_workspace(self.base / "missing", self.workspaces / "x", self.workspaces, self.base_sha, "task/x", self.git)
        with self.assertRaises(WorkspaceProvisionError) as cm:
            provision_workspace(self.source, self.workspaces / "x", self.workspaces, "abc", "task/x", self.git)
        self.assertEqual(cm.exception.code, "BASE_SHA_INVALID")
        with self.assertRaises(WorkspaceProvisionError) as cm:
            provision_workspace(self.source, self.workspaces / "x", self.workspaces, self.base_sha, "../bad", self.git)
        self.assertEqual(cm.exception.code, "BRANCH_INVALID")
        with self.assertRaises(WorkspaceProvisionError) as cm:
            provision_workspace(self.source, self.base / "outside", self.workspaces, self.base_sha, "task/x", self.git)
        self.assertEqual(cm.exception.code, "WORKSPACE_ESCAPE")
        self.assertEqual({p for p in self.workspaces.iterdir() if p.name != QUARANTINE_DIRNAME}, before)
        not_git = self.base / "not-git"
        not_git.mkdir()
        with self.assertRaises(WorkspaceProvisionError):
            inspect_source(not_git, self.base_sha, self.git)

    def test_source_and_workspace_symlink_aliases_fail_closed(self):
        source_link = self.base / "source-link"
        workspace_link = self.workspaces / "workspace-link"
        try:
            source_link.symlink_to(self.source, target_is_directory=True)
            target = self.workspaces / "real"
            provision_workspace(self.source, target, self.workspaces, self.base_sha, "task/one", self.git)
            workspace_link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(WorkspaceProvisionError):
            inspect_source(source_link, self.base_sha, self.git)
        with self.assertRaises(WorkspaceProvisionError):
            verify_workspace(workspace_link, self.workspaces, self.base_sha, "task/one", self.git)

    def test_post_clone_failure_cleans_and_proves_absence_before_reraising_original(self):
        target = self.workspaces / "worker-a"
        from forgeboss.control import workspace as workspace_module
        with mock.patch.object(workspace_module, "verify_workspace", side_effect=WorkspaceProvisionError("INJECTED", "forced post-clone failure")):
            with self.assertRaises(WorkspaceProvisionError) as cm:
                provision_workspace(self.source, target, self.workspaces, self.base_sha, "task/one", self.git)
        self.assertEqual(cm.exception.code, "INJECTED")
        self.assertFalse(target.exists())
        self.assertIsNone(quarantine_status(target, self.workspaces))
        self.assertEqual(list(self.workspaces.glob(f"{STAGE_PREFIX}*")), [])

    def test_cleanup_failure_is_quarantined_and_both_failures_are_observable(self):
        target = self.workspaces / "worker-a"
        from forgeboss.control import workspace as workspace_module
        real_rmtree = workspace_module.shutil.rmtree
        def fail_generation_cleanup(path, *args, **kwargs):
            if Path(path).name.startswith(STAGE_PREFIX) or Path(path) == target:
                raise PermissionError("injected rmtree failure")
            return real_rmtree(path, *args, **kwargs)
        with mock.patch.object(workspace_module, "verify_workspace", side_effect=WorkspaceProvisionError("INJECTED", "forced post-clone failure")), mock.patch.object(workspace_module.shutil, "rmtree", side_effect=fail_generation_cleanup):
            with self.assertRaises(WorkspaceProvisionError) as cm:
                provision_workspace(self.source, target, self.workspaces, self.base_sha, "task/one", self.git)
        self.assertEqual(cm.exception.code, "WORKSPACE_PROVISION_CLEANUP_FAILED")
        self.assertEqual(cm.exception.provision_code, "INJECTED")
        self.assertEqual(cm.exception.cleanup_code, "PERMISSIONERROR")
        self.assertTrue(cm.exception.generation_id)
        status = quarantine_status(target, self.workspaces)
        self.assertIsNotNone(status)
        self.assertEqual(status["state"], "quarantined")
        self.assertEqual(status["provisionError"]["code"], "INJECTED")
        self.assertEqual(status["cleanupError"]["code"], "PERMISSIONERROR")
        with self.assertRaises(WorkspaceProvisionError) as blocked:
            provision_workspace(self.source, target, self.workspaces, self.base_sha, "task/two", self.git)
        self.assertEqual(blocked.exception.code, "WORKSPACE_QUARANTINED")

    def test_restart_discovery_and_explicit_reconciliation_clear_only_after_absence(self):
        target = self.workspaces / "worker-a"
        from forgeboss.control import workspace as workspace_module
        real_rmtree = workspace_module.shutil.rmtree
        hit = {"failed": False}
        def fail_once(path, *args, **kwargs):
            p = Path(path)
            if not hit["failed"] and (p.name.startswith(STAGE_PREFIX) or p == target):
                hit["failed"] = True
                raise PermissionError("first cleanup fails")
            return real_rmtree(path, *args, **kwargs)
        with mock.patch.object(workspace_module, "verify_workspace", side_effect=WorkspaceProvisionError("INJECTED", "forced failure")), mock.patch.object(workspace_module.shutil, "rmtree", side_effect=fail_once):
            with self.assertRaises(WorkspaceProvisionError) as cm:
                provision_workspace(self.source, target, self.workspaces, self.base_sha, "task/one", self.git)
        generation = cm.exception.generation_id
        discovered = discover_quarantined_workspaces(self.workspaces)
        self.assertTrue(any(x.get("generation") == generation for x in discovered))
        result = reconcile_quarantined_workspace(target, self.workspaces, generation)
        self.assertTrue(result["reconciled"])
        self.assertFalse(target.exists())
        self.assertIsNone(quarantine_status(target, self.workspaces))
        identity = provision_workspace(self.source, target, self.workspaces, self.base_sha, "task/two", self.git)
        self.assertEqual(identity.branch, "task/two")

    def test_wrong_generation_cannot_clear_quarantine_or_newer_target(self):
        target = self.workspaces / "worker-a"
        from forgeboss.control import workspace as workspace_module
        real_rmtree = workspace_module.shutil.rmtree
        def fail_cleanup(path, *args, **kwargs):
            p = Path(path)
            if p.name.startswith(STAGE_PREFIX) or p == target:
                raise PermissionError("cleanup denied")
            return real_rmtree(path, *args, **kwargs)
        with mock.patch.object(workspace_module, "verify_workspace", side_effect=WorkspaceProvisionError("INJECTED", "forced failure")), mock.patch.object(workspace_module.shutil, "rmtree", side_effect=fail_cleanup):
            with self.assertRaises(WorkspaceProvisionError) as cm:
                provision_workspace(self.source, target, self.workspaces, self.base_sha, "task/one", self.git)
        generation = cm.exception.generation_id
        with self.assertRaises(WorkspaceProvisionError) as wrong:
            reconcile_quarantined_workspace(target, self.workspaces, "0" * 32)
        self.assertEqual(wrong.exception.code, "WORKSPACE_GENERATION_MISMATCH")
        status = quarantine_status(target, self.workspaces)
        surviving = target if target.exists() else Path(status["stage"])
        real_rmtree(surviving)
        surviving.mkdir()
        sentinel = surviving / "newer.txt"
        sentinel.write_text("new generation", encoding="utf-8")
        with self.assertRaises(WorkspaceProvisionError) as mismatch:
            reconcile_quarantined_workspace(target, self.workspaces, generation)
        self.assertEqual(mismatch.exception.code, "WORKSPACE_GENERATION_MISMATCH")
        self.assertTrue(sentinel.exists())
        self.assertIsNotNone(quarantine_status(target, self.workspaces))

    def test_cleanup_refuses_escape_link_and_quarantined_target(self):
        outside = self.base / "outside"
        outside.mkdir()
        with self.assertRaises(WorkspaceProvisionError) as cm:
            cleanup_workspace(outside, self.workspaces)
        self.assertEqual(cm.exception.code, "WORKSPACE_ESCAPE")
        target = self.workspaces / "real"
        target.mkdir()
        link = self.workspaces / "link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(WorkspaceProvisionError):
            cleanup_workspace(link, self.workspaces)
        self.assertTrue(target.exists())

    def test_git_executable_must_be_explicit_absolute_regular_path(self):
        with self.assertRaises(WorkspaceProvisionError) as cm:
            inspect_source(self.source, self.base_sha, "git")
        self.assertEqual(cm.exception.code, "GIT_EXECUTABLE_INVALID")


if __name__ == "__main__":
    unittest.main()
