from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from forgeboss.control.self_build_workspace import (
    SelfBuildWorkspaceError,
    create_successor_workspace,
)


@unittest.skipUnless(shutil.which("git"), "git is required")
class SelfBuildWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.live = self.root / "live"
        self.live.mkdir()
        self._git(self.live, "init", "-q")
        self._git(self.live, "config", "user.email", "forgeboss-test@example.invalid")
        self._git(self.live, "config", "user.name", "ForgeBoss Test")
        (self.live / "tracked.txt").write_text("known-good\n", encoding="utf-8")
        self._git(self.live, "add", "tracked.txt")
        self._git(self.live, "commit", "-qm", "base")
        self.base = self._git(self.live, "rev-parse", "HEAD").strip()
        self.worktrees = self.root / "worktrees"
        self.state = self.root / "state"

    def tearDown(self):
        self.td.cleanup()

    def _git(self, cwd: Path, *args: str, allow_failure: bool = False) -> str:
        p = subprocess.run(
            [shutil.which("git"), "-C", str(cwd), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if p.returncode and not allow_failure:
            self.fail(f"git {' '.join(args)} failed: {p.stderr}")
        return p.stdout

    def _create(self, wid: str = "workspace-test-0001"):
        return create_successor_workspace(
            self.live,
            self.base,
            worktree_root=self.worktrees,
            state_root=self.state,
            workspace_id=wid,
        )

    def test_exact_sha_successor_is_created_pristine(self):
        r = self._create()
        work = Path(r["worktree_root"])
        self.assertEqual(self._git(work, "rev-parse", "HEAD").strip(), self.base)
        self.assertEqual(self._git(work, "status", "--porcelain=v1").strip(), "")
        self.assertEqual(r["schema"], 2)
        self.assertEqual(r["base_sha"], self.base)
        self.assertEqual(r["head_sha"], self.base)
        self.assertEqual(r["network_policy"], "LOCAL_ONLY")
        self.assertFalse(r["network_transport_requested"])
        self.assertFalse(r["network_isolation_proven"])
        self.assertRegex(r["git_executable_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(r["source_git_metadata_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(r["successor_git_metadata_sha256"], r"^[0-9a-f]{64}$")
        receipt = Path(r["receipt_path"])
        self.assertTrue(receipt.is_file())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)

    def test_live_dirty_and_untracked_files_do_not_leak(self):
        (self.live / "tracked.txt").write_text("DIRTY LIVE\n", encoding="utf-8")
        (self.live / "untracked.txt").write_text("LIVE ONLY\n", encoding="utf-8")
        r = self._create("workspace-test-0002")
        work = Path(r["worktree_root"])
        self.assertEqual((work / "tracked.txt").read_text(encoding="utf-8"), "known-good\n")
        self.assertFalse((work / "untracked.txt").exists())

    def test_successor_write_does_not_change_live_tree(self):
        r = self._create("workspace-test-0003")
        work = Path(r["worktree_root"])
        (work / "tracked.txt").write_text("SUCCESSOR CHANGE\n", encoding="utf-8")
        self.assertEqual((self.live / "tracked.txt").read_text(encoding="utf-8"), "known-good\n")

    def test_destination_inside_live_root_is_refused(self):
        with self.assertRaises(SelfBuildWorkspaceError):
            create_successor_workspace(
                self.live,
                self.base,
                worktree_root=self.live / "BAD-WORKTREES",
                state_root=self.state,
                workspace_id="workspace-test-0004",
            )
        self.assertFalse((self.live / "BAD-WORKTREES").exists())

    def test_state_inside_live_root_is_refused(self):
        with self.assertRaises(SelfBuildWorkspaceError):
            create_successor_workspace(
                self.live,
                self.base,
                worktree_root=self.worktrees,
                state_root=self.live / "BAD-STATE",
                workspace_id="workspace-test-0005",
            )
        self.assertFalse((self.live / "BAD-STATE").exists())

    @unittest.skipIf(os.name == "nt", "portable hook proof; native Windows proof remains separate")
    def test_repository_post_checkout_hook_is_not_executed(self):
        marker = self.root / "HOOK-RAN.txt"
        hook = self.live / ".git" / "hooks" / "post-checkout"
        hook.write_text(
            "#!/bin/sh\nprintf 'ran' > '" + marker.as_posix().replace("'", "'\\''") + "'\n",
            encoding="utf-8",
        )
        hook.chmod(0o700)

        result = self._create("workspace-test-hook1")
        self.assertTrue(Path(result["worktree_root"]).is_dir())
        self.assertFalse(marker.exists(), "repository post-checkout hook executed")

    def test_execution_capable_filter_config_is_refused_before_mutation(self):
        self._git(self.live, "config", "filter.evil.smudge", "echo SHOULD-NOT-RUN")
        wid = "workspace-test-filter"
        with self.assertRaisesRegex(SelfBuildWorkspaceError, "unsafe Git execution/config state"):
            self._create(wid)
        self.assertFalse((self.worktrees / wid).exists())
        branch = self._git(
            self.live,
            "show-ref",
            "--verify",
            "--quiet",
            f"refs/heads/forgeboss/selfbuild/{wid}",
            allow_failure=True,
        )
        self.assertEqual(branch, "")

    def test_external_core_hooks_path_is_refused_before_mutation(self):
        external = self.root / "external-hooks"
        external.mkdir()
        self._git(self.live, "config", "core.hooksPath", str(external))
        wid = "workspace-test-hooks"
        with self.assertRaisesRegex(SelfBuildWorkspaceError, "unsafe Git execution/config state"):
            self._create(wid)
        self.assertFalse((self.worktrees / wid).exists())

    def test_state_root_inside_future_successor_is_refused(self):
        wid = "workspace-test-statein"
        nested_state = self.worktrees / wid / "state"
        with self.assertRaisesRegex(SelfBuildWorkspaceError, "state/receipt path"):
            create_successor_workspace(
                self.live,
                self.base,
                worktree_root=self.worktrees,
                state_root=nested_state,
                workspace_id=wid,
            )
        self.assertFalse((self.worktrees / wid).exists())

    def test_dangling_link_at_successor_destination_is_refused_when_supported(self):
        wid = "workspace-test-link1"
        self.worktrees.mkdir(parents=True)
        destination = self.worktrees / wid
        try:
            destination.symlink_to(self.root / "missing-target", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks unavailable")
        with self.assertRaisesRegex(SelfBuildWorkspaceError, "link-like"):
            self._create(wid)
        self.assertTrue(destination.is_symlink())

    def test_existing_link_at_receipt_destination_is_refused_when_supported(self):
        wid = "workspace-test-link2"
        self.state.mkdir(parents=True)
        receipt = self.state / f"{wid}.json"
        try:
            receipt.symlink_to(self.root / "missing-receipt")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(SelfBuildWorkspaceError, "receipt destination is link-like"):
            self._create(wid)
        self.assertTrue(receipt.is_symlink())

    def test_existing_regular_receipt_is_not_overwritten(self):
        wid = "workspace-test-receipt"
        self.state.mkdir(parents=True)
        receipt = self.state / f"{wid}.json"
        receipt.write_text("KEEP-ME\n", encoding="utf-8")
        with self.assertRaisesRegex(SelfBuildWorkspaceError, "receipt already exists"):
            self._create(wid)
        self.assertEqual(receipt.read_text(encoding="utf-8"), "KEEP-ME\n")
        self.assertFalse((self.worktrees / wid).exists())

    def test_invalid_or_unknown_sha_fails_closed(self):
        with self.assertRaises(SelfBuildWorkspaceError):
            create_successor_workspace(
                self.live,
                "not-a-sha",
                worktree_root=self.worktrees,
                state_root=self.state,
                workspace_id="workspace-test-0006",
            )
        with self.assertRaises(SelfBuildWorkspaceError):
            create_successor_workspace(
                self.live,
                "f" * 40,
                worktree_root=self.worktrees,
                state_root=self.state,
                workspace_id="workspace-test-0007",
            )

    def test_workspace_id_rejects_path_escape(self):
        with self.assertRaises(SelfBuildWorkspaceError):
            create_successor_workspace(
                self.live,
                self.base,
                worktree_root=self.worktrees,
                state_root=self.state,
                workspace_id="../escape",
            )


if __name__ == "__main__":
    unittest.main()