from __future__ import annotations

import shutil
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

    def _git(self, cwd: Path, *args: str) -> str:
        p = subprocess.run(
            [shutil.which("git"), "-C", str(cwd), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if p.returncode:
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
        self.assertEqual(r["base_sha"], self.base)
        self.assertEqual(r["head_sha"], self.base)
        self.assertFalse(r["network_used"])
        self.assertTrue(Path(r["receipt_path"]).is_file())

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
