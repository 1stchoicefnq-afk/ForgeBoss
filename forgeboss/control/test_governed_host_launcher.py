from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import forgeboss.control.governed_host_launcher as launcher


class GovernedHostLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state" / "launch-packets"
        self.workspace = self.root / "worktree"
        self.workspace.mkdir(parents=True)

    def test_pristine_workspace_is_accepted(self):
        with mock.patch.object(launcher, "guarded_git", return_value=""):
            out = launcher.assert_governed_workspace_ready(self.state, self.workspace)
        self.assertEqual(out, self.workspace.resolve())

    def test_dirty_workspace_is_rejected_before_paid_launch(self):
        with mock.patch.object(
            launcher,
            "guarded_git",
            return_value="?? forbidden.txt\x00",
        ):
            with self.assertRaisesRegex(
                launcher.GovernedHostLaunchError,
                "must be pristine",
            ):
                launcher.assert_governed_workspace_ready(self.state, self.workspace)

    def test_quarantine_marker_blocks_future_run_even_after_workspace_is_clean(self):
        marker = launcher.quarantine_workspace(
            self.state,
            self.workspace,
            "postflight rejected out-of-scope mutation",
        )
        self.assertTrue(marker.is_file())
        with mock.patch.object(launcher, "guarded_git", return_value="") as git:
            with self.assertRaisesRegex(
                launcher.GovernedHostLaunchError,
                "quarantined",
            ):
                launcher.assert_governed_workspace_ready(self.state, self.workspace)
        git.assert_not_called()

    def test_force_cleanup_removes_every_container_holding_workspace(self):
        ok = mock.Mock(returncode=0, stdout="", stderr="")
        with (
            mock.patch.object(
                launcher,
                "_docker_workspace_containers",
                side_effect=[["abc", "def"], []],
            ),
            mock.patch.object(launcher.subprocess, "run", return_value=ok) as run,
        ):
            launcher._ensure_workspace_containers_absent(
                self.workspace,
                {"PATH": "x"},
                force=True,
            )
        self.assertEqual(run.call_args.args[0], ["docker", "rm", "-f", "abc", "def"])

    def test_cleanup_uncertainty_is_not_safe_to_release(self):
        ok = mock.Mock(returncode=0, stdout="", stderr="")
        with (
            mock.patch.object(
                launcher,
                "_docker_workspace_containers",
                side_effect=[["abc"], ["abc"]],
            ),
            mock.patch.object(launcher.subprocess, "run", return_value=ok),
        ):
            with self.assertRaises(launcher.GovernedHostLaunchError) as ctx:
                launcher._ensure_workspace_containers_absent(
                    self.workspace,
                    {"PATH": "x"},
                    force=True,
                )
        self.assertFalse(ctx.exception.release_safe)
        self.assertTrue(ctx.exception.quarantine)

    def test_timeout_quarantines_workspace_and_requires_cleanup_proof(self):
        runner = self.root / "forgeboss" / "executors" / "mini_swe_runner.py"
        runner.parent.mkdir(parents=True)
        runner.write_text("print('runner')\n", encoding="utf-8")
        packet = self.state / "fake.json"
        fake_task = {
            "purpose": "x",
            "allowed_paths_json": "[\"src/a.py\"]",
            "required_tests_json": "[]",
            "task_id": "T1",
            "governance_mode": "reuse-v1",
            "work_kind": "small-repair",
            "subsystem": "x",
        }
        envelope = {"runId": "R1"}
        real_run = subprocess.run

        def timeout_worker_only(command, *args, **kwargs):
            if (
                isinstance(command, list)
                and command
                and command[0] == sys.executable
                and len(command) > 1
                and str(command[1]).endswith("mini_swe_runner.py")
            ):
                raise subprocess.TimeoutExpired("runner", 1200)
            return real_run(command, *args, **kwargs)

        with (
            mock.patch.object(
                launcher,
                "assert_governed_workspace_ready",
                return_value=self.workspace.resolve(),
            ),
            mock.patch.object(
                launcher,
                "runner_identity",
                return_value=("forgeboss/executors/mini_swe_runner.py", "a" * 64),
            ),
            mock.patch.object(
                launcher,
                "_write_private_packet",
                return_value=packet,
            ),
            mock.patch.object(
                launcher,
                "_issue_executor_guard_lease",
                return_value={"lease": "lease.json", "token": "token"},
            ),
            mock.patch.object(
                launcher,
                "_ensure_workspace_containers_absent",
                side_effect=[None, None],
            ),
            mock.patch.object(
                launcher.subprocess,
                "run",
                side_effect=timeout_worker_only,
            ),
        ):
            with self.assertRaises(launcher.GovernedHostLaunchError) as ctx:
                launcher.run_governed_worker(
                    root=self.root,
                    state_dir=self.state,
                    task=fake_task,
                    workspace=str(self.workspace),
                    current_head="a" * 40,
                    runtime_id="mini-swe",
                    launch_envelope=envelope,
                    expected_runner_sha256="a" * 64,
                    budget_usd=0.25,
                    model="openai/gpt-5.6-luna",
                    timeout_seconds=1200,
                )
        self.assertTrue(ctx.exception.release_safe)
        self.assertTrue(ctx.exception.quarantine)
        marker = launcher._quarantine_marker(self.state, self.workspace)
        self.assertTrue(marker.is_file())


if __name__ == "__main__":
    unittest.main()
