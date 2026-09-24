from __future__ import annotations

from contextlib import contextmanager
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from forgeboss.control.governed_sandbox import (
    DockerIdentity,
    GovernedSandboxError,
    ProcessResult,
    build_extract_argv,
    build_stage_argv,
    build_worker_argv,
    resolve_docker_identity,
    run_governed_sandbox,
)


IMAGE = "example/worker@sha256:" + "a" * 64


class GovernedSandboxTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.source = self.root / "source"
        self.result = self.root / "result"
        self.source.mkdir()
        self.result.mkdir()
        (self.source / "a.txt").write_text("x", encoding="utf-8")
        self.docker = self.root / "docker"
        self.docker.write_bytes(b"fake-docker-binary")
        self.docker.chmod(0o700)

    def identity(self):
        return DockerIdentity(
            str(self.docker.resolve()),
            hashlib.sha256(self.docker.read_bytes()).hexdigest(),
        )

    def test_argv_never_mounts_forgeboss_control_state_into_worker(self):
        ident = self.identity()
        stage = build_stage_argv(ident, IMAGE, "forgeboss_gov_abc", self.source)
        worker = build_worker_argv(
            ident,
            IMAGE,
            "forgeboss_gov_abc",
            ["python", "worker.py"],
        )
        extract = build_extract_argv(
            ident,
            IMAGE,
            "forgeboss_gov_abc",
            self.result,
        )
        worker_text = "\n".join(worker)
        self.assertIn("--network\nnone", worker_text)
        self.assertIn("--read-only", worker)
        self.assertIn("--cap-drop", worker)
        self.assertIn("ALL", worker)
        self.assertIn("no-new-privileges", worker)
        self.assertIn("type=volume,src=forgeboss_gov_abc,dst=/workspace", worker)
        self.assertNotIn(str(self.source), worker_text)
        self.assertNotIn(str(self.result), worker_text)
        self.assertFalse(any("forgeboss.db" in x or "secret" in x for x in worker))
        self.assertTrue(any("dst=/source,readonly" in x for x in stage))
        self.assertTrue(any("dst=/result" in x for x in extract))

    def test_mutable_image_tag_is_rejected(self):
        with self.assertRaisesRegex(GovernedSandboxError, "pinned"):
            build_worker_argv(self.identity(), "python:3.12", "forgeboss_gov_abc", ["python"])

    def test_worker_command_is_argv_not_shell_string(self):
        with self.assertRaisesRegex(GovernedSandboxError, "argv"):
            build_worker_argv(self.identity(), IMAGE, "forgeboss_gov_abc", "python worker.py")

    def test_mount_paths_with_docker_csv_control_chars_are_rejected(self):
        bad = self.root / "bad,name"
        bad.mkdir()
        with self.assertRaisesRegex(GovernedSandboxError, "mount path"):
            build_stage_argv(self.identity(), IMAGE, "forgeboss_gov_abc", bad)

    def test_resolve_docker_identity_detects_file_hash(self):
        ident = resolve_docker_identity(self.docker)
        self.assertEqual(
            ident.sha256,
            hashlib.sha256(self.docker.read_bytes()).hexdigest(),
        )

    @mock.patch("forgeboss.control.governed_sandbox.paid_start_authority")
    @mock.patch("forgeboss.control.governed_sandbox.resolve_docker_identity")
    def test_host_authority_wraps_only_worker_execution_and_volume_is_removed(
        self,
        resolve_identity,
        paid_authority,
    ):
        resolve_identity.return_value = self.identity()
        calls = []
        inside = {"value": False}

        @contextmanager
        def authority(*args, **kwargs):
            inside["value"] = True
            try:
                yield {"taskId": "T1"}
            finally:
                inside["value"] = False

        paid_authority.side_effect = authority

        def runner(argv, *, timeout_seconds):
            argv = tuple(argv)
            calls.append((argv, inside["value"]))
            if len(argv) >= 3 and argv[1:3] == ("volume", "create"):
                return ProcessResult(argv, 0, argv[-1], "", 0.01)
            if "cp" in argv and "/result/" in argv:
                (self.result / "a.txt").write_text("changed", encoding="utf-8")
            return ProcessResult(argv, 0, "", "", 0.01)

        out = run_governed_sandbox(
            source_workspace=self.source,
            result_dir=self.result,
            image=IMAGE,
            worker_command=["python", "worker.py"],
            lease_path=self.root / "lease.json",
            lease_token="token",
            packet_path=self.root / "packet.json",
            executor="mini-swe",
            control_envelope={"signed": True},
            cli_budget=1.0,
            docker_path=self.docker,
            process_runner=runner,
        )
        worker_calls = [
            x for x in calls
            if IMAGE in x[0] and "python" in x[0] and "worker.py" in x[0]
        ]
        self.assertEqual(len(worker_calls), 1)
        self.assertTrue(worker_calls[0][1])
        self.assertFalse(calls[0][1])
        self.assertFalse(calls[-1][1])
        self.assertEqual(out.result_dir, str(self.result.resolve()))
        self.assertEqual(calls[-1][0][1:4], ("volume", "rm", "-f"))

    @mock.patch("forgeboss.control.governed_sandbox.paid_start_authority")
    @mock.patch("forgeboss.control.governed_sandbox.resolve_docker_identity")
    def test_cleanup_runs_after_worker_failure(self, resolve_identity, paid_authority):
        resolve_identity.return_value = self.identity()

        @contextmanager
        def authority(*args, **kwargs):
            yield {"taskId": "T1"}

        paid_authority.side_effect = authority
        calls = []

        def runner(argv, *, timeout_seconds):
            argv = tuple(argv)
            calls.append(argv)
            if IMAGE in argv and "worker.py" in argv:
                return ProcessResult(argv, 7, "", "boom", 0.01)
            return ProcessResult(argv, 0, "", "", 0.01)

        with self.assertRaisesRegex(GovernedSandboxError, "sandbox worker"):
            run_governed_sandbox(
                source_workspace=self.source,
                result_dir=self.result,
                image=IMAGE,
                worker_command=["python", "worker.py"],
                lease_path=self.root / "lease.json",
                lease_token="token",
                packet_path=self.root / "packet.json",
                executor="mini-swe",
                control_envelope={"signed": True},
                cli_budget=1.0,
                docker_path=self.docker,
                process_runner=runner,
            )
        self.assertEqual(calls[-1][1:4], ("volume", "rm", "-f"))

    def test_result_tree_rejects_symlink(self):
        target = self.root / "outside.txt"
        target.write_text("secret", encoding="utf-8")
        link = self.result / "link"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation unavailable")
        from forgeboss.control.governed_sandbox import _assert_result_tree_safe
        with self.assertRaisesRegex(GovernedSandboxError, "symlink"):
            _assert_result_tree_safe(self.result)


if __name__ == "__main__":
    unittest.main()
