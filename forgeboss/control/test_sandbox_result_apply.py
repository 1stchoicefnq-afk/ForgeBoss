from __future__ import annotations

from contextlib import nullcontext
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from forgeboss.control.governed_sandbox import (
    DockerIdentity,
    ProcessResult,
    SandboxResult,
    create_sanitized_source,
    manifest_sha256,
    manifest_tree,
)
from forgeboss.control.sandbox_result_apply import (
    SandboxApplyError,
    apply_sandbox_result,
    capture_sanitized_manifest,
)


class SandboxApplyTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.source = self.root / "workspace"
        self.result = self.root / "result"
        self.source.mkdir()
        self.result.mkdir()
        (self.source / "a.txt").write_text("A0", encoding="utf-8")
        (self.source / "b.txt").write_text("B0", encoding="utf-8")
        self.source_manifest, self.source_digest = capture_sanitized_manifest(self.source)

    def rebuild_result(self):
        if self.result.exists():
            shutil.rmtree(self.result)
        self.result.mkdir()
        create_sanitized_source(self.source, self.result)

    def sandbox(self):
        result_manifest = manifest_tree(self.result)
        return SandboxResult(
            docker=DockerIdentity("/fake/docker", "d" * 64),
            image="example/worker@sha256:" + "a" * 64,
            volume="forgeboss_gov_test",
            worker=ProcessResult(("/fake/docker",), 0, "", "", 0.01),
            result_dir=str(self.result.resolve()),
            task_id="T1",
            run_id="RUN1",
            owner_epoch=7,
            executor="mini-swe",
            source_manifest=self.source_manifest,
            source_manifest_sha256=self.source_digest,
            result_manifest=result_manifest,
            result_manifest_sha256=manifest_sha256(result_manifest),
        )

    def patches(self):
        return (
            mock.patch(
                "forgeboss.control.sandbox_result_apply._WorkspaceFence",
                side_effect=lambda source: nullcontext(),
            ),
            mock.patch(
                "forgeboss.control.sandbox_result_apply._verify_unlocked",
                return_value={"ok": True},
            ),
            mock.patch(
                "forgeboss.control.sandbox_result_apply._assert_live_control_lease",
                return_value=True,
            ),
        )

    def apply(self, sandbox, allowed_paths, *, live_side_effect=None):
        p1, p2, p3 = self.patches()
        with p1, p2, p3 as live:
            if live_side_effect is not None:
                live.side_effect = live_side_effect
            return apply_sandbox_result(
                sandbox,
                source_workspace=self.source,
                allowed_paths=allowed_paths,
                lease_path=self.root / "lease.json",
                lease_token="token",
                packet_path=self.root / "packet.json",
            )

    def test_allowed_modify_add_and_delete_apply_exact_result(self):
        self.rebuild_result()
        (self.result / "a.txt").write_text("A1", encoding="utf-8")
        (self.result / "b.txt").unlink()
        (self.result / "c.txt").write_text("C1", encoding="utf-8")

        evidence = self.apply(
            self.sandbox(),
            ["a.txt", "b.txt", "c.txt"],
        )

        self.assertEqual((self.source / "a.txt").read_text(), "A1")
        self.assertFalse((self.source / "b.txt").exists())
        self.assertEqual((self.source / "c.txt").read_text(), "C1")
        self.assertEqual(set(evidence.changed_paths), {"a.txt", "b.txt", "c.txt"})
        self.assertEqual(
            evidence.after_manifest_sha256,
            evidence.result_manifest_sha256,
        )

    def test_change_outside_allowed_paths_is_blocked_before_mutation(self):
        self.rebuild_result()
        (self.result / "b.txt").write_text("B1", encoding="utf-8")
        with self.assertRaisesRegex(SandboxApplyError, "outside exact allowedPaths"):
            self.apply(self.sandbox(), ["a.txt"])
        self.assertEqual((self.source / "b.txt").read_text(), "B0")

    def test_sensitive_high_impact_allowed_path_is_rejected(self):
        (self.source / "package.json").write_text("{}", encoding="utf-8")
        self.source_manifest, self.source_digest = capture_sanitized_manifest(self.source)
        self.rebuild_result()
        (self.result / "package.json").write_text('{"changed":true}', encoding="utf-8")
        with self.assertRaisesRegex(SandboxApplyError, "allowed path contract is invalid"):
            self.apply(self.sandbox(), ["package.json"])
        self.assertEqual((self.source / "package.json").read_text(), "{}")

    def test_windows_trailing_dot_alias_is_blocked(self):
        self.rebuild_result()
        (self.result / "a.txt").unlink()
        (self.result / "a.txt.").write_text("A1", encoding="utf-8")
        with self.assertRaisesRegex(SandboxApplyError, "Windows alias"):
            self.apply(self.sandbox(), ["a.txt"])
        self.assertEqual((self.source / "a.txt").read_text(), "A0")

    def test_case_only_rename_is_blocked(self):
        self.rebuild_result()
        (self.result / "a.txt").unlink()
        (self.result / "A.TXT").write_text("A1", encoding="utf-8")
        with self.assertRaises(SandboxApplyError):
            self.apply(self.sandbox(), ["a.txt"])
        self.assertEqual((self.source / "a.txt").read_text(), "A0")

    def test_result_tamper_after_manifest_is_blocked(self):
        self.rebuild_result()
        (self.result / "a.txt").write_text("A1", encoding="utf-8")
        sandbox = self.sandbox()
        (self.result / "a.txt").write_text("A2-tampered", encoding="utf-8")
        with self.assertRaisesRegex(SandboxApplyError, "changed after extraction"):
            self.apply(sandbox, ["a.txt"])
        self.assertEqual((self.source / "a.txt").read_text(), "A0")

    def test_host_drift_since_sandbox_baseline_is_blocked(self):
        self.rebuild_result()
        (self.result / "a.txt").write_text("A1", encoding="utf-8")
        sandbox = self.sandbox()
        (self.source / "b.txt").write_text("B-host-drift", encoding="utf-8")
        with self.assertRaisesRegex(SandboxApplyError, "drifted"):
            self.apply(sandbox, ["a.txt"])
        self.assertEqual((self.source / "a.txt").read_text(), "A0")
        self.assertEqual((self.source / "b.txt").read_text(), "B-host-drift")

    def test_live_authority_revocation_mid_apply_rolls_back_prior_file(self):
        self.rebuild_result()
        (self.result / "a.txt").write_text("A1", encoding="utf-8")
        (self.result / "b.txt").write_text("B1", encoding="utf-8")
        sandbox = self.sandbox()
        calls = {"n": 0}

        def live(*args, **kwargs):
            calls["n"] += 1
            # 1 initial, 2 immediately before mutation, 3 before first file,
            # 4 before second file. Revoke on the second file.
            if calls["n"] == 4:
                raise RuntimeError("cancelled")
            return True

        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            self.apply(sandbox, ["a.txt", "b.txt"], live_side_effect=live)

        self.assertEqual((self.source / "a.txt").read_text(), "A0")
        self.assertEqual((self.source / "b.txt").read_text(), "B0")

    def test_noop_result_returns_no_changes(self):
        self.rebuild_result()
        evidence = self.apply(self.sandbox(), ["a.txt"])
        self.assertEqual(evidence.changed_paths, ())
        self.assertEqual((self.source / "a.txt").read_text(), "A0")
        self.assertEqual((self.source / "b.txt").read_text(), "B0")

    def test_addition_parent_directory_is_created_only_at_commit(self):
        self.rebuild_result()
        nested = self.result / "new" / "dir"
        nested.mkdir(parents=True)
        (nested / "c.txt").write_text("C1", encoding="utf-8")
        evidence = self.apply(self.sandbox(), ["new/dir/c.txt"])
        self.assertEqual((self.source / "new" / "dir" / "c.txt").read_text(), "C1")
        self.assertEqual(evidence.changed_paths, ("new/dir/c.txt",))

    def test_parent_symlink_in_real_workspace_blocks_apply(self):
        self.rebuild_result()
        outside = self.root / "outside"
        outside.mkdir()
        target_dir = self.source / "new"
        try:
            target_dir.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        result_dir = self.result / "new"
        result_dir.mkdir()
        (result_dir / "c.txt").write_text("C1", encoding="utf-8")
        sandbox = self.sandbox()
        with self.assertRaises(SandboxApplyError):
            self.apply(sandbox, ["new/c.txt"])
        self.assertFalse((outside / "c.txt").exists())


if __name__ == "__main__":
    unittest.main()
