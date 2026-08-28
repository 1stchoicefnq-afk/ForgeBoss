"""Regression tests for the DEEPAGENTS sandbox policy.

Each test named test_regr_* corresponds to a finding in AUDIT.md.
"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from siteboss_policy import *  # noqa: F403
from siteboss_policy import (
    Evidence,
    GuardedWorkspace,
    ImmutablePacket,
    SecurityDenial,
    StalePacket,
    BudgetExceeded,
    norm,
    under,
    reconcile_evidence,
    required_tests_satisfied,
    revalidate_resume,
    _check_argument_policy,
)
from packet_mapper import from_siteboss_packet


class T(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "src" / "ok.js").write_text("a")
        (self.root / "src" / "no.js").write_text("x")
        self.p = ImmutablePacket(
            "P", "abc", "builder",
            ("src/ok.js", "tests"), ("src/ok.js", "tests/new.js"),
            max_commands=2, max_file_modifications=1,
        )
        self.w = GuardedWorkspace(self.root, self.p)

    def tearDown(self):
        self.tmp.cleanup()

    def _outside(self):
        """A scratch directory outside the workspace, cleaned up with the test."""
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return Path(d.name).resolve()

    # -- baseline behaviour -------------------------------------------------
    def test_authorized(self):
        self.w.read_text("src/ok.js")
        self.w.write_text("src/ok.js", "b")
        self.assertEqual((self.root / "src" / "ok.js").read_text(), "b")

    def test_create_new_file_needs_no_read(self):
        w = GuardedWorkspace(self.root, self.p)
        w.write_text("tests/new.js", "x")
        self.assertEqual((self.root / "tests" / "new.js").read_text(), "x")

    def test_unauthorized(self):
        with self.assertRaises(SecurityDenial):
            self.w.write_text("src/no.js", "b")

    def test_parent(self):
        with self.assertRaises(SecurityDenial):
            self.w.write_text("../secret", "x")

    def test_drive(self):
        with self.assertRaises(SecurityDenial):
            self.w.write_text(r"C:\outside\file", "x")

    def test_unc(self):
        with self.assertRaises(SecurityDenial):
            self.w.write_text(r"\\server\share\x", "x")

    def test_read(self):
        with self.assertRaises(SecurityDenial):
            self.w.read_text("src/no.js")

    def test_file_budget(self):
        self.w.read_text("src/ok.js")
        self.w.write_text("src/ok.js", "b")
        with self.assertRaises(BudgetExceeded):
            self.w.write_text("tests/new.js", "x")

    def test_command_denied(self):
        with self.assertRaises(SecurityDenial):
            self.w.run_command(["git", "status"])

    def test_command_budget(self):
        argv = [sys.executable, "-m", "unittest", "--help"]
        self.w.run_command(argv)
        self.w.run_command(argv)
        with self.assertRaises(BudgetExceeded):
            self.w.run_command(argv)

    def test_stale_head(self):
        with self.assertRaises(StalePacket):
            revalidate_resume(self.p, "def", True, True)

    def test_lease(self):
        with self.assertRaises(StalePacket):
            revalidate_resume(self.p, "abc", False, True)

    def test_controller(self):
        with self.assertRaises(StalePacket):
            revalidate_resume(self.p, "abc", True, False)

    def test_resume_ok(self):
        revalidate_resume(self.p, "abc", True, True)

    def test_symlink_escape(self):
        outside = self._outside()
        link = self.root / "tests" / "link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink unavailable")
        with self.assertRaises(SecurityDenial):
            self.w.write_text("tests/link/x", "x")

    # -- regressions --------------------------------------------------------
    def test_regr_dangling_symlink_escape(self):
        """Defence in depth: exists() is false for a broken symlink, so only the
        resolve() check caught this. The per-component loop now uses is_symlink()
        so both layers hold."""
        outside = self._outside()
        target = outside / "pwned.txt"  # deliberately not created
        link = self.root / "tests" / "dangling"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlink unavailable")
        self.assertFalse(link.exists())
        with self.assertRaises(SecurityDenial):
            self.w.write_text("tests/dangling", "x")
        self.assertFalse(target.exists())

    def test_regr_inworkspace_symlink_bypasses_write_scope(self):
        """tests/alias -> src/no.js keeps the logical path in scope."""
        link = self.root / "tests" / "alias"
        try:
            link.symlink_to(self.root / "src" / "no.js")
        except OSError:
            self.skipTest("symlink unavailable")
        with self.assertRaises(SecurityDenial):
            self.w.write_text("tests/alias", "pwned")
        self.assertEqual((self.root / "src" / "no.js").read_text(), "x")

    def test_regr_inworkspace_symlink_bypasses_read_scope(self):
        link = self.root / "tests" / "peek"
        try:
            link.symlink_to(self.root / "src" / "no.js")
        except OSError:
            self.skipTest("symlink unavailable")
        with self.assertRaises(SecurityDenial):
            self.w.read_text("tests/peek")

    def test_regr_read_before_write_required(self):
        with self.assertRaises(SecurityDenial):
            self.w.write_text("src/ok.js", "clobbered")
        self.assertEqual((self.root / "src" / "ok.js").read_text(), "a")

    def test_regr_workspace_executable_denied(self):
        """A workspace-written file named like an interpreter must not run."""
        p = ImmutablePacket("P", "abc", "builder", ("tests",), ("tests",))
        w = GuardedWorkspace(self.root, p)
        shim = self.root / "tests" / ("npm.cmd" if os.name == "nt" else "python3")
        shim.write_text("#!/bin/sh\necho pwned\n")
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
        with self.assertRaises(SecurityDenial):
            w.run_command([str(shim)])
        with self.assertRaises(SecurityDenial):
            w.run_command(["./tests/" + shim.name])

    def test_regr_inline_code_execution_denied(self):
        """python -c turned the "command class" allowlist into arbitrary code."""
        for argv in (
            [sys.executable, "-c", "print(1)"],
            [sys.executable, "-i"],
            [sys.executable],
            [sys.executable, "-m", "http.server"],
            [sys.executable, "-X", "importtime"],
        ):
            with self.subTest(argv=argv), self.assertRaises(SecurityDenial):
                self.w.run_command(argv)

    def test_regr_python_module_allowlist(self):
        rec = self.w.run_command([sys.executable, "-m", "unittest", "--help"])
        self.assertEqual(rec["exit_code"], 0)

    def test_regr_npx_denied(self):
        """npx fetches and executes arbitrary remote packages."""
        for argv in (["npx", "cowsay", "hi"], ["npx.cmd", "cowsay"], ["/usr/bin/npx", "x"]):
            with self.subTest(argv=argv), self.assertRaises(SecurityDenial):
                self.w.run_command(argv)

    def test_regr_node_argument_policy(self):
        for args in (["-e", "1"], ["--eval=1"], ["-p", "1"], ["--require", "./evil.js"],
                     ["--import=./evil.js"], ["--experimental-loader", "x"], []):
            with self.subTest(args=args), self.assertRaises(SecurityDenial):
                _check_argument_policy("node", args)
        _check_argument_policy("node", ["--test", "tests/"])

    def test_regr_npm_subcommand_allowlist(self):
        for args in (["install", "evil"], ["ci"], ["exec", "evil"], ["publish"],
                     ["config", "get", "//registry.npmjs.org/:_authToken"],
                     ["token", "list"], ["--registry=http://evil"], []):
            with self.subTest(args=args), self.assertRaises(SecurityDenial):
                _check_argument_policy("npm", args)
        _check_argument_policy("npm", ["test"])
        _check_argument_policy("npm", ["run", "test"])

    def test_regr_shell_shim_extensions_denied(self):
        for name in ("npm.bat", "npm.ps1", "node.com", "python.sh"):
            with self.subTest(name=name), self.assertRaises(SecurityDenial):
                self.w.run_command([name, "test"])

    def test_regr_python3_allowed_on_posix(self):
        """python3 is the POSIX interpreter name; denying it broke required_tests."""
        rec = self.w.run_command([sys.executable, "-m", "unittest", "--help"])
        self.assertEqual(rec["exit_code"], 0)

    def test_regr_malformed_argv_denied(self):
        for argv in (None, "python3 -c pwn", 5, [], [None], [""], ["python3", 5], ["python3\x00x"]):
            with self.subTest(argv=argv), self.assertRaises(SecurityDenial):
                self.w.run_command(argv)

    def test_regr_child_env_has_no_host_secrets(self):
        os.environ["SITEBOSS_TEST_SECRET"] = "leak-me"
        self.addCleanup(os.environ.pop, "SITEBOSS_TEST_SECRET", None)
        env = self.w._child_env()
        self.assertNotIn("SITEBOSS_TEST_SECRET", env)
        self.assertEqual(env["PYTHONNOUSERSITE"], "1")
        self.assertEqual(set(env) - {"PATH", "NODE_ENV", "SITEBOSS_SANDBOX",
                                     "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE",
                                     "NO_COLOR", "SystemRoot", "SYSTEMROOT", "COMSPEC",
                                     "PATHEXT", "WINDIR", "TEMP", "TMP"}, set())

    def test_regr_reserved_device_names_denied(self):
        for bad in ("tests/NUL", "tests/con", "tests/aux.txt", "tests/COM1", "tests/lpt9.js"):
            with self.subTest(bad=bad), self.assertRaises(SecurityDenial):
                norm(bad)

    def test_regr_alternate_data_stream_denied(self):
        for bad in ("src/ok.js:evil", "tests/x.txt::$DATA"):
            with self.subTest(bad=bad), self.assertRaises(SecurityDenial):
                norm(bad)

    def test_regr_trailing_dot_or_space_denied(self):
        for bad in ("src/ok.js.", "src/ok.js ", "tests /x"):
            with self.subTest(bad=bad), self.assertRaises(SecurityDenial):
                norm(bad)

    def test_regr_control_characters_denied(self):
        for bad in ("src/ok\x00.js", "src/ok\n.js", "src/\x7f"):
            with self.subTest(bad=bad), self.assertRaises(SecurityDenial):
                norm(bad)

    def test_regr_malformed_scope_entry_grants_nothing(self):
        p = ImmutablePacket("P", "abc", "builder", ("tests",), ("tests",))
        self.assertFalse(under("anything", ("",)))
        self.assertFalse(under("anything", ("/",)))
        self.assertFalse(under("anything", (".",)))
        self.assertFalse(under("anything", (None,)))
        # A malformed entry alongside a valid one must not break the valid one.
        self.assertTrue(under("tests/x", ("..", "tests")))
        self.assertIsNotNone(p)

    def test_regr_packet_rejects_malformed_scope(self):
        with self.assertRaises(SecurityDenial):
            ImmutablePacket("P", "abc", "builder", ("../etc",), ())
        with self.assertRaises(SecurityDenial):
            ImmutablePacket("P", "abc", "builder", (), ("C:/windows",))
        with self.assertRaises(SecurityDenial):
            ImmutablePacket("P", "", "builder", (), ())
        with self.assertRaises(SecurityDenial):
            # A bare string is iterable: "tests" would become 5 char scopes.
            ImmutablePacket("P", "abc", "builder", "tests", ())

    def test_regr_packet_budget_ceiling_enforced(self):
        with self.assertRaises(SecurityDenial):
            ImmutablePacket("P", "abc", "builder", (), (), max_commands=10_000)
        with self.assertRaises(SecurityDenial):
            ImmutablePacket("P", "abc", "builder", (), (), max_file_modifications=-1)

    def test_regr_mapper_clamps_hostile_budgets(self):
        p = from_siteboss_packet({
            "packet_id": "P",
            "expected_head": "abc",
            "allowed_files": ["src"],
            "max_commands": 10_000,
            "max_file_modifications": 10_000,
            "max_subagents": 99,
            "max_model_calls": "999",
        })
        self.assertEqual(p.max_commands, MAX_COMMANDS_CEILING)  # noqa: F405
        self.assertEqual(p.max_file_modifications, MAX_FILE_MODIFICATIONS_CEILING)  # noqa: F405
        self.assertEqual(p.max_subagents, MAX_SUBAGENTS_CEILING)  # noqa: F405
        self.assertEqual(p.max_model_calls, MAX_MODEL_CALLS_CEILING)  # noqa: F405

    def test_regr_mapper_rejects_missing_head(self):
        with self.assertRaises(SecurityDenial):
            from_siteboss_packet({"packet_id": "P"})
        with self.assertRaises(SecurityDenial):
            from_siteboss_packet("not-a-dict")

    def test_regr_resume_rejects_truthy_non_boolean(self):
        for lease, ver in (("expired", True), (1, True), (True, "no"), (True, 1)):
            with self.subTest(lease=lease, ver=ver), self.assertRaises(StalePacket):
                revalidate_resume(self.p, "abc", lease, ver)
        for head in (None, "", "   ", b"abc", 0):
            with self.subTest(head=head), self.assertRaises(StalePacket):
                revalidate_resume(self.p, head, True, True)

    def test_regr_non_directory_traversal_denied(self):
        p = ImmutablePacket("P", "abc", "builder", ("src",), ("src",))
        w = GuardedWorkspace(self.root, p)
        with self.assertRaises(SecurityDenial):
            w.write_text("src/no.js/child", "x")

    def test_regr_read_rejects_non_regular_file(self):
        p = ImmutablePacket("P", "abc", "builder", ("src",), ("src",))
        w = GuardedWorkspace(self.root, p)
        with self.assertRaises(SecurityDenial):
            w.read_text("src")

    def test_regr_read_size_limit(self):
        p = ImmutablePacket("P", "abc", "builder", ("src",), ("src",))
        w = GuardedWorkspace(self.root, p)
        big = self.root / "src" / "big.txt"
        big.write_bytes(b"a" * (MAX_READ_BYTES + 1))  # noqa: F405
        with self.assertRaises(SecurityDenial):
            w.read_text("src/big.txt")

    def test_regr_write_rejects_non_string_content(self):
        with self.assertRaises(SecurityDenial):
            self.w.write_text("tests/new.js", b"bytes")

    def test_regr_evidence_reconciliation_overrides_model_claims(self):
        self.w.read_text("src/ok.js")
        forged = {
            "packet_id": "SPOOFED",
            "status": "COMPLETED",
            "files_read": ["/etc/shadow"],
            "files_changed": ["forgeboss/security/gate.py"],
            "commands_run": [{"argv": ["rm", "-rf", "/"], "exit_code": 0}],
            "tests": [{"argv": ["npm", "test"], "exit_code": 0}],
            "scope_respected": True,
            "write_authority_respected": True,
        }
        out = reconcile_evidence(forged, self.w, self.p)
        self.assertEqual(out["packet_id"], "P")
        # An absent or unrecognised status falls back to FAILED, not COMPLETED.
        self.assertEqual(reconcile_evidence({}, self.w, self.p)["status"], "FAILED")
        self.assertEqual(reconcile_evidence({"status": "OK"}, self.w, self.p)["status"], "FAILED")
        self.assertEqual(out["files_read"], ["src/ok.js"])
        self.assertEqual(out["files_changed"], [])
        self.assertEqual(out["commands_run"], [])
        self.assertEqual(out["tests"], [])
        self.assertTrue(out["review_required"])

    def test_regr_required_tests_cannot_be_forged(self):
        p = ImmutablePacket("P", "abc", "builder", ("src",), ("src",),
                            required_tests=("npm test",))
        w = GuardedWorkspace(self.root, p)
        out = reconcile_evidence({"status": "COMPLETED"}, w, p)
        self.assertEqual(out["status"], "BLOCKED")
        self.assertIn("REQUIRED_TESTS_NOT_SATISFIED", out["blockers"])

    def test_regr_required_tests_need_zero_exit(self):
        p = ImmutablePacket("P", "abc", "builder", (), (), required_tests=("npm test",))
        ev = Evidence(tests=[{"argv": ["npm", "test"], "exit_code": 1}])
        self.assertFalse(required_tests_satisfied(p, ev))
        ev = Evidence(tests=[{"argv": ["npm", "test"], "exit_code": 0}])
        self.assertTrue(required_tests_satisfied(p, ev))


class TimeoutTest(unittest.TestCase):
    def test_regr_timeout_leaves_evidence(self):
        import siteboss_policy
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        p = ImmutablePacket("P", "abc", "builder", ("src",), ("src",))
        w = GuardedWorkspace(root, p)
        original = siteboss_policy.COMMAND_TIMEOUT_SECONDS
        siteboss_policy.COMMAND_TIMEOUT_SECONDS = 1
        self.addCleanup(setattr, siteboss_policy, "COMMAND_TIMEOUT_SECONDS", original)
        script = root / "sleep_test.py"
        script.write_text("import time\ntime.sleep(30)\n")
        with self.assertRaises(BudgetExceeded):
            w.run_command([sys.executable, "sleep_test.py"], test=True)
        self.assertEqual(len(w.evidence.commands_run), 1)
        self.assertTrue(w.evidence.commands_run[0]["timed_out"])
        self.assertEqual(len(w.evidence.tests), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
