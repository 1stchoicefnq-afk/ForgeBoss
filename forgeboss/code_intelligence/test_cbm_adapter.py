from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import tempfile
import unittest

from forgeboss.code_intelligence.cbm_adapter import (
    CodeIntelligenceError,
    CodebaseMemoryAdapter,
)


FAKE_BODY = r"""
import json, os, subprocess, sys, time

tool = sys.argv[2]
args = json.loads(sys.argv[3])

if args.get("emit_bytes"):
    count = int(args["emit_bytes"])
    sys.stdout.write('{"blob":"' + ("x" * count) + '"}')
    raise SystemExit(0)

if args.get("stderr_bytes"):
    sys.stderr.write("e" * int(args["stderr_bytes"]))
    raise SystemExit(0)

if args.get("spawn_child_pid_file"):
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(args["spawn_child_pid_file"], "w", encoding="utf-8") as handle:
        handle.write(str(child.pid))
    time.sleep(float(args.get("sleep", 60)))

if args.get("sleep"):
    time.sleep(float(args["sleep"]))

print(json.dumps({
    "tool": tool,
    "args": args,
    "allowed_root": os.environ.get("CBM_ALLOWED_ROOT"),
    "cache_dir": os.environ.get("CBM_CACHE_DIR"),
    "leaked_secret": os.environ.get("FORGEBOSS_TEST_SECRET"),
}, sort_keys=True))
"""


class AdapterFixture(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.workspace = self.root / "project"
        self.workspace.mkdir()
        self.state = self.root / "state"
        self.cache = self.state / "cache"
        self.runtime = self.state / "runtime"
        self.binary = self.root / "fake-cbm.py"
        self.binary.write_text("#!" + sys.executable + "\n" + FAKE_BODY, encoding="utf-8")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def adapter(self, *, timeout_seconds=10):
        return CodebaseMemoryAdapter(
            binary_path=self.binary,
            expected_sha256=self.digest,
            workspace=self.workspace,
            cache_dir=self.cache,
            runtime_dir=self.runtime,
            timeout_seconds=timeout_seconds,
        )


class CodebaseMemoryAdapterTests(AdapterFixture):
    def test_requires_exact_binary_hash(self):
        with self.assertRaises(CodeIntelligenceError):
            CodebaseMemoryAdapter(
                binary_path=self.binary,
                expected_sha256="0" * 64,
                workspace=self.workspace,
                cache_dir=self.cache,
                runtime_dir=self.runtime,
            )

    def test_state_dirs_must_be_disjoint_from_project(self):
        with self.assertRaises(CodeIntelligenceError):
            CodebaseMemoryAdapter(
                binary_path=self.binary,
                expected_sha256=self.digest,
                workspace=self.workspace,
                cache_dir=self.workspace / "cache",
                runtime_dir=self.runtime,
            )
        with self.assertRaises(CodeIntelligenceError):
            CodebaseMemoryAdapter(
                binary_path=self.binary,
                expected_sha256=self.digest,
                workspace=self.workspace,
                cache_dir=self.root,
                runtime_dir=self.root / "other-runtime",
            )

    @unittest.skipIf(os.name == "nt", "POSIX executable fixture")
    def test_index_is_bound_to_exact_workspace_and_environment_is_minimal(self):
        old = os.environ.get("FORGEBOSS_TEST_SECRET")
        os.environ["FORGEBOSS_TEST_SECRET"] = "do-not-leak"
        try:
            result = self.adapter().call("index_repository", {"mode": "full"})
        finally:
            if old is None:
                os.environ.pop("FORGEBOSS_TEST_SECRET", None)
            else:
                os.environ["FORGEBOSS_TEST_SECRET"] = old

        payload = result.payload
        self.assertEqual(payload["args"]["repo_path"], str(self.workspace))
        self.assertEqual(payload["allowed_root"], str(self.workspace))
        self.assertEqual(payload["cache_dir"], str(self.cache))
        self.assertIsNone(payload["leaked_secret"])
        self.assertTrue(result.advisory)
        self.assertFalse(result.freshness_proven)

    def test_index_rejects_different_repo_path(self):
        with self.assertRaises(CodeIntelligenceError):
            self.adapter().call(
                "index_repository",
                {"repo_path": str(self.root / "other")},
            )

    def test_unknown_tool_is_blocked_before_process_start(self):
        with self.assertRaises(CodeIntelligenceError):
            self.adapter().call("install", {})

    def test_binary_change_after_initialization_is_blocked(self):
        adapter = self.adapter()
        self.binary.write_text("#!" + sys.executable + "\n" + FAKE_BODY + "\n# changed\n", encoding="utf-8")
        with self.assertRaises(CodeIntelligenceError):
            adapter.call("list_projects", {})

    def test_staged_binary_change_is_blocked(self):
        adapter = self.adapter()
        adapter.staged_binary.write_bytes(adapter.staged_binary.read_bytes() + b"\n# tampered\n")
        with self.assertRaises(CodeIntelligenceError):
            adapter.call("list_projects", {})

    def test_verified_binary_is_staged_outside_workspace(self):
        adapter = self.adapter()
        self.assertTrue(adapter.staged_binary.is_file())
        self.assertFalse(str(adapter.staged_binary).startswith(str(self.workspace)))
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(adapter.staged_binary.stat().st_mode), 0o700)

    def test_payload_is_read_only_after_success(self):
        if os.name == "nt":
            self.skipTest("POSIX executable fixture")
        result = self.adapter().call("get_architecture", {})
        with self.assertRaises(TypeError):
            result.payload["new"] = True

    @unittest.skipIf(os.name == "nt", "POSIX executable fixture")
    def test_live_stdout_limit_fails_closed(self):
        with self.assertRaisesRegex(CodeIntelligenceError, "stdout exceeded"):
            self.adapter().call("search_code", {"emit_bytes": 2_100_000})

    @unittest.skipIf(os.name == "nt", "POSIX executable fixture")
    def test_completed_stderr_limit_fails_closed(self):
        with self.assertRaisesRegex(CodeIntelligenceError, "stderr exceeded"):
            self.adapter().call("search_code", {"stderr_bytes": 1_100_000})

    def test_oversized_or_non_json_arguments_fail_closed(self):
        with self.assertRaisesRegex(CodeIntelligenceError, "arguments exceed"):
            self.adapter().call("search_code", {"query": "x" * 30_000})
        with self.assertRaisesRegex(CodeIntelligenceError, "not valid JSON data"):
            self.adapter().call("search_code", {"bad": float("nan")})

    @unittest.skipIf(os.name == "nt", "POSIX process-group assertion")
    def test_timeout_reaps_same_group_descendant(self):
        pid_file = self.state / "child.pid"
        with self.assertRaisesRegex(CodeIntelligenceError, "timed out"):
            self.adapter(timeout_seconds=1).call(
                "search_code",
                {
                    "spawn_child_pid_file": str(pid_file),
                    "sleep": 60,
                },
            )
        for _ in range(50):
            if pid_file.exists():
                break
            time.sleep(0.02)
        self.assertTrue(pid_file.exists())
        pid = int(pid_file.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_overlapping_cache_and_runtime_are_rejected(self):
        with self.assertRaises(CodeIntelligenceError):
            CodebaseMemoryAdapter(
                binary_path=self.binary,
                expected_sha256=self.digest,
                workspace=self.workspace,
                cache_dir=self.state,
                runtime_dir=self.state / "runtime",
            )


if __name__ == "__main__":
    unittest.main()