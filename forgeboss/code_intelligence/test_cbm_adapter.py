from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from forgeboss.code_intelligence.cbm_adapter import (
    CodeIntelligenceError,
    CodebaseMemoryAdapter,
)


FAKE = r"""#!/usr/bin/env python3
import json, os, sys

tool = sys.argv[2]
args = json.loads(sys.argv[3])
if tool == "fail":
    print("forced failure", file=sys.stderr)
    raise SystemExit(7)
if tool == "bad-json":
    print("not-json")
    raise SystemExit(0)
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
        self.binary.write_text(FAKE, encoding="utf-8")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def adapter(self):
        return CodebaseMemoryAdapter(
            binary_path=self.binary,
            expected_sha256=self.digest,
            workspace=self.workspace,
            cache_dir=self.cache,
            runtime_dir=self.runtime,
            timeout_seconds=10,
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
        self.binary.write_text(FAKE + "\n# changed\n", encoding="utf-8")
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