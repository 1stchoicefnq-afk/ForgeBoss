from __future__ import annotations

import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import forgeboss.executors.isolation_broker as broker


class IsolationBrokerReintegrationTests(unittest.TestCase):
    def _pre(self, root: Path):
        (root / "a.txt").write_text("old", encoding="utf-8")
        authority = {
            "ordinary": {"a.txt": {"kind": "file", "sha256": broker.hashlib.sha256(b"old").hexdigest(), "size": 3}},
            "git": {"g": "same"},
            "head": "h" * 40,
            "worktree": str(root),
        }
        targets = {"a.txt": dict(authority["ordinary"]["a.txt"])}
        return authority, targets

    def test_override_is_test_only(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "broker"
            fake.write_text("x", encoding="utf-8")
            with mock.patch.dict(os.environ, {"FORGEBOSS_TEST_ISOLATION_BROKER": str(fake)}, clear=False):
                os.environ.pop("FORGEBOSS_TEST_MODE", None)
                with self.assertRaises(broker.IsolationBrokerError):
                    broker._broker_path()
            with mock.patch.dict(os.environ, {"FORGEBOSS_TEST_ISOLATION_BROKER": str(fake), "FORGEBOSS_TEST_MODE": "YES"}, clear=False):
                self.assertEqual(broker._broker_path(), fake.resolve())

    def test_broker_must_own_protected_reintegration(self):
        base = {
            "schema": 2, "ok": True, "isolated": True, "paidConsumed": True,
            "reintegrated": True, "reintegrationProtected": True,
            "ordinaryWorkersDeniedDirectWrite": True, "preopenedWritableHandlesExcluded": True,
            "hostWorkspaceMounted": False, "workerHasRuntimeControl": False,
            "localCopybackRequired": False,
        }
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "broker"
            fake.write_text("x", encoding="utf-8")
            env = {"FORGEBOSS_TEST_ISOLATION_BROKER": str(fake), "FORGEBOSS_TEST_MODE": "YES"}
            with mock.patch.dict(os.environ, env, clear=False), mock.patch("subprocess.run") as run:
                run.return_value = mock.Mock(returncode=0, stdout=json.dumps(base).encode(), stderr=b"")
                self.assertTrue(broker._call_broker({"schema": 2})["reintegrated"])
                for field, value in (
                    ("reintegrated", False), ("reintegrationProtected", False),
                    ("ordinaryWorkersDeniedDirectWrite", False), ("preopenedWritableHandlesExcluded", False),
                    ("hostWorkspaceMounted", True), ("workerHasRuntimeControl", True),
                    ("localCopybackRequired", True),
                ):
                    bad = dict(base); bad[field] = value
                    run.return_value = mock.Mock(returncode=0, stdout=json.dumps(bad).encode(), stderr=b"")
                    with self.subTest(field=field), self.assertRaises(broker.IsolationBrokerError):
                        broker._call_broker({"schema": 2})
                bad = dict(base); bad["changes"] = [{"path": "a.txt"}]
                run.return_value = mock.Mock(returncode=0, stdout=json.dumps(bad).encode(), stderr=b"")
                with self.assertRaisesRegex(broker.IsolationBrokerError, "local file payloads"):
                    broker._call_broker({"schema": 2})

    def test_receipt_binds_request_preimages_and_post_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pre_authority, pre_targets = self._pre(root)
            packet = {"allowed_files": ["a.txt"], "context_files": []}
            request = {"schema": 2, "x": 1}
            new_state = {"kind": "file", "sha256": broker.hashlib.sha256(b"new").hexdigest(), "size": 3}
            (root / "a.txt").write_text("new", encoding="utf-8")
            post_authority = {"ordinary": {"a.txt": new_state}, "git": {"g": "same"}, "head": "h" * 40, "worktree": str(root)}
            reply = {"reintegrationReceipt": {
                "schema": 1,
                "requestSha256": broker._digest(request),
                "preAuthoritySha256": broker._digest(pre_authority),
                "preTargetsSha256": broker._digest(pre_targets),
                "appliedPaths": ["a.txt"],
                "postTargets": {"a.txt": new_state},
                "postAuthoritySha256": broker._digest(post_authority),
            }}
            with mock.patch.object(broker.guard, "validate_packet", return_value=(["a.txt"], [])), \
                 mock.patch.object(broker.guard, "snapshot", return_value={"a.txt": new_state}), \
                 mock.patch.object(broker.guard, "git_metadata_snapshot", return_value={"g": "same"}), \
                 mock.patch.object(broker.guard, "git", side_effect=lambda _h, *args: str(root) if "--show-toplevel" in args else "h" * 40):
                self.assertEqual(broker._verify_receipt(reply, request, root, packet, pre_authority, pre_targets), ["a.txt"])
            bad = json.loads(json.dumps(reply)); bad["reintegrationReceipt"]["requestSha256"] = "0" * 64
            with self.assertRaisesRegex(broker.IsolationBrokerError, "request binding mismatch"):
                broker._verify_receipt(bad, request, root, packet, pre_authority, pre_targets)

    def test_local_module_has_no_copyback_mutation_path(self):
        src = inspect.getsource(broker)
        self.assertNotIn("_apply_changes", src)
        self.assertNotIn("_atomic_write_bytes", src)
        self.assertNotIn("contentBase64", src)
        self.assertNotIn(".unlink()", src)
        self.assertNotIn("os.replace", src)
        self.assertIn("run-mini-swe-v2", src)
        self.assertIn("reintegrated", src)
        self.assertIn("ordinaryWorkersDeniedDirectWrite", src)

    def test_receipt_rejects_out_of_scope_applied_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pre_authority, pre_targets = self._pre(root)
            packet = {"allowed_files": ["a.txt"], "context_files": []}
            request = {"schema": 2}
            receipt = {
                "schema": 1,
                "requestSha256": broker._digest(request),
                "preAuthoritySha256": broker._digest(pre_authority),
                "preTargetsSha256": broker._digest(pre_targets),
                "appliedPaths": ["b.txt"],
                "postTargets": {},
                "postAuthoritySha256": "0" * 64,
            }
            with mock.patch.object(broker.guard, "validate_packet", return_value=(["a.txt"], [])):
                with self.assertRaisesRegex(broker.IsolationBrokerError, "out-of-scope"):
                    broker._verify_receipt({"reintegrationReceipt": receipt}, request, root, packet, pre_authority, pre_targets)


if __name__ == "__main__":
    unittest.main()
