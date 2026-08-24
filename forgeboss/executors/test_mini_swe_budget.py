from __future__ import annotations
import json, os, tempfile, unittest
from pathlib import Path
from unittest import mock
import forgeboss.executors.mini_swe_runner as runner


class MiniSweBudgetTests(unittest.TestCase):
    def test_positive_budget_rejects_invalid_or_nonpositive(self):
        for value in (0, -1, float("nan"), float("inf"), float("-inf"), "NaN", "bad", None, True, False):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner._positive_budget(value)
        self.assertEqual(runner._positive_budget("0.25"), 0.25)

    def test_unknown_or_invalid_measured_cost_remains_null(self):
        for value in (None, float("nan"), float("inf"), float("-inf"), -0.01, "bad", True):
            with self.subTest(value=value):
                self.assertIsNone(runner._observed_cost(value))
        self.assertEqual(runner._observed_cost(0), 0.0)
        self.assertEqual(runner._observed_cost("0.42"), 0.42)

    def _authority_env(self, root):
        lease = root / "lease.json"
        envelope = root / "control-envelope.json"
        lease.write_text("{}", encoding="utf-8")
        envelope.write_text("{}", encoding="utf-8")
        return {
            "FORGEBOSS_EXECUTOR_LEASE": str(lease),
            "FORGEBOSS_EXECUTOR_LEASE_TOKEN": "token",
            "FORGEBOSS_CONTROL_ENVELOPE": str(envelope),
        }

    def test_consume_requires_complete_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work = root / "work"
            work.mkdir()
            packet = root / "packet.json"
            packet.write_text("{}", encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(PermissionError):
                runner._consume_executor_budget(packet, work, "0.4")

    def test_consumed_budget_is_only_authority_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work = root / "work"
            work.mkdir()
            packet = root / "packet.json"
            packet.write_text("{}", encoding="utf-8")
            ok = mock.Mock(returncode=0, stdout=json.dumps({"ok": True, "consumed": True, "budget_usd": 0.4}) + "\n", stderr="")
            with mock.patch.object(runner, "ROOT", root), mock.patch.dict(os.environ, self._authority_env(root), clear=True), mock.patch.object(runner.subprocess, "run", ok):
                self.assertEqual(runner._consume_executor_budget(packet, work, "0.4"), 0.4)
            argv = ok.call_args.args[0]
            self.assertIn("consume", argv)
            self.assertIn("--control-envelope", argv)

    def test_cli_budget_cannot_change_consumed_authority(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work = root / "work"
            work.mkdir()
            packet = root / "packet.json"
            packet.write_text("{}", encoding="utf-8")
            ok = mock.Mock(returncode=0, stdout=json.dumps({"ok": True, "consumed": True, "budget_usd": 0.4}) + "\n", stderr="")
            with mock.patch.object(runner, "ROOT", root), mock.patch.dict(os.environ, self._authority_env(root), clear=True), mock.patch.object(runner.subprocess, "run", ok), self.assertRaises(PermissionError):
                runner._consume_executor_budget(packet, work, "0.5")

    def test_failed_or_unconsumed_guard_result_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work = root / "work"
            work.mkdir()
            packet = root / "packet.json"
            packet.write_text("{}", encoding="utf-8")
            cases = [
                mock.Mock(returncode=13, stdout="denied", stderr=""),
                mock.Mock(returncode=0, stdout=json.dumps({"ok": True, "consumed": False, "budget_usd": 0.4}) + "\n", stderr=""),
                mock.Mock(returncode=0, stdout=json.dumps({"ok": True, "consumed": True, "budget_usd": None}) + "\n", stderr=""),
            ]
            for proc in cases:
                with self.subTest(proc=proc), mock.patch.object(runner, "ROOT", root), mock.patch.dict(os.environ, self._authority_env(root), clear=True), mock.patch.object(runner.subprocess, "run", proc), self.assertRaises((PermissionError, ValueError)):
                    runner._consume_executor_budget(packet, work, "0.4")

    def test_main_never_imports_paid_agent_when_consume_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            work = root / "work"
            work.mkdir()
            packet = root / "packet.json"
            packet.write_text(json.dumps({"objective": "x", "allowed_files": ["x"], "context_files": [], "acceptance_criteria": []}), encoding="utf-8")
            old_argv = list(runner.sys.argv)
            runner.sys.argv = ["mini_swe_runner.py", str(packet), str(work), "0.4"]
            try:
                with mock.patch.dict(os.environ, {"FORGEBOSS_ALLOW_PAID_EXECUTOR": "YES"}, clear=True), mock.patch.object(runner, "_consume_executor_budget", side_effect=PermissionError("denied")):
                    self.assertEqual(runner.main(), 12)
            finally:
                runner.sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
