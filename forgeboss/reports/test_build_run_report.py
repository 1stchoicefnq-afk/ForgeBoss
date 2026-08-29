from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from forgeboss.reports import build_run_report as report


class BuildRunReportHardeningTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        self.state = self.base / "run-reports"
        self.input = self.base / "input.json"
        self.argv = mock.patch.object(sys, "argv", ["build_run_report", "--input", str(self.input)])
        self.argv.start()
        self.state_patch = mock.patch.object(report, "STATE", self.state)
        self.state_patch.start()

    def tearDown(self):
        self.state_patch.stop()
        self.argv.stop()
        self.td.cleanup()

    def _write_input(self, value):
        self.input.write_text(json.dumps(value), encoding="utf-8")

    def _valid(self, run_id="run-123"):
        return {"run_id": run_id, "session": {}, "cycles": []}

    def test_rejects_unsafe_run_ids_before_any_state_write(self):
        bad = ["../escape", "/tmp/x", r"C:\x", r"\\server\share", "a/b", r"a\b", "C:relative", ".", "..", ""]
        for value in bad:
            with self.subTest(value=value):
                self._write_input(self._valid(value))
                with self.assertRaises(report.ReportEvidenceError):
                    report.main()
                self.assertFalse(self.state.exists())

    def test_malformed_nonobject_and_missing_shape_fail_without_output(self):
        cases = [
            "{not-json",
            "[]",
            json.dumps({"run_id": "ok", "cycles": []}),
            json.dumps({"run_id": "ok", "session": {}, "cycles": {}}),
            json.dumps({"run_id": "ok", "session": {}, "cycles": [1]}),
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                if self.state.exists():
                    for p in self.state.iterdir(): p.unlink()
                    self.state.rmdir()
                self.input.write_text(raw, encoding="utf-8")
                with self.assertRaises(report.ReportEvidenceError):
                    report.main()
                self.assertFalse(self.state.exists())

    def test_declared_cycle_evidence_missing_or_malformed_fails_closed(self):
        missing = self.base / "missing.json"
        self._write_input({"run_id": "ok", "session": {}, "cycles": [{"cycle": 1, "report_path": str(missing)}]})
        with self.assertRaises(report.ReportEvidenceError):
            report.main()
        self.assertFalse(self.state.exists())

        bad = self.base / "bad.json"
        bad.write_text("[]", encoding="utf-8")
        self._write_input({"run_id": "ok", "session": {}, "cycles": [{"cycle": 1, "report_path": str(bad)}]})
        with self.assertRaises(report.ReportEvidenceError):
            report.main()
        self.assertFalse(self.state.exists())

    def test_valid_report_writes_all_artifacts_then_last_pointer(self):
        self._write_input(self._valid("good_run-1"))
        self.assertEqual(report.main(), 0)
        jp = self.state / "good_run-1.json"
        tp = self.state / "good_run-1.txt"
        mp = self.state / "good_run-1-github.md"
        last = self.state / "last.json"
        for p in (jp, tp, mp, last): self.assertTrue(p.is_file(), p)
        pointer = json.loads(last.read_text(encoding="utf-8"))
        self.assertEqual(pointer["run_id"], "good_run-1")
        self.assertEqual(pointer["json"], str(jp.resolve(strict=False)))
        self.assertEqual(pointer["text"], str(tp.resolve(strict=False)))
        self.assertEqual(pointer["github_markdown"], str(mp.resolve(strict=False)))
        obj = json.loads(jp.read_text(encoding="utf-8"))
        self.assertEqual(obj["run_id"], "good_run-1")
        self.assertEqual(pointer["sha256"], obj["text_sha256"])

    def test_intermediate_write_failure_never_advances_last_pointer(self):
        self.state.mkdir(parents=True)
        last = self.state / "last.json"
        sentinel = {"run_id": "previous"}
        last.write_text(json.dumps(sentinel), encoding="utf-8")
        self._write_input(self._valid("next"))
        real = report._atomic_write_text
        def fail_text(path, text):
            if Path(path).name == "next.txt":
                raise OSError("injected write failure")
            return real(path, text)
        with mock.patch.object(report, "_atomic_write_text", side_effect=fail_text):
            with self.assertRaises(OSError):
                report.main()
        self.assertEqual(json.loads(last.read_text(encoding="utf-8")), sentinel)

    def test_containment_helper_rejects_escape_even_if_called_directly(self):
        root = self.base / "root"
        with self.assertRaises(report.ReportEvidenceError):
            report._contained_path(root, "../outside")
        self.assertEqual(report._contained_path(root, "inside.json"), (root / "inside.json").resolve(strict=False))


if __name__ == "__main__":
    unittest.main()
