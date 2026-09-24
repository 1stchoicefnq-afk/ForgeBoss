from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import forgeboss.control.governed_host_launcher as launcher


class GovernedCancellationHostTests(unittest.TestCase):
    def test_cancel_before_spawn_never_starts_runner_and_cleans_private_signals(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            runner=root/"trusted_runner.py"
            runner.write_text("print('should not start')\n",encoding="utf-8")
            workspace=root/"worktree"
            workspace.mkdir()
            state=root/"state"/"forgebossd"/"launch-packets"
            event=threading.Event();event.set()
            task={
                "task_id":"T1",
                "purpose":"bounded repair",
                "allowed_paths_json":json.dumps(["src/a.py"]),
                "required_tests_json":"[]",
                "governance_mode":"reuse-v1",
                "work_kind":"small-repair",
                "subsystem":"tests",
            }
            with (
                mock.patch.object(launcher,"runner_identity",return_value=("trusted_runner.py","f"*64)),
                mock.patch.object(launcher,"_issue_executor_guard_lease",return_value={"ok":True,"lease":"lease.json","token":"tok"}),
                mock.patch.object(launcher.subprocess,"Popen") as popen,
            ):
                with self.assertRaises(launcher.GovernedHostLaunchCancelled):
                    launcher.run_governed_worker(
                        root=root,
                        state_dir=state,
                        task=task,
                        workspace=str(workspace),
                        current_head="a"*40,
                        runtime_id="mini-swe",
                        launch_envelope={"signed":True},
                        expected_runner_sha256="f"*64,
                        budget_usd=.25,
                        model="openai/test",
                        cancel_event=event,
                        timeout_seconds=10,
                    )
                popen.assert_not_called()
            self.assertEqual(list(state.glob("governed-packet-*.json")),[])
            self.assertEqual(list(state.glob("cancel-*.signal")),[])

    def test_cancel_signal_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"cancel.signal"
            launcher._signal_cancel(p)
            launcher._signal_cancel(p)
            self.assertEqual(p.read_text(encoding="utf-8"),"cancel\n")

    def test_output_tail_is_bounded(self):
        with tempfile.TemporaryFile(mode="w+b") as f:
            f.write(("x"*20000+"END").encode("utf-8"))
            tail=launcher._tail_file(f,max_bytes=256,max_chars=64)
            self.assertLessEqual(len(tail),64)
            self.assertTrue(tail.endswith("END"))


if __name__=="__main__":
    unittest.main()
