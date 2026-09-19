from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeboss.executors.mini_swe_runner import _initial_result, _persist_result


class MiniSweResultEvidenceTests(unittest.TestCase):
    def test_initial_result_binds_packet_workspace_and_exact_base(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            packet=root/"packet.json";workspace=root/"work";workspace.mkdir()
            packet.write_text(json.dumps({
                "task_id":"task-a","builder_id":"builder-a","run_id":"fl1-r",
                "expected_head_revision":"A"*40,
            }),encoding="utf-8")
            result=_initial_result(packet,str(workspace),"openai/test")
            self.assertEqual(result["schema"],1)
            self.assertEqual(result["task_id"],"task-a")
            self.assertEqual(result["builder_id"],"builder-a")
            self.assertEqual(result["run_id"],"fl1-r")
            self.assertEqual(result["expected_head_revision"],"a"*40)
            self.assertEqual(result["workspace"],str(workspace.resolve()))
            self.assertEqual(len(result["packet_sha256"]),64)
            self.assertFalse(result["completed"])
            self.assertIsNone(result["postflight"])

    def test_result_is_written_atomically_under_external_state_root(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"state"
            target=root/"self-build"/"run-a"/"builder-a-result.json"
            result={"executor":"mini-swe","cost_usd":0.25,"completed":True,"error":None}
            with patch.dict(os.environ,{
                "FORGEBOSS_STATE_ROOT":str(root),
                "FORGEBOSS_RESULT_FILE":str(target),
            },clear=False):
                _persist_result(result)
            self.assertTrue(target.is_file())
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")),result)
            self.assertEqual(list(target.parent.glob(target.name+".tmp-*")),[])

    def test_result_path_escape_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"state";outside=Path(td)/"outside.json"
            with patch.dict(os.environ,{
                "FORGEBOSS_STATE_ROOT":str(root),
                "FORGEBOSS_RESULT_FILE":str(outside),
            },clear=False):
                with self.assertRaisesRegex(RuntimeError,"escapes external state root"):
                    _persist_result({"completed":False})

    def test_result_file_without_external_state_root_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            target=Path(td)/"result.json"
            env=dict(os.environ)
            env.pop("FORGEBOSS_STATE_ROOT",None)
            env["FORGEBOSS_RESULT_FILE"]=str(target)
            with patch.dict(os.environ,env,clear=True):
                with self.assertRaisesRegex(RuntimeError,"FORGEBOSS_STATE_ROOT required"):
                    _persist_result({"completed":False})

    def test_no_result_file_is_a_noop(self):
        env=dict(os.environ)
        env.pop("FORGEBOSS_RESULT_FILE",None)
        with patch.dict(os.environ,env,clear=True):
            self.assertIsNone(_persist_result({"completed":False}))


if __name__=="__main__":
    unittest.main()
