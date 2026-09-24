from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeboss.executors.mini_swe_runner import _initial_result, _persist_result, _persist_early_failure, _guard_subprocess, _exception_detail, _hidden_run, _trusted_docker_executable_from_env, CREATE_NO_WINDOW


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

    def test_early_guard_failure_is_persisted_before_runner_exit(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"state"
            target=root/"self-build"/"result.json"
            result={"schema":1,"completed":False,"error":None,"cost_usd":0.0,"calls":0}
            with patch.dict(os.environ,{
                "FORGEBOSS_STATE_ROOT":str(root),
                "FORGEBOSS_RESULT_FILE":str(target),
            },clear=False):
                code=_persist_early_failure(result,"protected paid-start guard denied: fixture",13)
            self.assertEqual(code,13)
            saved=json.loads(target.read_text(encoding="utf-8"))
            self.assertIn("protected paid-start guard denied",saved["error"])
            self.assertFalse(saved["completed"])

    def test_docker_called_process_error_preserves_daemon_stderr(self):
        import subprocess
        ex=subprocess.CalledProcessError(125,["docker","run"],output="",stderr="docker: Error response from daemon: Access is denied.")
        detail=_exception_detail(ex)
        self.assertIn("CalledProcessError",detail)
        self.assertIn("Access is denied",detail)

    def test_hidden_run_applies_windows_no_console_flag(self):
        with patch("forgeboss.executors.mini_swe_runner.subprocess.run") as run:
            run.return_value=type("CP",(),{"returncode":0})()
            _hidden_run(["docker","version"],capture_output=True,text=True)
        self.assertEqual(run.call_args.kwargs["creationflags"],CREATE_NO_WINDOW)

    def test_runner_has_no_processwide_subprocess_monkeypatch(self):
        import inspect
        import forgeboss.executors.mini_swe_runner as m
        source=inspect.getsource(m)
        self.assertNotIn("subprocess.Popen =",source)
        self.assertNotIn("subprocess.Popen=",source)

    @unittest.skipUnless(os.name=="nt","native Windows console proof")
    def test_hidden_child_has_no_console_window_on_windows(self):
        import sys
        code="import ctypes;print(int(bool(ctypes.windll.kernel32.GetConsoleWindow())))"
        cp=_hidden_run([sys.executable,"-I","-S","-c",code],capture_output=True,text=True,check=True)
        self.assertEqual(cp.stdout.strip(),"0")

    def test_installed_docker_path_and_sha_are_enforced_without_path_lookup(self):
        import hashlib,tempfile
        from pathlib import Path
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
        exe=Path(td.name)/("docker.exe" if os.name=="nt" else "docker")
        exe.write_bytes(b"trusted-docker")
        digest=hashlib.sha256(exe.read_bytes()).hexdigest()
        env={"FORGEBOSS_TRUSTED_DOCKER_PATH":str(exe.resolve()),"FORGEBOSS_TRUSTED_DOCKER_SHA256":digest}
        with patch.dict(os.environ,env,clear=False):
            self.assertEqual(_trusted_docker_executable_from_env(),str(exe.resolve()))
        with patch.dict(os.environ,{**env,"FORGEBOSS_TRUSTED_DOCKER_SHA256":"0"*64},clear=False):
            with self.assertRaisesRegex(RuntimeError,"identity changed"):
                _trusted_docker_executable_from_env()

    def test_guard_module_resolves_from_exact_engine_even_with_poisoned_pythonpath(self):
        with tempfile.TemporaryDirectory() as td:
            poison=Path(td)/"not-the-engine"
            poison.mkdir()
            with patch.dict(os.environ,{"PYTHONPATH":str(poison)},clear=False):
                cp=_guard_subprocess(["--help"])
            self.assertEqual(cp.returncode,0,msg=(cp.stdout or "")+(cp.stderr or ""))
            self.assertNotIn("ModuleNotFoundError",(cp.stdout or "")+(cp.stderr or ""))

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