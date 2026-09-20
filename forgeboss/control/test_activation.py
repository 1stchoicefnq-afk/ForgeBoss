from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeboss.control.activation import ActivationError, ActivationManager, _candidate_launch_command, _same_process, _terminate_posix_pidfd
from forgeboss.control.activation_probe import ActivationProbeError,read_activation_ready,write_activation_ready
from forgeboss.control.envelope import daemon_state_root


class ActivationTests(unittest.TestCase):
    def test_external_daemon_state_requires_self_build_and_must_be_outside_code_root(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);code=base/"code";code.mkdir();external=base/"external"
            with patch.dict(os.environ,{"FORGEBOSS_DAEMON_STATE_ROOT":str(external)},clear=False):
                os.environ.pop("FORGEBOSS_SELF_BUILD_MODE",None)
                with self.assertRaisesRegex(RuntimeError,"only in self-build mode"):daemon_state_root(code)
            with patch.dict(os.environ,{"FORGEBOSS_SELF_BUILD_MODE":"YES","FORGEBOSS_DAEMON_STATE_ROOT":str(external)},clear=False):
                self.assertEqual(daemon_state_root(code),external.resolve(strict=False))
            inside=code/"state-external"
            with patch.dict(os.environ,{"FORGEBOSS_SELF_BUILD_MODE":"YES","FORGEBOSS_DAEMON_STATE_ROOT":str(inside)},clear=False):
                with self.assertRaisesRegex(RuntimeError,"outside code root"):daemon_state_root(code)

    def test_activation_ready_protocol_is_exact_exclusive_and_round_trips(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"ready.json";identity={"revision":"a"*40,"manifestSha256":"b"*64,"treeSha256":"c"*64,"identitySha256":"d"*64}
            written=write_activation_ready(path,pid=123,nonce="n"*64,generation=7,host="127.0.0.1",port=32123,identity=identity,state_root=str(Path(td)/"runtime"))
            observed,digest=read_activation_ready(path,timeout=0.2)
            self.assertEqual(observed,written);self.assertEqual(len(digest),64)
            with self.assertRaises(ActivationProbeError):write_activation_ready(path,pid=123,nonce="n"*64,generation=7,host="127.0.0.1",port=32123,identity=identity,state_root=str(Path(td)/"runtime"))

    def test_isolated_module_bootstrap_supports_relative_imports_and_ignores_hostile_pythonpath(self):
        import subprocess,sys
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);root=base/"candidate";good=root/"forgeboss"/"control";good.mkdir(parents=True)
            (good/"helper.py").write_text("VALUE='GOOD'\n",encoding="utf-8")
            entry=good/"daemon.py"
            entry.write_text(
                "from pathlib import Path\nfrom .helper import VALUE\nimport sys\n"
                "def main(): Path(sys.argv[1]).write_text(VALUE,encoding='utf-8')\n",
                encoding="utf-8",
            )
            hostile=base/"hostile"/"forgeboss"/"control";hostile.mkdir(parents=True)
            (hostile/"daemon.py").write_text(
                "from pathlib import Path\nimport sys\n"
                "def main(): Path(sys.argv[1]).write_text('EVIL',encoding='utf-8')\n",
                encoding="utf-8",
            )
            marker=base/"marker.txt"
            argv=_candidate_launch_command(root,entry,"forgeboss/control/daemon.py",[str(marker)])
            env=dict(os.environ);env["PYTHONPATH"]=str(base/"hostile")
            p=subprocess.run(argv,cwd=root,env=env,capture_output=True,text=True,timeout=20)
            self.assertEqual(p.returncode,0,msg=p.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"),"GOOD")

    def test_candidate_module_path_rejects_escape_and_nonmodule(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);entry=root/"x.py";entry.write_text("pass\n",encoding="utf-8")
            with self.assertRaises(ActivationError):
                _candidate_launch_command(root,entry,"../x.py",[])
            with self.assertRaises(ActivationError):
                _candidate_launch_command(root,entry,"forgeboss/control/__init__.py",[])

    def _identity(self, root, revision="1" * 40, verified=True):
        return {"verified": verified, "revision": revision if verified else None, "codeRoot": str(root.resolve()), "entrypoint": "forgeboss/daemon.py", "manifestPath": str(root / "manifest.json"), "manifestSha256": "2" * 64 if verified else None, "identitySha256": "3" * 64 if verified else None, "treeSha256": "4" * 64 if verified else None, "files": {}}

    def _manager(self, base, verified=True):
        running = base / "running"
        running.mkdir()
        return ActivationManager(base / "state", self._identity(running, verified=verified))

    def _stage(self, manager, base, revision="a" * 40, expected_generation=None):
        root = base / ("candidate-" + revision[:4])
        pkg = root / "forgeboss"
        pkg.mkdir(parents=True)
        (pkg / "daemon.py").write_text("print('candidate')\n", encoding="utf-8")
        manifest = base / ("manifest-" + revision[:4] + ".json")
        manifest.write_text("{}", encoding="utf-8")
        candidate = {"verified": True, "revision": revision, "codeRoot": str(root.resolve()), "entrypoint": "forgeboss/daemon.py", "manifestPath": str(manifest.resolve()), "manifestSha256": "5" * 64, "identitySha256": "6" * 64, "treeSha256": "7" * 64, "files": {"forgeboss/daemon.py": "8" * 64}}
        with patch("forgeboss.control.activation.verify_build_manifest", return_value=candidate):
            return manager.stage(root, manifest, revision, "5" * 64, expected_generation=expected_generation)

    def _probe(self, manager, state):
        manager.begin_probe(expected_generation=state["generation"])
        identity={"revision": state["candidate"]["revision"], "manifestSha256": state["candidate"]["manifestSha256"], "treeSha256": state["candidate"]["treeSha256"], "identitySha256": state["candidate"]["identitySha256"]}
        evidence={"schema":1,"fixture":True,"identity":identity}
        digest=hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        return manager.record_probe({"startup": True, "health": True, "control": True, "selftests": True, "multiAgent": True, "identity": identity, "evidence":evidence, "evidenceSha256":digest}, expected_generation=state["generation"], _authority=manager._probe_authority)

    def test_caller_supplied_probe_and_health_are_denied(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);manager.initialize_known_good();state=self._stage(manager,base)
            with self.assertRaisesRegex(ActivationError,"caller-supplied activation probe denied"):
                manager.record_probe({},expected_generation=state["generation"])
            with self.assertRaisesRegex(ActivationError,"caller-supplied activation health denied"):
                manager.activation_health(True,expected_generation=state["generation"],evidence={})

    def test_authoritative_probe_binds_ready_process_control_tests_and_identity(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);manager.initialize_known_good();state=self._stage(manager,base)
            saved=manager.status();process={"pid":44,"startToken":"tok","exe":str(Path(__import__("sys").executable).resolve())}
            saved.update({"phase":"STARTING","activationNonce":"n"*64,"readyPath":str(base/"ready.json"),"candidateStateRoot":str(base/"candidate-runtime"),"processIdentity":process,"pid":44})
            manager.state_path.write_text(json.dumps(saved),encoding="utf-8")
            candidate=saved["candidate"]
            ready={"schema":1,"pid":44,"nonce":"n"*64,"generation":saved["generation"],"host":"127.0.0.1","port":32123,"identity":candidate,"stateRoot":str(base/"candidate-runtime")}
            control={"connected":True,"healthy":True,"control":True,"multiAgentCapability":True,"capabilities":["smart-parallel"],"identity":candidate,"snapshotDigest":"a"*64}
            tests={"rows":[{"label":"selftests"},{"label":"multiAgent"}],"selftests":True,"multiAgent":True}
            with patch("forgeboss.control.activation.read_activation_ready",return_value=(ready,"b"*64)),patch("forgeboss.control.activation.probe_control_endpoint",return_value=control),patch("forgeboss.control.activation.run_activation_core_tests",return_value=tests),patch("forgeboss.control.activation.process_identity",return_value=process),patch("forgeboss.control.activation.verify_build_manifest",return_value=candidate):
                out=manager.authoritative_probe(expected_generation=saved["generation"])
            self.assertEqual(out["phase"],"PROBED")
            self.assertEqual(out["probeEvidence"]["endpoint"],{"host":"127.0.0.1","port":32123})
            self.assertEqual(out["probe"]["evidenceSha256"],hashlib.sha256(json.dumps(out["probeEvidence"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest())

    def test_start_candidate_strips_secrets_disables_paid_and_keeps_checkout_byte_clean(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);manager.initialize_known_good();state=self._stage(manager,base)
            captured={}
            class Proc:pid=4321
            def fake_popen(argv,**kw):captured["argv"]=list(argv);captured["env"]=dict(kw["env"]);return Proc()
            identity={"pid":4321,"startToken":"tok","exe":str(Path(__import__("sys").executable).resolve())}
            hostile={"OPENAI_API_KEY":"secret","GITHUB_TOKEN":"secret","GIT_DIR":"evil","PYTHONPATH":"evil","FORGEBOSS_AUTHORITY_PEER_KEY":"secret"}
            with patch.dict(os.environ,hostile,clear=False),patch("forgeboss.control.activation.subprocess.Popen",side_effect=fake_popen),patch("forgeboss.control.activation.process_identity",return_value=identity):
                manager.start_candidate(expected_generation=state["generation"])
            env=captured["env"]
            for key in hostile:self.assertNotIn(key,env)
            self.assertEqual(env["FORGEBOSS_ALLOW_PAID_EXECUTOR"],"NO")
            self.assertEqual(env["PYTHONDONTWRITEBYTECODE"],"1")
            self.assertEqual(env["PYTHONUTF8"],"1")
            self.assertIn("--host",captured["argv"]);self.assertIn("127.0.0.1",captured["argv"])
            self.assertIn("--port",captured["argv"]);self.assertIn("0",captured["argv"])
            self.assertIn("--activation-ready-file",captured["argv"])

    def test_unverified_running_controller_cannot_stage(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base, False)
            root = base / "candidate"
            root.mkdir()
            manifest = base / "m"
            manifest.write_text("{}")
            with self.assertRaisesRegex(ActivationError, "verified running known-good"):
                manager.stage(root, manifest)

    def test_initialize_pointer_is_exact_and_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            p1 = manager.initialize_known_good()
            p2 = manager.initialize_known_good()
            self.assertEqual(p1["current"]["revision"], "1" * 40)
            self.assertEqual(p1, p2)

    def test_stale_generation_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            manager.initialize_known_good()
            state = self._stage(manager, base)
            with self.assertRaisesRegex(ActivationError, "stale activation generation"):
                manager.begin_probe(expected_generation=state["generation"] - 1)

    def test_duplicate_stage_same_candidate_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            manager.initialize_known_good()
            first = self._stage(manager, base)
            root = Path(first["candidate"]["codeRoot"])
            manifest = Path(first["candidate"]["manifestPath"])
            with patch("forgeboss.control.activation.verify_build_manifest", return_value=first["candidate"]):
                second = manager.stage(root, manifest, first["candidate"]["revision"], first["candidate"]["manifestSha256"], expected_generation=first["generation"])
            self.assertEqual(first["generation"], second["generation"])
            self.assertEqual(first["requestId"], second["requestId"])

    def test_probe_then_promote_preserves_previous_known_good(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            prior = manager.initialize_known_good()["current"]
            state = self._stage(manager, base)
            self._probe(manager, state)
            pointer = manager.promote(expected_generation=state["generation"])
            self.assertEqual(pointer["previous"]["revision"], prior["revision"])
            self.assertEqual(pointer["current"]["revision"], state["candidate"]["revision"])
            self.assertEqual(manager.promote(expected_generation=state["generation"]), pointer)

    def test_failed_probe_retains_prior_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            prior = manager.initialize_known_good()["current"]
            state = self._stage(manager, base)
            manager.begin_probe(expected_generation=state["generation"])
            evidence={"schema":1,"fixture":"failed"}
            digest=hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
            with self.assertRaisesRegex(ActivationError, "candidate probe failed"):
                manager.record_probe({"startup": True, "health": False, "control": True, "selftests": True, "multiAgent": True, "identity": {}, "evidence":evidence, "evidenceSha256":digest}, expected_generation=state["generation"], _authority=manager._probe_authority)
            self.assertEqual(manager.known_good_pointer()["current"]["revision"], prior["revision"])
            self.assertEqual(manager.status()["phase"], "ROLLED_BACK")

    def test_forced_rollback_revokes_candidate_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            prior = manager.initialize_known_good()["current"]
            state = self._stage(manager, base)
            self._probe(manager, state)
            manager.promote(expected_generation=state["generation"])
            one = manager.rollback("forced", expected_generation=state["generation"])
            two = manager.rollback("forced", expected_generation=state["generation"])
            self.assertEqual(one["current"]["revision"], prior["revision"])
            self.assertEqual(two["current"]["revision"], prior["revision"])
            self.assertIsNone(manager.status()["processIdentity"])

    def test_recover_completes_pointer_written_promoting_state(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            manager.initialize_known_good()
            state = self._stage(manager, base)
            self._probe(manager, state)
            state = manager.status()
            state["phase"] = "PROMOTING"
            manager.state_path.write_text(json.dumps(state), encoding="utf-8")
            pointer = {"schema": 2, "generation": state["generation"], "current": state["candidate"], "previous": state["prior"], "updatedAt": 1}
            manager.pointer_path.write_text(json.dumps(pointer), encoding="utf-8")
            recovered = ActivationManager(manager.state_dir, manager.running_identity).recover()
            self.assertEqual(recovered["current"]["revision"], state["candidate"]["revision"])
            self.assertEqual(manager.status()["phase"], "PROMOTED")

    def test_newer_pointer_blocks_stale_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            manager.initialize_known_good()
            state = self._stage(manager, base)
            pointer = manager.known_good_pointer()
            pointer["current"] = {**pointer["current"], "revision": "f" * 40}
            manager.pointer_path.write_text(json.dumps(pointer), encoding="utf-8")
            with self.assertRaisesRegex(ActivationError, "newer known-good authority"):
                manager.rollback("stale", expected_generation=state["generation"])

    def test_termination_failure_quarantines_without_pointer_advance(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            manager = self._manager(base)
            prior = manager.initialize_known_good()["current"]
            state = self._stage(manager, base)
            saved = manager.status()
            saved["processIdentity"] = {"pid": 123, "startToken": "t", "exe": "python"}
            saved["pid"] = 123
            manager.state_path.write_text(json.dumps(saved), encoding="utf-8")
            with patch("forgeboss.control.activation.terminate_verified_process", side_effect=ActivationError("no stable authority")):
                with self.assertRaisesRegex(ActivationError, "termination authority unavailable"):
                    manager.rollback("forced", expected_generation=state["generation"])
            self.assertEqual(manager.status()["phase"], "QUARANTINED")
            self.assertEqual(manager.known_good_pointer()["current"]["revision"], prior["revision"])

    def test_pid_reuse_mismatch_is_not_same_process(self):
        self.assertFalse(_same_process({"pid": 10, "startToken": "old", "exe": "python"}, {"pid": 10, "startToken": "new", "exe": "python"}))

    @unittest.skipIf(os.name == "nt", "Linux pidfd regression")
    def test_pidfd_handle_is_acquired_before_identity_and_replacement_not_signaled(self):
        expected = {"pid": 44, "startToken": "old", "exe": "/usr/bin/python"}
        replacement = {"pid": 44, "startToken": "new", "exe": "/usr/bin/python"}
        with patch("forgeboss.control.activation.os.pidfd_open", return_value=91) as opened, patch("forgeboss.control.activation._posix_identity", return_value=replacement) as identity, patch("forgeboss.control.activation.signal.pidfd_send_signal") as sent, patch("forgeboss.control.activation.os.close") as closed:
            self.assertTrue(_terminate_posix_pidfd(expected, 1.0))
        opened.assert_called_once_with(44, 0)
        identity.assert_called_once_with(44)
        sent.assert_not_called()
        closed.assert_called_once_with(91)

    @unittest.skipIf(os.name == "nt", "Linux pidfd regression")
    def test_pidfd_unavailable_fails_closed_without_numeric_pid_fallback(self):
        expected = {"pid": 44, "startToken": "old", "exe": "/usr/bin/python"}
        with patch.object(os, "pidfd_open", None, create=True), patch("forgeboss.control.activation.signal.pidfd_send_signal", None, create=True), patch("forgeboss.control.activation.os.kill") as numeric_kill:
            with self.assertRaisesRegex(ActivationError, "stable POSIX process handle unavailable"):
                _terminate_posix_pidfd(expected, 1.0)
        numeric_kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
