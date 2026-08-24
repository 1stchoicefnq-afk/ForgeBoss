from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from forgeboss.control.activation import ActivationError, ActivationManager, _same_process


def _sha(path: Path):return hashlib.sha256(path.read_bytes()).hexdigest()


class ActivationTests(unittest.TestCase):
    def _identity(self,root:Path,revision="1"*40,verified=True):return {"verified":verified,"revision":revision if verified else None,"codeRoot":str(root.resolve()),"entrypoint":"daemon.py","manifestPath":str(root/"manifest.json"),"manifestSha256":"2"*64 if verified else None,"identitySha256":"3"*64 if verified else None,"files":{}}
    def _candidate(self,base:Path,revision="a"*40):
        root=base/"candidate";root.mkdir();entry=root/"daemon.py";entry.write_text("print('candidate')\n",encoding="utf-8");manifest=base/"candidate-manifest.json";manifest.write_text(json.dumps({"schema":1,"revision":revision,"codeRoot":str(root.resolve()),"entrypoint":"daemon.py","files":{"daemon.py":_sha(entry)}},sort_keys=True),encoding="utf-8");return root,manifest,revision
    def _manager(self,base:Path,verified=True):running=base/"running";running.mkdir();return ActivationManager(base/"state",self._identity(running,verified=verified))
    def _stage(self,manager,base):root,manifest,revision=self._candidate(base);state=manager.stage(root,manifest,revision,_sha(manifest));return root,manifest,revision,state

    def test_unverified_running_controller_cannot_stage_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base,verified=False);root,manifest,revision=self._candidate(base)
            with self.assertRaisesRegex(ActivationError,"verified running known-good"):manager.stage(root,manifest,revision,_sha(manifest))

    def test_stage_denies_in_place_activation(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);running=base/"running";running.mkdir();manager=ActivationManager(base/"state",self._identity(running));entry=running/"daemon.py";entry.write_text("x=1\n",encoding="utf-8");manifest=running/"manifest.json";manifest.write_text(json.dumps({"schema":1,"revision":"a"*40,"codeRoot":str(running.resolve()),"entrypoint":"daemon.py","files":{"daemon.py":_sha(entry)}}),encoding="utf-8")
            with self.assertRaisesRegex(ActivationError,"in-place"):manager.stage(running,manifest)

    def test_probe_then_promote_preserves_previous_known_good(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);prior=manager.running_identity;root,manifest,revision,staged=self._stage(manager,base);manager.begin_probe();manager.record_probe({"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"identity":{"revision":revision,"manifestSha256":staged["candidate"]["manifestSha256"]}});pointer=manager.promote();self.assertEqual(pointer["current"]["revision"],revision);self.assertEqual(pointer["previous"]["revision"],prior["revision"])

    def test_start_candidate_persists_process_identity_and_fence_env(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);root,manifest,revision,staged=self._stage(manager,base);fake=Mock();fake.pid=12345;ident={"pid":12345,"startToken":"token","exe":"python"}
            with patch("forgeboss.control.activation.subprocess.Popen",return_value=fake) as popen,patch("forgeboss.control.activation.process_identity",return_value=ident):manager.start_candidate(["--port","0"])
            _,kwargs=popen.call_args;state=manager.status();self.assertEqual(state["processIdentity"],ident);self.assertTrue(kwargs["env"]["FORGEBOSS_ACTIVATION_NONCE"]);self.assertEqual(Path(kwargs["env"]["FORGEBOSS_ACTIVATION_STATE"]),manager.state_path.resolve())

    def test_failed_probe_proves_candidate_dead_before_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);self._stage(manager,base);fake=Mock();fake.pid=123;ident={"pid":123,"startToken":"t","exe":"python"}
            with patch("forgeboss.control.activation.subprocess.Popen",return_value=fake),patch("forgeboss.control.activation.process_identity",return_value=ident):manager.start_candidate([])
            manager.begin_probe()
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=True) as term:
                with self.assertRaisesRegex(ActivationError,"probe failed"):manager.record_probe({"startup":True,"health":False,"control":True,"selftests":True,"multiAgent":True,"identity":{}})
            term.assert_called_once_with(ident,5.0);self.assertEqual(manager.status()["phase"],"ROLLED_BACK")

    def test_termination_failure_quarantines_and_does_not_advance_pointer(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);self._stage(manager,base);fake=Mock();fake.pid=123;ident={"pid":123,"startToken":"t","exe":"python"}
            with patch("forgeboss.control.activation.subprocess.Popen",return_value=fake),patch("forgeboss.control.activation.process_identity",return_value=ident):manager.start_candidate([])
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=False):
                with self.assertRaisesRegex(ActivationError,"quarantined"):manager.rollback("forced")
            self.assertEqual(manager.status()["phase"],"QUARANTINED");self.assertIsNone(manager.known_good_pointer())

    def test_interrupted_recovery_fences_persisted_process_before_restoring_prior(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);prior=manager.running_identity;self._stage(manager,base);state=manager.status();ident={"pid":777,"startToken":"start","exe":"python"};state.update({"phase":"STARTING","pid":777,"processIdentity":ident});manager.state_path.write_text(json.dumps(state),encoding="utf-8");recovered=ActivationManager(base/"state",prior)
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=True) as term:pointer=recovered.recover()
            term.assert_called_once_with(ident,5.0);self.assertEqual(pointer["current"]["revision"],prior["revision"]);self.assertEqual(recovered.status()["phase"],"ROLLED_BACK")

    def test_pid_reuse_identity_mismatch_is_not_same_process(self):self.assertFalse(_same_process({"pid":10,"startToken":"old","exe":"python"},{"pid":10,"startToken":"new","exe":"python"}))

    def test_missing_process_identity_quarantines_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);self._stage(manager,base);state=manager.status();state.update({"phase":"STARTING","pid":888,"processIdentity":None});manager.state_path.write_text(json.dumps(state),encoding="utf-8")
            with self.assertRaisesRegex(ActivationError,"quarantined"):ActivationManager(base/"state",manager.running_identity).recover()
            self.assertEqual(manager.status()["phase"],"QUARANTINED")

    def test_promoted_health_failure_uses_verified_termination_then_rolls_back(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);prior=manager.running_identity;root,manifest,revision,staged=self._stage(manager,base);fake=Mock();fake.pid=321;ident={"pid":321,"startToken":"s","exe":"python"}
            with patch("forgeboss.control.activation.subprocess.Popen",return_value=fake),patch("forgeboss.control.activation.process_identity",return_value=ident):manager.start_candidate([])
            manager.begin_probe();manager.record_probe({"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"identity":{"revision":revision,"manifestSha256":staged["candidate"]["manifestSha256"]}});manager.promote()
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=True):pointer=manager.activation_health(False)
            self.assertEqual(pointer["current"]["revision"],prior["revision"]);self.assertEqual(manager.status()["phase"],"ROLLED_BACK")


if __name__=="__main__":unittest.main()
