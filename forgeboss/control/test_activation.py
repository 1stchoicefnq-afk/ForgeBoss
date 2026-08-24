from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from forgeboss.control.activation import ActivationError, ActivationManager, _same_process


class ActivationTests(unittest.TestCase):
    def _identity(self,root,revision="1"*40,verified=True):
        return {"verified":verified,"revision":revision if verified else None,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","manifestPath":str(root/"manifest.json"),"manifestSha256":"2"*64 if verified else None,"identitySha256":"3"*64 if verified else None,"treeSha256":"4"*64 if verified else None,"files":{}}

    def _manager(self,base,verified=True):
        running=base/"running";running.mkdir();return ActivationManager(base/"state",self._identity(running,verified=verified))

    def _stage(self,manager,base,revision="a"*40):
        root=base/"candidate";pkg=root/"forgeboss";pkg.mkdir(parents=True);(pkg/"daemon.py").write_text("print('candidate')\n",encoding="utf-8");manifest=base/"manifest.json";manifest.write_text("{}",encoding="utf-8")
        candidate={"verified":True,"revision":revision,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","manifestPath":str(manifest.resolve()),"manifestSha256":"5"*64,"identitySha256":"6"*64,"treeSha256":"7"*64,"files":{"forgeboss/daemon.py":"8"*64}}
        with patch("forgeboss.control.activation.verify_build_manifest",return_value=candidate):state=manager.stage(root,manifest,revision,"5"*64)
        return state

    def test_unverified_running_controller_cannot_stage(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base,False);root=base/"candidate";root.mkdir();manifest=base/"m";manifest.write_text("{}")
            with self.assertRaisesRegex(ActivationError,"verified running known-good"):manager.stage(root,manifest)

    def test_probe_then_promote_preserves_previous_known_good(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);prior=manager.running_identity;state=self._stage(manager,base);manager.begin_probe();manager.record_probe({"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"identity":{"revision":state["candidate"]["revision"],"manifestSha256":state["candidate"]["manifestSha256"]}});pointer=manager.promote();self.assertEqual(pointer["previous"]["revision"],prior["revision"])

    def test_failed_probe_requires_candidate_death_before_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);self._stage(manager,base);fake=Mock(pid=123);ident={"pid":123,"startToken":"t","exe":"python"}
            with patch("forgeboss.control.activation.subprocess.Popen",return_value=fake),patch("forgeboss.control.activation.process_identity",return_value=ident):manager.start_candidate([])
            manager.begin_probe()
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=True) as term:
                with self.assertRaisesRegex(ActivationError,"probe failed"):manager.record_probe({"startup":True,"health":False,"control":True,"selftests":True,"multiAgent":True,"identity":{}})
            term.assert_called_once_with(ident,5.0);self.assertEqual(manager.status()["phase"],"ROLLED_BACK")

    def test_termination_failure_quarantines_without_pointer_advance(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);self._stage(manager,base);fake=Mock(pid=123);ident={"pid":123,"startToken":"t","exe":"python"}
            with patch("forgeboss.control.activation.subprocess.Popen",return_value=fake),patch("forgeboss.control.activation.process_identity",return_value=ident):manager.start_candidate([])
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=False):
                with self.assertRaisesRegex(ActivationError,"quarantined"):manager.rollback("forced")
            self.assertEqual(manager.status()["phase"],"QUARANTINED");self.assertIsNone(manager.known_good_pointer())

    def test_pid_reuse_mismatch_is_not_same_process(self):
        self.assertFalse(_same_process({"pid":10,"startToken":"old","exe":"python"},{"pid":10,"startToken":"new","exe":"python"}))


if __name__=="__main__":unittest.main()
