from __future__ import annotations

import json
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

    def _stage(self,manager,base,revision="a"*40,expected_generation=None):
        root=base/("candidate-"+revision[:4]);pkg=root/"forgeboss";pkg.mkdir(parents=True);(pkg/"daemon.py").write_text("print('candidate')\n",encoding="utf-8");manifest=base/("manifest-"+revision[:4]+".json");manifest.write_text("{}",encoding="utf-8")
        candidate={"verified":True,"revision":revision,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","manifestPath":str(manifest.resolve()),"manifestSha256":"5"*64,"identitySha256":"6"*64,"treeSha256":"7"*64,"files":{"forgeboss/daemon.py":"8"*64}}
        with patch("forgeboss.control.activation.verify_build_manifest",return_value=candidate):return manager.stage(root,manifest,revision,"5"*64,expected_generation=expected_generation)

    def _probe(self,manager,state):
        manager.begin_probe(expected_generation=state["generation"])
        return manager.record_probe({"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"identity":{"revision":state["candidate"]["revision"],"manifestSha256":state["candidate"]["manifestSha256"],"treeSha256":state["candidate"]["treeSha256"],"identitySha256":state["candidate"]["identitySha256"]}},expected_generation=state["generation"])

    def test_unverified_running_controller_cannot_stage(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base,False);root=base/"candidate";root.mkdir();manifest=base/"m";manifest.write_text("{}")
            with self.assertRaisesRegex(ActivationError,"verified running known-good"):manager.stage(root,manifest)

    def test_initialize_pointer_is_exact_and_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);p1=manager.initialize_known_good();p2=manager.initialize_known_good();self.assertEqual(p1["current"]["revision"],"1"*40);self.assertEqual(p1,p2)

    def test_stale_generation_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);manager.initialize_known_good();state=self._stage(manager,base)
            with self.assertRaisesRegex(ActivationError,"stale activation generation"):manager.begin_probe(expected_generation=state["generation"]-1)

    def test_duplicate_stage_same_candidate_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);manager.initialize_known_good();s1=self._stage(manager,base);root=Path(s1["candidate"]["codeRoot"]);manifest=Path(s1["candidate"]["manifestPath"])
            with patch("forgeboss.control.activation.verify_build_manifest",return_value=s1["candidate"]):s2=manager.stage(root,manifest,s1["candidate"]["revision"],s1["candidate"]["manifestSha256"],expected_generation=s1["generation"])
            self.assertEqual(s1["generation"],s2["generation"]);self.assertEqual(s1["requestId"],s2["requestId"])

    def test_probe_then_promote_preserves_previous_known_good(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);prior=manager.initialize_known_good()["current"];state=self._stage(manager,base)
            with patch("forgeboss.control.activation.process_identity",return_value=None):self._probe(manager,state)
            pointer=manager.promote(expected_generation=state["generation"]);self.assertEqual(pointer["previous"]["revision"],prior["revision"]);self.assertEqual(pointer["current"]["revision"],state["candidate"]["revision"])
            self.assertEqual(manager.promote(expected_generation=state["generation"]),pointer)

    def test_failed_probe_retains_prior_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);prior=manager.initialize_known_good()["current"];state=self._stage(manager,base);manager.begin_probe(expected_generation=state["generation"])
            with self.assertRaisesRegex(ActivationError,"candidate probe failed"):manager.record_probe({"startup":True,"health":False,"control":True,"selftests":True,"multiAgent":True,"identity":{}},expected_generation=state["generation"])
            self.assertEqual(manager.known_good_pointer()["current"]["revision"],prior["revision"]);self.assertEqual(manager.status()["phase"],"ROLLED_BACK")

    def test_candidate_identity_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);manager.initialize_known_good();state=self._stage(manager,base);manager.begin_probe(expected_generation=state["generation"])
            with self.assertRaisesRegex(ActivationError,"identity mismatch"):manager.record_probe({"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"identity":{"revision":"b"*40,"manifestSha256":state["candidate"]["manifestSha256"],"treeSha256":state["candidate"]["treeSha256"],"identitySha256":state["candidate"]["identitySha256"]}},expected_generation=state["generation"])

    def test_forced_rollback_revokes_candidate_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);prior=manager.initialize_known_good()["current"];state=self._stage(manager,base)
            manager.begin_probe(expected_generation=state["generation"]);manager.record_probe({"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"identity":{"revision":state["candidate"]["revision"],"manifestSha256":state["candidate"]["manifestSha256"],"treeSha256":state["candidate"]["treeSha256"],"identitySha256":state["candidate"]["identitySha256"]}},expected_generation=state["generation"]);manager.promote(expected_generation=state["generation"])
            p1=manager.rollback("forced",expected_generation=state["generation"]);p2=manager.rollback("forced",expected_generation=state["generation"]);self.assertEqual(p1["current"]["revision"],prior["revision"]);self.assertEqual(p2["current"]["revision"],prior["revision"]);self.assertIsNone(manager.status()["processIdentity"])

    def test_recover_completes_pointer_written_promoting_state(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);manager.initialize_known_good();state=self._stage(manager,base);self._probe(manager,state)
            state=manager.status();state["phase"]="PROMOTING";manager.state_path.write_text(json.dumps(state),encoding="utf-8");pointer={"schema":2,"generation":state["generation"],"current":state["candidate"],"previous":state["prior"],"updatedAt":1};manager.pointer_path.write_text(json.dumps(pointer),encoding="utf-8")
            recovered=ActivationManager(manager.state_dir,manager.running_identity).recover();self.assertEqual(recovered["current"]["revision"],state["candidate"]["revision"]);self.assertEqual(manager.status()["phase"],"PROMOTED")

    def test_recover_incomplete_stage_restores_prior(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);prior=manager.initialize_known_good()["current"];state=self._stage(manager,base)
            recovered=ActivationManager(manager.state_dir,manager.running_identity).recover();self.assertEqual(recovered["current"]["revision"],prior["revision"]);self.assertEqual(manager.status()["phase"],"ROLLED_BACK")

    def test_newer_pointer_blocks_stale_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);manager.initialize_known_good();state=self._stage(manager,base);p=manager.known_good_pointer();p["current"]={**p["current"],"revision":"f"*40};manager.pointer_path.write_text(json.dumps(p),encoding="utf-8")
            with self.assertRaisesRegex(ActivationError,"newer known-good authority"):manager.rollback("stale",expected_generation=state["generation"])

    def test_termination_failure_quarantines_without_pointer_advance(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);manager=self._manager(base);prior=manager.initialize_known_good()["current"];state=self._stage(manager,base);s=manager.status();s["processIdentity"]={"pid":123,"startToken":"t","exe":"python"};s["pid"]=123;manager.state_path.write_text(json.dumps(s),encoding="utf-8")
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=False):
                with self.assertRaisesRegex(ActivationError,"quarantined"):manager.rollback("forced",expected_generation=state["generation"])
            self.assertEqual(manager.status()["phase"],"QUARANTINED");self.assertEqual(manager.known_good_pointer()["current"]["revision"],prior["revision"])

    def test_pid_reuse_mismatch_is_not_same_process(self):
        self.assertFalse(_same_process({"pid":10,"startToken":"old","exe":"python"},{"pid":10,"startToken":"new","exe":"python"}))


if __name__=="__main__":unittest.main()
