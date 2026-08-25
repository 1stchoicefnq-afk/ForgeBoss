from __future__ import annotations
import tempfile, unittest
from pathlib import Path
from unittest.mock import Mock, patch
from forgeboss.control.activation import ActivationError,ActivationManager,_same_process,process_is_same_and_alive

class ActivationTests(unittest.TestCase):
    def _identity(self,root,tag):
        return {"verified":True,"revision":tag*40,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","manifestPath":str(root/"manifest.json"),"manifestSha256":tag*64,"identitySha256":tag.upper()*64,"treeSha256":tag*64,"files":{}}
    def _setup(self,base):
        running=base/"running";running.mkdir();candidate=base/"candidate";(candidate/"forgeboss").mkdir(parents=True);(candidate/"forgeboss"/"daemon.py").write_text("print('x')\n")
        oldp={"pid":100,"startToken":"old-start","exe":"python"};newp={"pid":200,"startToken":"new-start","exe":"python"}
        old=self._identity(running,"1");new=self._identity(candidate,"2");m=ActivationManager(base/"state",old,oldp)
        manifest=base/"candidate-manifest.json";manifest.write_text("{}")
        with patch("forgeboss.control.activation.verify_build_manifest",return_value=new),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.stage(candidate,manifest,new["revision"],new["manifestSha256"])
        return m,old,new,oldp,newp
    def _started(self,m,newp):
        fake=Mock(pid=newp["pid"])
        with patch("forgeboss.control.activation.subprocess.Popen",return_value=fake),patch("forgeboss.control.activation.process_identity",return_value=newp),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.start_candidate([])
    def _probed(self,m,new,newp):
        with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.begin_probe();s=m.status();m.record_probe({"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"identity":{"revision":new["revision"],"manifestSha256":new["manifestSha256"],"identitySha256":new["identitySha256"]},"proof":{"activationNonce":s["activationNonce"],"processIdentity":newp}})
    def test_staged_cannot_begin_probe_without_started_process(self):
        with tempfile.TemporaryDirectory() as td:
            m,_,_,_,_=self._setup(Path(td))
            with self.assertRaisesRegex(ActivationError,"STARTING"):m.begin_probe()
    def test_probe_wrong_nonce_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            m,_,new,_,newp=self._setup(Path(td));self._started(m,newp)
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.begin_probe();s=m.status()
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):
                with self.assertRaisesRegex(ActivationError,"nonce mismatch"):m.record_probe({"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"identity":{"revision":new["revision"],"manifestSha256":new["manifestSha256"],"identitySha256":new["identitySha256"]},"proof":{"activationNonce":"wrong","processIdentity":newp}})
    def test_probe_wrong_process_start_token_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            m,_,new,_,newp=self._setup(Path(td));self._started(m,newp)
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.begin_probe();s=m.status()
            bad=dict(newp);bad["startToken"]="reused"
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):
                with self.assertRaisesRegex(ActivationError,"process identity mismatch"):m.record_probe({"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"identity":{"revision":new["revision"],"manifestSha256":new["manifestSha256"],"identitySha256":new["identitySha256"]},"proof":{"activationNonce":s["activationNonce"],"processIdentity":bad}})
    def test_mutation_authority_transfers_atomically_on_promotion(self):
        with tempfile.TemporaryDirectory() as td:
            m,old,new,oldp,newp=self._setup(Path(td));self._started(m,newp);self._probed(m,new,newp)
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.assert_mutation_authority(old,oldp)
            with self.assertRaises(ActivationError):m.assert_mutation_authority(new,newp)
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.promote();m.assert_mutation_authority(new,newp)
            with self.assertRaises(ActivationError):m.assert_mutation_authority(old,oldp)
            self.assertEqual(m.known_good_pointer()["current"]["identitySha256"],new["identitySha256"])
    def test_candidate_dies_after_probe_before_promote_old_authority_survives(self):
        with tempfile.TemporaryDirectory() as td:
            m,old,new,oldp,newp=self._setup(Path(td));self._started(m,newp);self._probed(m,new,newp)
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=False),patch("forgeboss.control.activation.terminate_verified_process",return_value=True):
                with self.assertRaisesRegex(ActivationError,"unavailable"):m.promote()
            self.assertEqual(m.status()["phase"],"ROLLED_BACK")
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.assert_mutation_authority(old,oldp)
    def test_restart_after_promotion_adopts_new_process_only_when_old_owner_dead(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);m,old,new,oldp,newp=self._setup(base);self._started(m,newp);self._probed(m,new,newp)
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.promote()
            restarted={"pid":201,"startToken":"restart","exe":"python"};r=ActivationManager(base/"state",new,restarted)
            with patch("forgeboss.control.activation.process_is_same_and_alive",side_effect=lambda p:p==restarted):r.recover();r.assert_mutation_authority(new,restarted)
            with self.assertRaises(ActivationError):r.assert_mutation_authority(old,oldp)
    def test_parent_pid_reuse_same_pid_different_start_token_is_not_alive(self):
        expected={"pid":77,"startToken":"A","exe":"python"};reused={"pid":77,"startToken":"B","exe":"python"}
        self.assertFalse(_same_process(expected,reused))
        with patch("forgeboss.control.activation.process_identity",return_value=reused):self.assertFalse(process_is_same_and_alive(expected))
    def test_failed_death_proof_quarantines_without_pointer_advance(self):
        with tempfile.TemporaryDirectory() as td:
            m,_,_,_,newp=self._setup(Path(td));self._started(m,newp)
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=False):
                with self.assertRaisesRegex(ActivationError,"quarantined"):m.rollback("forced")
            self.assertEqual(m.status()["phase"],"QUARANTINED");self.assertIsNone(m.known_good_pointer())

if __name__=="__main__":unittest.main()
