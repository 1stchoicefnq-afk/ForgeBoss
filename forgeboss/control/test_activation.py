from __future__ import annotations
import ast,json,multiprocessing,os,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from forgeboss.control.activation import ActivationError,ActivationManager,_PosixProbeServer,_same_process,_atomic_json,process_identity,_validate_probe_result

class ActivationTests(unittest.TestCase):
    def _identity(self,root,revision="1"*40,digest="3"*64,verified=True):
        return {"verified":verified,"revision":revision if verified else None,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","manifestPath":str(root/"manifest.json"),"manifestSha256":"2"*64 if verified else None,"identitySha256":digest if verified else None,"treeSha256":"4"*64 if verified else None,"files":{}}
    def _manager(self,b):
        r=b/"running";r.mkdir();return ActivationManager(b/"state",self._identity(r),{"pid":111,"startToken":"prior","exe":"python"})
    def _stage(self,m,b):
        r=b/"candidate";p=r/"forgeboss";p.mkdir(parents=True);(p/"daemon.py").write_text("x=1\n");mf=b/"manifest.json";mf.write_text("{}")
        c=self._identity(r,"a"*40,"6"*64)
        with patch("forgeboss.control.activation.verify_build_manifest",return_value=c),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.stage(r,mf)
        return c
    def test_pid_reuse_mismatch(self):
        self.assertFalse(_same_process({"pid":1,"startToken":"a","exe":"x"},{"pid":1,"startToken":"b","exe":"x"}))
    def test_direct_probe_submission_denied(self):
        with tempfile.TemporaryDirectory() as td:
            m=self._manager(Path(td))
            with self.assertRaisesRegex(ActivationError,"direct probe submission denied"):m.record_probe({})
    def test_posix_peer_pid_is_kernel_credential(self):
        if os.name=="nt":self.skipTest("posix only")
        with tempfile.TemporaryDirectory() as td:
            import socket,threading
            s=_PosixProbeServer(td,"x");payload=json.dumps({"x":1}).encode();done=[]
            def client():
                c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.connect(s.endpoint[5:]);c.sendall(payload);c.shutdown(socket.SHUT_WR);c.close();done.append(True)
            t=threading.Thread(target=client);t.start();pid,obj=s.accept(2);t.join();self.assertEqual(pid,os.getpid());self.assertEqual(obj,{"x":1});self.assertTrue(done)
    def test_non_candidate_peer_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);m=self._manager(b);self._stage(m,b);fake=Mock(pid=222);pi={"pid":222,"startToken":"cand","exe":"python"}
            class S:
                endpoint="unix:x"
                def accept(self,t):return 333,{"activationNonce":"n","probeChallenge":"c","identity":{},"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True}
                def close(self):pass
            with patch("forgeboss.control.activation._new_probe_server",return_value=S()),patch("forgeboss.control.activation.subprocess.Popen",return_value=fake),patch("forgeboss.control.activation.process_identity",side_effect=lambda p:pi if p==222 else {"pid":333,"startToken":"other","exe":"python"}),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):
                m.start_candidate([]);m.begin_probe()
                with self.assertRaisesRegex(ActivationError,"peer process mismatch"):m.accept_probe(.1)
    def test_probe_timeout_rolls_back_not_probed(self):
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);m=self._manager(b);self._stage(m,b);fake=Mock(pid=222);pi={"pid":222,"startToken":"cand","exe":"python"}
            class S:
                endpoint="unix:x"
                def accept(self,t):raise ActivationError("candidate probe read timed out")
                def close(self):pass
            with patch("forgeboss.control.activation._new_probe_server",return_value=S()),patch("forgeboss.control.activation.subprocess.Popen",return_value=fake),patch("forgeboss.control.activation.process_identity",return_value=pi),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True),patch("forgeboss.control.activation.terminate_verified_process",return_value=True):
                m.start_candidate([]);m.begin_probe()
                with self.assertRaisesRegex(ActivationError,"timed out"):m.accept_probe(.01)
                self.assertNotEqual(m.status()["phase"],"PROBED")
    def test_failed_or_missing_probe_boolean_cannot_validate(self):
        state={"activationNonce":"n","probeChallenge":"c","processIdentity":{"pid":22,"startToken":"s","exe":"python"},"candidate":{"revision":"a","manifestSha256":"b","identitySha256":"c"}}
        result={"activationNonce":"n","probeChallenge":"c","identity":{"revision":"a","manifestSha256":"b","identitySha256":"c"},"startup":True,"health":True,"control":True,"selftests":False,"multiAgent":True}
        with self.assertRaisesRegex(ActivationError,"candidate probe failed"):_validate_probe_result(result,state,state["processIdentity"])
    def test_production_daemon_main_calls_candidate_probe_submission(self):
        source=Path(__file__).with_name("daemon.py").read_text(encoding="utf-8");tree=ast.parse(source)
        mains=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="main"]
        self.assertEqual(len(mains),1)
        calls=[n for n in ast.walk(mains[0]) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
        self.assertIn("_submit_candidate_activation_probe",{n.func.id for n in calls})
        self.assertIn("submit_candidate_probe",source)
    def test_promoted_health_is_request_only(self):
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);m=self._manager(b);c=self._stage(m,b);s=m.status();s.update({"phase":"PROMOTED","candidate":c,"processIdentity":{"pid":222,"startToken":"cand","exe":"python"},"pointer":{"current":c}});_atomic_json(m.state_path,s)
            candidate=ActivationManager(m.state_dir,c,{"pid":222,"startToken":"cand","exe":"python"});self.assertEqual(candidate.activation_health(False)["phase"],"ROLLBACK_PENDING")

if __name__=="__main__":unittest.main()
