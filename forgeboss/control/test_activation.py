from __future__ import annotations

import multiprocessing,os,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from forgeboss.control.activation import ActivationError,ActivationManager,_atomic_json,_same_process,process_identity

def _restart_adoption_worker(state_dir,identity,ready,go,hold,out):
    try:
        runtime=process_identity(os.getpid());m=ActivationManager(state_dir,identity,runtime);ready.put(os.getpid());go.wait(10);m.recover();out.put(("OK",os.getpid()));hold.wait(10)
    except Exception as ex:out.put(("ERR",os.getpid(),type(ex).__name__,str(ex)))

class FakeProbeServer:
    def __init__(self,pid,result):self.pid=pid;self.result=result;self.used=False;self.closed=False
    @property
    def endpoint(self):return "unix:/fake"
    def accept(self,timeout):
        if self.used:raise ActivationError("candidate probe channel already consumed")
        self.used=True;self.closed=True;return self.pid,self.result
    def close(self):self.closed=True

class ActivationTests(unittest.TestCase):
    def _identity(self,root,revision="1"*40,verified=True,digest="3"*64):
        return {"verified":verified,"revision":revision if verified else None,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","manifestPath":str(root/"manifest.json"),"manifestSha256":"2"*64 if verified else None,"identitySha256":digest if verified else None,"treeSha256":"4"*64 if verified else None,"files":{}}
    def _manager(self,base,verified=True):
        running=base/"running";running.mkdir();return ActivationManager(base/"state",self._identity(running,verified=verified),{"pid":111,"startToken":"prior","exe":"python"})
    def _stage(self,m,base,revision="a"*40):
        root=base/"candidate";pkg=root/"forgeboss";pkg.mkdir(parents=True);(pkg/"daemon.py").write_text("print('candidate')\n",encoding="utf-8");manifest=base/"manifest.json";manifest.write_text("{}",encoding="utf-8")
        c={"verified":True,"revision":revision,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","manifestPath":str(manifest.resolve()),"manifestSha256":"5"*64,"identitySha256":"6"*64,"treeSha256":"7"*64,"files":{"forgeboss/daemon.py":"8"*64}}
        with patch("forgeboss.control.activation.verify_build_manifest",return_value=c),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):s=m.stage(root,manifest,revision,"5"*64)
        return s
    def _start(self,m,base):
        s=self._stage(m,base);fake=Mock(pid=222);cp={"pid":222,"startToken":"cand","exe":"python"};server=FakeProbeServer(222,{})
        with patch("forgeboss.control.activation._new_probe_server",return_value=server),patch("forgeboss.control.activation.subprocess.Popen",return_value=fake),patch("forgeboss.control.activation.process_identity",return_value=cp),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.start_candidate([])
        return s,cp,server
    def _result(self,m,s):
        st=m.status();return {"startup":True,"health":True,"control":True,"selftests":True,"multiAgent":True,"activationNonce":st["activationNonce"],"probeChallenge":st["probeChallenge"],"identity":{"revision":s["candidate"]["revision"],"manifestSha256":s["candidate"]["manifestSha256"],"identitySha256":s["candidate"]["identitySha256"]}}
    def _promote(self,m,base):
        s,cp,server=self._start(m,base);server.result=self._result(m,s);m.begin_probe()
        with patch("forgeboss.control.activation.process_identity",return_value=cp),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):m.accept_probe();m.promote()
        return cp
    def test_direct_caller_probe_submission_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);m=self._manager(b);s,cp,server=self._start(m,b);m.begin_probe()
            with self.assertRaisesRegex(ActivationError,"direct probe submission denied"):m.record_probe(self._result(m,s))
    def test_exact_kernel_peer_probe_succeeds_once(self):
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);m=self._manager(b);s,cp,server=self._start(m,b);server.result=self._result(m,s);m.begin_probe()
            with patch("forgeboss.control.activation.process_identity",return_value=cp),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):out=m.accept_probe();self.assertEqual(out["phase"],"PROBED")
            with self.assertRaises(ActivationError):m.accept_probe()
    def test_non_candidate_or_proxy_peer_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);m=self._manager(b);s,cp,server=self._start(m,b);server.pid=333;server.result=self._result(m,s);m.begin_probe();other={"pid":333,"startToken":"proxy","exe":"python"}
            with patch("forgeboss.control.activation.process_identity",return_value=other),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):
                with self.assertRaisesRegex(ActivationError,"peer authentication failed"):m.accept_probe()
            self.assertEqual(m.status()["phase"],"ROLLBACK_PENDING")
    def test_pid_reuse_peer_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);m=self._manager(b);s,cp,server=self._start(m,b);server.result=self._result(m,s);m.begin_probe();reused={"pid":222,"startToken":"new","exe":"python"}
            with patch("forgeboss.control.activation.process_identity",return_value=reused),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):
                with self.assertRaises(ActivationError):m.accept_probe()
    def test_wrong_nonce_build_or_cross_candidate_is_rejected(self):
        for field in ("activationNonce","build"):
            with self.subTest(field=field),tempfile.TemporaryDirectory() as td:
                b=Path(td);m=self._manager(b);s,cp,server=self._start(m,b);r=self._result(m,s)
                if field=="activationNonce":r["activationNonce"]="stale"
                else:r["identity"]["identitySha256"]="9"*64
                server.result=r;m.begin_probe()
                with patch("forgeboss.control.activation.process_identity",return_value=cp),patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):
                    with self.assertRaises(ActivationError):m.accept_probe()
    def test_candidate_denied_before_and_old_denied_after_promotion(self):
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);m=self._manager(b);self._stage(m,b);c=self._identity(b/"candidate","a"*40,digest="6"*64);cp={"pid":222,"startToken":"cand","exe":"python"}
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):
                with self.assertRaises(ActivationError):m.assert_mutation_authority(c,cp)
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);m=self._manager(b);cp=self._promote(m,b);c=m.status()["candidate"]
            with patch("forgeboss.control.activation.process_is_same_and_alive",return_value=True):
                with self.assertRaises(ActivationError):m.assert_mutation_authority(m.running_identity,m.runtime_process_identity)
                self.assertTrue(m.assert_mutation_authority(c,cp))
    def test_promoted_health_rollback_and_quarantine_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);prior=self._manager(b);cp=self._promote(prior,b);c=prior.status()["candidate"];candidate=ActivationManager(b/"state",c,cp);self.assertEqual(candidate.activation_health(False)["phase"],"ROLLBACK_PENDING")
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=True):self.assertEqual(prior.finalize_rollback()["current"]["identitySha256"],prior.running_identity["identitySha256"])
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);prior=self._manager(b);cp=self._promote(prior,b);c=prior.status()["candidate"];ActivationManager(b/"state",c,cp).activation_health(False)
            with patch("forgeboss.control.activation.terminate_verified_process",return_value=False):
                with self.assertRaises(ActivationError):prior.finalize_rollback()
            self.assertEqual(prior.status()["phase"],"QUARANTINED")
    def test_concurrent_restart_adoption_one_winner(self):
        ctx=multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as td:
            b=Path(td);sd=b/"state";sd.mkdir();cr=b/"candidate";cr.mkdir();pr=b/"prior";pr.mkdir();c=self._identity(cr,"a"*40,digest="6"*64);p=self._identity(pr);dead={"pid":999999,"startToken":"dead","exe":"python"};_atomic_json(sd/"activation.json",{"schema":5,"phase":"PROMOTED","prior":p,"priorProcessIdentity":None,"candidate":c,"processIdentity":dead,"pid":dead["pid"],"pointer":{"schema":5,"current":c,"previous":p,"promotedAt":1.0}})
            ready=ctx.Queue();out=ctx.Queue();go=ctx.Event();hold=ctx.Event();ws=[ctx.Process(target=_restart_adoption_worker,args=(str(sd),c,ready,go,hold,out)) for _ in range(2)]
            for w in ws:w.start()
            ready.get(timeout=10);ready.get(timeout=10);go.set();rs=[out.get(timeout=10),out.get(timeout=10)];hold.set()
            for w in ws:w.join(10)
            self.assertEqual(sum(r[0]=="OK" for r in rs),1);self.assertEqual(sum(r[0]=="ERR" for r in rs),1)
    def test_pid_reuse_mismatch_is_not_same_process(self):self.assertFalse(_same_process({"pid":10,"startToken":"old","exe":"python"},{"pid":10,"startToken":"new","exe":"python"}))

if __name__=="__main__":unittest.main()
