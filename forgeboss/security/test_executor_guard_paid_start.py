from __future__ import annotations
import json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch

from forgeboss.control.envelope import sign_envelope
from forgeboss.security import executor_guard as g

class PaidStartAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.work=Path(self.td.name)/"work";self.work.mkdir();self.packet=self.work/"packet.json"
        self.packet.write_text(json.dumps({"allowed_files":["x.py"],"context_files":[]}),encoding="utf-8")
        self.secret=b"s"*32
        self.lease_path=Path(self.td.name)/"lease.json"
        self.lease={"schema":3,"executor":"mini-swe","workspace":str(self.work.resolve()),"packet_sha256":g.phash(self.packet),"allowed_files":["x.py"],"allowed_keys":["x.py"],"issued_at":time.time(),"expires_at":time.time()+300,"token_sha256":"unused-in-mocked-verify","baseline":{},"git_metadata":{},"isolation_verified":True,"paid_consumed":False,"paid_authority":None}
        self._save()
    def tearDown(self):self.td.cleanup()
    def _save(self):self.lease_path.write_text(json.dumps(self.lease),encoding="utf-8")
    def _env(self,**changes):
        p={"envelopeVersion":1,"protocolVersion":1,"taskId":"task-1","repository":"1stchoicefnq-afk/ForgeBoss","baseSha":"abc","branch":"w","worktreePath":str(self.work.resolve()),"runId":"run-1","attempt":1,"ownerEpoch":7,"runtime":{"adapter":"mini-swe","provider":"openai","model":"gpt"},"allowedPaths":["x.py"],"deniedPaths":[],"allowedTools":["python"],"contextBundleHash":None,"transcript":{},"events":{},"budgetUsd":0.25,"expiresAt":time.time()+120}
        p.update(changes);return json.dumps(sign_envelope(p,self.secret))
    def _patches(self,metadata=None):
        metadata={} if metadata is None else metadata
        def fake_verify(path,*_):return json.loads(Path(path).read_text(encoding="utf-8"))
        return patch.object(g,"_verify_unlocked",side_effect=fake_verify),patch.object(g,"git_metadata_snapshot",return_value=metadata),patch("forgeboss.control.envelope.secret_file",return_value=(Path("unused"),self.secret))
    def test_success_durably_consumes_exact_authority(self):
        a,b,c=self._patches()
        with a,b,c:
            with g.paid_start_authority(self.lease_path,"tok",self.packet,self.work,"mini-swe",self._env(),0.25) as auth:
                self.assertEqual(auth["taskId"],"task-1");self.assertEqual(auth["runId"],"run-1");self.assertEqual(auth["ownerEpoch"],7);self.assertEqual(auth["budgetUsd"],0.25)
                persisted=json.loads(self.lease_path.read_text(encoding="utf-8"));self.assertTrue(persisted["paid_consumed"]);self.assertEqual(persisted["paid_authority"]["taskId"],"task-1")
    def test_replay_after_persisted_consume_fails_closed(self):
        self.lease["paid_consumed"]=True;self._save();a,b,c=self._patches()
        with a,b,c:
            with self.assertRaises(g.SecurityError):
                with g.paid_start_authority(self.lease_path,"tok",self.packet,self.work,"mini-swe",self._env(),0.25):pass
    def test_cli_budget_mismatch_does_not_consume(self):
        a,b,c=self._patches()
        with a,b,c:
            with self.assertRaises(g.SecurityError):
                with g.paid_start_authority(self.lease_path,"tok",self.packet,self.work,"mini-swe",self._env(),0.20):pass
        self.assertFalse(json.loads(self.lease_path.read_text(encoding="utf-8"))["paid_consumed"])
    def test_tampered_control_envelope_does_not_consume(self):
        env=json.loads(self._env());env["budgetUsd"]=9.0;a,b,c=self._patches()
        with a,b,c:
            with self.assertRaises(g.SecurityError):
                with g.paid_start_authority(self.lease_path,"tok",self.packet,self.work,"mini-swe",json.dumps(env),9.0):pass
        self.assertFalse(json.loads(self.lease_path.read_text(encoding="utf-8"))["paid_consumed"])
    def test_wrong_runtime_identity_rejected(self):
        env=self._env(runtime={"adapter":"openhands","provider":"openai","model":"gpt"});a,b,c=self._patches()
        with a,b,c:
            with self.assertRaises(g.SecurityError):
                with g.paid_start_authority(self.lease_path,"tok",self.packet,self.work,"mini-swe",env,0.25):pass
    def test_final_metadata_drift_rejected_before_consume(self):
        self.lease["git_metadata"]={"git:effective-config":{"sha256":"old"}};self._save();a,b,c=self._patches({"git:effective-config":{"sha256":"new"}})
        with a,b,c:
            with self.assertRaises(g.SecurityError):
                with g.paid_start_authority(self.lease_path,"tok",self.packet,self.work,"mini-swe",self._env(),0.25):pass
        self.assertFalse(json.loads(self.lease_path.read_text(encoding="utf-8"))["paid_consumed"])

if __name__=="__main__":unittest.main()
