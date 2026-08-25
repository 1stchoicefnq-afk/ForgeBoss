from __future__ import annotations
import json,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from forgeboss.broker import server
class FakeSigner:
    def sign(self,obj):return {"signedReceipt":obj,"receiptSignature":"test"}
class GoodVerifier:
    def verify(self,req):return SimpleNamespace(attestation_id="protected-attestation-1",result_ref=req["resultRef"],runtime=req["runtime"])
def envelope(work,allowed=("x.py",)):
    return {"envelopeVersion":1,"protocolVersion":1,"taskId":"task-1","repository":"1stchoicefnq-afk/ForgeBoss","baseSha":"a"*40,"branch":"w","worktreePath":str(work.resolve()),"runId":"run-1","attempt":1,"ownerEpoch":7,"runtime":{"adapter":"mini-swe","provider":"openai","model":"openai/gpt-test"},"allowedPaths":list(allowed),"deniedPaths":[],"allowedTools":["python"],"contextBundleHash":None,"transcript":{},"events":{},"budgetUsd":0.25,"expiresAt":time.time()+120,"signature":"hmac-sha256:legacy-worker-readable"}
def request(work,allowed=("x.py",)):
    e=envelope(work,allowed);unsigned=dict(e);unsigned.pop("signature");esha=server._digest(unsigned);pre={};targets={}
    return {"schema":3,"operation":"run-mini-swe-v3","workspace":str(work.resolve()),"packetPath":str((work/"packet.json").resolve()),"packet":{"objective":"x","allowed_files":list(allowed),"context_files":[]},"leasePath":str((work/"lease.json").resolve()),"leaseToken":"legacy","controlEnvelope":json.dumps(e),"budgetUsd":0.25,"model":"openai/gpt-test","image":"node:22-bookworm","expectedAuthority":{"taskId":"task-1","runId":"run-1","ownerEpoch":7,"envelopeSha256":esha,"budgetUsd":0.25,"worktreePath":str(work.resolve()),"baseSha":"a"*40,"allowedPaths":list(allowed),"expiresAt":unsigned["expiresAt"]},"preAuthority":pre,"preAuthoritySha256":server._digest(pre),"preTargets":targets,"preTargetsSha256":server._digest(targets)}
class BrokerServerTests(unittest.TestCase):
    def setUp(self):self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name)/"broker";self.work=Path(self.td.name)/"work";self.work.mkdir()
    def tearDown(self):self.td.cleanup()
    def patches(self):return mock.patch.object(server,"broker_root",return_value=self.root)
    def test_legacy_hmac_alone_fails_before_materializer(self):
        verifier=mock.Mock();verifier.verify.side_effect=RuntimeError("protected authority unavailable");materializer=mock.Mock();b=server.BrokerServer(authority_verifier=verifier,signer=FakeSigner(),materializer=materializer)
        with self.patches(),self.assertRaisesRegex(RuntimeError,"protected authority unavailable"):b.handle(request(self.work))
        materializer.assert_not_called()
    def test_protected_attestation_binds_runtime_and_result_ref(self):
        verifier=GoodVerifier();req=request(self.work);view=server._authority_view(req);got=verifier.verify({"resultRef":view["resultRef"],"runtime":view["runtime"]});self.assertEqual(got.result_ref,view["resultRef"]);self.assertEqual(got.runtime,view["runtime"])
    def test_protected_consume_is_durable_before_runtime_and_replay_denied(self):
        materializer=mock.Mock(side_effect=RuntimeError("crash after consume"));b=server.BrokerServer(authority_verifier=GoodVerifier(),signer=FakeSigner(),materializer=materializer);req=request(self.work)
        with self.patches():first=b.handle(req)
        self.assertFalse(first["signedReceipt"]["completed"]);self.assertTrue(first["signedReceipt"]["paidConsumed"]);self.assertIn("crash after consume",first["signedReceipt"]["error"])
        with self.patches(),self.assertRaisesRegex(server.BrokerServerError,"already consumed/replay"):b.handle(req)
        self.assertEqual(materializer.call_count,1)
    def test_paid_runtime_failure_returns_signed_truthful_cost_and_calls(self):
        repo=self.work/"private";repo.mkdir();rr=SimpleNamespace(completed=False,cost_usd=.17,calls=4,error="provider failed");b=server.BrokerServer(authority_verifier=GoodVerifier(),signer=FakeSigner(),materializer=lambda *_:repo,runner=lambda *_:rr)
        with self.patches():env=b.handle(request(self.work))
        signed=env["signedReceipt"];self.assertFalse(signed["completed"]);self.assertFalse(signed["reintegrated"]);self.assertEqual(signed["cost_usd"],.17);self.assertEqual(signed["calls"],4);self.assertTrue(signed["reintegrationReceipt"]["failedBeforeResult"])
    def test_scope_or_prehash_mismatch_fails_before_protected_authority(self):
        req=request(self.work);req["packet"]["allowed_files"]=["other.py"];verifier=mock.Mock();b=server.BrokerServer(authority_verifier=verifier,signer=FakeSigner())
        with self.assertRaisesRegex(server.BrokerServerError,"packet scope differs"):b.handle(req)
        verifier.verify.assert_not_called();req=request(self.work);req["preAuthoritySha256"]="0"*64
        with self.assertRaisesRegex(server.BrokerServerError,"preAuthority digest mismatch"):b.handle(req)
    def test_success_receipt_is_commit_ref_handoff_not_file_payload(self):
        repo=self.work/"private";repo.mkdir();rr=SimpleNamespace(completed=True,cost_usd=.1,calls=2,error=None);ref=server.make_result_ref("task-1","run-1");hand=SimpleNamespace(base_commit="a"*40,result_commit="b"*40,result_tree="c"*40,result_ref=ref,old_oid="0"*40,new_oid="b"*40,applied_paths=("x.py",),diff_sha256="d"*64,handoff_repo_id="e"*64)
        b=server.BrokerServer(authority_verifier=GoodVerifier(),signer=FakeSigner(),materializer=lambda *_:repo,runner=lambda *_:rr,handoff=lambda *_:hand)
        with self.patches():env=b.handle(request(self.work))
        signed=env["signedReceipt"];r=signed["reintegrationReceipt"];self.assertEqual(signed["changes"],[]);self.assertFalse(signed["hostWorkspaceMounted"]);self.assertFalse(signed["localCopybackRequired"]);self.assertFalse(r["hostWorktreeAuthoritative"]);self.assertEqual(r["resultCommit"],"b"*40);self.assertEqual(r["resultRef"],ref)
    def test_workspace_budget_and_runtime_image_are_exactly_bound(self):
        for field,value,pattern in (("workspace",str(self.work.parent/"other"),"workspace differs"),("budgetUsd",9.0,"budget differs"),("image","attacker/image:latest","unapproved broker runtime image")):
            req=request(self.work);req[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(server.BrokerServerError,pattern):server._authority_view(req)
if __name__=="__main__":unittest.main()
