from __future__ import annotations
import base64,inspect,json,os,tempfile,unittest
from pathlib import Path
from unittest import mock
import forgeboss.executors.isolation_broker as broker

class IsolationBrokerIdentityTests(unittest.TestCase):
    def test_production_has_no_env_or_path_broker_override(self):
        src=inspect.getsource(broker);self.assertNotIn("FORGEBOSS_TEST_ISOLATION_BROKER",src);self.assertNotIn("ProgramFiles",src);self.assertNotIn("shutil.which",src);self.assertNotIn("TokenUser",src);self.assertIn(r"\\.\pipe\ForgeBossIsolationBroker.v3",src);self.assertIn("/run/forgeboss/isolation-broker-v3.sock",src)
    def test_trust_anchor_is_os_pinned_not_worker_argument(self):
        src=inspect.getsource(broker._trust_anchor);self.assertNotIn("environ",src);self.assertNotIn("argv",src);self.assertIn("_windows_trust",src);self.assertIn("_linux_trust",src)
    def test_service_sid_is_enabled_token_group_not_token_user(self):
        sid="S-1-5-80-1234";self.assertTrue(broker._has_enabled_service_sid([(sid,broker._SE_GROUP_ENABLED)],sid));self.assertFalse(broker._has_enabled_service_sid([],sid));self.assertFalse(broker._has_enabled_service_sid([(sid,0)],sid));self.assertFalse(broker._has_enabled_service_sid([(sid,broker._SE_GROUP_ENABLED|broker._SE_GROUP_USE_FOR_DENY_ONLY)],sid));self.assertFalse(broker._has_enabled_service_sid([("S-1-5-80-9999",broker._SE_GROUP_ENABLED)],sid))
    def _trust(self):return {"serviceName":"ForgeBossIsolationBroker","serviceSid":"S-1-5-80-1234","imagePath":os.path.normcase(os.path.normpath(r"C:\Program Files\ForgeBoss\broker.exe"))}
    def _ctx(self,service=(77,77),pipe=(77,77),images=None,groups=None):
        k=mock.Mock();a=mock.Mock();k.OpenProcess.return_value=123
        images=images or [self._trust()["imagePath"]]*2;groups=groups or [(self._trust()["serviceSid"],broker._SE_GROUP_ENABLED)]
        return (mock.patch.object(broker,"_win_libs",return_value=(k,a,None)),mock.patch.object(broker,"_pipe_server_pid",side_effect=list(pipe)),mock.patch.object(broker,"_registered_service_pid",side_effect=list(service)),mock.patch.object(broker,"_process_image",side_effect=list(images)),mock.patch.object(broker,"_token_group_sids",return_value=groups))
    def test_windows_auth_accepts_exact_service_sid_pid_image(self):
        p=self._ctx()
        with p[0],p[1],p[2],p[3],p[4]:broker._authenticate_windows_server(456,self._trust())
    def test_windows_auth_rejects_same_account_different_service_sid(self):
        p=self._ctx(groups=[("S-1-5-80-9999",broker._SE_GROUP_ENABLED)])
        with p[0],p[1],p[2],p[3],p[4],self.assertRaisesRegex(broker.IsolationBrokerError,"service SID"):broker._authenticate_windows_server(456,self._trust())
    def test_windows_auth_rejects_wrong_registered_service_pid(self):
        p=self._ctx(service=(88,88))
        with p[0],p[1],p[2],p[3],p[4],self.assertRaisesRegex(broker.IsolationBrokerError,"service instance"):broker._authenticate_windows_server(456,self._trust())
    def test_windows_auth_rejects_wrong_image_and_pid_replacement(self):
        bad=os.path.normcase(os.path.normpath(r"C:\evil\broker.exe"));p=self._ctx(images=[bad,bad])
        with p[0],p[1],p[2],p[3],p[4],self.assertRaisesRegex(broker.IsolationBrokerError,"process image"):broker._authenticate_windows_server(456,self._trust())
        p=self._ctx(pipe=(77,99))
        with p[0],p[1],p[2],p[3],p[4],self.assertRaisesRegex(broker.IsolationBrokerError,"changed during authentication"):broker._authenticate_windows_server(456,self._trust())
    def test_source_uses_correct_windows_identity_and_handle_primitives(self):
        src=inspect.getsource(broker);self.assertIn("TokenGroups=2",src);self.assertIn("QueryServiceStatusEx",src);self.assertIn("QueryFullProcessImageNameW",src);self.assertIn("GetNamedPipeServerProcessId",src);self.assertIn("CreateFileW.restype=H",src);self.assertIn("OpenProcess.restype=H",src);self.assertIn("OpenProcessToken.restype=B",src);self.assertIn("ConvertSidToStringSidW.restype=B",src)
    def test_linux_trust_requires_pinned_service_uid_and_gid(self):
        src=inspect.getsource(broker._linux_trust);self.assertIn("serviceUid",src);self.assertIn("serviceGid",src);self.assertIn("root-owned/write-protected",src)
    def test_signed_reply_rejects_bad_signature(self):
        env={"signedReceipt":{"schema":3,"ok":True},"receiptSignature":base64.b64encode(b"x"*64).decode()}
        with self.assertRaises(broker.IsolationBrokerError):broker._verify_signed_reply(env,b"k"*32)
    def test_call_broker_rejects_unprotected_or_local_copyback_claims(self):
        trust={"publicKey":b"k"*32,"serviceUid":0,"serviceGid":0};good={"schema":3,"ok":True,"isolated":True,"paidConsumed":True,"reintegrated":True,"reintegrationProtected":True,"ordinaryWorkersDeniedDirectWrite":True,"preopenedWritableHandlesExcluded":True,"hostWorkspaceMounted":False,"workerHasRuntimeControl":False,"localCopybackRequired":False,"changes":[]}
        with mock.patch.object(broker,"_trust_anchor",return_value=trust),mock.patch.object(broker,"_linux_exchange",return_value={}),mock.patch.object(broker,"_verify_signed_reply",return_value=dict(good)):self.assertTrue(broker._call_broker({"schema":3})["reintegrated"])
        for key,value in (("reintegrationProtected",False),("ordinaryWorkersDeniedDirectWrite",False),("preopenedWritableHandlesExcluded",False),("localCopybackRequired",True),("changes",[{"path":"x"}])):
            bad=dict(good);bad[key]=value
            with self.subTest(key=key),mock.patch.object(broker,"_trust_anchor",return_value=trust),mock.patch.object(broker,"_linux_exchange",return_value={}),mock.patch.object(broker,"_verify_signed_reply",return_value=bad),self.assertRaises(broker.IsolationBrokerError):broker._call_broker({"schema":3})

class ResultReceiptTests(unittest.TestCase):
    def fixture(self):
        host=Path("/tmp/fake-host");packet={"allowed_files":["A.txt"],"context_files":[]};pre={"ordinary":{"A.txt":{"kind":"file","sha256":"old","size":3}},"git":{"g":1},"head":"a"*40,"worktree":str(host)};targets={"A.txt":{"kind":"file","sha256":"old","size":3}};authority={"taskId":"t","runId":"r","ownerEpoch":1,"envelopeSha256":"e"*64,"budgetUsd":1.0};request={"schema":3,"expectedAuthority":{"baseSha":"a"*40},"x":1};result="b"*40;tree="c"*40
        receipt={"schema":3,"requestSha256":broker._digest(request),"preAuthoritySha256":broker._digest(pre),"preTargetsSha256":broker._digest(targets),"authoritySha256":broker._digest(authority),"protectedAuthorityAttestationId":"att","paidConsumeId":"consume","baseCommit":"a"*40,"resultCommit":result,"resultTree":tree,"appliedPaths":["a.TXT"],"allowedPathsSha256":broker._digest(["A.txt"]),"diffSha256":"d"*64,"resultRef":broker._result_ref("t","r"),"expectedOldOid":"0"*40,"committedNewOid":result,"handoffRepoId":"f"*64,"hostWorktreeAuthoritative":False,"receiptId":"rid"}
        return host,packet,pre,targets,request,{"authority":authority,"reintegrationReceipt":receipt}
    def test_commit_ref_receipt_accepts_case_only_alias_and_host_bytes_are_non_authoritative(self):
        host,packet,pre,targets,request,reply=self.fixture();current={"ordinary":{"A.txt":{"kind":"file","sha256":"HOSTILE","size":7}},"git":{"g":1},"head":"a"*40,"worktree":str(host)}
        with mock.patch.object(broker.guard,"validate_packet",return_value=(["A.txt"],[])),mock.patch.object(broker,"_capture_authority",return_value=current):
            applied,r=broker._verify_receipt(reply,request,host,packet,pre,targets)
        self.assertEqual(applied,["A.txt"]);self.assertFalse(r["hostWorktreeAuthoritative"])
    def test_receipt_rejects_wrong_result_ref_cas_or_out_of_scope_path(self):
        host,packet,pre,targets,request,reply=self.fixture();current={"ordinary":{},"git":{"g":1},"head":"a"*40,"worktree":str(host)}
        for field,value in (("resultRef","refs/evil"),("expectedOldOid","1"*40),("committedNewOid","9"*40)):
            bad=json.loads(json.dumps(reply));bad["reintegrationReceipt"][field]=value
            with self.subTest(field=field),mock.patch.object(broker.guard,"validate_packet",return_value=(["A.txt"],[])),mock.patch.object(broker,"_capture_authority",return_value=current),self.assertRaises(broker.IsolationBrokerError):broker._verify_receipt(bad,request,host,packet,pre,targets)
        bad=json.loads(json.dumps(reply));bad["reintegrationReceipt"]["appliedPaths"]=["other.txt"]
        with mock.patch.object(broker.guard,"validate_packet",return_value=(["A.txt"],[])),mock.patch.object(broker,"_capture_authority",return_value=current),self.assertRaises(broker.IsolationBrokerError):broker._verify_receipt(bad,request,host,packet,pre,targets)
    def test_source_keeps_kernel_peer_signature_and_no_local_file_copyback(self):
        src=inspect.getsource(broker);self.assertIn("SO_PEERCRED",src);self.assertIn("HKEY_LOCAL_MACHINE",src);self.assertIn("Ed25519PublicKey",src);self.assertIn("hostWorktreeAuthoritative",src);self.assertNotIn("os.replace",inspect.getsource(broker._verify_receipt))

if __name__=="__main__":unittest.main()
