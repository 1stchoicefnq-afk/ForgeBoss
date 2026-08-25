from __future__ import annotations

import base64
import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import forgeboss.executors.isolation_broker as broker


class IsolationBrokerIdentityTests(unittest.TestCase):
    def test_production_has_no_env_or_path_broker_override(self):
        src=inspect.getsource(broker)
        self.assertNotIn("FORGEBOSS_TEST_ISOLATION_BROKER",src)
        self.assertNotIn("ProgramFiles",src)
        self.assertNotIn("shutil.which",src)
        self.assertNotIn("TokenUser",src)
        self.assertIn(r"\\.\pipe\ForgeBossIsolationBroker.v3",src)
        self.assertIn("/run/forgeboss/isolation-broker-v3.sock",src)

    def test_trust_anchor_is_os_pinned_not_worker_argument(self):
        src=inspect.getsource(broker._trust_anchor)
        self.assertNotIn("environ",src)
        self.assertNotIn("argv",src)
        self.assertIn("_windows_trust",src)
        self.assertIn("_linux_trust",src)

    def test_service_sid_is_enabled_token_group_not_token_user(self):
        sid="S-1-5-80-1234"
        self.assertTrue(broker._has_enabled_service_sid([(sid,broker._SE_GROUP_ENABLED)],sid))
        self.assertFalse(broker._has_enabled_service_sid([],sid))
        self.assertFalse(broker._has_enabled_service_sid([(sid,0)],sid))
        self.assertFalse(broker._has_enabled_service_sid([(sid,broker._SE_GROUP_ENABLED|broker._SE_GROUP_USE_FOR_DENY_ONLY)],sid))
        self.assertFalse(broker._has_enabled_service_sid([("S-1-5-80-9999",broker._SE_GROUP_ENABLED)],sid))

    def _auth_trust(self):
        return {"serviceName":"ForgeBossIsolationBroker","serviceSid":"S-1-5-80-1234","imagePath":os.path.normcase(os.path.normpath(r"C:\Program Files\ForgeBoss\broker.exe"))}

    def _auth_context(self,service_pids=(77,77),pipe_pids=(77,77),images=None,groups=None):
        kernel=mock.Mock();adv=mock.Mock();kernel.OpenProcess.return_value=123
        if images is None:images=[self._auth_trust()["imagePath"],self._auth_trust()["imagePath"]]
        if groups is None:groups=[(self._auth_trust()["serviceSid"],broker._SE_GROUP_ENABLED)]
        return (mock.patch.object(broker,"_win_libs",return_value=(kernel,adv,None)),
                mock.patch.object(broker,"_pipe_server_pid",side_effect=list(pipe_pids)),
                mock.patch.object(broker,"_registered_service_pid",side_effect=list(service_pids)),
                mock.patch.object(broker,"_process_image",side_effect=list(images)),
                mock.patch.object(broker,"_token_group_sids",return_value=groups))

    def test_windows_auth_accepts_shared_account_when_exact_service_sid_present(self):
        patches=self._auth_context()
        with patches[0],patches[1],patches[2],patches[3],patches[4]:
            broker._authenticate_windows_server(456,self._auth_trust())

    def test_windows_auth_rejects_same_account_different_service_sid(self):
        patches=self._auth_context(groups=[("S-1-5-80-9999",broker._SE_GROUP_ENABLED)])
        with patches[0],patches[1],patches[2],patches[3],patches[4]:
            with self.assertRaisesRegex(broker.IsolationBrokerError,"service SID"):
                broker._authenticate_windows_server(456,self._auth_trust())

    def test_windows_auth_rejects_wrong_registered_service_pid(self):
        patches=self._auth_context(service_pids=(88,88))
        with patches[0],patches[1],patches[2],patches[3],patches[4]:
            with self.assertRaisesRegex(broker.IsolationBrokerError,"service instance"):
                broker._authenticate_windows_server(456,self._auth_trust())

    def test_windows_auth_rejects_wrong_image(self):
        bad=os.path.normcase(os.path.normpath(r"C:\evil\broker.exe"))
        patches=self._auth_context(images=[bad,bad])
        with patches[0],patches[1],patches[2],patches[3],patches[4]:
            with self.assertRaisesRegex(broker.IsolationBrokerError,"process image"):
                broker._authenticate_windows_server(456,self._auth_trust())

    def test_windows_auth_rejects_pid_replacement_during_auth(self):
        patches=self._auth_context(pipe_pids=(77,99))
        with patches[0],patches[1],patches[2],patches[3],patches[4]:
            with self.assertRaisesRegex(broker.IsolationBrokerError,"changed during authentication"):
                broker._authenticate_windows_server(456,self._auth_trust())

    def test_source_uses_correct_windows_identity_and_handle_primitives(self):
        src=inspect.getsource(broker)
        self.assertIn("TokenGroups = 2",src)
        self.assertIn("QueryServiceStatusEx",src)
        self.assertIn("QueryFullProcessImageNameW",src)
        self.assertIn("GetNamedPipeServerProcessId",src)
        self.assertIn("CreateFileW.restype = HANDLE",src)
        self.assertIn("OpenProcess.restype = HANDLE",src)
        self.assertIn("OpenProcessToken.restype = BOOL",src)
        self.assertIn("ConvertSidToStringSidW.restype = BOOL",src)

    def test_linux_trust_rejects_non_root_or_writable_file(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"trust.json";p.write_text(json.dumps({"serviceUid":0,"ed25519PublicKeyBase64":base64.b64encode(b"k"*32).decode()}),encoding="utf-8")
            with mock.patch.object(broker,"_LINUX_TRUST",p):
                real=p.stat()
                with mock.patch.object(Path,"stat",return_value=mock.Mock(st_uid=1,st_mode=real.st_mode)):
                    with self.assertRaises(broker.IsolationBrokerError):broker._linux_trust()
                with mock.patch.object(Path,"stat",return_value=mock.Mock(st_uid=0,st_mode=0o100666)):
                    with self.assertRaises(broker.IsolationBrokerError):broker._linux_trust()

    def test_signed_reply_rejects_bad_signature(self):
        env={"signedReceipt":{"schema":3,"ok":True},"receiptSignature":base64.b64encode(b"x"*64).decode()}
        with self.assertRaises(broker.IsolationBrokerError):broker._verify_signed_reply(env,b"k"*32)

    def test_call_broker_rejects_unprotected_or_local_copyback_claims(self):
        trust={"publicKey":b"k"*32,"serviceUid":0}
        good={"schema":3,"ok":True,"isolated":True,"paidConsumed":True,"reintegrated":True,"reintegrationProtected":True,"ordinaryWorkersDeniedDirectWrite":True,"preopenedWritableHandlesExcluded":True,"hostWorkspaceMounted":False,"workerHasRuntimeControl":False,"localCopybackRequired":False,"changes":[]}
        with mock.patch.object(broker,"_trust_anchor",return_value=trust),mock.patch.object(broker,"_linux_exchange",return_value={}),mock.patch.object(broker,"_verify_signed_reply",return_value=dict(good)):
            self.assertTrue(broker._call_broker({"schema":3})["reintegrated"])
        for key,value in (("reintegrationProtected",False),("ordinaryWorkersDeniedDirectWrite",False),("preopenedWritableHandlesExcluded",False),("localCopybackRequired",True),("changes",[{"path":"x"}])):
            bad=dict(good);bad[key]=value
            with mock.patch.object(broker,"_trust_anchor",return_value=trust),mock.patch.object(broker,"_linux_exchange",return_value={}),mock.patch.object(broker,"_verify_signed_reply",return_value=bad):
                with self.subTest(key=key),self.assertRaises(broker.IsolationBrokerError):broker._call_broker({"schema":3})

    def test_receipt_binds_exact_request_and_authority(self):
        host=Path("/tmp/fake-host");packet={"allowed_files":["a.txt"],"context_files":[]};pre_authority={"ordinary":{},"git":{"g":1},"head":"h"*40,"worktree":str(host)};pre_targets={"a.txt":{"kind":"missing"}};request={"schema":3,"x":1};authority={"taskId":"t","runId":"r","ownerEpoch":1,"envelopeSha256":"e","budgetUsd":1.0};current=dict(pre_authority)
        receipt={"schema":2,"requestSha256":broker._digest(request),"preAuthoritySha256":broker._digest(pre_authority),"preTargetsSha256":broker._digest(pre_targets),"authoritySha256":broker._digest(authority),"appliedPaths":[],"postTargets":{"a.txt":{"kind":"missing"}},"postAuthoritySha256":broker._digest(current),"postTargetsSha256":broker._digest({"a.txt":{"kind":"missing"}})}
        reply={"authority":authority,"reintegrationReceipt":receipt}
        with mock.patch.object(broker.guard,"validate_packet",return_value=(["a.txt"],[])),mock.patch.object(broker,"_file_state",return_value={"kind":"missing"}),mock.patch.object(broker,"_capture_authority",return_value=current):
            self.assertEqual(broker._verify_receipt(reply,request,host,packet,pre_authority,pre_targets),[])
            stale=dict(receipt);stale["requestSha256"]="0"*64
            with self.assertRaises(broker.IsolationBrokerError):broker._verify_receipt({"authority":authority,"reintegrationReceipt":stale},request,host,packet,pre_authority,pre_targets)

    def test_casefold_identity_map_accepts_one_spelling_and_rejects_collision(self):
        state={"kind":"missing"}
        mapped=broker._casefold_state_map({"Src/File.TXT":state},"x")
        self.assertEqual(mapped["src/file.txt"][0],"Src/File.TXT")
        with self.assertRaisesRegex(broker.IsolationBrokerError,"case collision"):
            broker._casefold_state_map({"Src/File.TXT":state,"src/file.txt":state},"x")

    def test_receipt_accepts_case_only_variation_and_returns_canonical_allowed_path(self):
        host=Path("/tmp/fake-host");canonical="Src/A.txt";state={"kind":"file","sha256":"a"*64,"size":1}
        packet={"allowed_files":[canonical],"context_files":[]}
        pre_authority={"ordinary":{"SRC/a.TXT":state},"git":{"g":1},"head":"h"*40,"worktree":str(host)}
        pre_targets={"src/A.TXT":state};request={"schema":3,"x":1};authority={"taskId":"t","runId":"r","ownerEpoch":1,"envelopeSha256":"e","budgetUsd":1.0}
        current={"ordinary":{"src/a.txt":state},"git":{"g":1},"head":"h"*40,"worktree":str(host)}
        canonical_post={canonical:state}
        receipt={"schema":2,"requestSha256":broker._digest(request),"preAuthoritySha256":broker._digest(pre_authority),"preTargetsSha256":broker._digest(pre_targets),"authoritySha256":broker._digest(authority),"appliedPaths":["sRC/a.TxT"],"postTargets":{"SRC/A.txt":state},"postAuthoritySha256":broker._digest(current),"postTargetsSha256":broker._digest(canonical_post)}
        reply={"authority":authority,"reintegrationReceipt":receipt}
        with mock.patch.object(broker.guard,"validate_packet",return_value=([canonical],[])),mock.patch.object(broker,"_file_state",return_value=state),mock.patch.object(broker,"_capture_authority",return_value=current):
            self.assertEqual(broker._verify_receipt(reply,request,host,packet,pre_authority,pre_targets),[canonical])

    def test_receipt_rejects_case_colliding_post_targets(self):
        host=Path("/tmp/fake-host");state={"kind":"missing"};packet={"allowed_files":["a.txt"],"context_files":[]};pre_authority={"ordinary":{},"git":{"g":1},"head":"h"*40,"worktree":str(host)};pre_targets={"a.txt":state};request={"schema":3};authority={"taskId":"t","runId":"r","ownerEpoch":1,"envelopeSha256":"e","budgetUsd":1.0}
        receipt={"schema":2,"requestSha256":broker._digest(request),"preAuthoritySha256":broker._digest(pre_authority),"preTargetsSha256":broker._digest(pre_targets),"authoritySha256":broker._digest(authority),"appliedPaths":[],"postTargets":{"a.txt":state,"A.TXT":state},"postAuthoritySha256":"x","postTargetsSha256":"y"}
        with mock.patch.object(broker.guard,"validate_packet",return_value=(["a.txt"],[])):
            with self.assertRaisesRegex(broker.IsolationBrokerError,"case collision"):broker._verify_receipt({"authority":authority,"reintegrationReceipt":receipt},request,host,packet,pre_authority,pre_targets)

    def test_source_keeps_kernel_peer_and_signature_authentication(self):
        src=inspect.getsource(broker)
        self.assertIn("SO_PEERCRED",src)
        self.assertIn("HKEY_LOCAL_MACHINE",src)
        self.assertIn("Ed25519PublicKey",src)
        self.assertIn("protected host prerequisite missing: pinned cryptography package",src)


if __name__=="__main__":unittest.main()
