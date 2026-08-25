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
        self.assertNotIn("PATH",src)
        self.assertIn(r"\\.\pipe\ForgeBossIsolationBroker.v3",src)
        self.assertIn("/run/forgeboss/isolation-broker-v3.sock",src)

    def test_trust_anchor_is_os_pinned_not_worker_argument(self):
        src=inspect.getsource(broker._trust_anchor)
        self.assertNotIn("environ",src)
        self.assertNotIn("argv",src)
        self.assertIn("_windows_trust",src)
        self.assertIn("_linux_trust",src)

    def test_linux_trust_rejects_non_root_or_writable_file(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"trust.json";p.write_text(json.dumps({"serviceUid":0,"ed25519PublicKeyBase64":base64.b64encode(b"k"*32).decode()}),encoding="utf-8")
            with mock.patch.object(broker,"_LINUX_TRUST",p):
                real=p.stat()
                fake=mock.Mock(st_uid=1,st_mode=real.st_mode)
                with mock.patch.object(Path,"stat",return_value=fake):
                    with self.assertRaises(broker.IsolationBrokerError):broker._linux_trust()
                fake=mock.Mock(st_uid=0,st_mode=0o100666)
                with mock.patch.object(Path,"stat",return_value=fake):
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
        host=Path("/tmp/fake-host")
        packet={"allowed_files":["a.txt"],"context_files":[]}
        pre_authority={"ordinary":{},"git":{"g":1},"head":"h"*40,"worktree":str(host)}
        pre_targets={"a.txt":{"kind":"missing"}}
        request={"schema":3,"x":1}
        authority={"taskId":"t","runId":"r","ownerEpoch":1,"envelopeSha256":"e","budgetUsd":1.0}
        current=dict(pre_authority)
        receipt={"schema":2,"requestSha256":broker._digest(request),"preAuthoritySha256":broker._digest(pre_authority),"preTargetsSha256":broker._digest(pre_targets),"authoritySha256":broker._digest(authority),"appliedPaths":[],"postTargets":{"a.txt":{"kind":"missing"}},"postAuthoritySha256":broker._digest(current),"postTargetsSha256":broker._digest({"a.txt":{"kind":"missing"}})}
        reply={"authority":authority,"reintegrationReceipt":receipt}
        with mock.patch.object(broker.guard,"validate_packet",return_value=(["a.txt"],[])),mock.patch.object(broker,"_file_state",return_value={"kind":"missing"}),mock.patch.object(broker,"_capture_authority",return_value=current):
            self.assertEqual(broker._verify_receipt(reply,request,host,packet,pre_authority,pre_targets),[])
            stale=dict(receipt);stale["requestSha256"]="0"*64
            with self.assertRaises(broker.IsolationBrokerError):broker._verify_receipt({"authority":authority,"reintegrationReceipt":stale},request,host,packet,pre_authority,pre_targets)

    def test_source_contains_kernel_peer_authentication(self):
        src=inspect.getsource(broker)
        self.assertIn("SO_PEERCRED",src)
        self.assertIn("GetNamedPipeServerProcessId",src)
        self.assertIn("OpenProcessToken",src)
        self.assertIn("ConvertSidToStringSidW",src)
        self.assertIn("HKEY_LOCAL_MACHINE",src)
        self.assertIn("Ed25519PublicKey",src)


if __name__=="__main__":unittest.main()
