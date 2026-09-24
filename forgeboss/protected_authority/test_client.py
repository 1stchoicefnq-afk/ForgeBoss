from __future__ import annotations

import base64, ctypes, tempfile, unittest
from ctypes import wintypes
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forgeboss.protected_authority.client import ProtectedAuthorityClient
from forgeboss.protected_authority.protocol import AuthorityError, canonical_digest, strict_loads
from forgeboss.protected_authority.signing import ReceiptSigner


class ProtectedAuthorityClientTests(unittest.TestCase):
    def setUp(self):
        self.peer=Ed25519PrivateKey.generate();self.service=Ed25519PrivateKey.generate()
        raw=self.service.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
        self.pin=base64.b64encode(raw).decode("ascii")
        self.signer=ReceiptSigner.from_private_key(self.service)

    def transport(self,raw):
        req=strict_loads(raw)
        receipt={"schema":3,"operation":req["operation"],"requestId":req["requestId"],"peerId":req["peerId"],
                 "peerPrincipal":"test","repository":"1stchoicefnq-afk/ForgeBoss","controlRevision":req["controlRevision"],
                 "requestDigest":req["requestDigest"],"resultDigest":canonical_digest({"verified":True,"envelopeDigest":req["payload"]["envelopeDigest"]}),
                 "servicePrincipal":"service"}
        return __import__("forgeboss.protected_authority.protocol",fromlist=["canonical_json"]).canonical_json(
            {**self.signer.sign(receipt),"result":{"verified":True,"envelopeDigest":req["payload"]["envelopeDigest"]}})

    def client(self,transport=None):
        return ProtectedAuthorityClient(peer_id="controller-a",repository="1stchoicefnq-afk/ForgeBoss",control_revision=1,
                                        peer_private_key=self.peer,receipt_public_key_b64=self.pin,transport=transport or self.transport)

    def test_verified_launch_round_trip(self):
        env={"signed":{"taskId":"A"},"signature":"x"};dig=canonical_digest(env["signed"])
        out=self.client().verify_launch_authority(envelope=env,envelope_digest=dig)
        self.assertTrue(out["result"]["verified"])

    def test_tampered_receipt_rejected(self):
        def bad(raw):
            obj=strict_loads(self.transport(raw));obj["result"]["verified"]=False
            return __import__("forgeboss.protected_authority.protocol",fromlist=["canonical_json"]).canonical_json(obj)
        with self.assertRaises(AuthorityError) as cm:
            self.client(bad).verify_launch_authority(envelope={"signed":{"taskId":"A"},"signature":"x"},envelope_digest=canonical_digest({"taskId":"A"}))
        self.assertEqual(cm.exception.code,"SERVICE_RECEIPT_INVALID")

    def test_wrong_request_binding_rejected_even_with_valid_service_signature(self):
        def bad(raw):
            req=strict_loads(raw);result={"verified":True,"envelopeDigest":req["payload"]["envelopeDigest"]}
            receipt={"schema":3,"operation":req["operation"],"requestId":req["requestId"],"peerId":"controller-other",
                     "peerPrincipal":"test","repository":"1stchoicefnq-afk/ForgeBoss","controlRevision":req["controlRevision"],
                     "requestDigest":req["requestDigest"],"resultDigest":canonical_digest(result),"servicePrincipal":"service"}
            return __import__("forgeboss.protected_authority.protocol",fromlist=["canonical_json"]).canonical_json({**self.signer.sign(receipt),"result":result})
        with self.assertRaises(AuthorityError) as cm:
            self.client(bad).verify_launch_authority(envelope={"signed":{"taskId":"A"},"signature":"x"},envelope_digest=canonical_digest({"taskId":"A"}))
        self.assertEqual(cm.exception.code,"SERVICE_RECEIPT_BINDING_MISMATCH")

    def test_attest_launch_payload_signs_exact_canonical_payload(self):
        signed={"schema":1,"taskId":"A","expiresAt":9999999999.0}
        captured={}
        def transport(raw):
            req=strict_loads(raw);captured["req"]=req
            result={"verified":True,"envelopeDigest":req["payload"]["envelopeDigest"]}
            receipt={"schema":3,"operation":req["operation"],"requestId":req["requestId"],"peerId":req["peerId"],
                     "peerPrincipal":"test","repository":"1stchoicefnq-afk/ForgeBoss","controlRevision":req["controlRevision"],
                     "requestDigest":req["requestDigest"],"resultDigest":canonical_digest(result),"servicePrincipal":"service"}
            return __import__("forgeboss.protected_authority.protocol",fromlist=["canonical_json"]).canonical_json(
                {**self.signer.sign(receipt),"result":result})
        bundle=self.client(transport).attest_launch_payload(signed)
        self.assertEqual(bundle["schema"],1)
        self.assertEqual(bundle["envelope"]["signed"],signed)
        digest=canonical_digest(signed)
        self.peer.public_key().verify(base64.b64decode(bundle["envelope"]["signature"]),bytes.fromhex(digest))
        self.assertEqual(captured["req"]["payload"]["envelopeDigest"],digest)

    def _raw_client(self,*,timeout=0.2,cancel=None):
        return ProtectedAuthorityClient(
            peer_id="controller-a",repository="1stchoicefnq-afk/ForgeBoss",control_revision=1,
            peer_private_key=self.peer,receipt_public_key_b64=self.pin,transport=None,
            timeout=timeout,cancellation_predicate=cancel,
        )

    class _Clock:
        def __init__(self):self.now=0.0
        def monotonic(self):return self.now
        def sleep(self,seconds):self.now+=max(0.0,float(seconds))

    class _FakePipe:
        def __init__(self,clock,wait_steps,create_steps=None,on_wait=None,on_create=None):
            self.clock=clock;self.wait_steps=list(wait_steps);self.create_steps=list(create_steps or [])
            self.on_wait=on_wait;self.on_create=on_create;self.last_error=0
            self.wait_calls=[];self.create_calls=0;self.write_calls=0;self.close_calls=0
        def WaitNamedPipeW(self,name,wait_ms):
            self.wait_calls.append((self.clock.monotonic(),int(wait_ms)))
            if self.on_wait:self.on_wait(self)
            ok,err,consume=(self.wait_steps.pop(0) if self.wait_steps else (False,121,int(wait_ms)))
            self.last_error=int(err);self.clock.now+=min(int(wait_ms),int(consume))/1000.0
            return bool(ok)
        def CreateFileW(self,*args):
            self.create_calls+=1
            if self.on_create:self.on_create(self)
            value,err=(self.create_steps.pop(0) if self.create_steps else (ctypes.c_void_p(-1).value,231))
            self.last_error=int(err);return value
        def WriteFile(self,h,buf,n,written,overlapped):
            self.write_calls+=1;ctypes.cast(written,ctypes.POINTER(wintypes.DWORD)).contents.value=n;return True
        def ReadFile(self,h,buf,n,got,overlapped):
            payload=b"{}";ctypes.memmove(buf,payload,len(payload))
            ctypes.cast(got,ctypes.POINTER(wintypes.DWORD)).contents.value=len(payload);self.last_error=0;return True
        def CloseHandle(self,h):self.close_calls+=1;return True

    def _exchange_fake(self,client,api,clock,*,allow_after_stop=False):
        return client._exchange_windows_api(
            b"{}",k=api,monotonic=clock.monotonic,sleep=clock.sleep,
            get_last_error=lambda:api.last_error,invalid=ctypes.c_void_p(-1).value,
            allow_after_stop=allow_after_stop,
        )

    def test_windows_reconnect_handles_missing_then_busy_then_single_write(self):
        clock=self._Clock();invalid=ctypes.c_void_p(-1).value
        api=self._FakePipe(clock,[(False,2,0),(True,0,0),(True,0,0)],[(invalid,231),(77,0)])
        out=self._exchange_fake(self._raw_client(timeout=0.2),api,clock)
        self.assertEqual(out,b"{}");self.assertEqual(api.create_calls,2);self.assertEqual(api.write_calls,1)
        self.assertEqual(api.close_calls,1)

    def test_windows_terminal_connect_error_fails_immediately_with_native_code(self):
        clock=self._Clock();invalid=ctypes.c_void_p(-1).value
        api=self._FakePipe(clock,[(True,0,0)],[(invalid,5)])
        with self.assertRaises(AuthorityError) as cm:self._exchange_fake(self._raw_client(timeout=0.2),api,clock)
        self.assertEqual(cm.exception.code,"IPC_CONNECT_FAILED");self.assertIn("win32=5",str(cm.exception))
        self.assertEqual(api.create_calls,1);self.assertEqual(api.write_calls,0)

    def test_windows_wait_never_exceeds_remaining_deadline(self):
        clock=self._Clock();api=self._FakePipe(clock,[(False,121,9999)])
        with self.assertRaises(AuthorityError) as cm:self._exchange_fake(self._raw_client(timeout=0.05),api,clock)
        self.assertEqual(cm.exception.code,"IPC_CONNECT_FAILED")
        self.assertTrue(api.wait_calls);self.assertLessEqual(api.wait_calls[0][1],50)
        self.assertEqual(api.write_calls,0)

    def test_windows_stop_after_wait_prevents_open_and_write(self):
        stop={"value":False};clock=self._Clock()
        def on_wait(_):stop["value"]=True
        api=self._FakePipe(clock,[(True,0,0)],[(77,0)],on_wait=on_wait)
        with self.assertRaises(AuthorityError) as cm:self._exchange_fake(self._raw_client(cancel=lambda:stop["value"]),api,clock)
        self.assertEqual(cm.exception.code,"IPC_STOPPED");self.assertEqual(api.create_calls,0);self.assertEqual(api.write_calls,0)

    def test_windows_stop_after_open_prevents_write_and_closes_handle(self):
        stop={"value":False};clock=self._Clock()
        def on_create(_):stop["value"]=True
        api=self._FakePipe(clock,[(True,0,0)],[(77,0)],on_create=on_create)
        with self.assertRaises(AuthorityError) as cm:self._exchange_fake(self._raw_client(cancel=lambda:stop["value"]),api,clock)
        self.assertEqual(cm.exception.code,"IPC_STOPPED");self.assertEqual(api.write_calls,0);self.assertEqual(api.close_calls,1)

    def test_owner_stop_blocks_new_operation_but_allows_revoke_cleanup(self):
        calls=[]
        def generic(raw):
            req=strict_loads(raw);calls.append(req["operation"]);result={"ok":True}
            receipt={"schema":3,"operation":req["operation"],"requestId":req["requestId"],"peerId":req["peerId"],
                     "peerPrincipal":"test","repository":req["repository"],"controlRevision":req["controlRevision"],
                     "requestDigest":req["requestDigest"],"resultDigest":canonical_digest(result),"servicePrincipal":"service"}
            return __import__("forgeboss.protected_authority.protocol",fromlist=["canonical_json"]).canonical_json(
                {**self.signer.sign(receipt),"result":result})
        c=ProtectedAuthorityClient(peer_id="controller-a",repository="1stchoicefnq-afk/ForgeBoss",control_revision=1,
                                   peer_private_key=self.peer,receipt_public_key_b64=self.pin,transport=generic,
                                   cancellation_predicate=lambda:True)
        with self.assertRaises(AuthorityError) as cm:c.activate_self_build_successor(run_id="R1")
        self.assertEqual(cm.exception.code,"IPC_STOPPED");self.assertEqual(calls,[])
        c.revoke_self_build_worker(run_id="R1",task_id="T1",worker_run_id="W1",owner_epoch=1,reason="owner stop")
        self.assertEqual(calls,["revoke_self_build_worker"])

    def test_from_files_loads_raw_ed25519_key_and_pin(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);keyfile=root/"peer.key";pinfile=root/"receipt.pub"
            raw=self.peer.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
            keyfile.write_bytes(raw);pinfile.write_text(self.pin,encoding="ascii")
            c=ProtectedAuthorityClient.from_files(peer_id="controller-a",repository="1stchoicefnq-afk/ForgeBoss",control_revision=1,
                                                  peer_private_key_file=str(keyfile),receipt_public_key_file=str(pinfile))
            self.assertEqual(c.peer_id,"controller-a")


if __name__=="__main__":unittest.main()
