from __future__ import annotations

import base64, os, tempfile, unittest
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

    def launch(self):
        return {
            "schema":1,"repository":"1stchoicefnq-afk/ForgeBoss","controlRevision":1,
            "taskId":"FL1-A","runId":"worker-a","ownerEpoch":1,"builderId":"builder-a",
            "assignmentGeneration":1,"assignmentSha256":"2"*64,
            "branch":"forgeboss/fl1-selfbuild-a","worktreePath":"C:\\ForgeBoss\\worker-a",
            "runtimeId":"mini-swe","allowedPaths":["forgeboss/x.py"],"packetSha256":"3"*64,
            "budgetUsd":"1.00","globalBudgetRunId":"fl1-run",
            "globalBudgetReservationId":"FL1-A","expiresAt":9999999999.0,
        }

    def transport(self,raw):
        req=strict_loads(raw);launch=req["payload"]["launch"]
        result={
            "verified":True,"launchDigest":canonical_digest(launch),
            "sourceIdentity":{"revision":"a"*40,"manifestSha256":"b"*64,"identitySha256":"c"*64,"treeSha256":"d"*64,"codeRoot":"C:\\ForgeBoss"},
            "trustGrade":"OWNER_DECLARED_TRUSTED_LOCAL_BOOTSTRAP",
        }
        receipt={"schema":3,"operation":req["operation"],"requestId":req["requestId"],"peerId":req["peerId"],
                 "peerPrincipal":"test","repository":"1stchoicefnq-afk/ForgeBoss","controlRevision":req["controlRevision"],
                 "requestDigest":req["requestDigest"],"resultDigest":canonical_digest(result),
                 "servicePrincipal":"service"}
        return __import__("forgeboss.protected_authority.protocol",fromlist=["canonical_json"]).canonical_json(
            {**self.signer.sign(receipt),"result":result})

    def client(self,transport=None):
        return ProtectedAuthorityClient(peer_id="controller-a",repository="1stchoicefnq-afk/ForgeBoss",control_revision=1,
                                        peer_private_key=self.peer,receipt_public_key_b64=self.pin,transport=transport or self.transport)

    def test_runtime_authorized_launch_round_trip(self):
        launch=self.launch();out=self.client().authorize_self_build_launch(launch)
        self.assertEqual(out["schema"],2)
        self.assertEqual(out["launch"],launch)
        self.assertEqual(out["authorityResponse"]["result"]["launchDigest"],canonical_digest(launch))

    def test_tampered_receipt_rejected(self):
        def bad(raw):
            obj=strict_loads(self.transport(raw));obj["result"]["verified"]=False
            return __import__("forgeboss.protected_authority.protocol",fromlist=["canonical_json"]).canonical_json(obj)
        with self.assertRaises(AuthorityError) as cm:
            self.client(bad).authorize_self_build_launch(self.launch())
        self.assertEqual(cm.exception.code,"SERVICE_RECEIPT_INVALID")

    def test_wrong_request_binding_rejected_even_with_valid_service_signature(self):
        def bad(raw):
            req=strict_loads(raw);launch=req["payload"]["launch"]
            result={"verified":True,"launchDigest":canonical_digest(launch),
                    "sourceIdentity":{"revision":"a"*40},"trustGrade":"OWNER_DECLARED_TRUSTED_LOCAL_BOOTSTRAP"}
            receipt={"schema":3,"operation":req["operation"],"requestId":req["requestId"],"peerId":"controller-other",
                     "peerPrincipal":"test","repository":"1stchoicefnq-afk/ForgeBoss","controlRevision":req["controlRevision"],
                     "requestDigest":req["requestDigest"],"resultDigest":canonical_digest(result),"servicePrincipal":"service"}
            return __import__("forgeboss.protected_authority.protocol",fromlist=["canonical_json"]).canonical_json({**self.signer.sign(receipt),"result":result})
        with self.assertRaises(AuthorityError) as cm:
            self.client(bad).authorize_self_build_launch(self.launch())
        self.assertEqual(cm.exception.code,"SERVICE_RECEIPT_BINDING_MISMATCH")

    def test_controller_self_signed_launch_path_is_disabled(self):
        with self.assertRaises(AuthorityError) as cm:
            self.client().attest_launch_payload(self.launch())
        self.assertEqual(cm.exception.code,"LEGACY_SELF_SIGNED_LAUNCH_DISABLED")

    def test_windows_exchange_source_has_bounded_listener_turnover_retry(self):
        import inspect
        from forgeboss.protected_authority import client as client_module
        source=inspect.getsource(client_module.ProtectedAuthorityClient._exchange_windows)
        self.assertIn("deadline=time.monotonic()+self.timeout",source)
        self.assertIn("while True:",source)
        self.assertIn("WaitNamedPipeW",source)
        self.assertIn("CreateFileW",source)
        self.assertIn("time.sleep",source)
        self.assertIn('raise AuthorityError("IPC_CONNECT_FAILED")',source)

    def test_from_environment_binds_versioned_pipe_name(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);keyfile=root/"peer.key";pinfile=root/"receipt.pub"
            raw=self.peer.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
            keyfile.write_bytes(raw);pinfile.write_text(self.pin,encoding="ascii")
            pipe=r"\\.\pipe\ForgeBossAuthorityStage1-v28"
            env={
                "FORGEBOSS_AUTHORITY_PEER_KEY":str(keyfile),
                "FORGEBOSS_AUTHORITY_RECEIPT_PUBLIC_KEY":str(pinfile),
                "FORGEBOSS_AUTHORITY_PEER_ID":"controller-a",
                "FORGEBOSS_CONTROL_REVISION":"1",
                "FORGEBOSS_AUTHORITY_PIPE_NAME":pipe,
                # Non-Windows also needs its Unix endpoint; Windows ignores it.
                # Do not monkeypatch os.name here because pathlib selects its
                # concrete path class from that global value.
                "FORGEBOSS_AUTHORITY_ENDPOINT_DIR":str(root),
            }
            client=ProtectedAuthorityClient.from_environment(env)
            self.assertEqual(client.pipe_name,pipe)

    def test_from_files_loads_raw_ed25519_key_and_pin(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);keyfile=root/"peer.key";pinfile=root/"receipt.pub"
            raw=self.peer.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
            keyfile.write_bytes(raw);pinfile.write_text(self.pin,encoding="ascii")
            c=ProtectedAuthorityClient.from_files(peer_id="controller-a",repository="1stchoicefnq-afk/ForgeBoss",control_revision=1,
                                                  peer_private_key_file=str(keyfile),receipt_public_key_file=str(pinfile))
            self.assertEqual(c.peer_id,"controller-a")


if __name__=="__main__":unittest.main()
