from __future__ import annotations

import base64, tempfile, unittest
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

    def test_from_files_loads_raw_ed25519_key_and_pin(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);keyfile=root/"peer.key";pinfile=root/"receipt.pub"
            raw=self.peer.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
            keyfile.write_bytes(raw);pinfile.write_text(self.pin,encoding="ascii")
            c=ProtectedAuthorityClient.from_files(peer_id="controller-a",repository="1stchoicefnq-afk/ForgeBoss",control_revision=1,
                                                  peer_private_key_file=str(keyfile),receipt_public_key_file=str(pinfile))
            self.assertEqual(c.peer_id,"controller-a")


if __name__=="__main__":unittest.main()
