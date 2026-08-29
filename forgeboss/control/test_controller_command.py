from __future__ import annotations
import base64,copy,time,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from forgeboss.control.controller_command import *
import forgeboss.control.controller_command as cc

def fixture(method='worker.revoke',payload=None,gen=3):
    sk=Ed25519PrivateKey.generate();pk=sk.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    key=ControllerKey('controller-1','ctl-key',base64.b64encode(pk).decode(),gen,100,1000);trust=CommandTrust(gen,(key,))
    payload={'taskId':'task-1','runId':'run-1','ownerEpoch':2} if payload is None else payload
    rec={'domain':DOMAIN,'version':1,'commandId':'cmd-1','method':method,'controllerId':'controller-1','keyId':'ctl-key','generation':gen,
         'issuedAt':200,'expiresAt':230,'nonce':'a'*32,'payloadSha256':payload_digest(payload),'payload':payload}
    rec['signature']=base64.b64encode(sk.sign(cc._strict_json(rec))).decode();return sk,trust,rec

class Tests(unittest.TestCase):
    def test_valid_exact_command(self):
        _,t,r=fixture();v=verify_controller_command(r,t,nonce_ledger=NonceLedger(),now=210);self.assertEqual(v.method,'worker.revoke')
    def test_every_signed_field_tamper_fails(self):
        _,t,r=fixture()
        mutations={'commandId':'cmd-x','method':'worker.reassign','controllerId':'other','keyId':'other','generation':4,'issuedAt':201,'expiresAt':229,'nonce':'b'*32,'payloadSha256':'0'*64}
        for k,v in mutations.items():
            x=copy.deepcopy(r);x[k]=v
            with self.subTest(k=k),self.assertRaises(Exception):verify_controller_command(x,t,nonce_ledger=NonceLedger(),now=210)
        x=copy.deepcopy(r);x['payload']['ownerEpoch']=3
        with self.assertRaises(Exception):verify_controller_command(x,t,nonce_ledger=NonceLedger(),now=210)
    def test_unknown_method_fails_even_if_signed(self):
        sk,t,r=fixture();r['method']='shell.exec';r['signature']=base64.b64encode(sk.sign(cc._strict_json({k:v for k,v in r.items() if k!='signature'}))).decode()
        with self.assertRaises(PermissionError):verify_controller_command(r,t,nonce_ledger=NonceLedger(),now=210)
    def test_replay_denied(self):
        _,t,r=fixture();n=NonceLedger();verify_controller_command(r,t,nonce_ledger=n,now=210)
        with self.assertRaises(PermissionError):verify_controller_command(r,t,nonce_ledger=n,now=210)
    def test_generation_downgrade_fails(self):
        _,t,r=fixture(gen=3);x=copy.deepcopy(r);x['generation']=2
        with self.assertRaises(PermissionError):verify_controller_command(x,t,nonce_ledger=NonceLedger(),now=210)
    def test_expiry_and_lifetime_fail(self):
        _,t,r=fixture()
        with self.assertRaises(PermissionError):verify_controller_command(r,t,nonce_ledger=NonceLedger(),now=231)
        x=copy.deepcopy(r);x['expiresAt']=500
        with self.assertRaises(Exception):verify_controller_command(x,t,nonce_ledger=NonceLedger(),now=210)
    def test_duplicate_or_extra_fields_fail(self):
        _,t,r=fixture();x=copy.deepcopy(r);x['extra']=1
        with self.assertRaises(ControllerCommandError):verify_controller_command(x,t,nonce_ledger=NonceLedger(),now=210)
    def test_payload_noncanonical_float_rejected(self):
        with self.assertRaises(ControllerCommandError):payload_digest({'x':1.25})
    def test_resigned_controller_impersonation_fails(self):
        sk,t,r=fixture();r['controllerId']='controller-evil';r['signature']=base64.b64encode(sk.sign(cc._strict_json({k:v for k,v in r.items() if k!='signature'}))).decode()
        with self.assertRaises(PermissionError):verify_controller_command(r,t,nonce_ledger=NonceLedger(),now=210)
    def test_wrong_key_fails(self):
        _,t,r=fixture();sk2=Ed25519PrivateKey.generate();x=copy.deepcopy(r);x['signature']=base64.b64encode(sk2.sign(cc._strict_json({k:v for k,v in x.items() if k!='signature'}))).decode()
        with self.assertRaises(PermissionError):verify_controller_command(x,t,nonce_ledger=NonceLedger(),now=210)

if __name__=='__main__':unittest.main()
