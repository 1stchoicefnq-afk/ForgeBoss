from __future__ import annotations
import base64,copy,time,unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from forgeboss.control.authority import (AUTHORITY_ALGORITHM,AUTHORITY_PURPOSE,AUTHORITY_VERSION,AuthorityError,
    PinnedAuthorityTrust,WorkerLaunchSignerClient,validate_unsigned_authority,verify_protected_authority)
from forgeboss.control.auth import derive_client_auth_key,make_connect_proof
from forgeboss.control.envelope import canonical

NOW=2000000000.0

def authority():
    return {"authorityId":"auth-1","assignmentId":"assign-1","taskId":"task-1","runId":"run-1","ownerEpoch":2,
      "repository":"1stchoicefnq-afk/ForgeBoss","baseSha":"a"*40,"branch":"forgeboss/task-1","worktreePath":"C:/ForgeBoss/worktrees/task-1",
      "runtime":{"adapter":"mini-swe","provider":"openai","model":"gpt-5"},"allowedPaths":["src/a.py"],"deniedPaths":["state/"],
      "allowedTools":["git","python"],"contextBundleHash":"b"*64,"budgetUsd":1.25,"issuedAt":NOW-1,"expiresAt":NOW+60,
      "controllerKnownGood":"c"*40}

def pub_raw(private):return private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
def signed(private,key_id="k1",auth=None):
    doc={"authorityVersion":AUTHORITY_VERSION,"algorithm":AUTHORITY_ALGORITHM,"keyId":key_id,"purpose":AUTHORITY_PURPOSE,"authority":auth or authority()}
    sig=private.sign(canonical(doc));doc["signature"]="ed25519:"+base64.urlsafe_b64encode(sig).decode().rstrip("=");return doc

class ProtectedAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.key=Ed25519PrivateKey.generate();self.other=Ed25519PrivateKey.generate();self.trust=PinnedAuthorityTrust(3,{"k1":pub_raw(self.key)})
    def test_valid_and_tamper_wrong_key_and_key_id(self):
        doc=signed(self.key);self.assertEqual(verify_protected_authority(doc,self.trust,now=NOW)["taskId"],"task-1")
        bad=copy.deepcopy(doc);bad["authority"]["budgetUsd"]=1.5
        with self.assertRaises(AuthorityError):verify_protected_authority(bad,self.trust,now=NOW)
        with self.assertRaises(AuthorityError):verify_protected_authority(signed(self.other),self.trust,now=NOW)
        wrong=signed(self.key,"unknown")
        with self.assertRaisesRegex(AuthorityError,"keyId"):verify_protected_authority(wrong,self.trust,now=NOW)
    def test_expiry_not_yet_valid_unknown_purpose_and_legacy_hmac_rejected(self):
        expired=authority();expired["issuedAt"]=NOW-100;expired["expiresAt"]=NOW-1
        with self.assertRaisesRegex(AuthorityError,"expired"):verify_protected_authority(signed(self.key,auth=expired),self.trust,now=NOW)
        future=authority();future["issuedAt"]=NOW+20;future["expiresAt"]=NOW+80
        with self.assertRaisesRegex(AuthorityError,"not yet"):verify_protected_authority(signed(self.key,auth=future),self.trust,now=NOW)
        purpose=signed(self.key);purpose["purpose"]="admin"
        with self.assertRaisesRegex(AuthorityError,"purpose"):verify_protected_authority(purpose,self.trust,now=NOW)
        legacy=signed(self.key);legacy["signature"]="hmac-sha256:"+"0"*64
        with self.assertRaisesRegex(AuthorityError,"ed25519"):verify_protected_authority(legacy,self.trust,now=NOW)
    def test_schema_paths_budget_and_request_supplied_trust_fail_closed(self):
        a=authority();a["allowedPaths"]=["SRC/a.py","src/A.py"]
        with self.assertRaisesRegex(AuthorityError,"duplicate"):validate_unsigned_authority(a,now=NOW)
        a=authority();a["budgetUsd"]=float("nan")
        with self.assertRaisesRegex(AuthorityError,"finite"):validate_unsigned_authority(a,now=NOW)
        doc=signed(self.key);doc["trust"]={"k1":"attacker"}
        with self.assertRaisesRegex(AuthorityError,"unexpected"):verify_protected_authority(doc,self.trust,now=NOW)
    def test_rotation_generation_is_pinned(self):
        doc=signed(self.key)
        self.assertEqual(verify_protected_authority(doc,self.trust,now=NOW,required_generation=3)["runId"],"run-1")
        with self.assertRaisesRegex(AuthorityError,"generation"):verify_protected_authority(doc,self.trust,now=NOW,required_generation=4)
    def test_signer_client_is_narrow_and_cannot_change_authority(self):
        seen=[]
        def transport(req):
            seen.append(req);self.assertEqual(req["operation"],"sign-worker-launch");self.assertEqual(req["purpose"],AUTHORITY_PURPOSE)
            return signed(self.key,auth=req["authority"])
        client=WorkerLaunchSignerClient(transport,self.trust,required_generation=3)
        out=client.request_worker_launch(authority(),now=NOW);self.assertEqual(out["keyId"],"k1");self.assertEqual(len(seen),1)
        def mutating(req):
            changed=copy.deepcopy(req["authority"]);changed["taskId"]="other";return signed(self.key,auth=changed)
        with self.assertRaisesRegex(AuthorityError,"changed"):WorkerLaunchSignerClient(mutating,self.trust).request_worker_launch(authority(),now=NOW)
    def test_client_auth_domain_is_not_protected_launch_signature(self):
        root=b"r"*32;derived=derive_client_auth_key(root);self.assertNotEqual(root,derived)
        p={"protocolVersion":1,"client":"test","capabilities":[],"timestamp":int(NOW),"nonce":"n"*32}
        proof=make_connect_proof(p,root);self.assertTrue(proof.startswith("hmac-sha256:"))
        doc=signed(self.key);doc["signature"]=proof
        with self.assertRaises(AuthorityError):verify_protected_authority(doc,self.trust,now=NOW)

if __name__=="__main__":unittest.main()
