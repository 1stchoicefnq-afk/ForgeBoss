from __future__ import annotations
import base64
import copy
import math
import os
import tempfile
import unittest
from pathlib import Path
from forgeboss.control.authority import (
    AUTHORITY_VERSION, PROTOCOL_VERSION, AuthorityKey, ControllerAuthoritySignerClient,
    ControllerAuthorityVerifier, PinnedAuthorityTrust, load_pinned_trust,
    validate_authority, write_pinned_trust,
)
from forgeboss.control.envelope import canonical
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception:
    Ed25519PrivateKey=None

def sample(key_id="k1",branch=True,worktree="C:/work/one"):
    a={"authorityVersion":AUTHORITY_VERSION,"protocolVersion":PROTOCOL_VERSION,"algorithm":"ed25519","keyId":key_id,"purpose":"worker-launch","authorityId":"a1","assignmentId":"as1","assignmentSha256":"1"*64,"builderId":"worker-a","taskId":"t1","runId":"r1","ownerEpoch":1,"attempt":1,"repository":"owner/repo","baseSha":"a"*40,"currentHead":"b"*40,"worktreePath":worktree,"runtime":{"adapter":"mini-swe","provider":"openai","model":"gpt-5.6"},"allowedPaths":["src/a.py"],"deniedPaths":["secrets"],"allowedTools":["python"],"contextBundleHash":"c"*64,"budgetUsd":1.0,"issuedAt":100.0,"expiresAt":200.0,"controllerKnownGood":{"revision":"d"*40,"manifestSha256":"e"*64,"identitySha256":"f"*64},"reviewPolicy":{"independentReviewRequired":True,"authorMayReview":False,"reviewerId":"worker-b"}}
    if branch:a["branch"]="forgeboss/task-1"
    return a

def key(kid="k1",activation=90.0,retirement=None,cutoff=180.0,byte=b"k"):
    return AuthorityKey(kid,base64.b64encode(byte*32).decode(),activation,retirement,cutoff)

class SchemaTests(unittest.TestCase):
    def test_branch_optional_and_null_rejected(self):
        self.assertNotIn("branch",validate_authority(sample(branch=False)))
        a=sample();a["branch"]=None
        with self.assertRaises(ValueError):validate_authority(a)
    def test_branch_matches_git_and_windows_component_rules(self):
        a=sample();a["branch"]="@";self.assertEqual(validate_authority(a)["branch"],"@")
        for bad in ("-topic","topic/.hidden","topic.lock/child","topic.LOCK/child","topic/child.LoCk","topic/.hidden/child","topic/child.lock/grandchild"):
            a=sample();a["branch"]=bad
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate_authority(a)
    def test_known_good_revision_is_git_sha_not_integer(self):
        validate_authority(sample());a=sample();a["controllerKnownGood"]["revision"]=1
        with self.assertRaises(ValueError):validate_authority(a)
    def test_repo_must_be_canonical(self):
        for bad in ("Owner/Repo","owner\\repo","https://x/y"):
            a=sample();a["repository"]=bad
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate_authority(a)
    def test_assignment_builder_head_bound(self):
        for field,bad in (("assignmentSha256","x"*64),("builderId",""),("currentHead","A"*40)):
            a=sample();a[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):validate_authority(a)
    def test_scope_hostile_windows_forms(self):
        for bad in ("C:/src/a.py","/src/a.py","//server/share/a.py","src\\a.py","src/a.py.","src/a.py ","src/a.py:ads","NUL.txt","COM¹","COM².txt","LPT³.log","CONIN$","conout$","ConOut$","src//a.py","src/../a.py"):
            a=sample();a["allowedPaths"]=[bad]
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate_authority(a)
        a=sample();a["allowedPaths"]=["src/a.py"];a["deniedPaths"]=["SRC"]
        with self.assertRaises(ValueError):validate_authority(a)
    def test_worktree_lexical_root_bound(self):
        validate_authority(sample(),worktree_root="C:/work")
        for bad in ("relative/work","c:/work/one","C:\\work\\one","C:/work/../one","C:/work/one.","C:/work/COM¹","C:/work/LPT².txt","C:/work/CONIN$","C:/work/conout$"):
            a=sample();a["worktreePath"]=bad
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate_authority(a,worktree_root="C:/work")
        with self.assertRaises(ValueError):validate_authority(sample(),worktree_root="C:/other")
    def test_nonfinite_and_independence(self):
        for field,bad in (("budgetUsd",math.nan),("issuedAt",math.inf),("expiresAt",math.nan)):
            a=sample();a[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):validate_authority(a)
        a=sample();a["reviewPolicy"]["reviewerId"]="WORKER-A"
        with self.assertRaises(ValueError):validate_authority(a)

class TrustTests(unittest.TestCase):
    def test_rotation_and_generation(self):
        cur=key("k1",90,150,180,b"a");nxt=key("k2",160,None,300,b"b");t=PinnedAuthorityTrust(3,(cur,nxt),"k1","k2",minimum_generation=3)
        self.assertEqual(t.key_for("k1",170).key_id,"k1")
        with self.assertRaises(PermissionError):t.key_for("k1",180)
        with self.assertRaises(ValueError):PinnedAuthorityTrust(3,(cur,key("k2",181,None,300,b"b")),"k1","k2")
        with self.assertRaises(PermissionError):PinnedAuthorityTrust(2,(cur,),"k1",minimum_generation=3)
    def test_durable_serialized_monotonic_updates(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"trust.json";t3=PinnedAuthorityTrust(3,(key(byte=b"a"),),"k1",minimum_generation=3);write_pinned_trust(p,t3);before=p.read_bytes()
            lower=PinnedAuthorityTrust(2,(key(byte=b"a"),),"k1",minimum_generation=1)
            with self.assertRaises(PermissionError):write_pinned_trust(p,lower)
            self.assertEqual(before,p.read_bytes());self.assertEqual(write_pinned_trust(p,t3),p)
            changed=PinnedAuthorityTrust(3,(key(byte=b"b"),),"k1",minimum_generation=1)
            with self.assertRaises(PermissionError):write_pinned_trust(p,changed)
            t4=PinnedAuthorityTrust(4,(key(byte=b"b"),),"k1",minimum_generation=4);lock=p.parent/f".{p.name}.update.lock";lock.write_text("other\n")
            with self.assertRaises(RuntimeError):write_pinned_trust(p,t4)
            self.assertEqual(before,p.read_bytes());lock.unlink();write_pinned_trust(p,t4);self.assertEqual(load_pinned_trust(p,4).generation,4)

@unittest.skipIf(Ed25519PrivateKey is None,"cryptography unavailable")
class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name).resolve();self.root=(root/"work");self.root.mkdir();self.work=self.root/"one";self.work.mkdir();self.alt=self.root/"two";self.alt.mkdir()
        self.private=Ed25519PrivateKey.generate();pub=self.private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.trust=PinnedAuthorityTrust(2,(AuthorityKey("k1",base64.b64encode(pub).decode(),90,150,180),),"k1",minimum_generation=2)
    def authority(self,branch=True):return sample(branch=branch,worktree=self.work.as_posix())
    def packet(self,a,private=None):
        private=private or self.private
        return {"authority":copy.deepcopy(a),"signature":"ed25519:"+base64.b64encode(private.sign(canonical(a))).decode()}
    def verifier(self,trust=None):return ControllerAuthorityVerifier(trust or self.trust,self.root.as_posix())
    def signer(self,transport):return ControllerAuthoritySignerClient(transport,"controller-1",self.root.as_posix())

    def test_protected_verifier_requires_root_and_existing_plain_worktree(self):
        with self.assertRaises((ValueError,TypeError)):ControllerAuthorityVerifier(self.trust,None)
        a=self.authority();self.assertEqual(self.verifier().verify(self.packet(a),110)["currentHead"],"b"*40)
        outside=Path(self.tmp.name)/"outside";outside.mkdir();a=self.authority();a["worktreePath"]=outside.as_posix()
        with self.assertRaises(ValueError):self.verifier().verify(self.packet(a),110)
    def test_linklike_worktree_denied(self):
        external=Path(self.tmp.name)/"external";external.mkdir();link=self.root/"link"
        try:os.symlink(external,link,target_is_directory=True)
        except (OSError,NotImplementedError):self.skipTest("symlink creation unavailable")
        a=self.authority();a["worktreePath"]=link.as_posix()
        with self.assertRaises(ValueError):self.verifier().verify(self.packet(a),110)

    def test_every_signed_authority_field_mutation_is_rejected(self):
        base=self.authority()
        mutations={
            "authorityVersion":2,"protocolVersion":2,"algorithm":"ed25519-v2","keyId":"k2","purpose":"other-purpose",
            "authorityId":"a2","assignmentId":"as2","assignmentSha256":"2"*64,"builderId":"worker-c","taskId":"t2","runId":"r2",
            "ownerEpoch":2,"attempt":2,"repository":"owner/repo2","baseSha":"c"*40,"currentHead":"c"*40,
            "worktreePath":self.alt.as_posix(),"runtime":{"adapter":"mini-swe","provider":"openai","model":"gpt-5.7"},
            "allowedPaths":["src/b.py"],"deniedPaths":["private"],"allowedTools":["git"],"contextBundleHash":"d"*64,
            "budgetUsd":2.0,"issuedAt":101.0,"expiresAt":199.0,
            "controllerKnownGood":{"revision":"e"*40,"manifestSha256":"a"*64,"identitySha256":"b"*64},
            "reviewPolicy":{"independentReviewRequired":True,"authorMayReview":False,"reviewerId":"worker-c"},
            "branch":"forgeboss/task-2",
        }
        original=self.packet(base)
        for field,value in mutations.items():
            p=copy.deepcopy(original);p["authority"][field]=value
            with self.subTest(field=field),self.assertRaises((PermissionError,ValueError)):
                self.verifier().verify(p,110)

    def test_wrong_key_unknown_key_and_unsupported_domain_rejected(self):
        a=self.authority();other=Ed25519PrivateKey.generate()
        with self.assertRaises(PermissionError):self.verifier().verify(self.packet(a,other),110)
        unknown=copy.deepcopy(a);unknown["keyId"]="k2"
        with self.assertRaises(PermissionError):self.verifier().verify(self.packet(unknown),110)
        for field,value in (("algorithm","rsa"),("authorityVersion",2),("protocolVersion",2),("purpose","arbitrary")):
            bad=copy.deepcopy(a);bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.verifier().verify(self.packet(bad),110)

    def test_time_boundaries_and_legacy_client_signatures_rejected(self):
        a=self.authority();p=self.packet(a)
        with self.assertRaises(PermissionError):self.verifier().verify(p,99)
        with self.assertRaises(PermissionError):self.verifier().verify(p,200)
        p=self.packet(a);p["signature"]="hmac-sha256:"+"0"*64
        with self.assertRaises(PermissionError):self.verifier().verify(p,110)
        p=self.packet(a);p["signature"]="client-hmac-sha256:"+"0"*64
        with self.assertRaises(PermissionError):self.verifier().verify(p,110)

    def test_request_supplied_trust_and_malformed_signature_rejected(self):
        a=self.authority();p=self.packet(a);p["trust"]={"keyId":"attacker"}
        with self.assertRaises(ValueError):self.verifier().verify(p,110)
        p=self.packet(a);p["signature"]="ed25519:not-base64!"
        with self.assertRaises(PermissionError):self.verifier().verify(p,110)

    def test_signer_is_narrow_unavailable_and_nested_mutation_fails_closed(self):
        a=self.authority()
        self.assertFalse(hasattr(ControllerAuthoritySignerClient,"sign_bytes"))
        def unavailable(_request):raise ConnectionError("signer unavailable")
        with self.assertRaises(ConnectionError):self.signer(unavailable).sign_worker_launch(a)
        bad=copy.deepcopy(a);bad["purpose"]="arbitrary"
        called=[]
        with self.assertRaises(ValueError):self.signer(lambda r:called.append(r)).sign_worker_launch(bad)
        self.assertEqual(called,[])
        def mutate(req):
            req["authority"]["runtime"]["model"]="evil"
            return {"authority":req["authority"],"signature":"ed25519:x"}
        with self.assertRaises(PermissionError):self.signer(mutate).sign_worker_launch(a)
        self.assertEqual(a["runtime"]["model"],"gpt-5.6")

    def test_signer_request_binds_controller_identity_and_exact_authority(self):
        a=self.authority();seen={}
        def transport(req):
            seen.update(copy.deepcopy(req));auth=req["authority"]
            return {"authority":auth,"signature":"ed25519:"+base64.b64encode(self.private.sign(canonical(auth))).decode()}
        out=self.signer(transport).sign_worker_launch(a)
        self.assertEqual(seen["type"],"sign-worker-launch")
        self.assertEqual(seen["controllerIdentity"],"controller-1")
        self.assertEqual(out["authority"],a)

if __name__=="__main__":unittest.main()
