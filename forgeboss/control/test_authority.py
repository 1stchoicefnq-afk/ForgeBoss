from __future__ import annotations
import base64
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
    def test_branch_matches_git_component_rules(self):
        a=sample();a["branch"]="@";self.assertEqual(validate_authority(a)["branch"],"@")
        for bad in ("topic/.hidden","topic.lock/child","topic/.hidden/child","topic/child.lock/grandchild"):
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
        for bad in ("C:/src/a.py","/src/a.py","//server/share/a.py","src\\a.py","src/a.py.","src/a.py ","src/a.py:ads","NUL.txt","src//a.py","src/../a.py"):
            a=sample();a["allowedPaths"]=[bad]
            with self.subTest(bad=bad),self.assertRaises(ValueError):validate_authority(a)
        a=sample();a["allowedPaths"]=["src/a.py"];a["deniedPaths"]=["SRC"]
        with self.assertRaises(ValueError):validate_authority(a)
    def test_worktree_lexical_root_bound(self):
        validate_authority(sample(),worktree_root="C:/work")
        for bad in ("relative/work","c:/work/one","C:\\work\\one","C:/work/../one","C:/work/one."):
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
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=Path(self.tmp.name).resolve();self.root=root.as_posix();self.work=(root/"work");self.work.mkdir();self.work=(self.work/"one");self.work.mkdir();self.work_path=self.work.as_posix()
        self.private=Ed25519PrivateKey.generate();pub=self.private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.trust=PinnedAuthorityTrust(2,(AuthorityKey("k1",base64.b64encode(pub).decode(),90,150,180),),"k1",minimum_generation=2)
    def packet(self,a):return {"authority":a,"signature":"ed25519:"+base64.b64encode(self.private.sign(canonical(a))).decode()}
    def verifier(self):return ControllerAuthorityVerifier(self.trust,(Path(self.tmp.name)/"work").as_posix())
    def test_protected_verifier_requires_root_and_existing_plain_worktree(self):
        with self.assertRaises((ValueError,TypeError)):ControllerAuthorityVerifier(self.trust,None)
        a=sample(worktree=self.work_path);self.assertEqual(self.verifier().verify(self.packet(a),110)["currentHead"],"b"*40)
        a=sample(worktree=(Path(self.tmp.name)/"outside").as_posix());Path(a["worktreePath"]).mkdir()
        with self.assertRaises(ValueError):self.verifier().verify(self.packet(a),110)
    def test_linklike_worktree_denied(self):
        external=Path(self.tmp.name)/"external";external.mkdir();link=Path(self.tmp.name)/"work"/"link"
        try:os.symlink(external,link,target_is_directory=True)
        except (OSError,NotImplementedError):self.skipTest("symlink creation unavailable")
        a=sample(worktree=link.as_posix())
        with self.assertRaises(ValueError):self.verifier().verify(self.packet(a),110)
    def test_valid_tamper_and_legacy(self):
        a=sample(worktree=self.work_path);v=self.verifier();self.assertEqual(v.verify(self.packet(a),110)["currentHead"],"b"*40)
        for field,value in (("attempt",2),("currentHead","c"*40),("builderId","worker-c"),("assignmentSha256","2"*64)):
            p=self.packet(a);p["authority"]=dict(a);p["authority"][field]=value
            with self.subTest(field=field),self.assertRaises(PermissionError):v.verify(p,110)
        p=self.packet(a);p["signature"]="hmac-sha256:"+"0"*64
        with self.assertRaises(PermissionError):v.verify(p,110)
    def test_branchless_and_signer_mutation(self):
        a=sample(branch=False,worktree=self.work_path);self.assertNotIn("branch",self.verifier().verify(self.packet(a),110))
        def mutate(req):req["authority"]["runtime"]["model"]="evil";return {"authority":req["authority"],"signature":"ed25519:x"}
        with self.assertRaises(PermissionError):ControllerAuthoritySignerClient(mutate,"controller-1",(Path(self.tmp.name)/"work").as_posix()).sign_worker_launch(a)

if __name__=="__main__":unittest.main()
