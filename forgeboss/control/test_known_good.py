from __future__ import annotations

import hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from forgeboss.control.known_good import IdentityError,runtime_identity_from_env,verify_build_manifest

def _sha(path:Path):return hashlib.sha256(path.read_bytes()).hexdigest()
def _tree(files):return hashlib.sha256(json.dumps([[k,files[k]] for k in sorted(files)],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
def _git(root,*args,binary=False):return subprocess.check_output(["git","-C",str(root),*args],text=not binary)
def _blob_hashes(root,revision):
    raw=_git(root,"ls-tree","-r","-z","--full-tree",revision,"--","forgeboss",binary=True);out={}
    for rec in raw.split(b"\0"):
        if not rec:continue
        meta,name=rec.split(b"\t",1);_,typ,oid=meta.decode().split(" ")
        if typ!="blob":continue
        rel=name.decode();blob=_git(root,"cat-file","blob",oid,binary=True);out[rel]=hashlib.sha256(blob).hexdigest()
    return out

class KnownGoodIdentityTests(unittest.TestCase):
    def _fixture(self,binary=False,attrs=None):
        td=tempfile.TemporaryDirectory();root=Path(td.name)/"root";pkg=root/"forgeboss";pkg.mkdir(parents=True)
        (pkg/"daemon.py").write_bytes(b"print('ok')\n")
        (pkg/"helper.py").write_bytes(b"A\x00B\r\nC\x00D\r\n" if binary else b"VALUE=1\n")
        if attrs is not None:(root/".gitattributes").write_text(attrs,encoding="utf-8")
        subprocess.run(["git","init",str(root)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["git","-C",str(root),"config","user.email","test@example.invalid"],check=True);subprocess.run(["git","-C",str(root),"config","user.name","ForgeBoss Test"],check=True)
        subprocess.run(["git","-C",str(root),"add","."],check=True);subprocess.run(["git","-C",str(root),"commit","-m","fixture"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        revision=_git(root,"rev-parse","HEAD").strip();files=_blob_hashes(root,revision)
        manifest=Path(td.name)/"manifest.json";manifest.write_text(json.dumps({"schema":1,"inventoryMode":"forgeboss-package-v2-git-bound","revision":revision,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","treeSha256":_tree(files),"files":files},sort_keys=True),encoding="utf-8")
        return td,root,manifest,revision
    def test_manifest_is_bound_to_real_git_head_and_complete_tree(self):
        td,root,manifest,revision=self._fixture()
        try:
            r=verify_build_manifest(manifest,root,revision,_sha(manifest));self.assertTrue(r["verified"]);self.assertEqual(r["fileCount"],2)
        finally:td.cleanup()
    def test_real_content_mutation_rejected_even_if_manifest_rewritten(self):
        td,root,manifest,revision=self._fixture()
        try:
            (root/"forgeboss/helper.py").write_text("VALUE=999\n",encoding="utf-8")
            with self.assertRaisesRegex(IdentityError,"content does not match"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()
    def test_untracked_module_fails_closed(self):
        td,root,manifest,revision=self._fixture()
        try:
            (root/"forgeboss/evil.py").write_text("PWN=1\n")
            with self.assertRaisesRegex(IdentityError,"file set"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()
    def test_autocrlf_crlf_materialization_is_accepted(self):
        if os.name=="nt":pass
        td,root,manifest,revision=self._fixture()
        try:
            subprocess.run(["git","-C",str(root),"config","core.autocrlf","true"],check=True)
            p=root/"forgeboss/helper.py";p.write_bytes(b"VALUE=1\r\n")
            r=verify_build_manifest(manifest,root,revision);self.assertTrue(r["verified"]);self.assertEqual(r["files"]["forgeboss/helper.py"],_blob_hashes(root,revision)["forgeboss/helper.py"])
        finally:td.cleanup()
    def test_autocrlf_real_mutation_still_rejected(self):
        td,root,manifest,revision=self._fixture()
        try:
            subprocess.run(["git","-C",str(root),"config","core.autocrlf","true"],check=True);(root/"forgeboss/helper.py").write_bytes(b"VALUE=2\r\n")
            with self.assertRaisesRegex(IdentityError,"content does not match"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()
    def test_binary_crlf_like_bytes_are_not_text_normalized(self):
        td,root,manifest,revision=self._fixture(binary=True)
        try:
            subprocess.run(["git","-C",str(root),"config","core.autocrlf","true"],check=True);p=root/"forgeboss/helper.py";p.write_bytes(p.read_bytes().replace(b"\r\n",b"\n"))
            with self.assertRaisesRegex(IdentityError,"content does not match"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()
    def test_explicit_minus_text_policy_respected(self):
        td,root,manifest,revision=self._fixture(attrs="forgeboss/helper.py -text\n")
        try:
            subprocess.run(["git","-C",str(root),"config","core.autocrlf","true"],check=True);self.assertTrue(verify_build_manifest(manifest,root,revision)["verified"])
            p=root/"forgeboss/helper.py";p.write_bytes(p.read_bytes().replace(b"\n",b"\r\n"))
            with self.assertRaises(IdentityError):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()
    def test_repository_controlled_filter_attribute_fails_closed_without_execution(self):
        td,root,manifest,revision=self._fixture(attrs="forgeboss/helper.py filter=evil\n")
        try:
            marker=Path(td.name)/"marker";subprocess.run(["git","-C",str(root),"config","filter.evil.clean",f"sh -c 'echo pwn > {marker}; cat'"],check=True)
            with self.assertRaisesRegex(IdentityError,"filters are unsupported"):verify_build_manifest(manifest,root,revision)
            self.assertFalse(marker.exists())
        finally:td.cleanup()
    def test_declared_revision_must_equal_checkout_head(self):
        td,root,manifest,revision=self._fixture()
        try:
            v=json.loads(manifest.read_text());v["revision"]="a"*40;manifest.write_text(json.dumps(v,sort_keys=True))
            with self.assertRaisesRegex(IdentityError,"checkout HEAD"):verify_build_manifest(manifest,root)
        finally:td.cleanup()
    def test_self_build_requires_verified_expected_identity(self):
        td,root,manifest,revision=self._fixture()
        try:
            env={"FORGEBOSS_SELF_BUILD_MODE":"YES","FORGEBOSS_BUILD_MANIFEST":str(manifest),"FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA":revision,"FORGEBOSS_EXPECTED_MANIFEST_SHA256":_sha(manifest)}
            with patch.dict(os.environ,env,clear=True):self.assertEqual(runtime_identity_from_env(root)["revision"],revision)
        finally:td.cleanup()

if __name__=="__main__":unittest.main()
