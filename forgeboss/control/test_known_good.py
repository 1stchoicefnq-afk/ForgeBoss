from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeboss.control.known_good import IdentityError, runtime_identity_from_env, verify_build_manifest


def _sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree(files):
    raw=json.dumps([[k,files[k]] for k in sorted(files)],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


class KnownGoodIdentityTests(unittest.TestCase):
    def _fixture(self):
        td=tempfile.TemporaryDirectory();root=Path(td.name)/"root";pkg=root/"forgeboss";pkg.mkdir(parents=True)
        (pkg/"daemon.py").write_bytes(b"print('ok')\n");(pkg/"helper.py").write_bytes(b"VALUE=1\n")
        subprocess.run(["git","init",str(root)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["git","-C",str(root),"config","user.email","test@example.invalid"],check=True)
        subprocess.run(["git","-C",str(root),"config","user.name","ForgeBoss Test"],check=True)
        subprocess.run(["git","-C",str(root),"add","forgeboss"],check=True)
        subprocess.run(["git","-C",str(root),"commit","-m","fixture"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        revision=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
        files={"forgeboss/daemon.py":_sha(pkg/"daemon.py"),"forgeboss/helper.py":_sha(pkg/"helper.py")}
        manifest=Path(td.name)/"manifest.json";manifest.write_text(json.dumps({"schema":1,"inventoryMode":"forgeboss-package-v2-git-bound","revision":revision,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","treeSha256":_tree(files),"files":files},sort_keys=True),encoding="utf-8")
        return td,root,manifest,revision

    def test_manifest_is_bound_to_real_git_head_and_complete_tree(self):
        td,root,manifest,revision=self._fixture()
        try:
            result=verify_build_manifest(manifest,root,revision,_sha(manifest));self.assertTrue(result["verified"]);self.assertEqual(result["revision"],revision);self.assertEqual(result["fileCount"],2)
        finally:td.cleanup()

    def test_forged_manifest_cannot_relabel_modified_checkout_as_known_good(self):
        td,root,manifest,revision=self._fixture()
        try:
            target=root/"forgeboss"/"helper.py";target.write_text("VALUE=999\n",encoding="utf-8")
            value=json.loads(manifest.read_text());value["files"]["forgeboss/helper.py"]=_sha(target);value["treeSha256"]=_tree(value["files"]);manifest.write_text(json.dumps(value,sort_keys=True),encoding="utf-8")
            with self.assertRaisesRegex(IdentityError,"declared git revision"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()

    def test_untracked_executable_module_fails_closed_even_if_manifest_rewritten(self):
        td,root,manifest,revision=self._fixture()
        try:
            extra=root/"forgeboss"/"evil.py";extra.write_text("PWN=1\n",encoding="utf-8")
            value=json.loads(manifest.read_text());value["files"]["forgeboss/evil.py"]=_sha(extra);value["treeSha256"]=_tree(value["files"]);manifest.write_text(json.dumps(value,sort_keys=True),encoding="utf-8")
            with self.assertRaisesRegex(IdentityError,"file set"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()

    def test_declared_revision_must_equal_checkout_head(self):
        td,root,manifest,revision=self._fixture()
        try:
            value=json.loads(manifest.read_text());value["revision"]="a"*40;manifest.write_text(json.dumps(value,sort_keys=True),encoding="utf-8")
            with self.assertRaisesRegex(IdentityError,"checkout HEAD"):verify_build_manifest(manifest,root)
        finally:td.cleanup()

    def test_hostile_git_environment_cannot_redirect_authoritative_checkout(self):
        td,root,manifest,revision=self._fixture()
        try:
            hostile=Path(td.name)/"hostile";hostile.mkdir()
            subprocess.run(["git","init",str(hostile)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            (hostile/"x.txt").write_text("evil\n",encoding="utf-8")
            subprocess.run(["git","-C",str(hostile),"config","user.email","test@example.invalid"],check=True)
            subprocess.run(["git","-C",str(hostile),"config","user.name","Evil"],check=True)
            subprocess.run(["git","-C",str(hostile),"add","."],check=True)
            subprocess.run(["git","-C",str(hostile),"commit","-m","evil"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            env={"GIT_DIR":str(hostile/".git"),"GIT_WORK_TREE":str(hostile),"GIT_CONFIG_GLOBAL":str(hostile/"fake-global")}
            with patch.dict(os.environ,env,clear=False):
                result=verify_build_manifest(manifest,root,revision,_sha(manifest))
            self.assertEqual(result["revision"],revision);self.assertEqual(result["fileCount"],2)
        finally:td.cleanup()

    def test_self_build_requires_verified_expected_identity(self):
        td,root,manifest,revision=self._fixture()
        try:
            env={"FORGEBOSS_SELF_BUILD_MODE":"YES","FORGEBOSS_BUILD_MANIFEST":str(manifest),"FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA":revision,"FORGEBOSS_EXPECTED_MANIFEST_SHA256":_sha(manifest)}
            # Keep the OS execution environment (especially PATH/SystemRoot) because
            # known-good verification intentionally shells out to the installed Git.
            with patch.dict(os.environ,env,clear=False):self.assertEqual(runtime_identity_from_env(root)["revision"],revision)
        finally:td.cleanup()


if __name__=="__main__":unittest.main()
