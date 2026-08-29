from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forgeboss.control.known_good import IdentityError, runtime_identity_from_env, verify_build_manifest


def _sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_digest(files):
    raw=json.dumps([[k,files[k]] for k in sorted(files)],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class KnownGoodIdentityTests(unittest.TestCase):
    def _fixture(self):
        td=tempfile.TemporaryDirectory();root=Path(td.name)/"root";pkg=root/"forgeboss";pkg.mkdir(parents=True)
        entry=pkg/"daemon.py";entry.write_text("print('ok')\n",encoding="utf-8")
        helper=pkg/"helper.py";helper.write_text("VALUE=1\n",encoding="utf-8")
        revision="a"*40;files={"forgeboss/daemon.py":_sha(entry),"forgeboss/helper.py":_sha(helper)}
        manifest=Path(td.name)/"manifest.json"
        manifest.write_text(json.dumps({"schema":1,"inventoryMode":"forgeboss-package-v1","revision":revision,"codeRoot":str(root.resolve()),"entrypoint":"forgeboss/daemon.py","treeSha256":_tree_digest(files),"files":files},sort_keys=True),encoding="utf-8")
        return td,root,manifest,revision

    def _rewrite(self,manifest,mutator):
        value=json.loads(manifest.read_text(encoding="utf-8"));mutator(value);manifest.write_text(json.dumps(value,sort_keys=True),encoding="utf-8")

    def test_verified_manifest_binds_complete_package_revision_root_entrypoint_and_tree(self):
        td,root,manifest,revision=self._fixture()
        try:
            result=verify_build_manifest(manifest,root,revision,_sha(manifest))
            self.assertTrue(result["verified"]);self.assertEqual(result["revision"],revision);self.assertEqual(result["fileCount"],2)
            self.assertEqual(result["inventoryMode"],"forgeboss-package-v1");self.assertEqual(Path(result["codeRoot"]),root.resolve())
        finally:td.cleanup()

    def test_file_tamper_fails_closed(self):
        td,root,manifest,revision=self._fixture()
        try:
            (root/"forgeboss"/"daemon.py").write_text("print('tampered')\n",encoding="utf-8")
            with self.assertRaisesRegex(IdentityError,"digest mismatch"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()

    def test_omitted_existing_module_fails_closed_even_with_recomputed_tree(self):
        td,root,manifest,revision=self._fixture()
        try:
            def mutate(v):
                v["files"].pop("forgeboss/helper.py");v["treeSha256"]=_tree_digest(v["files"])
            self._rewrite(manifest,mutate)
            with self.assertRaisesRegex(IdentityError,"inventory is incomplete or stale"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()

    def test_unexpected_new_module_fails_closed(self):
        td,root,manifest,revision=self._fixture()
        try:
            (root/"forgeboss"/"injected.py").write_text("PWN=1\n",encoding="utf-8")
            with self.assertRaisesRegex(IdentityError,"inventory is incomplete or stale"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()

    def test_manifest_only_file_fails_closed(self):
        td,root,manifest,revision=self._fixture()
        try:
            def mutate(v):
                v["files"]["forgeboss/missing.py"]="0"*64;v["treeSha256"]=_tree_digest(v["files"])
            self._rewrite(manifest,mutate)
            with self.assertRaisesRegex(IdentityError,"inventory is incomplete or stale"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()

    def test_tree_digest_mismatch_fails_closed(self):
        td,root,manifest,revision=self._fixture()
        try:
            self._rewrite(manifest,lambda v:v.__setitem__("treeSha256","0"*64))
            with self.assertRaisesRegex(IdentityError,"tree digest mismatch"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()

    def test_non_authoritative_inventory_mode_fails_closed(self):
        td,root,manifest,revision=self._fixture()
        try:
            self._rewrite(manifest,lambda v:v.__setitem__("inventoryMode","selected-files"))
            with self.assertRaisesRegex(IdentityError,"complete authoritative ForgeBoss package inventory"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()

    def test_expected_revision_mismatch_fails_closed(self):
        td,root,manifest,revision=self._fixture()
        try:
            with self.assertRaisesRegex(IdentityError,"expected known-good SHA"):verify_build_manifest(manifest,root,"b"*40,_sha(manifest))
        finally:td.cleanup()

    def test_self_build_requires_manifest_revision_and_manifest_digest(self):
        td,root,manifest,revision=self._fixture()
        try:
            with patch.dict(os.environ,{"FORGEBOSS_SELF_BUILD_MODE":"YES"},clear=True):
                with self.assertRaisesRegex(IdentityError,"BUILD_MANIFEST"):runtime_identity_from_env(root)
            with patch.dict(os.environ,{"FORGEBOSS_SELF_BUILD_MODE":"YES","FORGEBOSS_BUILD_MANIFEST":str(manifest),"FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA":revision,"FORGEBOSS_EXPECTED_MANIFEST_SHA256":_sha(manifest)},clear=True):
                identity=runtime_identity_from_env(root);self.assertEqual(identity["revision"],revision);self.assertEqual(identity["fileCount"],2)
        finally:td.cleanup()

    def test_non_self_build_can_run_unverified_but_reports_that_truthfully(self):
        td,root,manifest,revision=self._fixture()
        try:
            with patch.dict(os.environ,{},clear=True):
                identity=runtime_identity_from_env(root);self.assertFalse(identity["verified"]);self.assertIsNone(identity["revision"])
        finally:td.cleanup()

    def test_cache_artifacts_do_not_change_authoritative_inventory(self):
        td,root,manifest,revision=self._fixture()
        try:
            cache=root/"forgeboss"/"__pycache__";cache.mkdir();(cache/"daemon.cpython-313.pyc").write_bytes(b"cache")
            result=verify_build_manifest(manifest,root,revision);self.assertEqual(result["fileCount"],2)
        finally:td.cleanup()

    def test_symlinked_manifest_fails_closed(self):
        if not hasattr(os,"symlink"):self.skipTest("symlink unsupported")
        td,root,manifest,revision=self._fixture()
        try:
            link=Path(td.name)/"manifest-link.json"
            try:link.symlink_to(manifest)
            except OSError as ex:self.skipTest("symlink unavailable: "+str(ex))
            with self.assertRaisesRegex(IdentityError,"symlink/junction"):verify_build_manifest(link,root,revision)
        finally:td.cleanup()

    def test_symlinked_or_unexpected_package_entry_fails_closed(self):
        if not hasattr(os,"symlink"):self.skipTest("symlink unsupported")
        td,root,manifest,revision=self._fixture()
        try:
            target=Path(td.name)/"external.py";target.write_text("VALUE=1\n",encoding="utf-8");link=root/"forgeboss"/"evil.py"
            try:link.symlink_to(target)
            except OSError as ex:self.skipTest("symlink unavailable: "+str(ex))
            with self.assertRaisesRegex(IdentityError,"symlink/junction"):verify_build_manifest(manifest,root,revision)
        finally:td.cleanup()


if __name__=="__main__":unittest.main()
