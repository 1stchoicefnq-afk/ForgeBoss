from __future__ import annotations
import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from forgeboss.security import executor_guard as guard

class ExecutorGuardGitMetadataTests(unittest.TestCase):
    def _workspace(self):
        td=tempfile.TemporaryDirectory();work=Path(td.name);gitdir=work/".git";gitdir.mkdir()
        (gitdir/"refs"/"heads").mkdir(parents=True);(gitdir/"hooks").mkdir()
        (gitdir/"info").mkdir();(gitdir/"objects"/"info").mkdir(parents=True)
        (gitdir/"config").write_text("[core]\n\trepositoryformatversion = 0\n",encoding="utf-8")
        (gitdir/"HEAD").write_text("ref: refs/heads/main\n",encoding="utf-8")
        (gitdir/"refs"/"heads"/"main").write_text("a"*40+"\n",encoding="utf-8")
        (work/"allowed.txt").write_text("before",encoding="utf-8")
        return td,work

    def _lease(self,work):
        with patch.object(guard,"git",return_value="100644 deadbeef 0\tallowed.txt"):
            return {"baseline":guard.snapshot(work),"allowed_files":["allowed.txt"],
                    "git_metadata":guard.git_metadata_snapshot(work),"isolation_verified":True}

    def _postflight(self,work,lease,stage="100644 deadbeef 0\tallowed.txt"):
        with patch.object(guard,"verify",return_value=lease),patch.object(guard,"git",return_value=stage),patch.object(guard,"no_remotes"):
            return guard.postflight("lease","token","packet",work,"mini-swe")

    def test_safe_allowed_source_change_passes_with_unchanged_git_metadata(self):
        td,work=self._workspace()
        try:
            lease=self._lease(work);(work/"allowed.txt").write_text("after",encoding="utf-8")
            self.assertEqual(self._postflight(work,lease),0)
        finally:td.cleanup()

    def test_git_config_mutation_fails_even_when_remote_names_are_unchanged(self):
        td,work=self._workspace()
        try:
            lease=self._lease(work)
            (work/"allowed.txt").write_text("after",encoding="utf-8")
            (work/".git"/"config").write_text("[core]\n\trepositoryformatversion = 0\n\tsshCommand = hostile\n",encoding="utf-8")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):
                self._postflight(work,lease)
        finally:td.cleanup()

    def test_ref_mutation_fails(self):
        td,work=self._workspace()
        try:
            lease=self._lease(work);(work/".git"/"refs"/"heads"/"main").write_text("b"*40+"\n",encoding="utf-8")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):
                self._postflight(work,lease)
        finally:td.cleanup()

    def test_semantic_index_mutation_fails_but_raw_index_cache_is_not_fingerprinted(self):
        td,work=self._workspace()
        try:
            (work/".git"/"index").write_bytes(b"cache-v1")
            lease=self._lease(work)
            (work/".git"/"index").write_bytes(b"cache-v2")
            self.assertEqual(self._postflight(work,lease),0)
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):
                self._postflight(work,lease,stage="100644 cafebabe 0\tallowed.txt")
        finally:td.cleanup()

    def test_hook_mutation_fails(self):
        td,work=self._workspace()
        try:
            lease=self._lease(work);(work/".git"/"hooks"/"pre-commit").write_text("echo changed\n",encoding="utf-8")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):
                self._postflight(work,lease)
        finally:td.cleanup()

    def test_missing_git_metadata_baseline_fails_closed(self):
        td,work=self._workspace()
        try:
            lease={"baseline":guard.snapshot(work),"allowed_files":["allowed.txt"],"isolation_verified":True}
            with patch.object(guard,"verify",return_value=lease):
                with self.assertRaisesRegex(guard.SecurityError,"missing Git metadata baseline"):
                    guard.postflight("lease","token","packet",work,"mini-swe")
        finally:td.cleanup()

if __name__=="__main__":unittest.main()
