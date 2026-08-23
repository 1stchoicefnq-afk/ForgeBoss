from __future__ import annotations
import subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from forgeboss.security import executor_guard as guard

class ExecutorGuardGitMetadataTests(unittest.TestCase):
    def _run_git(self,work,*args):
        p=subprocess.run(["git",*args],cwd=work,capture_output=True,text=True,timeout=20)
        if p.returncode:raise guard.SecurityError((p.stdout+p.stderr).strip() or "git failed")
        return p.stdout.strip()

    def _repo(self):
        td=tempfile.TemporaryDirectory();root=Path(td.name)/"repo";root.mkdir()
        subprocess.run(["git","init"],cwd=root,check=True,capture_output=True)
        subprocess.run(["git","config","user.email","test@example.com"],cwd=root,check=True)
        subprocess.run(["git","config","user.name","Test"],cwd=root,check=True)
        (root/"allowed.txt").write_text("before",encoding="utf-8")
        subprocess.run(["git","add","allowed.txt"],cwd=root,check=True)
        subprocess.run(["git","commit","-m","base"],cwd=root,check=True,capture_output=True)
        return td,root

    def _linked_worktree(self):
        td,root=self._repo();work=Path(td.name)/"linked"
        subprocess.run(["git","worktree","add","-b","worker",str(work)],cwd=root,check=True,capture_output=True)
        return td,root,work

    def _lease(self,work):
        with patch.object(guard,"git",side_effect=lambda w,*a:self._run_git(w,*a)):
            return {"baseline":guard.snapshot(work),"allowed_files":["allowed.txt"],
                    "git_metadata":guard.git_metadata_snapshot(work),"isolation_verified":True}

    def _postflight(self,work,lease):
        with patch.object(guard,"verify",return_value=lease),patch.object(
            guard,"git",side_effect=lambda w,*a:self._run_git(w,*a)),patch.object(guard,"no_remotes"):
            return guard.postflight("lease","token","packet",work,"mini-swe")

    def test_safe_allowed_source_change_passes_with_unchanged_git_metadata(self):
        td,work=self._repo()
        try:
            lease=self._lease(work);(work/"allowed.txt").write_text("after",encoding="utf-8")
            self.assertEqual(self._postflight(work,lease),0)
        finally:td.cleanup()

    def test_ordinary_repo_config_mutation_fails(self):
        td,work=self._repo()
        try:
            lease=self._lease(work)
            subprocess.run(["git","config","test.guard","changed"],cwd=work,check=True)
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):
                self._postflight(work,lease)
        finally:td.cleanup()

    def test_linked_worktree_common_config_mutation_fails(self):
        td,root,work=self._linked_worktree()
        try:
            self.assertTrue((work/".git").is_file())
            lease=self._lease(work)
            subprocess.run(["git","config","test.guard","changed"],cwd=work,check=True)
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):
                self._postflight(work,lease)
        finally:td.cleanup()

    def test_linked_worktree_ref_mutation_fails(self):
        td,root,work=self._linked_worktree()
        try:
            lease=self._lease(work)
            with patch.object(guard,"git",side_effect=lambda w,*a:self._run_git(w,*a)):
                common=guard._resolve_git_root(work,"--git-common-dir")
            ref=common/"refs"/"heads"/"worker"
            old=ref.read_text(encoding="utf-8").strip()
            ref.write_text(("0"*40 if old!="0"*40 else "1"*40)+"\n",encoding="utf-8")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):
                self._postflight(work,lease)
        finally:td.cleanup()

    def test_linked_worktree_semantic_index_mutation_fails(self):
        td,root,work=self._linked_worktree()
        try:
            lease=self._lease(work)
            (work/"allowed.txt").write_text("after",encoding="utf-8")
            subprocess.run(["git","add","allowed.txt"],cwd=work,check=True)
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):
                self._postflight(work,lease)
        finally:td.cleanup()

    def test_read_only_git_stat_refresh_does_not_false_fail(self):
        td,root,work=self._linked_worktree()
        try:
            lease=self._lease(work)
            subprocess.run(["git","status","--short"],cwd=work,check=True,capture_output=True)
            (work/"allowed.txt").write_text("after",encoding="utf-8")
            self.assertEqual(self._postflight(work,lease),0)
        finally:td.cleanup()

    def test_git_metadata_resolution_failure_fails_closed(self):
        td,work=self._repo()
        try:
            def fail(w,*args):
                if args==("rev-parse","--git-dir"):raise guard.SecurityError("git failed")
                return self._run_git(w,*args)
            with patch.object(guard,"git",side_effect=fail):
                with self.assertRaisesRegex(guard.SecurityError,"git failed"):
                    guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_missing_git_metadata_baseline_fails_closed(self):
        td,work=self._repo()
        try:
            lease={"baseline":guard.snapshot(work),"allowed_files":["allowed.txt"],"isolation_verified":True}
            with patch.object(guard,"verify",return_value=lease):
                with self.assertRaisesRegex(guard.SecurityError,"missing Git metadata baseline"):
                    guard.postflight("lease","token","packet",work,"mini-swe")
        finally:td.cleanup()

if __name__=="__main__":unittest.main()
