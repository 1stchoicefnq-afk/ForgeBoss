from __future__ import annotations
import os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from forgeboss.security import executor_guard as guard

class ExecutorGuardGitMetadataTests(unittest.TestCase):
    def _git(self,work,*args):
        cp=subprocess.run(["git",*args],cwd=work,capture_output=True,text=True,check=True)
        return cp.stdout.strip()

    def _ordinary(self):
        td=tempfile.TemporaryDirectory();work=Path(td.name)
        self._git(work,"init","-q")
        self._git(work,"config","user.email","test@example.com");self._git(work,"config","user.name","Test")
        (work/"allowed.txt").write_text("before",encoding="utf-8")
        self._git(work,"add","allowed.txt");self._git(work,"commit","-qm","base")
        return td,work

    def _linked(self):
        td=tempfile.TemporaryDirectory();root=Path(td.name);repo=root/"repo";linked=root/"linked"
        repo.mkdir();self._git(repo,"init","-q");self._git(repo,"config","user.email","test@example.com");self._git(repo,"config","user.name","Test")
        (repo/"allowed.txt").write_text("before",encoding="utf-8")
        self._git(repo,"add","allowed.txt");self._git(repo,"commit","-qm","base")
        self._git(repo,"worktree","add","-q",str(linked),"-b","linked-test")
        return td,repo,linked

    def _real_guard_git(self,work,*args):return self._git(Path(work),*args)

    def _lease(self,work):
        with patch.object(guard,"git",side_effect=self._real_guard_git):
            return {"baseline":guard.snapshot(work),"allowed_files":["allowed.txt"],
                    "git_metadata":guard.git_metadata_snapshot(work),"isolation_verified":True}

    def _postflight(self,work,lease):
        with patch.object(guard,"verify",return_value=lease),patch.object(guard,"git",side_effect=self._real_guard_git),patch.object(guard,"no_remotes"):
            return guard.postflight("lease","token","packet",work,"mini-swe")

    def test_safe_allowed_source_change_passes_with_unchanged_git_metadata(self):
        td,work=self._ordinary()
        try:
            lease=self._lease(work);(work/"allowed.txt").write_text("after",encoding="utf-8")
            self.assertEqual(self._postflight(work,lease),0)
        finally:td.cleanup()

    def test_ordinary_git_config_mutation_fails(self):
        td,work=self._ordinary()
        try:
            lease=self._lease(work);self._git(work,"config","core.filemode","false")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):self._postflight(work,lease)
        finally:td.cleanup()

    def test_linked_worktree_common_config_mutation_fails(self):
        td,repo,work=self._linked()
        try:
            lease=self._lease(work);self._git(repo,"config","core.filemode","false")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):self._postflight(work,lease)
        finally:td.cleanup()

    def test_linked_worktree_ref_mutation_fails(self):
        td,repo,work=self._linked()
        try:
            lease=self._lease(work)
            ref=repo/".git"/"refs"/"heads"/"linked-test";ref.write_text("0"*40+"\n",encoding="utf-8")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):self._postflight(work,lease)
        finally:td.cleanup()

    def test_linked_worktree_semantic_index_mutation_fails(self):
        td,repo,work=self._linked()
        try:
            lease=self._lease(work);(work/"allowed.txt").write_text("staged",encoding="utf-8");self._git(work,"add","allowed.txt")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):self._postflight(work,lease)
        finally:td.cleanup()

    def test_linked_worktree_raw_index_stat_cache_churn_does_not_false_fail(self):
        td,repo,work=self._linked()
        try:
            lease=self._lease(work);self._git(work,"status","--porcelain")
            self.assertEqual(self._postflight(work,lease),0)
        finally:td.cleanup()

    def test_git_resolution_failure_fails_closed(self):
        td,work=self._ordinary()
        try:
            with patch.object(guard,"git",side_effect=guard.SecurityError("git failed")):
                with self.assertRaisesRegex(guard.SecurityError,"git failed"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_missing_git_metadata_baseline_fails_closed(self):
        td,work=self._ordinary()
        try:
            lease={"baseline":guard.snapshot(work),"allowed_files":["allowed.txt"],"isolation_verified":True}
            with patch.object(guard,"verify",return_value=lease):
                with self.assertRaisesRegex(guard.SecurityError,"missing Git metadata baseline"):
                    guard.postflight("lease","token","packet",work,"mini-swe")
        finally:td.cleanup()

    def test_symlinked_common_config_is_rejected_fail_closed(self):
        if not hasattr(os,"symlink"):self.skipTest("symlink unsupported")
        td,repo,work=self._linked()
        try:
            config=repo/".git"/"config";target=repo.parent/"external-config"
            target.write_bytes(config.read_bytes());config.unlink()
            try:config.symlink_to(target)
            except OSError as e:self.skipTest("symlink unavailable: "+str(e))
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"linklike Git metadata denied"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_symlinked_worktree_local_config_is_rejected_fail_closed(self):
        if not hasattr(os,"symlink"):self.skipTest("symlink unsupported")
        td,repo,work=self._linked()
        try:
            gitdir=Path(self._git(work,"rev-parse","--git-dir"));gitdir=(work/gitdir).resolve() if not gitdir.is_absolute() else gitdir.resolve()
            local=gitdir/"config.worktree";target=repo.parent/"external-worktree-config";target.write_text("[core]\n\tbare = false\n",encoding="utf-8")
            try:local.symlink_to(target)
            except OSError as e:self.skipTest("symlink unavailable: "+str(e))
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"linklike Git metadata denied"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_external_included_config_mutation_changes_effective_snapshot(self):
        td,repo,work=self._linked()
        try:
            external=repo.parent/"included-config";external.write_text("[alias]\n\tone = status\n",encoding="utf-8")
            with (repo/".git"/"config").open("a",encoding="utf-8") as f:f.write(f"\n[include]\n\tpath = {external.as_posix()}\n")
            with patch.object(guard,"git",side_effect=self._real_guard_git):before=guard.git_metadata_snapshot(work)
            external.write_text("[alias]\n\tone = log\n",encoding="utf-8")
            with patch.object(guard,"git",side_effect=self._real_guard_git):after=guard.git_metadata_snapshot(work)
            self.assertNotEqual(before["git:effective-config"],after["git:effective-config"])
        finally:td.cleanup()

    def test_external_core_hookspath_is_denied_before_lease_even_if_config_text_unchanged(self):
        td,work=self._ordinary()
        try:
            external=work.parent/"external-hooks";external.mkdir()
            hook=external/"pre-commit";hook.write_text("#!/bin/sh\nexit 0\n",encoding="utf-8")
            self._git(work,"config","core.hooksPath",str(external))
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"external Git execution target denied: core.hooksPath"):
                    guard.git_metadata_snapshot(work)
            hook.write_text("#!/bin/sh\nexit 1\n",encoding="utf-8")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"external Git execution target denied: core.hooksPath"):
                    guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_internal_default_hookspath_remains_allowed_and_snapshotted(self):
        td,work=self._ordinary()
        try:
            hooks=work/".git"/"hooks"
            self._git(work,"config","core.hooksPath",str(hooks))
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                snap=guard.git_metadata_snapshot(work)
            self.assertIn("gitdir/config",snap)
        finally:td.cleanup()

    def test_filter_command_config_is_denied_fail_closed(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","filter.evil.clean","python external.py")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: filter.evil.clean"):
                    guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_fsmonitor_boolean_is_allowed_but_path_target_is_denied(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","core.fsmonitor","false")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                guard.git_metadata_snapshot(work)
            self._git(work,"config","core.fsmonitor","../external-fsmonitor")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"external Git execution target denied: core.fsmonitor"):
                    guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_shell_alias_is_denied_before_lease_even_if_external_target_changes(self):
        td,work=self._ordinary()
        try:
            external=work.parent/"evil.sh";external.write_text("#!/bin/sh\nexit 0\n",encoding="utf-8")
            self._git(work,"config","alias.evil",f"!{external.as_posix()}")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: alias.evil"):
                    guard.git_metadata_snapshot(work)
            external.write_text("#!/bin/sh\nexit 1\n",encoding="utf-8")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: alias.evil"):
                    guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_non_shell_alias_remains_allowed_and_semantically_bound(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","alias.st","status")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                snap=guard.git_metadata_snapshot(work)
            self.assertIn("git:effective-config",snap)
        finally:td.cleanup()

if __name__=="__main__":unittest.main()
