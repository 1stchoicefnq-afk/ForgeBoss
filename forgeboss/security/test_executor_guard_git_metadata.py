from __future__ import annotations
import hashlib,json,os,shutil,subprocess,tempfile,time,unittest
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
            return {"baseline":guard.snapshot(work),"allowed_files":["allowed.txt"],"git_metadata":guard.git_metadata_snapshot(work),"isolation_verified":True}

    def _postflight(self,work,lease):
        with patch.object(guard,"verify",return_value=lease),patch.object(guard,"git",side_effect=self._real_guard_git),patch.object(guard,"no_remotes"):
            return guard.postflight("lease","token","packet",work,"mini-swe")

    def _verify(self,work,lease):
        token="verify-token"
        packet=work.parent/(work.name+"-packet.json")
        lease_path=work.parent/(work.name+"-lease.json")
        packet.write_text(json.dumps({"allowed_files":["allowed.txt"],"context_files":[]}),encoding="utf-8")
        full=dict(lease);full.update({"expires_at":time.time()+60,"executor":"mini-swe","workspace":str(work.resolve()),"packet_sha256":guard.phash(packet),"token_sha256":hashlib.sha256(token.encode()).hexdigest()})
        lease_path.write_text(json.dumps(full),encoding="utf-8")
        try:
            with patch.object(guard,"git",side_effect=self._real_guard_git),patch.object(guard,"no_remotes"):
                return guard.verify(lease_path,token,packet,work,"mini-swe")
        finally:
            packet.unlink(missing_ok=True);lease_path.unlink(missing_ok=True)

    def test_safe_allowed_source_change_passes_with_unchanged_git_metadata(self):
        td,work=self._ordinary()
        try:
            lease=self._lease(work);(work/"allowed.txt").write_text("after",encoding="utf-8")
            self.assertEqual(self._postflight(work,lease),0)
        finally:td.cleanup()

    def test_ordinary_git_config_mutation_fails(self):
        td,work=self._ordinary()
        try:
            lease=self._lease(work);current=self._git(work,"config","--bool","core.filemode").casefold();self._git(work,"config","core.filemode","true" if current=="false" else "false")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):self._postflight(work,lease)
        finally:td.cleanup()

    def test_linked_worktree_common_config_mutation_fails(self):
        td,repo,work=self._linked()
        try:
            lease=self._lease(work);current=self._git(repo,"config","--bool","core.filemode").casefold();self._git(repo,"config","core.filemode","true" if current=="false" else "false")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed"):self._postflight(work,lease)
        finally:td.cleanup()

    def test_linked_worktree_ref_mutation_fails(self):
        td,repo,work=self._linked()
        try:
            lease=self._lease(work);ref=repo/".git"/"refs"/"heads"/"linked-test";ref.write_text("0"*40+"\n",encoding="utf-8")
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
                with self.assertRaisesRegex(guard.SecurityError,"missing Git metadata baseline"):guard.postflight("lease","token","packet",work,"mini-swe")
        finally:td.cleanup()

    def test_symlinked_common_config_is_rejected_fail_closed(self):
        if not hasattr(os,"symlink"):self.skipTest("symlink unsupported")
        td,repo,work=self._linked()
        try:
            config=repo/".git"/"config";target=repo.parent/"external-config";target.write_bytes(config.read_bytes());config.unlink()
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
            external=work.parent/(work.name+"-external-hooks");external.mkdir();hook=external/"pre-commit";hook.write_text("#!/bin/sh\nexit 0\n",encoding="utf-8");self._git(work,"config","core.hooksPath",str(external))
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"external Git execution target denied: core.hooksPath"):guard.git_metadata_snapshot(work)
            hook.write_text("#!/bin/sh\nexit 1\n",encoding="utf-8")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"external Git execution target denied: core.hooksPath"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_internal_default_hookspath_remains_allowed_and_snapshotted(self):
        td,work=self._ordinary()
        try:
            hooks=work/".git"/"hooks";self._git(work,"config","core.hooksPath",str(hooks))
            with patch.object(guard,"git",side_effect=self._real_guard_git):snap=guard.git_metadata_snapshot(work)
            self.assertIn("gitdir/config",snap)
        finally:td.cleanup()

    def test_filter_command_config_is_denied_fail_closed(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","filter.evil.clean","python external.py")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: filter.evil.clean"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_fsmonitor_boolean_is_allowed_but_path_target_is_denied(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","core.fsmonitor","false")
            with patch.object(guard,"git",side_effect=self._real_guard_git):guard.git_metadata_snapshot(work)
            self._git(work,"config","core.fsmonitor","../external-fsmonitor")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"external Git execution target denied: core.fsmonitor"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_shell_alias_is_denied_before_lease_even_if_external_target_changes(self):
        td,work=self._ordinary()
        try:
            external=work.parent/"evil.sh";external.write_text("#!/bin/sh\nexit 0\n",encoding="utf-8");self._git(work,"config","alias.evil",f"!{external.as_posix()}")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: alias.evil"):guard.git_metadata_snapshot(work)
            external.write_text("#!/bin/sh\nexit 1\n",encoding="utf-8")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: alias.evil"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_non_shell_alias_remains_allowed_and_semantically_bound(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","alias.st","status")
            with patch.object(guard,"git",side_effect=self._real_guard_git):snap=guard.git_metadata_snapshot(work)
            self.assertIn("git:effective-config",snap)
        finally:td.cleanup()

    def test_credential_helper_is_allowed_local_only_and_semantically_bound(self):
        td,work=self._ordinary()
        try:
            helper1=work.parent/"cred-helper-one.sh";helper2=work.parent/"cred-helper-two.sh"
            helper1.write_text("#!/bin/sh\nexit 11\n",encoding="utf-8");helper2.write_text("#!/bin/sh\nexit 12\n",encoding="utf-8")
            self._git(work,"config","credential.helper",helper1.as_posix())
            with patch.object(guard,"git",side_effect=self._real_guard_git):first=guard.git_metadata_snapshot(work)
            self.assertIn("git:effective-config",first)
            self._git(work,"config","credential.helper",helper2.as_posix())
            with patch.object(guard,"git",side_effect=self._real_guard_git):second=guard.git_metadata_snapshot(work)
            self.assertNotEqual(first["git:effective-config"],second["git:effective-config"])
        finally:td.cleanup()

    def test_credential_helper_sentinel_not_invoked_by_metadata_or_verify(self):
        td,work=self._ordinary()
        try:
            marker=work.parent/"credential-helper-invoked.txt"
            self._git(work,"config","credential.helper",f'!echo invoked > "{marker.as_posix()}"')
            lease=self._lease(work)
            self.assertFalse(marker.exists())
            self._verify(work,lease)
            self.assertFalse(marker.exists())
        finally:td.cleanup()

    def test_diff_external_is_denied_fail_closed(self):
        td,work=self._ordinary()
        try:
            external=work.parent/"diff-tool.sh";external.write_text("#!/bin/sh\nexit 0\n",encoding="utf-8");self._git(work,"config","diff.external",external.as_posix())
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: diff.external"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_diff_textconv_is_denied_fail_closed(self):
        td,work=self._ordinary()
        try:
            external=work.parent/"textconv.sh";external.write_text("#!/bin/sh\nexit 0\n",encoding="utf-8");self._git(work,"config","diff.bin.textconv",external.as_posix())
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: diff.bin.textconv"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_untrusted_global_filter_and_textconv_override_is_denied_fail_closed(self):
        td,work=self._ordinary()
        try:
            global_cfg=work.parent/"git-for-windows-global.cfg"
            global_cfg.write_text('[diff "astextplain"]\n\ttextconv = astextplain\n[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n',encoding="utf-8")
            env={"GIT_CONFIG_GLOBAL":str(global_cfg),"GIT_CONFIG_NOSYSTEM":"1"}
            with patch.dict(os.environ,env,clear=False),patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_local_git_allowlist_rejects_execution_capable_shapes_before_subprocess(self):
        td,work=self._ordinary()
        try:
            cases=(("credential","fill"),("diff","--textconv","HEAD"),("checkout","--","allowed.txt"),("fetch",),("submodule","update"))
            for args in cases:
                with self.subTest(args=args),patch.object(guard.subprocess,"run") as run:
                    with self.assertRaisesRegex(guard.SecurityError,"non-local/transport-capable Git command denied"):guard.git(work,*args)
                    run.assert_not_called()
        finally:td.cleanup()

    def test_execution_config_failure_reason_is_deterministic(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","diff.external","external-diff");self._git(work,"config","core.editor","external-editor")
            messages=[]
            for _ in range(3):
                with patch.object(guard,"git",side_effect=self._real_guard_git):
                    with self.assertRaises(guard.SecurityError) as cm:guard.git_metadata_snapshot(work)
                messages.append(str(cm.exception))
            self.assertEqual(messages,["execution-capable Git config denied: core.editor"]*3)
        finally:td.cleanup()

    def test_editor_and_askpass_style_program_config_are_denied(self):
        for name in ("core.editor","core.askPass","sequence.editor","core.sshCommand","gpg.program"):
            with self.subTest(name=name):
                td,work=self._ordinary()
                try:
                    self._git(work,"config",name,"external-program")
                    with patch.object(guard,"git",side_effect=self._real_guard_git):
                        with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied"):guard.git_metadata_snapshot(work)
                finally:td.cleanup()

    def test_protocol_ext_allow_always_is_denied_before_execution(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","protocol.ext.allow","always")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git transport denied: protocol.ext.allow"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_protocol_ext_allow_never_remains_allowed(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","protocol.ext.allow","never")
            with patch.object(guard,"git",side_effect=self._real_guard_git):snap=guard.git_metadata_snapshot(work)
            self.assertIn("git:effective-config",snap)
        finally:td.cleanup()

    def test_protocol_allow_always_without_specific_ext_is_denied(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","protocol.allow","always")
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git transport denied: protocol.allow"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_specific_ext_never_overrides_permissive_generic_protocol_policy(self):
        td,work=self._ordinary()
        try:
            self._git(work,"config","protocol.allow","always");self._git(work,"config","protocol.ext.allow","never")
            with patch.object(guard,"git",side_effect=self._real_guard_git):snap=guard.git_metadata_snapshot(work)
            self.assertIn("git:effective-config",snap)
        finally:td.cleanup()

    def test_external_core_worktree_redirection_is_denied(self):
        td,work=self._ordinary()
        try:
            external=work.parent/(work.name+"-external-worktree");external.mkdir();self._git(work,"config","core.worktree",str(external))
            with patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"effective Git worktree escapes leased workspace"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_linked_worktree_effective_root_matches_leased_workspace(self):
        td,repo,work=self._linked()
        try:
            with patch.object(guard,"git",side_effect=self._real_guard_git):snap=guard.git_metadata_snapshot(work)
            self.assertIn("git:effective-config",snap)
        finally:td.cleanup()

    def test_verify_unchanged_git_metadata_passes(self):
        td,work=self._ordinary()
        try:
            lease=self._lease(work);self.assertEqual(self._verify(work,lease)["git_metadata"],lease["git_metadata"])
        finally:td.cleanup()

    def test_verify_missing_git_metadata_fails_closed(self):
        td,work=self._ordinary()
        try:
            lease=self._lease(work);lease.pop("git_metadata")
            with self.assertRaisesRegex(guard.SecurityError,"missing Git metadata baseline"):self._verify(work,lease)
        finally:td.cleanup()

    def test_verify_rejects_postlease_core_worktree_redirect(self):
        td,work=self._ordinary()
        try:
            lease=self._lease(work);external=work.parent/(work.name+"-external-worktree");external.mkdir();self._git(work,"config","core.worktree",str(external))
            with self.assertRaises(guard.SecurityError):self._verify(work,lease)
        finally:td.cleanup()

    def test_verify_rejects_postlease_protocol_policy_change(self):
        td,work=self._ordinary()
        try:
            lease=self._lease(work);self._git(work,"config","protocol.allow","always")
            with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git transport denied: protocol.allow"):self._verify(work,lease)
        finally:td.cleanup()

    def test_verify_rejects_postlease_linked_common_metadata_change(self):
        td,repo,work=self._linked()
        try:
            lease=self._lease(work);current=self._git(repo,"config","--bool","core.filemode").casefold();self._git(repo,"config","core.filemode","true" if current=="false" else "false")
            with self.assertRaisesRegex(guard.SecurityError,"Git metadata changed after lease before execution"):self._verify(work,lease)
        finally:td.cleanup()

    def test_verify_ignores_benign_raw_index_stat_cache_churn(self):
        td,repo,work=self._linked()
        try:
            lease=self._lease(work);self._git(work,"status","--porcelain")
            self.assertEqual(self._verify(work,lease)["git_metadata"],lease["git_metadata"])
        finally:td.cleanup()

    def test_real_production_git_path_works_on_posix(self):
        if os.name=="nt":self.skipTest("POSIX only")
        td,work=self._ordinary()
        try:
            self.assertEqual(guard.git(work,"rev-parse","HEAD"),self._git(work,"rev-parse","HEAD"))
            snap=guard.git_metadata_snapshot(work);self.assertIn("git:executable",snap)
            self.assertEqual(Path(snap["git:executable"]["path"]),Path(shutil.which("git")).resolve())
        finally:td.cleanup()

    def test_real_production_git_resolution_missing_fails_closed(self):
        td,work=self._ordinary()
        try:
            with patch.object(guard.shutil,"which",return_value=None),patch.object(guard.subprocess,"run") as run:
                with self.assertRaisesRegex(guard.SecurityError,"Git executable unavailable"):guard.git(work,"rev-parse","HEAD")
                run.assert_not_called()
        finally:td.cleanup()

    def test_git_executable_identity_is_bound_in_metadata(self):
        td,work=self._ordinary()
        try:
            snap=guard.git_metadata_snapshot(work);ident=snap["git:executable"]
            self.assertEqual(ident["kind"],"executable");self.assertTrue(Path(ident["path"]).is_absolute());self.assertEqual(len(ident["sha256"]),64);self.assertGreater(ident["size"],0)
        finally:td.cleanup()

    def test_git_executable_identity_drift_during_snapshot_fails_closed(self):
        td,work=self._ordinary()
        try:
            a={"kind":"executable","path":"/trusted/git","sha256":"a"*64,"size":1};b=dict(a);b["sha256"]="b"*64
            with patch.object(guard,"_git_executable_identity",side_effect=[a,b]),patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"identity changed during metadata snapshot"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_windows_resolver_ignores_path_decoy_and_uses_registry_root(self):
        td=tempfile.TemporaryDirectory()
        try:
            root=Path(td.name)/"Git";exe=root/"cmd"/"git.exe";exe.parent.mkdir(parents=True);exe.write_text("trusted",encoding="utf-8")
            decoy=Path(td.name)/"decoy"/"git.exe";decoy.parent.mkdir();decoy.write_text("fake",encoding="utf-8")
            with patch.object(guard,"_windows_trusted_roots",return_value=[root.resolve()]),\
                 patch.object(guard,"_assert_windows_git_trust") as trust,\
                 patch.object(guard.shutil,"which",return_value=str(decoy)) as which:
                resolved=guard._resolve_windows_git_executable()
            self.assertEqual(resolved,exe.resolve())
            trust.assert_called_once_with(exe.resolve())
            which.assert_not_called()
        finally:td.cleanup()

    def test_non_regular_or_linklike_git_executable_fails_closed(self):
        td=tempfile.TemporaryDirectory()
        try:
            root=Path(td.name);d=root/"git";d.mkdir()
            with patch.object(guard.shutil,"which",return_value=str(d)):
                with self.assertRaisesRegex(guard.SecurityError,"not a regular file"):guard._resolve_git_executable()
            if hasattr(os,"symlink"):
                target=root/"realgit";target.write_text("x");link=root/"gitlink"
                try:link.symlink_to(target)
                except OSError:return
                with patch.object(guard.shutil,"which",return_value=str(link)):
                    with self.assertRaisesRegex(guard.SecurityError,"linklike Git executable denied"):guard._resolve_git_executable()
        finally:td.cleanup()

    def test_hostile_path_fake_git_is_rejected_before_subprocess_and_marker(self):
        if os.name=="nt":self.skipTest("POSIX only")
        td,work=self._ordinary();fake_td=tempfile.TemporaryDirectory()
        try:
            fake_dir=Path(fake_td.name);fake_dir.chmod(0o777);fake=fake_dir/"git";marker=fake_dir/"marker";fake.write_text(f"#!/bin/sh\necho invoked > {marker}\nexit 0\n",encoding="utf-8");fake.chmod(0o755)
            with patch.dict(os.environ,{"PATH":str(fake_dir)+os.pathsep+os.environ.get("PATH","")},clear=False),patch.object(guard.subprocess,"run") as run:
                with self.assertRaisesRegex(guard.SecurityError,"writable Git trust path denied|untrusted Git path owner"):guard.git(work,"rev-parse","HEAD")
                run.assert_not_called()
            self.assertFalse(marker.exists())
        finally:td.cleanup();fake_td.cleanup()

    def test_posix_git_trust_chain_is_privileged_and_not_writable(self):
        if os.name=="nt":self.skipTest("POSIX only")
        p=guard._resolve_git_executable();cur=p
        while True:
            st=cur.stat();self.assertEqual(st.st_uid,0);self.assertEqual(st.st_mode & 0o022,0)
            if cur.parent==cur:break
            cur=cur.parent

    def test_windows_registry_install_root_ignores_mutable_programfiles_environment(self):
        td=tempfile.TemporaryDirectory()
        try:
            root=Path(td.name);trusted=root/"machine-git";trusted.mkdir();evil=root/"env-git";evil.mkdir()
            class Key:
                def __enter__(self):return self
                def __exit__(self,*_):return False
            class Registry:
                HKEY_LOCAL_MACHINE=object();KEY_READ=1;KEY_WOW64_64KEY=0x100;KEY_WOW64_32KEY=0x200;REG_SZ=1
                def OpenKey(self,*_):return Key()
                def QueryValueEx(self,*_):return str(trusted),self.REG_SZ
            with patch.dict(os.environ,{"ProgramFiles":str(evil),"ProgramFiles(x86)":str(evil)},clear=False):roots=guard._windows_trusted_roots(Registry())
            self.assertEqual(roots,[trusted.resolve()]);self.assertNotIn(evil.resolve(),roots)
        finally:td.cleanup()

    def test_windows_registry_install_root_missing_fails_closed(self):
        class Registry:
            HKEY_LOCAL_MACHINE=object();KEY_READ=1;KEY_WOW64_64KEY=0x100;KEY_WOW64_32KEY=0x200;REG_SZ=1
            def OpenKey(self,*_):raise OSError("missing")
        with self.assertRaisesRegex(guard.SecurityError,"HKLM install root unavailable"):guard._windows_trusted_roots(Registry())

    def test_windows_callback_allow_ace_offsets_are_recognized(self):
        self.assertEqual(guard._windows_allow_ace_sid_offset(9),8)
        self.assertEqual(guard._windows_allow_ace_sid_offset(11),12)
        self.assertEqual(guard._windows_allow_ace_sid_offset(11,0x1),28)
        self.assertEqual(guard._windows_allow_ace_sid_offset(11,0x3),44)
        self.assertIsNone(guard._windows_allow_ace_sid_offset(1))

    def test_windows_ace_layout_classification_fails_closed(self):
        self.assertEqual(guard._windows_checked_ace_sid_offset(0,20),8)
        self.assertEqual(guard._windows_checked_ace_sid_offset(1,20),8)
        self.assertEqual(guard._windows_checked_ace_sid_offset(9,24),8)
        self.assertEqual(guard._windows_checked_ace_sid_offset(10,24),8)
        self.assertEqual(guard._windows_checked_ace_sid_offset(5,24),12)
        self.assertEqual(guard._windows_checked_ace_sid_offset(6,24),12)
        self.assertEqual(guard._windows_checked_ace_sid_offset(11,56,0x3),44)
        self.assertEqual(guard._windows_checked_ace_sid_offset(12,56,0x3),44)
        for args in ((2,20,0),(0,12,0),(0,18,0),(5,20,0x4),(11,44,0x3)):
            with self.subTest(args=args),self.assertRaises(guard.SecurityError):guard._windows_checked_ace_sid_offset(*args)

    def test_windows_acl_requires_trusted_owner_and_rejects_any_untrusted_writer(self):
        p=Path("/synthetic/git.exe")
        safe={"S-1-5-18":guard._WIN_WRITE_RIGHTS,"S-1-5-32-544":guard._WIN_WRITE_RIGHTS,"S-1-5-11":0x1200A9}
        with patch.object(guard,"_windows_acl_facts",return_value=("S-1-5-18",safe)):guard._assert_windows_acl_trust(p)
        with patch.object(guard,"_windows_acl_facts",return_value=("S-1-5-32-545",safe)):
            with self.assertRaisesRegex(guard.SecurityError,"untrusted Windows Git path owner"):guard._assert_windows_acl_trust(p)
        for sid in ("S-1-5-21-111-222-333-1001","S-1-5-21-111-222-333-4242","S-1-1-0"):
            with self.subTest(sid=sid):
                bad=dict(safe);bad[sid]=guard._WIN_WRITE_RIGHTS
                with patch.object(guard,"_windows_acl_facts",return_value=("S-1-5-32-544",bad)):
                    with self.assertRaisesRegex(guard.SecurityError,"untrusted principal has write-capable"):guard._assert_windows_acl_trust(p)

    def test_windows_acl_read_only_untrusted_principal_does_not_false_fail(self):
        p=Path("/synthetic/git.exe")
        rights={"S-1-5-32-544":guard._WIN_WRITE_RIGHTS,"S-1-5-21-111-222-333-1001":0x1200A9}
        with patch.object(guard,"_windows_acl_facts",return_value=("S-1-5-32-544",rights)):guard._assert_windows_acl_trust(p)

    def test_windows_parent_replacement_rights_are_narrow_and_fail_closed(self):
        p=Path("/synthetic/volume")
        trusted=frozenset({"s-1-5-18","s-1-5-32-544"})
        safe={"S-1-5-18":guard._WIN_WRITE_RIGHTS,"S-1-5-11":0x1200AD}
        with patch.object(guard,"_windows_trusted_principal_sids",return_value=trusted),patch.object(guard,"_windows_acl_facts",return_value=("S-1-5-18",safe)):
            guard._assert_windows_parent_replacement_trust(p)
        for bit in (0x40,0x40000,0x80000):
            bad=dict(safe);bad["S-1-5-11"]=0x1200AD|bit
            with self.subTest(bit=bit),patch.object(guard,"_windows_trusted_principal_sids",return_value=trusted),patch.object(guard,"_windows_acl_facts",return_value=("S-1-5-18",bad)):
                with self.assertRaisesRegex(guard.SecurityError,"replacement-capable parent rights"):guard._assert_windows_parent_replacement_trust(p)

    def test_windows_trusted_install_policy_rejects_outside_root_and_checks_full_chain(self):
        td=tempfile.TemporaryDirectory()
        try:
            root=Path(td.name);trusted=root/"Git";inside=trusted/"cmd"/"git.exe";inside.parent.mkdir(parents=True);inside.write_text("x");outside=root/"fake"/"git.exe";outside.parent.mkdir();outside.write_text("x")
            safe={"S-1-5-18":0,"S-1-5-32-544":0,"S-1-5-11":0x1200A9}
            with patch.object(guard,"_windows_trusted_roots",return_value=[trusted.resolve()]),patch.object(guard,"_windows_acl_facts",return_value=("S-1-5-18",safe)) as facts:
                guard._assert_windows_git_trust(inside.resolve())
                calls=[c.args[0] for c in facts.call_args_list]
                self.assertEqual(calls[:3],[inside.resolve(),inside.parent.resolve(),trusted.resolve()])
                self.assertIn(trusted.parent.resolve(),calls);self.assertIn(Path(trusted.anchor).resolve(),calls)
                with self.assertRaisesRegex(guard.SecurityError,"untrusted Git-for-Windows install path"):guard._assert_windows_git_trust(outside.resolve())
        finally:td.cleanup()

    def test_windows_ancestor_volume_allows_nonreplacement_rights_but_denies_delete_child(self):
        td=tempfile.TemporaryDirectory()
        try:
            root=Path(td.name);trusted=root/"Git";inside=trusted/"cmd"/"git.exe";inside.parent.mkdir(parents=True);inside.write_text("x");volume=Path(trusted.anchor).resolve()
            safe={"S-1-5-18":0,"S-1-5-32-544":0,"S-1-5-11":0x1200A9}
            def facts(path):
                if Path(path)==volume:return "S-1-5-18",{"S-1-5-18":guard._WIN_WRITE_RIGHTS,"S-1-5-11":0x1200AD}
                return "S-1-5-18",safe
            with patch.object(guard,"_windows_trusted_roots",return_value=[trusted.resolve()]),patch.object(guard,"_windows_acl_facts",side_effect=facts):guard._assert_windows_git_trust(inside.resolve())
            def badfacts(path):
                if Path(path)==volume:return "S-1-5-18",{"S-1-5-18":guard._WIN_WRITE_RIGHTS,"S-1-5-11":0x1200AD|0x40}
                return "S-1-5-18",safe
            with patch.object(guard,"_windows_trusted_roots",return_value=[trusted.resolve()]),patch.object(guard,"_windows_acl_facts",side_effect=badfacts):
                with self.assertRaisesRegex(guard.SecurityError,"replacement-capable parent rights"):guard._assert_windows_git_trust(inside.resolve())
        finally:td.cleanup()

    def test_windows_hostile_path_fake_git_is_rejected_before_subprocess(self):
        td,temp=tempfile.TemporaryDirectory(),tempfile.TemporaryDirectory()
        try:
            root=Path(td.name);trusted=root/"Git";trusted.mkdir();fake_dir=Path(temp.name);fake=fake_dir/"git.exe";marker=fake_dir/"marker";fake.write_text("not executed",encoding="utf-8")
            with patch.object(guard,"_windows_trusted_roots",return_value=[trusted.resolve()]):
                with self.assertRaisesRegex(guard.SecurityError,"untrusted Git-for-Windows install path"):guard._assert_windows_git_trust(fake.resolve())
            with patch.object(guard,"_resolve_git_executable",side_effect=guard.SecurityError("untrusted Git-for-Windows install path")),patch.object(guard.subprocess,"run") as run:
                with self.assertRaisesRegex(guard.SecurityError,"untrusted Git-for-Windows install path"):guard.git(root,"rev-parse","HEAD")
                run.assert_not_called()
            self.assertFalse(marker.exists())
        finally:td.cleanup();temp.cleanup()

    def test_windows_trusted_git_exe_policy_accepts_registry_and_acl_trusted_path(self):
        td=tempfile.TemporaryDirectory()
        try:
            root=Path(td.name);trusted=root/"Git";exe=trusted/"cmd"/"git.exe";exe.parent.mkdir(parents=True);exe.write_text("x")
            safe={"S-1-5-18":0,"S-1-5-32-544":guard._WIN_WRITE_RIGHTS,"S-1-5-11":0x1200A9}
            with patch.object(guard,"_windows_trusted_roots",return_value=[trusted.resolve()]),patch.object(guard,"_windows_acl_facts",return_value=("S-1-5-32-544",safe)):
                guard._assert_windows_git_trust(exe.resolve())
        finally:td.cleanup()

    def test_windows_trustedinstaller_resolution_is_exact_and_mismatch_fails_closed(self):
        with patch.object(guard.os,"name","nt"),patch.object(guard,"_windows_lookup_account_sid",return_value=guard._WIN_TRUSTED_INSTALLER_SID.upper()):
            trusted=guard._windows_trusted_principal_sids()
        self.assertIn(guard._WIN_TRUSTED_INSTALLER_SID,trusted)
        with patch.object(guard.os,"name","nt"),patch.object(guard,"_windows_lookup_account_sid",return_value="S-1-5-80-111-222-333-444-555"):
            with self.assertRaisesRegex(guard.SecurityError,"TrustedInstaller SID identity mismatch"):guard._windows_trusted_principal_sids()

    def test_windows_acl_accepts_verified_trustedinstaller_and_rejects_other_service_sid(self):
        p=Path("/synthetic/git.exe");trusted=frozenset(set(guard._WIN_TRUSTED_OWNER_SIDS)|{guard._WIN_TRUSTED_INSTALLER_SID})
        safe={"S-1-5-32-544":guard._WIN_WRITE_RIGHTS,guard._WIN_TRUSTED_INSTALLER_SID.upper():guard._WIN_WRITE_RIGHTS,"S-1-5-11":0x1200A9}
        with patch.object(guard,"_windows_trusted_principal_sids",return_value=trusted),patch.object(guard,"_windows_acl_facts",return_value=(guard._WIN_TRUSTED_INSTALLER_SID.upper(),safe)):
            guard._assert_windows_acl_trust(p)
        bad=dict(safe);bad["S-1-5-80-111-222-333-444-555"]=guard._WIN_WRITE_RIGHTS
        with patch.object(guard,"_windows_trusted_principal_sids",return_value=trusted),patch.object(guard,"_windows_acl_facts",return_value=("S-1-5-32-544",bad)):
            with self.assertRaisesRegex(guard.SecurityError,"untrusted principal has write-capable"):guard._assert_windows_acl_trust(p)

    def test_windows_native_trustedinstaller_lookup_matches_canonical_sid(self):
        if os.name!="nt":self.skipTest("Windows only")
        self.assertEqual(guard._windows_lookup_account_sid(guard._WIN_TRUSTED_INSTALLER_ACCOUNT).casefold(),guard._WIN_TRUSTED_INSTALLER_SID)

class ExecutorGuardTrustedConfigOriginTests(unittest.TestCase):
    def _git(self,work,*args):
        cp=subprocess.run(["git",*args],cwd=work,capture_output=True,text=True,check=True)
        return cp.stdout.strip()
    def _ordinary(self):
        td=tempfile.TemporaryDirectory();work=Path(td.name)
        self._git(work,"init","-q");self._git(work,"config","user.email","test@example.com");self._git(work,"config","user.name","Test")
        (work/"allowed.txt").write_text("before",encoding="utf-8");self._git(work,"add","allowed.txt");self._git(work,"commit","-qm","base")
        return td,work
    def _real_guard_git(self,work,*args):return self._git(Path(work),*args)
    def _system_cfg(self,work):
        p=work.parent/(work.name+"-system.cfg")
        p.write_text('[diff "astextplain"]\n\ttextconv = astextplain\n[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n',encoding="utf-8")
        return p

    def test_effective_config_parser_binds_scope_origin_name_value(self):
        raw="system\x00file:/trusted/gitconfig\x00filter.lfs.clean\ngit-lfs clean -- %f\x00local\x00file:.git/config\x00user.name\nTest\x00"
        entries=guard._parse_effective_config(raw)
        self.assertEqual(entries[0],{"scope":"system","origin":"file:/trusted/gitconfig","name":"filter.lfs.clean","value":"git-lfs clean -- %f"})
        self.assertEqual(entries[1]["scope"],"local");self.assertEqual(entries[1]["name"],"user.name")
        with self.assertRaisesRegex(guard.SecurityError,"framing invalid"):guard._parse_effective_config("system\x00file:/x\x00")

    def test_trusted_system_lfs_and_textconv_are_allowed_and_origin_checked(self):
        td,work=self._ordinary()
        try:
            system_cfg=self._system_cfg(work);env={"GIT_CONFIG_SYSTEM":str(system_cfg),"GIT_CONFIG_GLOBAL":os.devnull}
            with patch.dict(os.environ,env,clear=False),patch.object(guard,"git",side_effect=self._real_guard_git),patch.object(guard,"_assert_trusted_system_config_origin",return_value=system_cfg.resolve()) as trust:
                snap=guard.git_metadata_snapshot(work)
            self.assertIn("git:effective-config",snap);self.assertEqual(trust.call_count,4)
            self.assertEqual({c.args[0]["scope"] for c in trust.call_args_list},{"system"})
        finally:td.cleanup()

    def test_local_override_of_trusted_system_filter_is_denied(self):
        td,work=self._ordinary()
        try:
            system_cfg=self._system_cfg(work);self._git(work,"config","filter.lfs.clean","python evil.py")
            env={"GIT_CONFIG_SYSTEM":str(system_cfg),"GIT_CONFIG_GLOBAL":os.devnull}
            with patch.dict(os.environ,env,clear=False),patch.object(guard,"git",side_effect=self._real_guard_git),patch.object(guard,"_assert_trusted_system_config_origin",return_value=system_cfg.resolve()):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: filter.lfs.clean from local"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_command_scope_override_is_denied_even_for_stock_lfs_value(self):
        td,work=self._ordinary()
        try:
            env={"GIT_CONFIG_COUNT":"1","GIT_CONFIG_KEY_0":"filter.lfs.clean","GIT_CONFIG_VALUE_0":"git-lfs clean -- %f"}
            with patch.dict(os.environ,env,clear=False),patch.object(guard,"git",side_effect=self._real_guard_git):
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: filter.lfs.clean from command"):guard.git_metadata_snapshot(work)
        finally:td.cleanup()

    def test_trusted_system_exception_does_not_allow_diff_command(self):
        td,work=self._ordinary()
        try:
            entries=({"scope":"system","origin":"file:/trusted/gitconfig","name":"diff.bin.command","value":"external-diff"},)
            with patch.object(guard,"_assert_effective_worktree"),patch.object(guard,"_assert_trusted_system_config_origin") as trust:
                with self.assertRaisesRegex(guard.SecurityError,"execution-capable Git config denied: diff.bin.command"):guard._assert_safe_execution_config(work,work/".git",work/".git",entries)
                trust.assert_not_called()
        finally:td.cleanup()

    def test_trusted_origin_requires_system_file_scope(self):
        for entry in ({"scope":"global","origin":"file:/trusted/gitconfig"},{"scope":"system","origin":"command line"}):
            with self.subTest(entry=entry),self.assertRaises(guard.SecurityError):guard._assert_trusted_system_config_origin(entry)

if __name__=="__main__":unittest.main()
