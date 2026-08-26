from __future__ import annotations
import hashlib,json,os,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from forgeboss.security import executor_guard as guard

class ExecutorGuardGitMetadataTests(unittest.TestCase):
    def _git(self,work,*args):
        return subprocess.run(["git",*args],cwd=work,capture_output=True,text=True,check=True).stdout.strip()
    def _ordinary(self):
        td=tempfile.TemporaryDirectory();w=Path(td.name)
        self._git(w,"init","-q");self._git(w,"config","user.email","test@example.com");self._git(w,"config","user.name","Test")
        (w/"allowed.txt").write_text("before");self._git(w,"add","allowed.txt");self._git(w,"commit","-qm","base")
        return td,w
    def _lease(self,w):
        return {"baseline":guard.snapshot(w),"allowed_files":["allowed.txt"],"git_metadata":guard.git_metadata_snapshot(w),"isolation_verified":True}
    def _verify(self,w,lease):
        token="t";packet=w.parent/(w.name+"-p.json");lp=w.parent/(w.name+"-l.json")
        packet.write_text(json.dumps({"allowed_files":["allowed.txt"],"context_files":[]}))
        x=dict(lease);x.update({"expires_at":time.time()+30,"executor":"mini-swe","workspace":str(w.resolve()),"packet_sha256":guard.phash(packet),"token_sha256":hashlib.sha256(token.encode()).hexdigest()});lp.write_text(json.dumps(x))
        try:
            with patch.object(guard,"no_remotes"):return guard.verify(lp,token,packet,w,"mini-swe")
        finally:packet.unlink(missing_ok=True);lp.unlink(missing_ok=True)
    def test_real_posix_production_git_path_and_identity(self):
        if os.name=="nt":self.skipTest("POSIX")
        td,w=self._ordinary()
        try:
            self.assertEqual(guard.git(w,"rev-parse","HEAD"),self._git(w,"rev-parse","HEAD"));ident=guard.git_metadata_snapshot(w)["git:executable"]
            self.assertTrue(Path(ident["path"]).is_absolute());self.assertEqual(len(ident["sha256"]),64)
        finally:td.cleanup()
    def test_hostile_path_fake_git_rejected_before_subprocess(self):
        if os.name=="nt":self.skipTest("POSIX")
        td,w=self._ordinary();bad=tempfile.TemporaryDirectory()
        try:
            d=Path(bad.name);d.chmod(0o777);m=d/"marker";g=d/"git";g.write_text(f"#!/bin/sh\necho x > {m}\n");g.chmod(0o755)
            with patch.dict(os.environ,{"PATH":str(d)+os.pathsep+os.environ.get("PATH","")},clear=False),patch.object(guard.subprocess,"run") as run:
                with self.assertRaisesRegex(guard.SecurityError,"writable Git trust path denied|untrusted Git path owner"):guard.git(w,"rev-parse","HEAD")
                run.assert_not_called()
            self.assertFalse(m.exists())
        finally:td.cleanup();bad.cleanup()
    def test_missing_linklike_nonregular_nonexecutable_git_fail_closed(self):
        td=tempfile.TemporaryDirectory()
        try:
            root=Path(td.name);root.chmod(0o755)
            with patch.object(guard.shutil,"which",return_value=None):self.assertRaisesRegex(guard.SecurityError,"unavailable",guard._resolve_git_executable)
            d=root/"d";d.mkdir()
            with patch.object(guard.shutil,"which",return_value=str(d)):self.assertRaisesRegex(guard.SecurityError,"not a regular file",guard._resolve_git_executable)
            if os.name!="nt":
                p=root/"p";p.write_text("x");p.chmod(0o644)
                with patch.object(guard.shutil,"which",return_value=str(p)):self.assertRaisesRegex(guard.SecurityError,"not executable",guard._resolve_git_executable)
            if hasattr(os,"symlink"):
                t=root/"t";t.write_text("x");t.chmod(0o755);l=root/"l"
                try:l.symlink_to(t)
                except OSError:return
                with patch.object(guard.shutil,"which",return_value=str(l)):self.assertRaisesRegex(guard.SecurityError,"linklike Git executable denied",guard._resolve_git_executable)
        finally:td.cleanup()
    def test_executable_identity_drift_fails_snapshot(self):
        td,w=self._ordinary()
        try:
            i=guard.git_metadata_snapshot(w)["git:executable"];j=dict(i);j["sha256"]="0"*64
            with patch.object(guard,"_git_executable_identity",side_effect=[i,j]):self.assertRaisesRegex(guard.SecurityError,"identity changed",guard.git_metadata_snapshot,w)
        finally:td.cleanup()
    def test_windows_selector_and_trusted_install_policy(self):
        with patch.object(guard.os,"name","nt"),patch.object(guard.shutil,"which",return_value=None) as which:
            self.assertRaisesRegex(guard.SecurityError,"git.exe",guard._resolve_git_executable);which.assert_called_once_with("git.exe")
        td=tempfile.TemporaryDirectory()
        try:
            r=Path(td.name);pf=r/"Program Files";inside=pf/"Git"/"cmd"/"git.exe";inside.parent.mkdir(parents=True);inside.write_text("x");outside=r/"fake"/"git.exe";outside.parent.mkdir();outside.write_text("x")
            with patch.dict(os.environ,{"ProgramFiles":str(pf),"ProgramFiles(x86)":""},clear=False):
                guard._assert_windows_git_trust(inside.resolve());self.assertRaisesRegex(guard.SecurityError,"untrusted Git-for-Windows install path",guard._assert_windows_git_trust,outside.resolve())
        finally:td.cleanup()
    def test_inert_lfs_textconv_config_allowed_and_effective_config_bound(self):
        td,w=self._ordinary()
        try:
            cfg=w.parent/"g.cfg";cfg.write_text('[diff "astextplain"]\n\ttextconv = astextplain\n[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n');env={"GIT_CONFIG_GLOBAL":str(cfg),"GIT_CONFIG_NOSYSTEM":"1"}
            with patch.dict(os.environ,env,clear=False):a=guard.git_metadata_snapshot(w)
            cfg.write_text(cfg.read_text()+"[alias]\n\tst = status\n")
            with patch.dict(os.environ,env,clear=False):b=guard.git_metadata_snapshot(w)
            self.assertNotEqual(a["git:effective-config"],b["git:effective-config"])
        finally:td.cleanup()
    def test_credential_helper_sentinel_zero_invocation_through_verify(self):
        td,w=self._ordinary()
        try:
            m=w.parent/"marker";self._git(w,"config","credential.helper",f'!echo x > "{m.as_posix()}"');lease=self._lease(w);self.assertFalse(m.exists());self._verify(w,lease);self.assertFalse(m.exists())
        finally:td.cleanup()
    def test_execution_capable_command_shapes_denied_before_subprocess(self):
        td,w=self._ordinary()
        try:
            for args in (("credential","fill"),("diff","--textconv","HEAD"),("fetch",),("checkout","--","allowed.txt")):
                with self.subTest(args=args),patch.object(guard.subprocess,"run") as run:
                    self.assertRaisesRegex(guard.SecurityError,"non-local/transport-capable",guard.git,w,*args);run.assert_not_called()
        finally:td.cleanup()
    def test_hook_fsmonitor_protocol_and_worktree_controls_preserved(self):
        td,w=self._ordinary()
        try:
            h=w.parent/(w.name+"-hooks");h.mkdir();self._git(w,"config","core.hooksPath",str(h));self.assertRaisesRegex(guard.SecurityError,"hooksPath",guard.git_metadata_snapshot,w)
            self._git(w,"config","--unset","core.hooksPath");self._git(w,"config","core.fsmonitor","../bad");self.assertRaisesRegex(guard.SecurityError,"fsmonitor",guard.git_metadata_snapshot,w)
            self._git(w,"config","--unset","core.fsmonitor");self._git(w,"config","protocol.ext.allow","always");self.assertRaisesRegex(guard.SecurityError,"protocol.ext.allow",guard.git_metadata_snapshot,w)
            self._git(w,"config","--unset","protocol.ext.allow");x=w.parent/(w.name+"-external");x.mkdir();self._git(w,"config","core.worktree",str(x));self.assertRaisesRegex(guard.SecurityError,"worktree escapes",guard.git_metadata_snapshot,w)
        finally:td.cleanup()
    def test_deterministic_execution_config_failure(self):
        td,w=self._ordinary()
        try:
            self._git(w,"config","alias.evil","!echo x");self._git(w,"config","core.editor","bad");msgs=[]
            for _ in range(3):
                with self.assertRaises(guard.SecurityError) as cm:guard.git_metadata_snapshot(w)
                msgs.append(str(cm.exception))
            self.assertEqual(msgs,["execution-capable Git config denied: alias.evil"]*3)
        finally:td.cleanup()
    def test_metadata_change_after_lease_is_rejected(self):
        td,w=self._ordinary()
        try:
            lease=self._lease(w);self._git(w,"config","core.filemode","false");self.assertRaisesRegex(guard.SecurityError,"Git metadata changed after lease",self._verify,w,lease)
        finally:td.cleanup()

if __name__=="__main__":unittest.main()
