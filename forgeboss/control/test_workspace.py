from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from forgeboss.control.workspace import (
    QUARANTINE_DIRNAME, STAGE_PREFIX, WorkspaceProvisionError, cleanup_workspace,
    discover_quarantined_workspaces, inspect_source, provision_workspace, quarantine_status,
    reconcile_quarantined_workspace, verify_workspace,
)


class WorkspaceProvisioningV3Tests(unittest.TestCase):
    def setUp(self):
        self.git = Path(shutil.which("git") or "").resolve()
        if not self.git.is_file(): self.skipTest("git executable unavailable")
        self.td = tempfile.TemporaryDirectory(); self.base = Path(self.td.name)
        self.source = self.base / "source"; self.workspaces = self.base / "workspaces"; self.workspaces.mkdir()
        self._git(["init", str(self.source)], self.base)
        self._git(["config", "user.email", "worker-c@example.invalid"], self.source)
        self._git(["config", "user.name", "Worker C"], self.source)
        (self.source / "a.txt").write_text("one\n", encoding="utf-8")
        self._git(["add", "a.txt"], self.source); self._git(["commit", "-m", "base"], self.source)
        self.base_sha = self._git(["rev-parse", "HEAD"], self.source)
        self.main_branch = self._git(["symbolic-ref", "--short", "HEAD"], self.source)
        self._git(["branch", "peer-proof", self.base_sha], self.source)

    def tearDown(self): self.td.cleanup()
    def _git(self, args, cwd):
        p = subprocess.run([str(self.git), *args], cwd=str(cwd), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if p.returncode: self.fail(f"git failed: {args}: {p.stderr}")
        return p.stdout.strip()

    def _make_quarantine(self, target):
        from forgeboss.control import workspace as m
        real = m._rmtree_windows_safe
        def fail(path,*a,**kw):
            if Path(path).name.startswith(STAGE_PREFIX) or Path(path)==target: raise PermissionError("cleanup denied")
            return real(path,*a,**kw)
        with mock.patch.object(m,"verify_workspace",side_effect=WorkspaceProvisionError("INJECTED","forced failure")), \
             mock.patch.object(m,"_rmtree_windows_safe",side_effect=fail):
            with self.assertRaises(WorkspaceProvisionError) as cm:
                provision_workspace(self.source,target,self.workspaces,self.base_sha,"task/one",self.git)
        return cm.exception, real

    def test_provisions_exact_private_git_authority_and_removes_remotes(self):
        target=self.workspaces/"worker-a"; ident=provision_workspace(self.source,target,self.workspaces,self.base_sha.upper(),"task/one",self.git)
        self.assertEqual((ident.base_sha,ident.head_sha,ident.branch,ident.remotes),(self.base_sha,self.base_sha,"task/one",()))
        self.assertTrue(Path(ident.git_dir).is_relative_to(target.resolve())); self.assertTrue(Path(ident.common_dir).is_relative_to(target.resolve()))
        self.assertNotEqual(Path(ident.git_dir),Path(ident.source_git_dir)); self.assertNotEqual(Path(ident.common_dir),Path(ident.source_common_dir))
        self.assertFalse((Path(ident.common_dir)/"objects"/"info"/"alternates").exists()); self.assertIsNone(quarantine_status(target,self.workspaces))

    def test_hostile_worker_ref_mutation_cannot_change_supervisor_or_peer_refs(self):
        before_main=self._git(["rev-parse",self.main_branch],self.source); before_peer=self._git(["rev-parse","peer-proof"],self.source)
        target=self.workspaces/"worker-a"; provision_workspace(self.source,target,self.workspaces,self.base_sha,"task/one",self.git)
        (target/"a.txt").write_text("worker mutation\n",encoding="utf-8"); self._git(["add","a.txt"],target)
        self._git(["config","user.email","worker@example.invalid"],target); self._git(["config","user.name","Worker"],target)
        self._git(["commit","-m","worker mutation"],target); self._git(["branch","-f",self.main_branch,"HEAD"],target); self._git(["branch","-f","peer-proof","HEAD"],target)
        self.assertEqual(self._git(["rev-parse",self.main_branch],self.source),before_main); self.assertEqual(self._git(["rev-parse","peer-proof"],self.source),before_peer)

    def test_verify_denies_wrong_head_wrong_branch_and_detached(self):
        target=self.workspaces/"worker-a"; provision_workspace(self.source,target,self.workspaces,self.base_sha,"task/one",self.git); src=inspect_source(self.source,self.base_sha,self.git)
        (target/"a.txt").write_text("two\n",encoding="utf-8"); self._git(["add","a.txt"],target); self._git(["config","user.email","x@y"],target); self._git(["config","user.name","x"],target); self._git(["commit","-m","other"],target)
        with self.assertRaises(WorkspaceProvisionError) as cm: verify_workspace(target,self.workspaces,self.base_sha,"task/one",self.git,source_identity=src)
        self.assertEqual(cm.exception.code,"WORKSPACE_HEAD_MISMATCH")
        self._git(["reset","--hard",self.base_sha],target); self._git(["checkout","-B","task/other",self.base_sha],target)
        with self.assertRaises(WorkspaceProvisionError) as cm: verify_workspace(target,self.workspaces,self.base_sha,"task/one",self.git,source_identity=src)
        self.assertEqual(cm.exception.code,"WORKSPACE_BRANCH_MISMATCH")
        self._git(["checkout","--detach",self.base_sha],target)
        with self.assertRaises(WorkspaceProvisionError): verify_workspace(target,self.workspaces,self.base_sha,"task/one",self.git,source_identity=src)

    def test_invalid_source_base_branch_escape_and_git_path_fail_closed(self):
        with self.assertRaises(WorkspaceProvisionError): provision_workspace(self.base/"missing",self.workspaces/"x",self.workspaces,self.base_sha,"task/x",self.git)
        with self.assertRaises(WorkspaceProvisionError) as cm: provision_workspace(self.source,self.workspaces/"x",self.workspaces,"abc","task/x",self.git)
        self.assertEqual(cm.exception.code,"BASE_SHA_INVALID")
        with self.assertRaises(WorkspaceProvisionError) as cm: provision_workspace(self.source,self.workspaces/"x",self.workspaces,self.base_sha,"../bad",self.git)
        self.assertEqual(cm.exception.code,"BRANCH_INVALID")
        with self.assertRaises(WorkspaceProvisionError) as cm: provision_workspace(self.source,self.base/"outside",self.workspaces,self.base_sha,"task/x",self.git)
        self.assertEqual(cm.exception.code,"WORKSPACE_ESCAPE")
        with self.assertRaises(WorkspaceProvisionError) as cm: inspect_source(self.source,self.base_sha,"git")
        self.assertEqual(cm.exception.code,"GIT_EXECUTABLE_INVALID")

    def test_symlink_aliases_fail_closed(self):
        sl=self.base/"source-link"
        try: sl.symlink_to(self.source,target_is_directory=True)
        except (OSError,NotImplementedError): self.skipTest("symlink unavailable")
        with self.assertRaises(WorkspaceProvisionError): inspect_source(sl,self.base_sha,self.git)
        target=self.workspaces/"real"; provision_workspace(self.source,target,self.workspaces,self.base_sha,"task/one",self.git); wl=self.workspaces/"link"
        wl.symlink_to(target,target_is_directory=True)
        with self.assertRaises(WorkspaceProvisionError): verify_workspace(wl,self.workspaces,self.base_sha,"task/one",self.git)

    def test_post_clone_failure_cleans_and_reraises_original(self):
        target=self.workspaces/"worker-a"; from forgeboss.control import workspace as m
        with mock.patch.object(m,"verify_workspace",side_effect=WorkspaceProvisionError("INJECTED","forced")):
            with self.assertRaises(WorkspaceProvisionError) as cm: provision_workspace(self.source,target,self.workspaces,self.base_sha,"task/one",self.git)
        self.assertEqual(cm.exception.code,"INJECTED"); self.assertFalse(target.exists()); self.assertIsNone(quarantine_status(target,self.workspaces))

    def test_cleanup_failure_quarantines_and_blocks_reprovision(self):
        target=self.workspaces/"worker-a"; ex,_=self._make_quarantine(target)
        self.assertEqual(ex.code,"WORKSPACE_PROVISION_CLEANUP_FAILED"); self.assertEqual(ex.provision_code,"INJECTED"); self.assertEqual(ex.cleanup_code,"PERMISSIONERROR")
        s=quarantine_status(target,self.workspaces); self.assertEqual(s["state"],"quarantined"); self.assertGreater(s["identity"]["ctimeNs"],0)
        with self.assertRaises(WorkspaceProvisionError) as cm: provision_workspace(self.source,target,self.workspaces,self.base_sha,"task/two",self.git)
        self.assertEqual(cm.exception.code,"WORKSPACE_QUARANTINED")

    def test_restart_discovery_and_reconciliation(self):
        target=self.workspaces/"worker-a"; ex,_=self._make_quarantine(target); gen=ex.generation_id
        self.assertTrue(any(x.get("generation")==gen for x in discover_quarantined_workspaces(self.workspaces)))
        out=reconcile_quarantined_workspace(target,self.workspaces,gen); self.assertTrue(out["reconciled"]); self.assertIsNone(quarantine_status(target,self.workspaces))
        self.assertEqual(provision_workspace(self.source,target,self.workspaces,self.base_sha,"task/two",self.git).branch,"task/two")

    def test_wrong_generation_and_recreated_target_are_denied(self):
        target=self.workspaces/"worker-a"; ex,real=self._make_quarantine(target); gen=ex.generation_id
        with self.assertRaises(WorkspaceProvisionError) as cm: reconcile_quarantined_workspace(target,self.workspaces,"0"*32)
        self.assertEqual(cm.exception.code,"WORKSPACE_GENERATION_MISMATCH")
        s=quarantine_status(target,self.workspaces); survivor=target if target.exists() else Path(s["stage"]); from forgeboss.control import workspace as m
        m._rmtree_windows_safe(survivor,m._path_identity(survivor)); survivor.mkdir(); (survivor/"newer").write_text("x")
        with self.assertRaises(WorkspaceProvisionError) as cm: reconcile_quarantined_workspace(target,self.workspaces,gen)
        self.assertEqual(cm.exception.code,"WORKSPACE_GENERATION_MISMATCH"); self.assertTrue((survivor/"newer").exists())

    def test_simulated_inode_reuse_same_dev_ino_mode_different_ctime_is_denied(self):
        target=self.workspaces/"worker-a"; ex,_=self._make_quarantine(target); gen=ex.generation_id; s=quarantine_status(target,self.workspaces)
        survivor=target if target.exists() else Path(s["stage"]); expected=dict(s["identity"])
        forged=dict(expected); forged["ctimeNs"]=int(expected["ctimeNs"])+1
        from forgeboss.control import workspace as m
        real_identity=m._path_identity
        def observed(path,*a,**kw):
            if Path(path)==survivor: return dict(forged)
            return real_identity(path,*a,**kw)
        with mock.patch.object(m,"_path_identity",side_effect=observed), mock.patch.object(m,"_rmtree_windows_safe") as rm:
            with self.assertRaises(WorkspaceProvisionError) as cm: reconcile_quarantined_workspace(target,self.workspaces,gen)
        self.assertEqual(cm.exception.code,"WORKSPACE_GENERATION_MISMATCH"); rm.assert_not_called()

    def test_missing_or_zero_identity_fields_fail_closed(self):
        from forgeboss.control import workspace as m
        target=self.workspaces/"worker-a"; target.mkdir()
        good=m._path_identity(target)
        for field in ("ino","ctimeNs"):
            bad=dict(good); bad[field]=0
            self.assertFalse(m._identity_matches(target,bad))
        bad=dict(good); bad.pop("ctimeNs")
        self.assertFalse(m._identity_matches(target,bad))

    def test_cleanup_refuses_escape_and_link(self):
        outside=self.base/"outside"; outside.mkdir()
        with self.assertRaises(WorkspaceProvisionError): cleanup_workspace(outside,self.workspaces)
        target=self.workspaces/"real"; target.mkdir(); link=self.workspaces/"link"
        try: link.symlink_to(target,target_is_directory=True)
        except (OSError,NotImplementedError): self.skipTest("symlink unavailable")
        with self.assertRaises(WorkspaceProvisionError): cleanup_workspace(link,self.workspaces)
        self.assertTrue(target.exists())

    @unittest.skipUnless(os.name=="nt","native Windows cleanup proof")
    def test_windows_handle_cleanup_removes_readonly_git_workspace(self):
        target=self.workspaces/"worker-win"
        provision_workspace(self.source,target,self.workspaces,self.base_sha,"task/win",self.git)
        marker=target/"readonly-marker.txt";marker.write_text("locked\n",encoding="utf-8");os.chmod(marker,stat.S_IREAD)
        self.assertTrue(cleanup_workspace(target,self.workspaces));self.assertFalse(target.exists())

    @unittest.skipUnless(os.name=="nt","native Windows reparse proof")
    def test_windows_cleanup_rejects_child_reparse_swap_before_mutation(self):
        from forgeboss.control import workspace as m
        from forgeboss.control import windows_cleanup as wc
        target=self.workspaces/"victim-root";target.mkdir();child=target/"victim";child.mkdir();(child/"inside.txt").write_text("inside")
        outside=self.base/"outside-junction-target";outside.mkdir();keep=outside/"keep.txt";keep.write_text("keep")
        real=wc._open_relative;swapped={"done":False}
        def swap(parent,name):
            if name=="victim" and not swapped["done"]:
                shutil.rmtree(child)
                cp=subprocess.run(["cmd.exe","/d","/c",f'mklink /J "{child}" "{outside}"'],capture_output=True,text=True)
                if cp.returncode: raise unittest.SkipTest("junction creation unavailable: "+cp.stderr)
                swapped["done"]=True
            return real(parent,name)
        try:
            with mock.patch.object(wc,"_open_relative",side_effect=swap):
                with self.assertRaises(WorkspaceProvisionError): cleanup_workspace(target,self.workspaces)
            self.assertTrue(keep.exists());self.assertTrue(swapped["done"])
        finally:
            if child.exists() and m._is_reparse(child): os.rmdir(child)


if __name__ == "__main__": unittest.main()
