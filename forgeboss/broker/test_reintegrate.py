from __future__ import annotations
import subprocess,tempfile,unittest
from pathlib import Path
from unittest import mock
from forgeboss.broker import reintegrate

class ReintegrationTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name);self.repo=self.root/"private";self.repo.mkdir();self._git("init","-q");self._git("config","user.email","test@example.com");self._git("config","user.name","Test");self._git("config","core.autocrlf","false");(self.repo/"allowed.txt").write_text("before\n",encoding="utf-8");self._git("add","allowed.txt");self._git("commit","-qm","base");self.base=self._git("rev-parse","HEAD");self.broker_root=self.root/"broker-root";self.broker_root.mkdir()
    def tearDown(self):self.td.cleanup()
    def _git(self,*args):return subprocess.run(["git",*args],cwd=self.repo,capture_output=True,text=True,check=True).stdout.strip()
    def test_out_of_scope_change_is_rejected_before_commit(self):
        (self.repo/"other.txt").write_text("evil",encoding="utf-8")
        with self.assertRaisesRegex(reintegrate.ReintegrationError,"out-of-scope"):reintegrate.create_result_commit(self.repo,self.base,["allowed.txt"],"t","r")
    def test_allowed_case_collision_is_rejected(self):
        with self.assertRaisesRegex(reintegrate.ReintegrationError,"allowed path case collision"):reintegrate.validate_private_diff(self.repo,["A.txt","a.txt"])
    def test_result_commit_and_ref_ignore_old_host_file_handle(self):
        (self.repo/"allowed.txt").write_text("protected-result\n",encoding="utf-8")
        commit,tree,paths,diff_sha=reintegrate.create_result_commit(self.repo,self.base,["allowed.txt"],"task","run")
        host=self.root/"ordinary-host.txt";host.write_text("old-host",encoding="utf-8")
        with host.open("r+b",buffering=0) as held,mock.patch.object(reintegrate,"broker_root",return_value=self.broker_root):
            result=reintegrate.handoff_result(self.repo,self.base,commit,tree,paths,diff_sha,"task","run")
            held.seek(0);held.write(b"HOSTILE!");held.flush()
            ref=subprocess.run(["git","--git-dir",str(self.broker_root/"handoff.git"),"show-ref","--verify","--hash",result.result_ref],capture_output=True,text=True,check=True).stdout.strip()
        self.assertEqual(ref,commit);self.assertEqual(result.result_commit,commit);self.assertNotEqual(host.read_bytes(),b"protected-result\n")
    def test_same_task_run_result_ref_cannot_be_reused(self):
        (self.repo/"allowed.txt").write_text("one\n",encoding="utf-8");commit,tree,paths,diff_sha=reintegrate.create_result_commit(self.repo,self.base,["allowed.txt"],"task","run")
        with mock.patch.object(reintegrate,"broker_root",return_value=self.broker_root):
            reintegrate.handoff_result(self.repo,self.base,commit,tree,paths,diff_sha,"task","run")
            with self.assertRaisesRegex(reintegrate.ReintegrationError,"already exists/replay"):reintegrate.handoff_result(self.repo,self.base,commit,tree,paths,diff_sha,"task","run")
    def test_result_ref_is_deterministic_and_in_fixed_namespace(self):
        a=reintegrate.result_ref("task","run");b=reintegrate.result_ref("task","run");self.assertEqual(a,b);self.assertTrue(a.startswith("refs/forgeboss/results/"));self.assertNotIn("task",a);self.assertNotIn("run",a)

if __name__=="__main__":unittest.main()
