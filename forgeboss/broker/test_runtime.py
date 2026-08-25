from __future__ import annotations
import inspect,subprocess,tempfile,unittest
from pathlib import Path
from unittest import mock
from forgeboss.broker import runtime
class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.root=Path(self.td.name);self.source=self.root/"source";self.source.mkdir();self._git("init","-q");self._git("config","user.email","test@example.com");self._git("config","user.name","Test");self._git("config","core.autocrlf","false");(self.source/"x.py").write_text("before\n",encoding="utf-8");self._git("add","x.py");self._git("commit","-qm","base");self.base=self._git("rev-parse","HEAD");self.protected=self.root/"protected";self.protected.mkdir()
    def tearDown(self):self.td.cleanup()
    def _git(self,*args):return subprocess.run(["git",*args],cwd=self.source,capture_output=True,text=True,check=True).stdout.strip()
    def test_materialize_base_uses_independent_no_hardlink_clone_at_exact_sha(self):
        with mock.patch.object(runtime,"broker_root",return_value=self.protected),mock.patch.object(runtime,"_assert_private_root",return_value=self.protected.resolve()):repo=runtime.materialize_base(self.source,self.base,"run-1",root=self.protected)
        self.assertEqual(runtime.git(repo,"rev-parse","HEAD"),self.base);(repo/"x.py").write_text("private\n",encoding="utf-8");self.assertEqual((self.source/"x.py").read_text(encoding="utf-8"),"before\n");self.assertFalse((repo/".git"/"objects"/"info"/"alternates").exists())
    def test_runtime_source_uses_private_mount_network_none_and_cost_limit(self):
        src=inspect.getsource(runtime.run_mini_swe);self.assertIn("--network",src);self.assertIn("none",src);self.assertIn("src={repo}",src);self.assertIn("cost_limit=budget",src);self.assertIn("LitellmModel",src);self.assertIn("DockerEnvironment",src)
    def test_git_subprocess_env_is_allowlisted_not_wholesale_host_environment(self):
        src=inspect.getsource(runtime._git_env);self.assertNotIn("{**os.environ",src);self.assertIn("keep=",src);self.assertIn("GIT_CONFIG_NOSYSTEM",src);self.assertIn("GIT_TERMINAL_PROMPT",src)
    def test_private_root_is_fixed_and_no_environment_override_exists(self):
        src=inspect.getsource(runtime);self.assertNotIn("FORGEBOSS_BROKER_ROOT",src);self.assertNotIn("shutil.which",src);self.assertIn("broker_root()",src);self.assertIn("private clone retained external object alternates",src)
if __name__=="__main__":unittest.main()
