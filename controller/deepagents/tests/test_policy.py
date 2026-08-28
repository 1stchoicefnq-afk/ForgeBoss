import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from siteboss_policy import *
class T(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);(self.root/"src").mkdir();(self.root/"tests").mkdir();(self.root/"src"/"ok.js").write_text("a");(self.root/"src"/"no.js").write_text("x")
  self.p=ImmutablePacket("P","abc","builder",("src/ok.js","tests"),("src/ok.js","tests/new.js"),max_commands=2,max_file_modifications=1);self.w=GuardedWorkspace(self.root,self.p)
 def tearDown(self):self.tmp.cleanup()
 def test_authorized(self):self.w.write_text("src/ok.js","b")
 def test_unauthorized(self):
  with self.assertRaises(SecurityDenial):self.w.write_text("src/no.js","b")
 def test_parent(self):
  with self.assertRaises(SecurityDenial):self.w.write_text("../secret","x")
 def test_drive(self):
  with self.assertRaises(SecurityDenial):self.w.write_text(r"C:\\outside\\file","x")
 def test_unc(self):
  with self.assertRaises(SecurityDenial):self.w.write_text(r"\\\\server\\share\\x","x")
 def test_read(self):
  with self.assertRaises(SecurityDenial):self.w.read_text("src/no.js")
 def test_file_budget(self):
  self.w.write_text("src/ok.js","b")
  with self.assertRaises(BudgetExceeded):self.w.write_text("tests/new.js","x")
 def test_command_denied(self):
  with self.assertRaises(SecurityDenial):self.w.run_command(["git","status"])
 def test_python3_allowed(self):
  self.w.run_command(["python3","-c","print(1)"])
 def test_command_budget(self):
  self.w.run_command([sys.executable,"-c","print(1)"]);self.w.run_command([sys.executable,"-c","print(2)"])
  with self.assertRaises(BudgetExceeded):self.w.run_command([sys.executable,"-c","print(3)"])
 def test_stale_head(self):
  with self.assertRaises(StalePacket):revalidate_resume(self.p,"def",True,True)
 def test_lease(self):
  with self.assertRaises(StalePacket):revalidate_resume(self.p,"abc",False,True)
 def test_controller(self):
  with self.assertRaises(StalePacket):revalidate_resume(self.p,"abc",True,False)
 def test_symlink_escape(self):
  outside=Path(self.tmp.name).parent/"sb-outside";outside.mkdir(exist_ok=True);link=self.root/"tests"/"link"
  try:link.symlink_to(outside,target_is_directory=True)
  except OSError:self.skipTest("symlink unavailable")
  with self.assertRaises(SecurityDenial):self.w.write_text("tests/link/x","x")
  try:outside.rmdir()
  except OSError:pass
if __name__=="__main__":unittest.main(verbosity=2)
