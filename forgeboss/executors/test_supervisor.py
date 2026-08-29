from __future__ import annotations
import ctypes,os,subprocess,sys,tempfile,unittest
from ctypes import wintypes
from pathlib import Path
from forgeboss.executors.supervisor import (
    CREATE_BREAKAWAY_FROM_JOB,CREATE_SUSPENDED,CREATE_UNICODE_ENVIRONMENT,SupervisorError,
    configure_windows_api,_launch_windows_suspended,windows_command_line,windows_environment_block,run_supervised,
)

class ContractTests(unittest.TestCase):
    def test_windows_flags_contract(self):
        self.assertTrue(CREATE_SUSPENDED & 0x4);self.assertTrue(CREATE_UNICODE_ENVIRONMENT & 0x400);self.assertEqual(CREATE_BREAKAWAY_FROM_JOB,0x01000000)
    def test_command_line_handles_spaces_quotes_backslashes_empty(self):
        argv=[r"C:\\Python\\python.exe","",r"a b",'x"y',r"tail\\"]
        line=windows_command_line(argv)
        self.assertIn('""',line);self.assertIn('"a b"',line);self.assertIn('\\"',line)
    def test_windows_env_block_rejects_case_collision_and_nul(self):
        with self.assertRaises(ValueError):windows_environment_block({"Path":"a","PATH":"b"})
        with self.assertRaises(ValueError):windows_environment_block({"A":"x\x00y"})
        self.assertTrue(windows_environment_block({"B":"2","a":"1"}).endswith("\x00\x00"))
    def test_ffi_prototypes_explicit(self):
        class Fn:argtypes=None;restype=None
        class K:pass
        k=K()
        names=("CreateJobObjectW","SetInformationJobObject","AssignProcessToJobObject","TerminateJobObject","QueryInformationJobObject","CreateProcessW","ResumeThread","TerminateProcess","WaitForSingleObject","GetExitCodeProcess","GetProcessTimes","QueryFullProcessImageNameW","CloseHandle")
        for n in names:setattr(k,n,Fn())
        configure_windows_api(k,ctypes,wintypes)
        self.assertIs(k.CreateJobObjectW.restype,wintypes.HANDLE);self.assertIs(k.CreateProcessW.restype,wintypes.BOOL);self.assertIs(k.ResumeThread.restype,wintypes.DWORD)
    def test_suspended_order_assign_then_authority_then_resume(self):
        events=[]
        class Fake:
            pid=123
            def __init__(self,a,c,e):events.append("create-suspended+assign")
            def resume(self):events.append("resume")
            def terminate(self):events.append("terminate")
            def wait_leader(self,t):events.append("wait")
            def close(self):events.append("close")
        def auth():events.append("authority");return True
        child=_launch_windows_suspended([sys.executable,"-c","pass"],None,dict(os.environ),auth,factory=Fake)
        self.assertEqual(events[:3],["create-suspended+assign","authority","resume"]);child.close()
    def test_pre_resume_revoke_never_resumes(self):
        events=[]
        class Fake:
            pid=1
            def __init__(self,a,c,e):events.append("create-suspended+assign")
            def resume(self):events.append("resume")
            def terminate(self):events.append("terminate")
            def wait_leader(self,t):events.append("wait")
            def close(self):events.append("close")
        with self.assertRaises(SupervisorError):_launch_windows_suspended([sys.executable,"-c","pass"],None,dict(os.environ),lambda:False,factory=Fake)
        self.assertNotIn("resume",events);self.assertIn("terminate",events)
    def test_relative_and_nul_inputs_rejected(self):
        with self.assertRaises(ValueError):run_supervised(["python","-c","pass"],lambda:True)
        with self.assertRaises(ValueError):run_supervised([sys.executable,"x\x00y"],lambda:True)

@unittest.skipIf(os.name=="nt","POSIX suite")
class PosixTests(unittest.TestCase):
    def test_success(self):
        r=run_supervised([sys.executable,"-c","pass"],lambda:True,poll_seconds=.01);self.assertTrue(r.tree_terminated);self.assertFalse(r.revoked)
    def test_revoke_before_start_zero_execution(self):
        with tempfile.TemporaryDirectory() as td:
            m=Path(td)/"ran"
            with self.assertRaises(SupervisorError):run_supervised([sys.executable,"-c",f"open({str(m)!r},'w').write('x')"],lambda:False)
            self.assertFalse(m.exists())
    def test_child_grandchild_killed(self):
        state={"n":0}
        def auth():state["n"]+=1;return state["n"]<4
        code="import subprocess,sys,time;subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);time.sleep(60)"
        r=run_supervised([sys.executable,"-c",code],auth,poll_seconds=.03,terminate_grace_seconds=.3);self.assertTrue(r.revoked);self.assertTrue(r.tree_terminated)
    def test_escalation(self):
        with tempfile.TemporaryDirectory() as td:
            ready=Path(td)/"ready";child=f"import signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);Path({str(ready)!r}).write_text('1');time.sleep(60)";code=f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child!r}]);time.sleep(60)"
            r=run_supervised([sys.executable,"-c",code],lambda:not ready.exists(),poll_seconds=.01,terminate_grace_seconds=.15);self.assertTrue(r.escalated);self.assertTrue(r.tree_terminated)
if __name__=="__main__":unittest.main()
