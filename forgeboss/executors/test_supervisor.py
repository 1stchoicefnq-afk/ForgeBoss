from __future__ import annotations
import os,sys,tempfile,unittest
from pathlib import Path
from forgeboss.executors.supervisor import SupervisorError,_configure_windows_api,run_supervised


class SupervisorContractTests(unittest.TestCase):
    def test_windows_api_prototypes_are_explicit(self):
        import ctypes
        from ctypes import wintypes
        class Fn:
            argtypes=None;restype=None
        class Kernel: pass
        k=Kernel()
        for name in ("CreateJobObjectW","SetInformationJobObject","OpenProcess","AssignProcessToJobObject","TerminateJobObject","QueryInformationJobObject","CloseHandle"):
            setattr(k,name,Fn())
        _configure_windows_api(k,ctypes,wintypes)
        self.assertIs(k.CreateJobObjectW.restype,wintypes.HANDLE)
        self.assertIs(k.OpenProcess.restype,wintypes.HANDLE)
        self.assertEqual(k.AssignProcessToJobObject.argtypes,[wintypes.HANDLE,wintypes.HANDLE])
        self.assertIs(k.QueryInformationJobObject.restype,wintypes.BOOL)

@unittest.skipIf(os.name=="nt","POSIX behavioral suite; Windows Job behavior needs native runner")
class SupervisorPosixTests(unittest.TestCase):
    def test_successful_child(self):
        r=run_supervised([sys.executable,"-c","print('ok')"],lambda:True,poll_seconds=.01)
        self.assertEqual(r.exit_code,0);self.assertFalse(r.revoked);self.assertFalse(r.quarantined);self.assertTrue(r.tree_terminated)
    def test_revoke_before_start_runs_zero_child(self):
        with tempfile.TemporaryDirectory() as td:
            marker=Path(td)/"ran"
            with self.assertRaises(SupervisorError):run_supervised([sys.executable,"-c",f"open({str(marker)!r},'w').write('x')"],lambda:False)
            self.assertFalse(marker.exists())
    def test_revoke_kills_child_and_grandchild(self):
        s={"n":0}
        def auth():s["n"]+=1;return s["n"]<4
        code="import subprocess,sys,time;subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);time.sleep(60)"
        r=run_supervised([sys.executable,"-c",code],auth,poll_seconds=.03,terminate_grace_seconds=.4)
        self.assertTrue(r.revoked);self.assertTrue(r.quarantined);self.assertTrue(r.tree_terminated)
    def test_sigterm_resistant_descendant_requires_escalation(self):
        with tempfile.TemporaryDirectory() as td:
            ready=Path(td)/"ready"
            child=f"import signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);Path({str(ready)!r}).write_text('1');time.sleep(60)"
            code=f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child!r}]);time.sleep(60)"
            def auth(): return not ready.exists()
            r=run_supervised([sys.executable,"-c",code],auth,poll_seconds=.01,terminate_grace_seconds=.15)
            self.assertTrue(ready.exists());self.assertTrue(r.escalated);self.assertTrue(r.tree_terminated);self.assertTrue(r.quarantined)
    def test_authority_channel_failure_fails_closed(self):
        s={"n":0}
        def auth():
            s["n"]+=1
            if s["n"]>=3:raise RuntimeError("store unavailable")
            return True
        r=run_supervised([sys.executable,"-c","import time;time.sleep(60)"],auth,poll_seconds=.03,terminate_grace_seconds=.2)
        self.assertEqual(r.reason,"authority-check-failed");self.assertTrue(r.revoked);self.assertTrue(r.quarantined);self.assertTrue(r.tree_terminated)
    def test_parent_exit_with_live_descendant_is_quarantined_and_killed(self):
        code="import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])"
        r=run_supervised([sys.executable,"-c",code],lambda:True,poll_seconds=.02,terminate_grace_seconds=.2)
        self.assertEqual(r.reason,"orphan-descendant");self.assertTrue(r.revoked);self.assertTrue(r.quarantined);self.assertTrue(r.tree_terminated)
if __name__=="__main__":unittest.main()
