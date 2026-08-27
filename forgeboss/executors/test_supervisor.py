from __future__ import annotations
import os, tempfile, time, unittest
from pathlib import Path
from unittest.mock import patch
from forgeboss.executors.supervisor import ExecutorSupervisor, SupervisorError

SHELL="/bin/sh"

class SupervisorTests(unittest.TestCase):
    @unittest.skipIf(os.name=="nt","POSIX shell regression")
    def test_rejects_invalid_args_and_timeouts(self):
        with self.assertRaises(SupervisorError): ExecutorSupervisor([])
        s=ExecutorSupervisor([SHELL,"-c","sleep 0.05"])
        s.start()
        with self.assertRaises(SupervisorError): s.stop(grace_seconds=0)
        if s.poll() is None: s.stop(grace_seconds=.2,kill_wait_seconds=.5)

    @unittest.skipIf(os.name=="nt","POSIX process-group proof")
    def test_revocation_terminates_parent_and_child_tree(self):
        with tempfile.TemporaryDirectory() as td:
            marker=Path(td)/"child.pid"
            script=f"sleep 60 & child=$!; echo $child > {marker}; wait $child"
            s=ExecutorSupervisor([SHELL,"-c",script])
            state={"n":0}
            def revoked():
                state["n"]+=1
                return state["n"]>=3
            start=time.time()
            out=s.run_until_revoked(revoked,poll_seconds=.05,grace_seconds=.3,kill_wait_seconds=1)
            self.assertTrue(out["revoked"])
            self.assertIsNotNone(s.poll())
            self.assertLess(time.time()-start,3)
            child=int(marker.read_text().strip())
            deadline=time.time()+1.5
            alive=True
            while time.time()<deadline:
                try: os.kill(child,0)
                except ProcessLookupError:
                    alive=False;break
                time.sleep(.05)
            if alive:
                stat=Path(f"/proc/{child}/stat")
                if stat.exists():
                    self.assertEqual(stat.read_text().split()[2],"Z")

    @unittest.skipIf(os.name=="nt","POSIX shell regression")
    def test_natural_exit_does_not_claim_revocation(self):
        s=ExecutorSupervisor([SHELL,"-c","exit 0"])
        out=s.run_until_revoked(lambda:False,poll_seconds=.01)
        self.assertFalse(out["revoked"])
        self.assertEqual(out["exitCode"],0)

    @unittest.skipIf(os.name=="nt","POSIX escalation proof")
    def test_escalates_when_sigterm_ignored(self):
        script="trap '' TERM; sleep 60 & wait $!"
        s=ExecutorSupervisor([SHELL,"-c",script]);s.start();time.sleep(.1)
        ev=s.stop(grace_seconds=.1,kill_wait_seconds=1)
        self.assertTrue(ev.escalated)
        self.assertIsNotNone(s.poll())

    def test_windows_commands_are_tree_scoped(self):
        fake=type("P",(),{})()
        fake.pid=1234;fake._poll=None
        fake.poll=lambda:fake._poll
        fake.wait=lambda timeout=None: setattr(fake,"_poll",1) or 1
        s=ExecutorSupervisor(["x"]);s.process=fake
        cp=type("CP",(),{"returncode":0})()
        with patch("forgeboss.executors.supervisor.os.name","nt"), patch("forgeboss.executors.supervisor.subprocess.run",return_value=cp) as run:
            ev=s.stop(grace_seconds=.1,kill_wait_seconds=.1)
            run.assert_called_once_with(["taskkill","/PID","1234","/T"],capture_output=True,text=True)
            self.assertFalse(ev.escalated)

    @unittest.skipIf(os.name=="nt","POSIX shell regression")
    def test_stop_is_idempotent_after_exit(self):
        s=ExecutorSupervisor([SHELL,"-c","exit 0"]);s.start();s.process.wait(timeout=1)
        a=s.stop();b=s.stop()
        self.assertEqual(a.exit_code,b.exit_code)

if __name__=="__main__":unittest.main()
