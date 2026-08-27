from __future__ import annotations
import os, signal, subprocess, time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

class SupervisorError(RuntimeError): pass

@dataclass(frozen=True)
class StopEvidence:
    pid: int
    requested_at: float
    terminated_at: float
    exit_code: int
    escalated: bool

def _finite_positive(value, name):
    if isinstance(value, bool):
        raise SupervisorError(f"{name} must be finite positive")
    try:
        x=float(value)
    except Exception as ex:
        raise SupervisorError(f"{name} must be finite positive") from ex
    if not (x > 0.0 and x < float("inf")):
        raise SupervisorError(f"{name} must be finite positive")
    return x

class ExecutorSupervisor:
    """Owns one child process tree and can synchronously revoke it.

    The caller remains responsible for durable controller authorization.
    This class only turns an already-authorized stop decision into process fencing.
    """
    def __init__(self, args: Sequence[str], *, cwd=None, env=None):
        if not isinstance(args, (list,tuple)) or not args or any(not isinstance(x,str) or not x for x in args):
            raise SupervisorError("args must be a non-empty string sequence")
        self.args=tuple(args); self.cwd=cwd; self.env=env
        self.process: Optional[subprocess.Popen] = None

    def start(self):
        if self.process is not None:
            raise SupervisorError("process already started")
        kwargs=dict(cwd=self.cwd, env=self.env)
        if os.name=="nt":
            flags=getattr(subprocess,"CREATE_NEW_PROCESS_GROUP",0)
            kwargs["creationflags"]=flags
        else:
            kwargs["start_new_session"]=True
        self.process=subprocess.Popen(self.args, **kwargs)
        return self.process.pid

    def poll(self):
        return None if self.process is None else self.process.poll()

    def _terminate_tree(self):
        p=self.process
        if p is None:
            raise SupervisorError("process not started")
        if p.poll() is not None:
            return
        if os.name=="nt":
            cp=subprocess.run(["taskkill","/PID",str(p.pid),"/T"],capture_output=True,text=True)
            if cp.returncode not in (0,128):
                raise SupervisorError(f"taskkill terminate failed: {cp.returncode}")
        else:
            try: os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError: pass

    def _kill_tree(self):
        p=self.process
        if p is None:
            raise SupervisorError("process not started")
        if p.poll() is not None:
            return
        if os.name=="nt":
            cp=subprocess.run(["taskkill","/PID",str(p.pid),"/T","/F"],capture_output=True,text=True)
            if cp.returncode not in (0,128):
                raise SupervisorError(f"taskkill force failed: {cp.returncode}")
        else:
            try: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass

    def stop(self, *, grace_seconds=2.0, kill_wait_seconds=3.0, now:Callable[[],float]=time.time):
        p=self.process
        if p is None:
            raise SupervisorError("process not started")
        grace=_finite_positive(grace_seconds,"grace_seconds")
        kill_wait=_finite_positive(kill_wait_seconds,"kill_wait_seconds")
        requested=now()
        escalated=False
        if p.poll() is None:
            self._terminate_tree()
            try:
                p.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                escalated=True
                self._kill_tree()
                try:
                    p.wait(timeout=kill_wait)
                except subprocess.TimeoutExpired as ex:
                    raise SupervisorError("executor process tree did not exit after force kill") from ex
        code=p.poll()
        if code is None:
            raise SupervisorError("executor process tree still running after stop")
        return StopEvidence(pid=p.pid, requested_at=requested, terminated_at=now(),
                            exit_code=int(code), escalated=escalated)

    def run_until_revoked(self, revoked:Callable[[],bool], *, poll_seconds=0.1,
                          grace_seconds=2.0, kill_wait_seconds=3.0, now=time.time):
        if not callable(revoked):
            raise SupervisorError("revoked callback required")
        interval=_finite_positive(poll_seconds,"poll_seconds")
        if self.process is None:
            self.start()
        while True:
            code=self.process.poll()
            if code is not None:
                return {"exitCode":int(code),"revoked":False,"stopEvidence":None}
            if revoked():
                ev=self.stop(grace_seconds=grace_seconds, kill_wait_seconds=kill_wait_seconds, now=now)
                return {"exitCode":ev.exit_code,"revoked":True,"stopEvidence":ev}
            time.sleep(interval)
