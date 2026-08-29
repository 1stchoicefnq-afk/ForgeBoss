from __future__ import annotations
import os,signal,subprocess,time
from typing import Callable,Mapping,Sequence
from .supervisor_common import *
from .supervisor_windows import WindowsSuspendedProcess

class _PosixProcess:
    def __init__(self,argv,cwd,env):
        self.proc=subprocess.Popen(list(argv),cwd=cwd,env=dict(env),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False,start_new_session=True);self.pid=int(self.proc.pid);self.pgid=self.pid
    def resume(self):return
    def poll(self):return self.proc.poll()
    def tree_alive(self):return posix_group_alive(self.pgid)
    def terminate(self):
        try:os.killpg(self.pgid,signal.SIGTERM)
        except ProcessLookupError:pass
    def kill(self):
        try:os.killpg(self.pgid,signal.SIGKILL)
        except ProcessLookupError:pass
    def wait_leader(self,timeout):
        try:self.proc.wait(timeout=max(.1,float(timeout)))
        except subprocess.TimeoutExpired as ex:raise SupervisorError("POSIX process leader did not exit") from ex
    def close(self):return

def _check_authority(authority_check,stage):
    try:
        if authority_check() is not True:raise SupervisorError(f"paid worker authority is not active at {stage}")
    except SupervisorError:raise
    except Exception as ex:raise SupervisorError(f"paid worker authority check failed at {stage}") from ex

def _launch_windows_suspended(argv,cwd,env,authority_check,factory=WindowsSuspendedProcess):
    child=factory(argv,cwd,env)
    try:_check_authority(authority_check,"pre-resume");child.resume();return child
    except Exception:
        try:child.terminate()
        except Exception:pass
        try:child.wait_leader(1.0)
        except Exception:pass
        child.close();raise

def run_supervised(argv:Sequence[str],authority_check:Callable[[],bool],*,cwd=None,env:Mapping[str,str]|None=None,poll_seconds=.10,terminate_grace_seconds=2.0,max_runtime_seconds:float|None=None)->SupervisedResult:
    argv=validate_argv(argv);cwd=validate_cwd(cwd);env=validate_env(env)
    if not callable(authority_check):raise TypeError("authority_check must be callable")
    poll_seconds=float(poll_seconds);terminate_grace_seconds=float(terminate_grace_seconds)
    if poll_seconds<=0 or terminate_grace_seconds<0:raise ValueError("supervisor timing values are invalid")
    if max_runtime_seconds is not None and float(max_runtime_seconds)<=0:raise ValueError("max_runtime_seconds must be positive")
    _check_authority(authority_check,"pre-launch");started=time.time();child=_launch_windows_suspended(argv,cwd,env,authority_check) if os.name=="nt" else _PosixProcess(argv,cwd,env)
    escalated=quarantined=revoked=False;reason="completed";deadline=None if max_runtime_seconds is None else time.monotonic()+float(max_runtime_seconds)
    try:
        while True:
            rc=child.poll();tree=child.tree_alive()
            if rc is not None:
                if not tree:break
                revoked=quarantined=True;reason="orphan-descendant";break
            if deadline is not None and time.monotonic()>=deadline:revoked=quarantined=True;reason="runtime-limit";break
            try:active=authority_check() is True
            except Exception:active=False;reason="authority-check-failed"
            if not active:
                revoked=quarantined=True
                if reason=="completed":reason="authority-revoked"
                break
            time.sleep(poll_seconds)
        if revoked:
            child.terminate()
            if os.name=="nt":
                if not wait_until(lambda:not child.tree_alive(),terminate_grace_seconds,poll_seconds):raise SupervisorError("Windows Job still has active processes after termination")
            elif not wait_until(lambda:not child.tree_alive(),terminate_grace_seconds,poll_seconds):
                escalated=True;child.kill()
                if not wait_until(lambda:not child.tree_alive(),max(1.0,terminate_grace_seconds),poll_seconds):raise SupervisorError("POSIX process group survived SIGKILL")
            child.wait_leader(max(1.0,terminate_grace_seconds))
        rc=child.poll();tree_terminated=not child.tree_alive()
        if not tree_terminated:quarantined=True;reason="tree-still-live"
        return SupervisedResult(rc,revoked,escalated,quarantined,tree_terminated,reason,child.pid,started,time.time())
    finally:child.close()
