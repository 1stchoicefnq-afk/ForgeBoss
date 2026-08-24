from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .known_good import IdentityError, verify_build_manifest

CNW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class ActivationError(RuntimeError):
    pass


def _sync_dir(path: Path):
    if os.name == "nt":
        return
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_json(path: Path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(value, fh, sort_keys=True, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        _sync_dir(path.parent)
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass


def _win_api():
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    return ctypes, wintypes, kernel


def _win_process_identity(pid: int):
    ctypes, wintypes, kernel = _win_api()
    handle = kernel.OpenProcess(0x1000, False, int(pid))
    if not handle:
        err = ctypes.get_last_error()
        if err == 87:
            return None
        raise ActivationError(f"cannot query candidate process identity: winerror={err}")
    try:
        creation=wintypes.FILETIME();exit_ft=wintypes.FILETIME();kernel_ft=wintypes.FILETIME();user_ft=wintypes.FILETIME()
        if not kernel.GetProcessTimes(handle,ctypes.byref(creation),ctypes.byref(exit_ft),ctypes.byref(kernel_ft),ctypes.byref(user_ft)):
            raise ActivationError(f"cannot read candidate process creation time: winerror={ctypes.get_last_error()}")
        size=wintypes.DWORD(32768);buf=ctypes.create_unicode_buffer(size.value)
        if not kernel.QueryFullProcessImageNameW(handle,0,buf,ctypes.byref(size)):
            raise ActivationError(f"cannot read candidate process image: winerror={ctypes.get_last_error()}")
        token=(int(creation.dwHighDateTime)<<32)|int(creation.dwLowDateTime)
        return {"pid":int(pid),"startToken":str(token),"exe":os.path.normcase(os.path.realpath(buf.value))}
    finally:
        kernel.CloseHandle(handle)


def _posix_process_identity(pid: int):
    proc=Path("/proc")/str(int(pid))
    if not proc.exists():return None
    try:
        stat=(proc/"stat").read_text(encoding="utf-8");tail=stat[stat.rfind(")")+2:].split();start_token=tail[19];exe=os.path.realpath(os.readlink(proc/"exe"))
    except FileNotFoundError:return None
    except Exception as ex:raise ActivationError("cannot establish candidate process identity") from ex
    return {"pid":int(pid),"startToken":str(start_token),"exe":exe}


def process_identity(pid:int):
    if int(pid)<=0:return None
    return _win_process_identity(pid) if os.name=="nt" else _posix_process_identity(pid)


def _same_process(expected,current)->bool:
    return bool(current) and int(current.get("pid",-1))==int(expected.get("pid",-2)) and str(current.get("startToken"))==str(expected.get("startToken")) and os.path.normcase(str(current.get("exe") or ""))==os.path.normcase(str(expected.get("exe") or ""))


def _wait_candidate_dead(expected,timeout=5.0):
    deadline=time.monotonic()+float(timeout)
    while time.monotonic()<deadline:
        if not _same_process(expected,process_identity(int(expected["pid"]))):return True
        time.sleep(0.05)
    return not _same_process(expected,process_identity(int(expected["pid"])))


def _win_terminate_verified(expected,timeout=5.0):
    ctypes,wintypes,kernel=_win_api();handle=kernel.OpenProcess(0x1000|0x0001|0x00100000,False,int(expected["pid"]))
    if not handle:
        err=ctypes.get_last_error()
        if err==87:return True
        raise ActivationError(f"cannot open candidate for termination: winerror={err}")
    try:
        creation=wintypes.FILETIME();exit_ft=wintypes.FILETIME();kernel_ft=wintypes.FILETIME();user_ft=wintypes.FILETIME()
        if not kernel.GetProcessTimes(handle,ctypes.byref(creation),ctypes.byref(exit_ft),ctypes.byref(kernel_ft),ctypes.byref(user_ft)):
            raise ActivationError(f"cannot revalidate candidate creation time: winerror={ctypes.get_last_error()}")
        token=str((int(creation.dwHighDateTime)<<32)|int(creation.dwLowDateTime))
        if token!=str(expected.get("startToken")):return True
        size=wintypes.DWORD(32768);buf=ctypes.create_unicode_buffer(size.value)
        if not kernel.QueryFullProcessImageNameW(handle,0,buf,ctypes.byref(size)):
            raise ActivationError(f"cannot revalidate candidate image: winerror={ctypes.get_last_error()}")
        if os.path.normcase(os.path.realpath(buf.value))!=os.path.normcase(str(expected.get("exe") or "")):return True
        if not kernel.TerminateProcess(handle,75):raise ActivationError(f"candidate termination failed: winerror={ctypes.get_last_error()}")
        if kernel.WaitForSingleObject(handle,max(1,int(float(timeout)*1000)))==0x00000102:return False
    finally:kernel.CloseHandle(handle)
    return _wait_candidate_dead(expected,0.5)


def _posix_terminate_verified(expected,timeout=5.0):
    if not _same_process(expected,process_identity(int(expected["pid"]))):return True
    try:os.kill(int(expected["pid"]),signal.SIGTERM)
    except ProcessLookupError:return True
    if _wait_candidate_dead(expected,min(2.0,timeout)):return True
    if not _same_process(expected,process_identity(int(expected["pid"]))):return True
    try:os.kill(int(expected["pid"]),signal.SIGKILL)
    except ProcessLookupError:return True
    return _wait_candidate_dead(expected,max(0.5,timeout-2.0))


def terminate_verified_process(expected,timeout=5.0):
    if not isinstance(expected,dict) or not expected.get("pid") or not expected.get("startToken") or not expected.get("exe"):raise ActivationError("candidate process identity is missing or incomplete")
    return _win_terminate_verified(expected,timeout) if os.name=="nt" else _posix_terminate_verified(expected,timeout)


class ActivationManager:
    def __init__(self,state_dir,running_identity):
        self.state_dir=Path(state_dir);self.state_dir.mkdir(parents=True,exist_ok=True);self.state_path=self.state_dir/"activation.json";self.pointer_path=self.state_dir/"known-good.json";self.running_identity=dict(running_identity or {})

    def status(self):
        if not self.state_path.exists():return {"phase":"IDLE","running":self.running_identity}
        try:value=json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception as ex:raise ActivationError("activation state is unreadable") from ex
        if not isinstance(value,dict):raise ActivationError("activation state is invalid")
        return value

    def known_good_pointer(self):
        if not self.pointer_path.exists():return None
        try:value=json.loads(self.pointer_path.read_text(encoding="utf-8"))
        except Exception as ex:raise ActivationError("known-good pointer is unreadable") from ex
        if not isinstance(value,dict):raise ActivationError("known-good pointer is invalid")
        return value

    def stage(self,candidate_root,manifest_path,expected_revision=None,expected_manifest_sha256=None):
        if self.running_identity.get("verified") is not True:raise ActivationError("activation requires a verified running known-good controller identity")
        candidate_root=Path(candidate_root).resolve(strict=True);running_root=Path(self.running_identity.get("codeRoot") or "").resolve(strict=True)
        if candidate_root==running_root:raise ActivationError("candidate must be a distinct checkout; in-place activation denied")
        try:candidate=verify_build_manifest(manifest_path,candidate_root,expected_revision,expected_manifest_sha256)
        except IdentityError as ex:raise ActivationError(str(ex)) from ex
        state={"schema":1,"phase":"STAGED","updatedAt":time.time(),"prior":self.running_identity,"candidate":candidate,"probe":None,"pid":None,"processIdentity":None,"activationNonce":None,"parentPID":os.getpid(),"reason":None};_atomic_json(self.state_path,state);return state

    def start_candidate(self,extra_args=None,extra_env=None):
        state=self.status()
        if state.get("phase")!="STAGED":raise ActivationError("candidate must be STAGED before start")
        candidate=state.get("candidate") or {};root=Path(candidate["codeRoot"]).resolve(strict=True);entry=(root/candidate["entrypoint"]).resolve(strict=True)
        if entry.suffix.lower()!=".py":raise ActivationError("candidate entrypoint must be a Python file")
        try:
            if os.path.commonpath([str(root),str(entry)])!=str(root):raise ActivationError("candidate entrypoint escapes candidate root")
        except ValueError as ex:raise ActivationError("candidate entrypoint escapes candidate root") from ex
        nonce=secrets.token_hex(32);state.update({"phase":"STARTING","activationNonce":nonce,"parentPID":os.getpid(),"updatedAt":time.time()});_atomic_json(self.state_path,state)
        env=os.environ.copy();env.update(extra_env or {});env.update({"FORGEBOSS_SELF_BUILD_MODE":"YES","FORGEBOSS_BUILD_MANIFEST":candidate["manifestPath"],"FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA":candidate["revision"],"FORGEBOSS_EXPECTED_MANIFEST_SHA256":candidate["manifestSha256"],"FORGEBOSS_ACTIVATION_NONCE":nonce,"FORGEBOSS_ACTIVATION_STATE":str(self.state_path.resolve()),"FORGEBOSS_ACTIVATION_PARENT_PID":str(os.getpid())})
        try:proc=subprocess.Popen([sys.executable,str(entry),*(extra_args or [])],cwd=str(root),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=CNW)
        except Exception as ex:state.update({"phase":"QUARANTINED","reason":"candidate start failed: "+str(ex),"updatedAt":time.time()});_atomic_json(self.state_path,state);raise ActivationError("candidate process failed to start") from ex
        state["pid"]=int(proc.pid)
        try:identity=process_identity(proc.pid)
        except Exception as ex:
            try:proc.terminate();proc.wait(timeout=5)
            except Exception:pass
            state.update({"phase":"QUARANTINED","reason":"candidate process identity unavailable","updatedAt":time.time()});_atomic_json(self.state_path,state);raise ActivationError("candidate process identity unavailable") from ex
        if not identity:state.update({"phase":"QUARANTINED","reason":"candidate exited before identity could be established","updatedAt":time.time()});_atomic_json(self.state_path,state);raise ActivationError("candidate exited before identity could be established")
        state["processIdentity"]=identity;state["updatedAt"]=time.time();_atomic_json(self.state_path,state);return proc

    def begin_probe(self):
        state=self.status()
        if state.get("phase") not in {"STAGED","STARTING"}:raise ActivationError("candidate is not ready for probe")
        state["phase"]="PROBING";state["updatedAt"]=time.time();_atomic_json(self.state_path,state);return state

    def record_probe(self,result):
        state=self.status()
        if state.get("phase") not in {"STARTING","PROBING"}:raise ActivationError("candidate is not in probe phase")
        if not isinstance(result,dict):raise ActivationError("probe result must be an object")
        candidate=state.get("candidate") or {};required=("startup","health","control","selftests","multiAgent")
        if any(result.get(k) is not True for k in required):self.rollback("candidate probe failed");raise ActivationError("candidate probe failed")
        identity=result.get("identity") or {}
        if identity.get("revision")!=candidate.get("revision") or identity.get("manifestSha256")!=candidate.get("manifestSha256"):self.rollback("candidate identity mismatch during probe");raise ActivationError("candidate probe identity mismatch")
        state["phase"]="PROBED";state["probe"]={k:result.get(k) for k in required};state["probe"]["identity"]=identity;state["updatedAt"]=time.time();_atomic_json(self.state_path,state);return state

    def promote(self):
        state=self.status()
        if state.get("phase")!="PROBED":raise ActivationError("candidate must pass probes before promotion")
        pointer={"schema":1,"current":state["candidate"],"previous":state.get("prior"),"promotedAt":time.time()};_atomic_json(self.pointer_path,pointer);state["phase"]="PROMOTED";state["updatedAt"]=time.time();_atomic_json(self.state_path,state);return pointer

    def _fence_candidate_or_quarantine(self,state,reason):
        if not state.get("pid"):return True
        identity=state.get("processIdentity")
        if not identity:state.update({"phase":"QUARANTINED","reason":"cannot prove candidate process identity during rollback","updatedAt":time.time()});_atomic_json(self.state_path,state);return False
        state.update({"phase":"ROLLBACK_PENDING","reason":str(reason),"updatedAt":time.time()});_atomic_json(self.state_path,state)
        try:dead=terminate_verified_process(identity,5.0)
        except Exception as ex:state.update({"phase":"QUARANTINED","reason":"candidate termination could not be proven: "+str(ex),"updatedAt":time.time()});_atomic_json(self.state_path,state);return False
        if not dead:state.update({"phase":"QUARANTINED","reason":"candidate remained alive after bounded termination","updatedAt":time.time()});_atomic_json(self.state_path,state);return False
        return True

    def rollback(self,reason="activation rollback"):
        state=self.status();prior=state.get("prior") or self.running_identity
        if not self._fence_candidate_or_quarantine(state,reason):raise ActivationError("rollback quarantined: candidate death not proven")
        pointer={"schema":1,"current":prior,"previous":None,"rolledBackAt":time.time(),"reason":reason};_atomic_json(self.pointer_path,pointer);state=self.status();state.update({"phase":"ROLLED_BACK","reason":str(reason),"updatedAt":time.time()});_atomic_json(self.state_path,state);return pointer

    def recover(self):
        state=self.status()
        if state.get("phase") in {"STAGED","STARTING","PROBING","PROBED","ROLLBACK_PENDING"}:return self.rollback("recovered incomplete activation")
        if state.get("phase")=="QUARANTINED":raise ActivationError("activation recovery blocked by quarantined candidate")
        return self.known_good_pointer()

    def activation_health(self,healthy:bool):
        state=self.status()
        if state.get("phase")!="PROMOTED":raise ActivationError("activation health is only valid after promotion")
        if healthy:return self.known_good_pointer()
        return self.rollback("promoted candidate failed activation health window")
