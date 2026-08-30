from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
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


def _read_json(path: Path, label: str):
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as ex:
        raise ActivationError(f"{label} is unreadable") from ex
    if not isinstance(value, dict):
        raise ActivationError(f"{label} is invalid")
    return value


@contextmanager
def _state_lock(path: Path, timeout: float = 10.0):
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = path.open("a+b")
    deadline = time.monotonic() + float(timeout)
    locked = False
    try:
        while not locked:
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    if not fh.read(1):
                        fh.seek(0); fh.write(b"0"); fh.flush()
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise ActivationError("activation state lock timed out")
                time.sleep(0.025)
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0); msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        fh.close()


def _posix_identity(pid: int):
    proc = Path("/proc") / str(int(pid))
    if not proc.exists():
        return None
    try:
        stat = (proc / "stat").read_text(encoding="utf-8")
        tail = stat[stat.rfind(")") + 2:].split()
        return {"pid": int(pid), "startToken": str(tail[19]), "exe": os.path.realpath(os.readlink(proc / "exe"))}
    except FileNotFoundError:
        return None
    except Exception as ex:
        raise ActivationError("cannot establish candidate process identity") from ex


def _win_api():
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];k.OpenProcess.restype=wintypes.HANDLE
    k.CloseHandle.argtypes=[wintypes.HANDLE];k.CloseHandle.restype=wintypes.BOOL
    k.GetProcessTimes.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.FILETIME),ctypes.POINTER(wintypes.FILETIME),ctypes.POINTER(wintypes.FILETIME),ctypes.POINTER(wintypes.FILETIME)];k.GetProcessTimes.restype=wintypes.BOOL
    k.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)];k.QueryFullProcessImageNameW.restype=wintypes.BOOL
    k.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT];k.TerminateProcess.restype=wintypes.BOOL
    k.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];k.WaitForSingleObject.restype=wintypes.DWORD
    return ctypes,wintypes,k


def _win_identity(pid: int):
    ctypes,wintypes,k=_win_api();h=k.OpenProcess(0x1000,False,int(pid))
    if not h:
        if ctypes.get_last_error() in {87,1168}: return None
        raise ActivationError("cannot query candidate process identity")
    try:
        c=wintypes.FILETIME();e=wintypes.FILETIME();kt=wintypes.FILETIME();ut=wintypes.FILETIME()
        if not k.GetProcessTimes(h,ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(ut)): raise ActivationError("cannot read candidate process creation time")
        n=wintypes.DWORD(32768);b=ctypes.create_unicode_buffer(n.value)
        if not k.QueryFullProcessImageNameW(h,0,b,ctypes.byref(n)): raise ActivationError("cannot read candidate process image")
        return {"pid":int(pid),"startToken":str((int(c.dwHighDateTime)<<32)|int(c.dwLowDateTime)),"exe":os.path.normcase(os.path.realpath(b.value))}
    finally:k.CloseHandle(h)


def process_identity(pid:int):
    if int(pid)<=0:return None
    return _win_identity(pid) if os.name=="nt" else _posix_identity(pid)


def _same_process(expected,current):
    return bool(current) and int(current.get("pid",-1))==int(expected.get("pid",-2)) and str(current.get("startToken"))==str(expected.get("startToken")) and os.path.normcase(str(current.get("exe") or ""))==os.path.normcase(str(expected.get("exe") or ""))


def terminate_verified_process(expected, timeout=5.0):
    if not isinstance(expected,dict) or not all(expected.get(k) for k in ("pid","startToken","exe")):
        raise ActivationError("candidate process identity is missing or incomplete")
    pid=int(expected["pid"])
    if not _same_process(expected,process_identity(pid)): return True
    if os.name=="nt":
        ctypes,wintypes,k=_win_api();h=k.OpenProcess(0x1000|0x0001|0x00100000,False,pid)
        if not h:return not _same_process(expected,process_identity(pid))
        try:
            current=_win_identity(pid)
            if not _same_process(expected,current):return True
            if not k.TerminateProcess(h,75):raise ActivationError("candidate termination failed")
            if k.WaitForSingleObject(h,max(1,int(float(timeout)*1000)))==0x00000102:return False
            return True
        finally:k.CloseHandle(h)
    try:os.kill(pid,signal.SIGTERM)
    except ProcessLookupError:return True
    deadline=time.monotonic()+min(float(timeout),2.0)
    while time.monotonic()<deadline:
        if not _same_process(expected,process_identity(pid)):return True
        time.sleep(0.05)
    if not _same_process(expected,process_identity(pid)):return True
    try:os.kill(pid,signal.SIGKILL)
    except ProcessLookupError:return True
    deadline=time.monotonic()+max(0.5,float(timeout)-2.0)
    while time.monotonic()<deadline:
        if not _same_process(expected,process_identity(pid)):return True
        time.sleep(0.05)
    return not _same_process(expected,process_identity(pid))


class ActivationManager:
    def __init__(self,state_dir,running_identity):
        self.state_dir=Path(state_dir);self.state_dir.mkdir(parents=True,exist_ok=True)
        self.state_path=self.state_dir/"activation.json";self.pointer_path=self.state_dir/"known-good.json";self.lock_path=self.state_dir/"activation.lock"
        self.running_identity=dict(running_identity or {})

    def status(self):
        v=_read_json(self.state_path,"activation state")
        if v is None:return {"schema":2,"phase":"IDLE","generation":0,"running":self.running_identity}
        if v.get("schema")!=2 or not isinstance(v.get("generation"),int):raise ActivationError("activation state schema/generation is invalid")
        return v

    def known_good_pointer(self):
        v=_read_json(self.pointer_path,"known-good pointer")
        if v is None:return None
        if v.get("schema")!=2 or not isinstance(v.get("generation"),int):raise ActivationError("known-good pointer schema/generation is invalid")
        return v

    def initialize_known_good(self):
        if self.running_identity.get("verified") is not True:raise ActivationError("known-good initialization requires verified running identity")
        with _state_lock(self.lock_path):
            p=self.known_good_pointer()
            if p:
                if (p.get("current") or {}).get("revision")!=self.running_identity.get("revision"):raise ActivationError("existing known-good pointer disagrees with running identity")
                return p
            p={"schema":2,"generation":0,"current":self.running_identity,"previous":None,"updatedAt":time.time()};_atomic_json(self.pointer_path,p);return p

    def _check_generation(self,state,expected):
        if expected is not None and int(expected)!=int(state.get("generation",-1)):raise ActivationError("stale activation generation")

    def stage(self,candidate_root,manifest_path,expected_revision=None,expected_manifest_sha256=None,*,expected_generation=None):
        if self.running_identity.get("verified") is not True:raise ActivationError("activation requires a verified running known-good controller identity")
        root=Path(candidate_root).resolve(strict=True);running=Path(self.running_identity.get("codeRoot") or "").resolve(strict=True)
        if root==running:raise ActivationError("candidate must be a distinct checkout; in-place activation denied")
        try:candidate=verify_build_manifest(manifest_path,root,expected_revision,expected_manifest_sha256)
        except IdentityError as ex:raise ActivationError(str(ex)) from ex
        with _state_lock(self.lock_path):
            s=self.status();self._check_generation(s,expected_generation)
            if s.get("phase") in {"STAGED","STARTING","PROBING","PROBED","PROMOTING","PROMOTED","ROLLBACK_PENDING"}:
                old=s.get("candidate") or {}
                if s.get("phase")=="STAGED" and old.get("revision")==candidate.get("revision") and old.get("manifestSha256")==candidate.get("manifestSha256"):return s
                raise ActivationError("another activation generation is already active")
            p=self.known_good_pointer();prior=(p or {}).get("current") or self.running_identity
            if prior.get("revision")!=self.running_identity.get("revision"):raise ActivationError("running identity is not current known-good authority")
            s={"schema":2,"phase":"STAGED","generation":int(s.get("generation",0))+1,"requestId":secrets.token_hex(16),"prior":prior,"candidate":candidate,"probe":None,"pid":None,"processIdentity":None,"activationNonce":None,"reason":None,"updatedAt":time.time()};_atomic_json(self.state_path,s);return s

    def start_candidate(self,extra_args=None,extra_env=None,*,expected_generation=None):
        with _state_lock(self.lock_path):
            s=self.status();self._check_generation(s,expected_generation)
            if s.get("phase")!="STAGED":raise ActivationError("candidate must be STAGED before start")
            c=s["candidate"];root=Path(c["codeRoot"]).resolve(strict=True);entry=(root/c["entrypoint"]).resolve(strict=True)
            if entry.suffix.lower()!=".py":raise ActivationError("candidate entrypoint must be a Python file")
            try:
                if os.path.commonpath([str(root),str(entry)])!=str(root):raise ActivationError("candidate entrypoint escapes candidate root")
            except ValueError as ex:raise ActivationError("candidate entrypoint escapes candidate root") from ex
            nonce=secrets.token_hex(32);s.update({"phase":"STARTING","activationNonce":nonce,"updatedAt":time.time()});_atomic_json(self.state_path,s)
            env=os.environ.copy();env.update(extra_env or {});env.update({"FORGEBOSS_SELF_BUILD_MODE":"YES","FORGEBOSS_BUILD_MANIFEST":c["manifestPath"],"FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA":c["revision"],"FORGEBOSS_EXPECTED_MANIFEST_SHA256":c["manifestSha256"],"FORGEBOSS_ACTIVATION_NONCE":nonce,"FORGEBOSS_ACTIVATION_GENERATION":str(s["generation"])})
            try:p=subprocess.Popen([sys.executable,str(entry),*(extra_args or [])],cwd=str(root),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=CNW)
            except Exception as ex:s.update({"phase":"QUARANTINED","reason":"candidate start failed","updatedAt":time.time()});_atomic_json(self.state_path,s);raise ActivationError("candidate process failed to start") from ex
            identity=process_identity(p.pid)
            if not identity:
                try:p.terminate();p.wait(timeout=5)
                except Exception:pass
                s.update({"phase":"QUARANTINED","reason":"candidate process identity unavailable","updatedAt":time.time()});_atomic_json(self.state_path,s);raise ActivationError("candidate process identity unavailable")
            s.update({"pid":int(p.pid),"processIdentity":identity,"updatedAt":time.time()});_atomic_json(self.state_path,s);return p

    def begin_probe(self,*,expected_generation=None):
        with _state_lock(self.lock_path):
            s=self.status();self._check_generation(s,expected_generation)
            if s.get("phase") not in {"STAGED","STARTING"}:raise ActivationError("candidate is not ready for probe")
            s["phase"]="PROBING";s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return s

    def record_probe(self,result,*,expected_generation=None):
        failure=None
        with _state_lock(self.lock_path):
            s=self.status();self._check_generation(s,expected_generation)
            if s.get("phase") not in {"STARTING","PROBING"}:raise ActivationError("candidate is not in probe phase")
            if not isinstance(result,dict):raise ActivationError("probe result must be an object")
            c=s.get("candidate") or {};required=("startup","health","control","selftests","multiAgent");ident=result.get("identity") or {}
            healthy=all(result.get(k) is True for k in required)
            bound=ident.get("revision")==c.get("revision") and ident.get("manifestSha256")==c.get("manifestSha256") and ident.get("treeSha256")==c.get("treeSha256") and ident.get("identitySha256")==c.get("identitySha256")
            if s.get("processIdentity"):healthy=healthy and _same_process(s["processIdentity"],process_identity(int(s["processIdentity"]["pid"])))
            if healthy and bound:
                s["phase"]="PROBED";s["probe"]={k:True for k in required};s["probe"]["identity"]=ident;s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return s
            failure="candidate probe failed" if not healthy else "candidate probe identity mismatch"
        self.rollback(failure,expected_generation=expected_generation);raise ActivationError(failure)

    def promote(self,*,expected_generation=None):
        with _state_lock(self.lock_path):
            s=self.status();self._check_generation(s,expected_generation)
            if s.get("phase")=="PROMOTED":
                p=self.known_good_pointer()
                if p and p.get("generation")==s.get("generation") and (p.get("current") or {}).get("revision")==s.get("candidate",{}).get("revision"):return p
                raise ActivationError("promoted state disagrees with known-good pointer")
            if s.get("phase")!="PROBED":raise ActivationError("candidate must pass probes before promotion")
            p=self.known_good_pointer();current=(p or {}).get("current") or s["prior"]
            if current.get("revision")!=s["prior"].get("revision"):raise ActivationError("known-good authority changed before promotion")
            if s.get("processIdentity") and not _same_process(s["processIdentity"],process_identity(int(s["processIdentity"]["pid"]))):raise ActivationError("candidate process identity is no longer live")
            s["phase"]="PROMOTING";s["updatedAt"]=time.time();_atomic_json(self.state_path,s)
            p={"schema":2,"generation":s["generation"],"current":s["candidate"],"previous":s["prior"],"updatedAt":time.time()};_atomic_json(self.pointer_path,p)
            s["phase"]="PROMOTED";s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return p

    def rollback(self,reason="activation rollback",*,expected_generation=None):
        with _state_lock(self.lock_path):
            s=self.status();self._check_generation(s,expected_generation);prior=s.get("prior") or self.running_identity;p=self.known_good_pointer()
            if s.get("phase")=="ROLLED_BACK":
                if p and (p.get("current") or {}).get("revision")==prior.get("revision"):return p
                raise ActivationError("rolled-back state disagrees with known-good pointer")
            if p:
                current=(p.get("current") or {}).get("revision");candidate=(s.get("candidate") or {}).get("revision")
                if current not in {candidate,prior.get("revision")}:raise ActivationError("newer known-good authority prevents stale rollback")
            identity=s.get("processIdentity")
            if identity:
                s["phase"]="ROLLBACK_PENDING";s["reason"]=str(reason);s["updatedAt"]=time.time();_atomic_json(self.state_path,s)
                if not terminate_verified_process(identity,5.0):s["phase"]="QUARANTINED";s["reason"]="candidate remained alive after bounded termination";s["updatedAt"]=time.time();_atomic_json(self.state_path,s);raise ActivationError("rollback quarantined: candidate death not proven")
            p={"schema":2,"generation":int(s.get("generation",0)),"current":prior,"previous":None,"rolledBackAt":time.time(),"reason":str(reason),"updatedAt":time.time()};_atomic_json(self.pointer_path,p)
            s=self.status();s.update({"phase":"ROLLED_BACK","pid":None,"processIdentity":None,"reason":str(reason),"updatedAt":time.time()});_atomic_json(self.state_path,s);return p

    def recover(self):
        with _state_lock(self.lock_path):
            s=self.status();p=self.known_good_pointer();phase=s.get("phase")
            if phase=="PROMOTING" and p and p.get("generation")==s.get("generation") and (p.get("current") or {}).get("revision")==s.get("candidate",{}).get("revision"):
                s["phase"]="PROMOTED";s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return p
            if phase=="PROMOTED":
                if not p or p.get("generation")!=s.get("generation") or (p.get("current") or {}).get("revision")!=s.get("candidate",{}).get("revision"):raise ActivationError("promoted activation cannot be reconciled")
                return p
            if phase=="ROLLED_BACK":
                prior=s.get("prior") or self.running_identity
                if not p or (p.get("current") or {}).get("revision")!=prior.get("revision"):raise ActivationError("rollback pointer cannot be reconciled")
                return p
            if phase=="QUARANTINED":raise ActivationError("activation recovery blocked by quarantined candidate")
            incomplete=phase in {"STAGED","STARTING","PROBING","PROBED","ROLLBACK_PENDING","PROMOTING"};generation=s.get("generation")
        if incomplete:return self.rollback("recovered incomplete activation",expected_generation=generation)
        return p

    def activation_health(self,healthy:bool,*,expected_generation=None):
        if not healthy:return self.rollback("promoted candidate failed activation health window",expected_generation=expected_generation)
        with _state_lock(self.lock_path):
            s=self.status();self._check_generation(s,expected_generation)
            if s.get("phase")!="PROMOTED":raise ActivationError("activation health is only valid after promotion")
            p=self.known_good_pointer()
            if not p or (p.get("current") or {}).get("revision")!=s.get("candidate",{}).get("revision"):raise ActivationError("activation health pointer mismatch")
            return p
