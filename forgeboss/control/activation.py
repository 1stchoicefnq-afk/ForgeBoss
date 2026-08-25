from __future__ import annotations

import json, os, secrets, signal, subprocess, sys, tempfile, time
from pathlib import Path
from .known_good import IdentityError, verify_build_manifest

CNW=getattr(subprocess,"CREATE_NO_WINDOW",0)
class ActivationError(RuntimeError): pass

def _sync_dir(path):
    if os.name=="nt": return
    fd=os.open(str(path),os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def _atomic_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as fh:
            json.dump(value,fh,sort_keys=True,indent=2);fh.write("\n");fh.flush();os.fsync(fh.fileno())
        os.replace(tmp,path);_sync_dir(path.parent)
    finally:
        try:
            if os.path.exists(tmp): os.unlink(tmp)
        except OSError: pass

def _win_api():
    import ctypes
    from ctypes import wintypes
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];k.OpenProcess.restype=wintypes.HANDLE
    k.CloseHandle.argtypes=[wintypes.HANDLE];k.CloseHandle.restype=wintypes.BOOL
    k.GetProcessTimes.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.FILETIME),ctypes.POINTER(wintypes.FILETIME),ctypes.POINTER(wintypes.FILETIME),ctypes.POINTER(wintypes.FILETIME)];k.GetProcessTimes.restype=wintypes.BOOL
    k.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)];k.QueryFullProcessImageNameW.restype=wintypes.BOOL
    k.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT];k.TerminateProcess.restype=wintypes.BOOL
    k.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];k.WaitForSingleObject.restype=wintypes.DWORD
    return ctypes,wintypes,k

def _win_process_identity(pid):
    ctypes,wintypes,k=_win_api();h=k.OpenProcess(0x1000,False,int(pid))
    if not h:
        if ctypes.get_last_error()==87:return None
        raise ActivationError("cannot query process identity")
    try:
        c=wintypes.FILETIME();e=wintypes.FILETIME();kt=wintypes.FILETIME();u=wintypes.FILETIME()
        if not k.GetProcessTimes(h,ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(u)): raise ActivationError("cannot read process creation time")
        n=wintypes.DWORD(32768);buf=ctypes.create_unicode_buffer(n.value)
        if not k.QueryFullProcessImageNameW(h,0,buf,ctypes.byref(n)): raise ActivationError("cannot read process image")
        token=(int(c.dwHighDateTime)<<32)|int(c.dwLowDateTime)
        return {"pid":int(pid),"startToken":str(token),"exe":os.path.normcase(os.path.realpath(buf.value))}
    finally:k.CloseHandle(h)

def _posix_process_identity(pid):
    p=Path("/proc")/str(int(pid))
    if not p.exists():return None
    try:
        stat=(p/"stat").read_text(encoding="utf-8");tail=stat[stat.rfind(")")+2:].split();token=tail[19];exe=os.path.realpath(os.readlink(p/"exe"))
    except FileNotFoundError:return None
    except Exception as ex:raise ActivationError("cannot establish process identity") from ex
    return {"pid":int(pid),"startToken":str(token),"exe":exe}

def process_identity(pid):
    if int(pid)<=0:return None
    return _win_process_identity(pid) if os.name=="nt" else _posix_process_identity(pid)

def _same_process(a,b):
    return isinstance(a,dict) and bool(b) and int(b.get("pid",-1))==int(a.get("pid",-2)) and str(b.get("startToken"))==str(a.get("startToken")) and os.path.normcase(str(b.get("exe") or ""))==os.path.normcase(str(a.get("exe") or ""))

def process_is_same_and_alive(expected):
    if not isinstance(expected,dict) or not expected.get("pid"):return False
    try:return _same_process(expected,process_identity(int(expected["pid"])))
    except Exception:return False

def _wait_dead(expected,timeout=5.0):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if not process_is_same_and_alive(expected):return True
        time.sleep(0.05)
    return not process_is_same_and_alive(expected)

def terminate_verified_process(expected,timeout=5.0):
    if not isinstance(expected,dict) or not expected.get("pid") or not expected.get("startToken") or not expected.get("exe"):raise ActivationError("candidate process identity is missing or incomplete")
    if os.name=="nt":
        ctypes,wintypes,k=_win_api();h=k.OpenProcess(0x1000|0x0001|0x00100000,False,int(expected["pid"]))
        if not h:
            if ctypes.get_last_error()==87:return True
            raise ActivationError("cannot open candidate for termination")
        try:
            cur=_win_process_identity(int(expected["pid"]))
            if not _same_process(expected,cur):return True
            if not k.TerminateProcess(h,75):raise ActivationError("candidate termination failed")
            if k.WaitForSingleObject(h,max(1,int(timeout*1000)))==0x00000102:return False
        finally:k.CloseHandle(h)
        return _wait_dead(expected,0.5)
    if not process_is_same_and_alive(expected):return True
    try:os.kill(int(expected["pid"]),signal.SIGTERM)
    except ProcessLookupError:return True
    if _wait_dead(expected,min(2.0,timeout)):return True
    if not process_is_same_and_alive(expected):return True
    try:os.kill(int(expected["pid"]),signal.SIGKILL)
    except ProcessLookupError:return True
    return _wait_dead(expected,max(0.5,timeout-2.0))

def _identity_key(v):
    if not isinstance(v,dict) or v.get("verified") is not True:return None
    return (str(v.get("identitySha256") or ""),str(v.get("revision") or ""),str(v.get("manifestSha256") or ""))

class ActivationManager:
    def __init__(self,state_dir,running_identity,runtime_process_identity=None):
        self.state_dir=Path(state_dir);self.state_dir.mkdir(parents=True,exist_ok=True)
        self.state_path=self.state_dir/"activation.json";self.pointer_path=self.state_dir/"known-good.json"
        self.running_identity=dict(running_identity or {});self.runtime_process_identity=dict(runtime_process_identity or {})
    def status(self):
        if not self.state_path.exists():return {"schema":2,"phase":"IDLE","running":self.running_identity,"prior":self.running_identity,"priorProcessIdentity":self.runtime_process_identity or None,"candidate":None,"processIdentity":None,"pointer":None}
        try:v=json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception as ex:raise ActivationError("activation state is unreadable") from ex
        if not isinstance(v,dict):raise ActivationError("activation state is invalid")
        return v
    def known_good_pointer(self):
        s=self.status()
        if isinstance(s.get("pointer"),dict):return s["pointer"]
        if not self.pointer_path.exists():return None
        try:v=json.loads(self.pointer_path.read_text(encoding="utf-8"))
        except Exception as ex:raise ActivationError("known-good pointer is unreadable") from ex
        return v if isinstance(v,dict) else None
    def _owner(self,s):
        phase=str(s.get("phase") or "")
        if phase=="PROMOTED":return s.get("candidate"),s.get("processIdentity")
        if phase in {"FAILED","QUARANTINED","ROLLBACK_PENDING"}:raise ActivationError("mutation authority is ambiguous/quarantined")
        ident=s.get("prior") or s.get("running") or self.running_identity
        proc=s.get("priorProcessIdentity") or (self.runtime_process_identity if phase=="IDLE" else None)
        return ident,proc
    def assert_mutation_authority(self,identity=None,process=None):
        ident,proc=self._owner(self.status());identity=identity or self.running_identity;process=process or self.runtime_process_identity
        if _identity_key(identity)!=_identity_key(ident):raise ActivationError("controller does not own mutation authority")
        if proc:
            if not _same_process(proc,process):raise ActivationError("controller process does not own mutation authority")
            if not process_is_same_and_alive(proc):raise ActivationError("mutation-authority process is not alive/identical")
        return True
    def stage(self,candidate_root,manifest_path,expected_revision=None,expected_manifest_sha256=None):
        self.assert_mutation_authority();candidate_root=Path(candidate_root).resolve(strict=True);running_root=Path(self.running_identity.get("codeRoot") or "").resolve(strict=True)
        if candidate_root==running_root:raise ActivationError("candidate must be a distinct checkout; in-place activation denied")
        try:candidate=verify_build_manifest(manifest_path,candidate_root,expected_revision,expected_manifest_sha256)
        except IdentityError as ex:raise ActivationError(str(ex)) from ex
        s={"schema":2,"phase":"STAGED","updatedAt":time.time(),"prior":self.running_identity,"priorProcessIdentity":self.runtime_process_identity or None,"candidate":candidate,"probe":None,"pid":None,"processIdentity":None,"activationNonce":None,"parentProcessIdentity":self.runtime_process_identity or None,"reason":None,"pointer":self.known_good_pointer()};_atomic_json(self.state_path,s);return s
    def start_candidate(self,extra_args=None,extra_env=None):
        s=self.status()
        if s.get("phase")!="STAGED":raise ActivationError("candidate must be STAGED before start")
        self.assert_mutation_authority();c=s["candidate"];root=Path(c["codeRoot"]).resolve(strict=True);entry=(root/c["entrypoint"]).resolve(strict=True)
        if entry.suffix.lower()!=".py":raise ActivationError("candidate entrypoint must be a Python file")
        nonce=secrets.token_hex(32);parent=self.runtime_process_identity or process_identity(os.getpid())
        if not parent or not process_is_same_and_alive(parent):raise ActivationError("activation parent process identity is unavailable")
        s.update({"phase":"STARTING","activationNonce":nonce,"parentProcessIdentity":parent,"updatedAt":time.time()});_atomic_json(self.state_path,s)
        env=os.environ.copy();env.update(extra_env or {});env.update({"FORGEBOSS_SELF_BUILD_MODE":"YES","FORGEBOSS_BUILD_MANIFEST":c["manifestPath"],"FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA":c["revision"],"FORGEBOSS_EXPECTED_MANIFEST_SHA256":c["manifestSha256"],"FORGEBOSS_ACTIVATION_NONCE":nonce,"FORGEBOSS_ACTIVATION_STATE":str(self.state_path.resolve()),"FORGEBOSS_ACTIVATION_PARENT_IDENTITY":json.dumps(parent,sort_keys=True,separators=(",",":"))})
        try:p=subprocess.Popen([sys.executable,str(entry),*(extra_args or [])],cwd=str(root),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=CNW)
        except Exception as ex:s.update({"phase":"ROLLED_BACK","reason":"candidate start failed","updatedAt":time.time()});_atomic_json(self.state_path,s);raise ActivationError("candidate process failed to start") from ex
        s["pid"]=int(p.pid);ident=process_identity(p.pid)
        if not ident:s.update({"phase":"ROLLED_BACK","reason":"candidate exited before identity could be established","updatedAt":time.time()});_atomic_json(self.state_path,s);raise ActivationError("candidate exited before identity could be established")
        s["processIdentity"]=ident;s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return p
    def _require_candidate(self,s):
        e=s.get("processIdentity")
        if not e or not process_is_same_and_alive(e):raise ActivationError("candidate process is not alive with expected identity")
        return e
    def begin_probe(self):
        s=self.status()
        if s.get("phase")!="STARTING":raise ActivationError("candidate must be STARTING before probe")
        self._require_candidate(s)
        if not s.get("activationNonce"):raise ActivationError("candidate activation nonce is missing")
        s["phase"]="PROBING";s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return s
    def record_probe(self,result):
        s=self.status()
        if s.get("phase")!="PROBING":raise ActivationError("candidate is not in probe phase")
        expected=self._require_candidate(s)
        if not isinstance(result,dict):raise ActivationError("probe result must be an object")
        proof=result.get("proof") or {};c=s.get("candidate") or {};ident=result.get("identity") or {}
        if proof.get("activationNonce")!=s.get("activationNonce"):raise ActivationError("candidate probe nonce mismatch")
        if not _same_process(expected,proof.get("processIdentity")):raise ActivationError("candidate probe process identity mismatch")
        if ident.get("revision")!=c.get("revision") or ident.get("manifestSha256")!=c.get("manifestSha256") or ident.get("identitySha256")!=c.get("identitySha256"):raise ActivationError("candidate probe identity mismatch")
        req=("startup","health","control","selftests","multiAgent")
        if any(result.get(k) is not True for k in req):self.rollback("candidate probe failed");raise ActivationError("candidate probe failed")
        s["phase"]="PROBED";s["probe"]={**{k:True for k in req},"identity":ident,"proof":{"activationNonce":s["activationNonce"],"processIdentity":expected}};s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return s
    def promote(self):
        s=self.status()
        if s.get("phase")!="PROBED":raise ActivationError("candidate must pass probes before promotion")
        try:self._require_candidate(s)
        except ActivationError as ex:self.rollback("candidate died or changed before promotion");raise ActivationError("candidate unavailable before promotion") from ex
        c=s.get("candidate") or {};p=s.get("probe") or {};proof=p.get("proof") or {}
        if proof.get("activationNonce")!=s.get("activationNonce") or not _same_process(s.get("processIdentity"),proof.get("processIdentity")) or (p.get("identity") or {}).get("identitySha256")!=c.get("identitySha256"):raise ActivationError("candidate probe proof is not bound to promotion target")
        pointer={"schema":2,"current":c,"previous":s.get("prior"),"promotedAt":time.time()}
        s.update({"phase":"PROMOTED","pointer":pointer,"updatedAt":time.time(),"reason":None});_atomic_json(self.state_path,s);return pointer
    def _fence(self,s,reason):
        if not s.get("pid"):return True
        ident=s.get("processIdentity")
        if not ident:s.update({"phase":"QUARANTINED","reason":"cannot prove candidate process identity during rollback","updatedAt":time.time()});_atomic_json(self.state_path,s);return False
        s.update({"phase":"ROLLBACK_PENDING","reason":str(reason),"updatedAt":time.time()});_atomic_json(self.state_path,s)
        try:dead=terminate_verified_process(ident,5.0)
        except Exception as ex:s.update({"phase":"QUARANTINED","reason":"candidate termination could not be proven: "+str(ex),"updatedAt":time.time()});_atomic_json(self.state_path,s);return False
        if not dead:s.update({"phase":"QUARANTINED","reason":"candidate remained alive after bounded termination","updatedAt":time.time()});_atomic_json(self.state_path,s);return False
        return True
    def rollback(self,reason="activation rollback"):
        s=self.status();prior=s.get("prior") or self.running_identity
        if not self._fence(s,reason):raise ActivationError("rollback quarantined: candidate death not proven")
        s=self.status();pointer={"schema":2,"current":prior,"previous":None,"rolledBackAt":time.time(),"reason":str(reason)};s.update({"phase":"ROLLED_BACK","pointer":pointer,"reason":str(reason),"updatedAt":time.time()});_atomic_json(self.state_path,s);return pointer
    def recover(self):
        s=self.status();phase=s.get("phase")
        if phase in {"STAGED","STARTING","PROBING","PROBED","ROLLBACK_PENDING"}:return self.rollback("recovered incomplete activation")
        if phase=="QUARANTINED":raise ActivationError("activation recovery blocked by quarantined candidate")
        if phase=="PROMOTED":
            c=s.get("candidate") or {}
            if _identity_key(self.running_identity)!=_identity_key(c):return self.known_good_pointer()
            expected=s.get("processIdentity")
            if expected and process_is_same_and_alive(expected):
                if not _same_process(expected,self.runtime_process_identity):raise ActivationError("promoted controller already has live authority owner")
                return self.known_good_pointer()
            if not self.runtime_process_identity or not process_is_same_and_alive(self.runtime_process_identity):raise ActivationError("cannot establish restarted promoted controller process identity")
            s["processIdentity"]=self.runtime_process_identity;s["updatedAt"]=time.time();_atomic_json(self.state_path,s)
        return self.known_good_pointer()
    def activation_health(self,healthy):
        s=self.status()
        if s.get("phase")!="PROMOTED" or healthy:return self.known_good_pointer()
        return self.rollback("promoted candidate health failed")
