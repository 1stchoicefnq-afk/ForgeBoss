from __future__ import annotations

import contextlib,json,os,secrets,signal,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
from .known_good import IdentityError,verify_build_manifest

CNW=getattr(subprocess,"CREATE_NO_WINDOW",0)
class ActivationError(RuntimeError): pass

def _sync_dir(path):
    if os.name=="nt":return
    fd=os.open(str(path),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def _atomic_json(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as fh:json.dump(value,fh,sort_keys=True,indent=2);fh.write("\n");fh.flush();os.fsync(fh.fileno())
        os.replace(tmp,path);_sync_dir(path.parent)
    finally:
        try:
            if os.path.exists(tmp):os.unlink(tmp)
        except OSError:pass

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
        if not k.GetProcessTimes(h,ctypes.byref(c),ctypes.byref(e),ctypes.byref(kt),ctypes.byref(u)):raise ActivationError("cannot read process creation time")
        n=wintypes.DWORD(32768);buf=ctypes.create_unicode_buffer(n.value)
        if not k.QueryFullProcessImageNameW(h,0,buf,ctypes.byref(n)):raise ActivationError("cannot read process image")
        return {"pid":int(pid),"startToken":str((int(c.dwHighDateTime)<<32)|int(c.dwLowDateTime)),"exe":os.path.normcase(os.path.realpath(buf.value))}
    finally:k.CloseHandle(h)

def _posix_process_identity(pid):
    p=Path("/proc")/str(int(pid))
    if not p.exists():return None
    try:stat=(p/"stat").read_text(encoding="utf-8");tail=stat[stat.rfind(")")+2:].split();return {"pid":int(pid),"startToken":str(tail[19]),"exe":os.path.realpath(os.readlink(p/"exe"))}
    except FileNotFoundError:return None
    except Exception as ex:raise ActivationError("cannot establish process identity") from ex

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
    end=time.monotonic()+float(timeout)
    while time.monotonic()<end:
        if not process_is_same_and_alive(expected):return True
        time.sleep(0.05)
    return not process_is_same_and_alive(expected)

def terminate_verified_process(expected,timeout=5.0):
    if not isinstance(expected,dict) or not expected.get("pid") or not expected.get("startToken") or not expected.get("exe"):raise ActivationError("candidate process identity is missing or incomplete")
    if os.name=="nt":
        ctypes,_,k=_win_api();h=k.OpenProcess(0x1000|0x0001|0x00100000,False,int(expected["pid"]))
        if not h:
            if ctypes.get_last_error()==87:return True
            raise ActivationError("cannot open candidate for termination")
        try:
            if not _same_process(expected,_win_process_identity(int(expected["pid"]))):return True
            if not k.TerminateProcess(h,75):raise ActivationError("candidate termination failed")
            if k.WaitForSingleObject(h,max(1,int(float(timeout)*1000)))==0x00000102:return False
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

@contextlib.contextmanager
def _interprocess_lock(path,timeout=10.0):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);fh=path.open("a+b")
    if path.stat().st_size==0:fh.write(b"\0");fh.flush()
    end=time.monotonic()+float(timeout);locked=False
    try:
        while time.monotonic()<end:
            try:
                if os.name=="nt":import msvcrt;fh.seek(0);msvcrt.locking(fh.fileno(),msvcrt.LK_NBLCK,1)
                else:import fcntl;fcntl.flock(fh.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                locked=True;break
            except (OSError,BlockingIOError):time.sleep(0.025)
        if not locked:raise ActivationError("activation transition lock unavailable")
        yield
    finally:
        if locked:
            try:
                if os.name=="nt":import msvcrt;fh.seek(0);msvcrt.locking(fh.fileno(),msvcrt.LK_UNLCK,1)
                else:import fcntl;fcntl.flock(fh.fileno(),fcntl.LOCK_UN)
            except OSError:pass
        fh.close()

def _validate_probe_result(result,state,peer_identity):
    if not isinstance(result,dict):raise ActivationError("probe result must be an object")
    c=state.get("candidate") or {};ident=result.get("identity") or {}
    if result.get("activationNonce")!=state.get("activationNonce") or result.get("probeChallenge")!=state.get("probeChallenge"):raise ActivationError("candidate probe activation binding mismatch")
    if not _same_process(state.get("processIdentity"),peer_identity):raise ActivationError("candidate probe peer identity mismatch")
    if ident.get("revision")!=c.get("revision") or ident.get("manifestSha256")!=c.get("manifestSha256") or ident.get("identitySha256")!=c.get("identitySha256"):raise ActivationError("candidate probe build identity mismatch")
    req=("startup","health","control","selftests","multiAgent")
    if any(result.get(k) is not True for k in req):raise ActivationError("candidate probe failed")
    return {**{k:True for k in req},"identity":ident,"proof":{"activationNonce":state["activationNonce"],"probeChallenge":state["probeChallenge"],"processIdentity":peer_identity,"transport":"kernel-peer-credentials"}}

class _PosixProbeServer:
    def __init__(self,state_dir,token):
        self.path=Path(state_dir)/("probe-"+token+".sock");self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:self.path.unlink()
        except FileNotFoundError:pass
        self.sock.bind(str(self.path));os.chmod(self.path,0o600);self.sock.listen(1);self.used=False
    @property
    def endpoint(self):return "unix:"+str(self.path)
    def accept(self,timeout):
        if self.used:raise ActivationError("candidate probe channel already consumed")
        self.used=True;self.sock.settimeout(float(timeout));conn=None
        try:
            conn,_=self.sock.accept();raw=conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i"));pid,_,_=struct.unpack("3i",raw);data=b""
            end=time.monotonic()+float(timeout);conn.settimeout(max(0.01,float(timeout)))
            while len(data)<=1024*1024 and time.monotonic()<end:
                chunk=conn.recv(65536)
                if not chunk:break
                data+=chunk
            if time.monotonic()>=end and data==b"":raise ActivationError("candidate probe read timed out")
            if len(data)>1024*1024:raise ActivationError("candidate probe payload too large")
            return int(pid),json.loads(data.decode("utf-8"))
        finally:
            if conn:conn.close()
            self.close()
    def close(self):
        try:self.sock.close()
        except Exception:pass
        try:self.path.unlink()
        except (FileNotFoundError,OSError):pass

class _WinProbeServer:
    def __init__(self,state_dir,token):
        import ctypes
        from ctypes import wintypes
        self.ctypes=ctypes;self.wintypes=wintypes;self.name=r"\\.\pipe\forgeboss-probe-"+token;self.used=False;self.k=ctypes.WinDLL("kernel32",use_last_error=True)
        ULONG_PTR=ctypes.c_size_t
        class OVERLAPPED(ctypes.Structure):_fields_=[("Internal",ULONG_PTR),("InternalHigh",ULONG_PTR),("Offset",wintypes.DWORD),("OffsetHigh",wintypes.DWORD),("hEvent",wintypes.HANDLE)]
        self.OVERLAPPED=OVERLAPPED
        self.k.CreateNamedPipeW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID];self.k.CreateNamedPipeW.restype=wintypes.HANDLE
        self.k.CreateEventW.argtypes=[wintypes.LPVOID,wintypes.BOOL,wintypes.BOOL,wintypes.LPCWSTR];self.k.CreateEventW.restype=wintypes.HANDLE
        self.k.ConnectNamedPipe.argtypes=[wintypes.HANDLE,ctypes.POINTER(OVERLAPPED)];self.k.ConnectNamedPipe.restype=wintypes.BOOL
        self.k.GetNamedPipeClientProcessId.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.ULONG)];self.k.GetNamedPipeClientProcessId.restype=wintypes.BOOL
        self.k.ReadFile.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(OVERLAPPED)];self.k.ReadFile.restype=wintypes.BOOL
        self.k.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];self.k.WaitForSingleObject.restype=wintypes.DWORD
        self.k.CancelIoEx.argtypes=[wintypes.HANDLE,ctypes.POINTER(OVERLAPPED)];self.k.CancelIoEx.restype=wintypes.BOOL
        self.k.GetOverlappedResult.argtypes=[wintypes.HANDLE,ctypes.POINTER(OVERLAPPED),ctypes.POINTER(wintypes.DWORD),wintypes.BOOL];self.k.GetOverlappedResult.restype=wintypes.BOOL
        self.k.CloseHandle.argtypes=[wintypes.HANDLE];self.k.CloseHandle.restype=wintypes.BOOL
        self.h=self.k.CreateNamedPipeW(self.name,0x00000001|0x40000000,0,1,1024*1024,1024*1024,0,None)
        invalid=ctypes.c_void_p(-1).value
        if not self.h or int(self.h)==int(invalid):raise ActivationError("cannot create candidate probe named pipe")
    @property
    def endpoint(self):return "pipe:"+self.name
    def _wait_overlapped(self,ov,timeout,what):
        ms=max(1,int(float(timeout)*1000));rc=self.k.WaitForSingleObject(ov.hEvent,ms)
        if rc==0x00000102:
            self.k.CancelIoEx(self.h,self.ctypes.byref(ov));self.k.WaitForSingleObject(ov.hEvent,1000)
            raise ActivationError(what+" timed out")
        if rc!=0:raise ActivationError(what+" wait failed")
        n=self.wintypes.DWORD()
        if not self.k.GetOverlappedResult(self.h,self.ctypes.byref(ov),self.ctypes.byref(n),False):raise ActivationError(what+" failed")
        return int(n.value)
    def _new_ov(self):
        ov=self.OVERLAPPED();ov.hEvent=self.k.CreateEventW(None,True,False,None)
        if not ov.hEvent:raise ActivationError("candidate probe event creation failed")
        return ov
    def accept(self,timeout):
        if self.used:raise ActivationError("candidate probe channel already consumed")
        self.used=True;deadline=time.monotonic()+float(timeout);conn_ov=self._new_ov()
        try:
            ok=self.k.ConnectNamedPipe(self.h,self.ctypes.byref(conn_ov))
            if not ok:
                err=self.ctypes.get_last_error()
                if err==535:pass
                elif err==997:self._wait_overlapped(conn_ov,max(0.01,deadline-time.monotonic()),"candidate probe pipe connect")
                else:raise ActivationError("candidate probe pipe connect failed")
            pid=self.wintypes.ULONG()
            if not self.k.GetNamedPipeClientProcessId(self.h,self.ctypes.byref(pid)):raise ActivationError("candidate probe client PID unavailable")
            data=b""
            while len(data)<=1024*1024:
                remain=deadline-time.monotonic()
                if remain<=0:raise ActivationError("candidate probe read timed out")
                ov=self._new_ov();buf=self.ctypes.create_string_buffer(65536);n=self.wintypes.DWORD()
                try:
                    ok=self.k.ReadFile(self.h,buf,65536,self.ctypes.byref(n),self.ctypes.byref(ov))
                    if ok:count=int(n.value)
                    else:
                        err=self.ctypes.get_last_error()
                        if err==997:count=self._wait_overlapped(ov,remain,"candidate probe read")
                        elif err in (109,232):count=0
                        else:raise ActivationError("candidate probe read failed")
                    if count<=0:break
                    data+=buf.raw[:count]
                finally:self.k.CloseHandle(ov.hEvent)
            if len(data)>1024*1024:raise ActivationError("candidate probe payload too large")
            return int(pid.value),json.loads(data.decode("utf-8"))
        finally:
            self.k.CloseHandle(conn_ov.hEvent);self.close()
    def close(self):
        if getattr(self,"h",None):self.k.CloseHandle(self.h);self.h=None

def _new_probe_server(state_dir):
    token=secrets.token_hex(24);return _WinProbeServer(state_dir,token) if os.name=="nt" else _PosixProbeServer(state_dir,token)

def submit_candidate_probe(result):
    endpoint=os.environ.get("FORGEBOSS_PROBE_ENDPOINT");nonce=os.environ.get("FORGEBOSS_ACTIVATION_NONCE");challenge=os.environ.get("FORGEBOSS_PROBE_CHALLENGE")
    if not endpoint or not nonce or not challenge:raise ActivationError("candidate probe IPC environment is incomplete")
    payload=dict(result or {});payload["activationNonce"]=nonce;payload["probeChallenge"]=challenge;raw=json.dumps(payload,sort_keys=True,separators=(",",":")).encode("utf-8")
    if len(raw)>1024*1024:raise ActivationError("candidate probe payload too large")
    if endpoint.startswith("unix:"):
        s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(5)
        try:s.connect(endpoint[5:]);s.sendall(raw);s.shutdown(socket.SHUT_WR)
        finally:s.close()
        return True
    if endpoint.startswith("pipe:") and os.name=="nt":
        import ctypes
        from ctypes import wintypes
        k=ctypes.WinDLL("kernel32",use_last_error=True);k.WaitNamedPipeW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD];k.WaitNamedPipeW.restype=wintypes.BOOL;k.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE];k.CreateFileW.restype=wintypes.HANDLE;k.WriteFile.argtypes=[wintypes.HANDLE,wintypes.LPCVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID];k.WriteFile.restype=wintypes.BOOL;k.CloseHandle.argtypes=[wintypes.HANDLE];k.CloseHandle.restype=wintypes.BOOL
        name=endpoint[5:]
        if not k.WaitNamedPipeW(name,5000):raise ActivationError("candidate probe named pipe unavailable")
        h=k.CreateFileW(name,0x40000000,0,None,3,0,None);invalid=ctypes.c_void_p(-1).value
        if not h or int(h)==int(invalid):raise ActivationError("candidate probe named pipe unavailable")
        try:n=wintypes.DWORD();buf=ctypes.create_string_buffer(raw);ok=k.WriteFile(h,buf,len(raw),ctypes.byref(n),None)
        finally:k.CloseHandle(h)
        if not ok or n.value!=len(raw):raise ActivationError("candidate probe write failed")
        return True
    raise ActivationError("unsupported candidate probe endpoint")

class ActivationManager:
    def __init__(self,state_dir,running_identity,runtime_process_identity=None):
        self.state_dir=Path(state_dir);self.state_dir.mkdir(parents=True,exist_ok=True);self.state_path=self.state_dir/"activation.json";self.pointer_path=self.state_dir/"known-good.json";self.lock_path=self.state_dir/"activation.lock";self.running_identity=dict(running_identity or {});self.runtime_process_identity=dict(runtime_process_identity or {});self._probe_server=None;self._probe_nonce=None
    def status(self):
        if not self.state_path.exists():return {"schema":6,"phase":"IDLE","running":self.running_identity,"prior":self.running_identity,"priorProcessIdentity":self.runtime_process_identity or None,"candidate":None,"processIdentity":None,"pointer":None}
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
        return s.get("prior") or s.get("running") or self.running_identity,s.get("priorProcessIdentity") or (self.runtime_process_identity if phase=="IDLE" else None)
    def assert_mutation_authority(self,identity=None,process=None):
        identity=identity or self.running_identity;process=process or self.runtime_process_identity
        with _interprocess_lock(self.lock_path):
            ident,proc=self._owner(self.status())
            if _identity_key(identity)!=_identity_key(ident):raise ActivationError("controller does not own mutation authority")
            if proc and (not _same_process(proc,process) or not process_is_same_and_alive(proc)):raise ActivationError("controller process does not own mutation authority")
        return True
    def stage(self,candidate_root,manifest_path,expected_revision=None,expected_manifest_sha256=None):
        with _interprocess_lock(self.lock_path):
            ident,proc=self._owner(self.status())
            if _identity_key(self.running_identity)!=_identity_key(ident) or (proc and not _same_process(proc,self.runtime_process_identity)):raise ActivationError("controller does not own mutation authority")
            root=Path(candidate_root).resolve(strict=True);running=Path(self.running_identity.get("codeRoot") or "").resolve(strict=True)
            if root==running:raise ActivationError("candidate must be a distinct checkout; in-place activation denied")
            try:c=verify_build_manifest(manifest_path,root,expected_revision,expected_manifest_sha256)
            except IdentityError as ex:raise ActivationError(str(ex)) from ex
            s={"schema":6,"phase":"STAGED","updatedAt":time.time(),"prior":self.running_identity,"priorProcessIdentity":self.runtime_process_identity or None,"candidate":c,"probe":None,"pid":None,"processIdentity":None,"activationNonce":None,"probeChallenge":None,"parentProcessIdentity":self.runtime_process_identity or None,"reason":None,"pointer":self.known_good_pointer(),"rollbackRequestedBy":None};_atomic_json(self.state_path,s);return s
    def start_candidate(self,extra_args=None,extra_env=None):
        with _interprocess_lock(self.lock_path):
            s=self.status()
            if s.get("phase")!="STAGED":raise ActivationError("candidate must be STAGED before start")
            c=s["candidate"];root=Path(c["codeRoot"]).resolve(strict=True);entry=(root/c["entrypoint"]).resolve(strict=True);nonce=secrets.token_hex(32);challenge=secrets.token_hex(32);parent=self.runtime_process_identity or process_identity(os.getpid());server=_new_probe_server(self.state_dir)
            if not parent or not process_is_same_and_alive(parent):server.close();raise ActivationError("activation parent process identity is unavailable")
            s.update({"phase":"STARTING","activationNonce":nonce,"probeChallenge":challenge,"parentProcessIdentity":parent,"updatedAt":time.time()});_atomic_json(self.state_path,s);self._probe_server=server;self._probe_nonce=nonce
        env=os.environ.copy();env.update(extra_env or {});env.update({"FORGEBOSS_SELF_BUILD_MODE":"YES","FORGEBOSS_BUILD_MANIFEST":c["manifestPath"],"FORGEBOSS_EXPECTED_KNOWN_GOOD_SHA":c["revision"],"FORGEBOSS_EXPECTED_MANIFEST_SHA256":c["manifestSha256"],"FORGEBOSS_ACTIVATION_NONCE":nonce,"FORGEBOSS_ACTIVATION_STATE":str(self.state_path.resolve()),"FORGEBOSS_ACTIVATION_PARENT_IDENTITY":json.dumps(parent,sort_keys=True,separators=(",",":")),"FORGEBOSS_PROBE_ENDPOINT":server.endpoint,"FORGEBOSS_PROBE_CHALLENGE":challenge})
        try:p=subprocess.Popen([sys.executable,str(entry),*(extra_args or [])],cwd=str(root),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=CNW)
        except Exception as ex:self._probe_server.close();self._probe_server=None;raise ActivationError("candidate process failed to start") from ex
        pi=process_identity(p.pid)
        with _interprocess_lock(self.lock_path):
            s=self.status();s["pid"]=int(p.pid);s["processIdentity"]=pi;s["updatedAt"]=time.time();_atomic_json(self.state_path,s)
        if not pi:raise ActivationError("candidate exited before identity could be established")
        return p
    def _require_candidate(self,s):
        e=s.get("processIdentity")
        if not e or not process_is_same_and_alive(e):raise ActivationError("candidate process is not alive with expected identity")
        return e
    def begin_probe(self):
        with _interprocess_lock(self.lock_path):
            s=self.status();self._require_candidate(s)
            if s.get("phase")!="STARTING" or not self._probe_server or self._probe_nonce!=s.get("activationNonce"):raise ActivationError("candidate probe channel unavailable")
            s["phase"]="PROBING";s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return s
    def record_probe(self,result):raise ActivationError("direct probe submission denied; kernel-authenticated candidate IPC required")
    def accept_probe(self,timeout=10.0):
        server=self._probe_server
        if not server:raise ActivationError("candidate probe channel unavailable")
        try:pid,result=server.accept(timeout)
        except Exception:
            self._probe_server=None;self._probe_nonce=None;self.rollback("candidate probe channel failed");raise
        self._probe_server=None;self._probe_nonce=None
        with _interprocess_lock(self.lock_path):
            s=self.status()
            if s.get("phase")!="PROBING":raise ActivationError("candidate is not in probe phase")
            expected=self._require_candidate(s);peer=process_identity(pid)
            if not peer or not _same_process(expected,peer):raise ActivationError("candidate probe peer process mismatch")
            proof=_validate_probe_result(result,s,peer);s["phase"]="PROBED";s["probe"]=proof;s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return s
    def promote(self):
        with _interprocess_lock(self.lock_path):
            s=self.status();self._require_candidate(s)
            if s.get("phase")!="PROBED":raise ActivationError("candidate must pass probes before promotion")
            c=s.get("candidate") or {};p=s.get("probe") or {};pr=p.get("proof") or {}
            if not _same_process(s.get("processIdentity"),pr.get("processIdentity")) or (p.get("identity") or {}).get("identitySha256")!=c.get("identitySha256"):raise ActivationError("candidate probe proof is not bound to promotion target")
            ptr={"schema":6,"current":c,"previous":s.get("prior"),"promotedAt":time.time()};s.update({"phase":"PROMOTED","pointer":ptr,"updatedAt":time.time(),"reason":None,"rollbackRequestedBy":None});_atomic_json(self.state_path,s);_atomic_json(self.pointer_path,ptr);return ptr
    def request_rollback(self,reason="activation rollback"):
        if self._probe_server:
            try:self._probe_server.close()
            except Exception:pass
        self._probe_server=None;self._probe_nonce=None
        with _interprocess_lock(self.lock_path):
            s=self.status()
            if s.get("phase") in {"ROLLED_BACK","QUARANTINED","ROLLBACK_PENDING"}:return s
            s.update({"phase":"ROLLBACK_PENDING","reason":str(reason),"rollbackRequestedBy":self.runtime_process_identity or None,"updatedAt":time.time()});_atomic_json(self.state_path,s);return s
    def finalize_rollback(self,reason=None):
        with _interprocess_lock(self.lock_path):
            s=self.status();prior=s.get("prior") or self.running_identity
            if s.get("phase")!="ROLLBACK_PENDING" or _identity_key(self.running_identity)!=_identity_key(prior):raise ActivationError("only prior known-good identity may finalize rollback")
            candidate=s.get("processIdentity")
            if candidate:
                try:dead=terminate_verified_process(candidate,5.0)
                except Exception as ex:s.update({"phase":"QUARANTINED","reason":"candidate termination could not be proven: "+str(ex),"updatedAt":time.time()});_atomic_json(self.state_path,s);raise ActivationError("rollback quarantined: candidate death not proven") from ex
                if not dead:s.update({"phase":"QUARANTINED","reason":"candidate remained alive after bounded termination","updatedAt":time.time()});_atomic_json(self.state_path,s);raise ActivationError("rollback quarantined: candidate death not proven")
            ptr={"schema":6,"current":prior,"previous":None,"rolledBackAt":time.time(),"reason":str(reason or s.get("reason") or "activation rollback")};s.update({"phase":"ROLLED_BACK","pointer":ptr,"processIdentity":None,"pid":None,"updatedAt":time.time()});_atomic_json(self.state_path,s);_atomic_json(self.pointer_path,ptr);return ptr
    def rollback(self,reason="activation rollback"):
        s=self.request_rollback(reason)
        if _identity_key(self.running_identity)!=_identity_key(s.get("prior") or self.running_identity):raise ActivationError("rollback requested; prior controller must finalize")
        return self.finalize_rollback(reason)
    def recover(self):
        finalize=False
        with _interprocess_lock(self.lock_path):
            s=self.status();phase=s.get("phase")
            if phase=="QUARANTINED":raise ActivationError("activation recovery blocked by quarantined candidate")
            if phase in {"STAGED","STARTING","PROBING","PROBED","ROLLBACK_PENDING"}:
                prior=s.get("prior") or {}
                if _identity_key(self.running_identity)!=_identity_key(prior):raise ActivationError("only prior known-good may recover incomplete activation")
                s.update({"phase":"ROLLBACK_PENDING","reason":"recovered incomplete activation","updatedAt":time.time()});_atomic_json(self.state_path,s);finalize=True
            elif phase=="PROMOTED":
                c=s.get("candidate") or {}
                if _identity_key(self.running_identity)!=_identity_key(c):return self.known_good_pointer()
                expected=s.get("processIdentity")
                if expected and process_is_same_and_alive(expected):
                    if not _same_process(expected,self.runtime_process_identity):raise ActivationError("promoted controller already has live authority owner")
                    return self.known_good_pointer()
                if not self.runtime_process_identity or not process_is_same_and_alive(self.runtime_process_identity):raise ActivationError("cannot establish restarted promoted controller process identity")
                s["processIdentity"]=self.runtime_process_identity;s["pid"]=int(self.runtime_process_identity["pid"]);s["updatedAt"]=time.time();_atomic_json(self.state_path,s);return s.get("pointer") or self.known_good_pointer()
            else:return self.known_good_pointer()
        if finalize:return self.finalize_rollback("recovered incomplete/pending activation")
    def activation_health(self,healthy):
        s=self.status()
        if s.get("phase")!="PROMOTED" or healthy:return self.known_good_pointer()
        return self.request_rollback("promoted candidate health failed")
