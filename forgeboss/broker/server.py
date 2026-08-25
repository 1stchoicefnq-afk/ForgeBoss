from __future__ import annotations
import ctypes,hashlib,json,math,os,secrets,socket,sqlite3,stat,struct,time
from pathlib import Path
from forgeboss.executors.isolation_broker import _canonical
from forgeboss.security import executor_guard as guard
from .crypto import ProtectedAuthorityVerifier,ReceiptSigner,broker_root
from .runtime import materialize_base,run_mini_swe,quarantine_run
from .reintegrate import build_and_handoff,result_ref

class BrokerServerError(RuntimeError):pass
MAX_REQUEST=16*1024*1024
WIN_PIPE=r"\\.\pipe\ForgeBossIsolationBroker.v3"
LINUX_SOCKET=Path("/run/forgeboss/isolation-broker-v3.sock")

def _digest(v):return hashlib.sha256(_canonical(v)).hexdigest()
def _positive(v):
    if isinstance(v,bool):raise BrokerServerError("budget must be finite positive")
    try:x=float(v)
    except Exception as e:raise BrokerServerError("budget must be finite positive") from e
    if not math.isfinite(x) or x<=0:raise BrokerServerError("budget must be finite positive")
    return x

def _envelope(raw):
    try:e=json.loads(raw) if isinstance(raw,str) else None
    except Exception as ex:raise BrokerServerError("control envelope invalid JSON") from ex
    if not isinstance(e,dict):raise BrokerServerError("control envelope missing")
    unsigned=dict(e);unsigned.pop("signature",None)
    return e,unsigned,_digest(unsigned)

def _norm_list(values):
    if not isinstance(values,list):raise BrokerServerError("path list invalid")
    out=[guard.norm(x) for x in values]
    if len({x.casefold() for x in out})!=len(out):raise BrokerServerError("path list case collision")
    return out

def _authority_view(req):
    if req.get("schema")!=3 or req.get("operation")!="run-mini-swe-v3":raise BrokerServerError("unsupported broker request")
    env,unsigned,env_sha=_envelope(req.get("controlEnvelope"))
    allowed=_norm_list(unsigned.get("allowedPaths"));packet=req.get("packet")
    if not isinstance(packet,dict):raise BrokerServerError("embedded packet missing")
    packet_allowed,_=guard.validate_packet(packet)
    if [x.casefold() for x in packet_allowed]!=[x.casefold() for x in allowed]:raise BrokerServerError("packet scope differs from control authority")
    task=str(unsigned.get("taskId") or "");run=str(unsigned.get("runId") or "");base=str(unsigned.get("baseSha") or "");work=str(unsigned.get("worktreePath") or "")
    try:epoch=int(unsigned.get("ownerEpoch"));exp=float(unsigned.get("expiresAt"))
    except Exception as e:raise BrokerServerError("control authority numeric identity invalid") from e
    if not task or not run or epoch<=0 or len(base)!=40 or not all(c in "0123456789abcdefABCDEF" for c in base) or not work:raise BrokerServerError("control authority identity incomplete")
    if exp<=time.time():raise BrokerServerError("control authority expired")
    budget=_positive(unsigned.get("budgetUsd"));runtime=unsigned.get("runtime")
    if not isinstance(runtime,dict) or runtime.get("adapter")!="mini-swe":raise BrokerServerError("control authority runtime is not mini-swe")
    expected=req.get("expectedAuthority")
    if not isinstance(expected,dict):raise BrokerServerError("expected authority missing")
    checks={"taskId":task,"runId":run,"ownerEpoch":epoch,"envelopeSha256":env_sha,"budgetUsd":budget,"worktreePath":str(Path(work).resolve()),"baseSha":base,"allowedPaths":allowed,"expiresAt":exp}
    for k,v in checks.items():
        got=expected.get(k)
        if k=="budgetUsd":
            if _positive(got)!=v:raise BrokerServerError("expected authority mismatch: "+k)
        elif k=="worktreePath":
            if str(Path(str(got)).resolve())!=v:raise BrokerServerError("expected authority mismatch: "+k)
        elif k=="allowedPaths":
            if [str(x).casefold() for x in (got or [])]!=[x.casefold() for x in v]:raise BrokerServerError("expected authority mismatch: "+k)
        elif got!=v:raise BrokerServerError("expected authority mismatch: "+k)
    if str(Path(str(req.get("workspace") or "")).resolve())!=checks["worktreePath"]:raise BrokerServerError("workspace differs from control authority")
    if _positive(req.get("budgetUsd"))!=budget:raise BrokerServerError("budget differs from control authority")
    if req.get("preAuthoritySha256")!=_digest(req.get("preAuthority")):raise BrokerServerError("preAuthority digest mismatch")
    if req.get("preTargetsSha256")!=_digest(req.get("preTargets")):raise BrokerServerError("preTargets digest mismatch")
    model=str(req.get("model") or "");image=str(req.get("image") or "")
    if runtime.get("model") and model!=str(runtime.get("model")):raise BrokerServerError("model differs from protected authority")
    if image!="node:22-bookworm":raise BrokerServerError("unapproved broker runtime image")
    return {**checks,"packet":packet,"runtime":runtime,"model":model,"image":image,"legacySignature":env.get("signature")}

def _db():
    root=broker_root();root.mkdir(parents=True,exist_ok=True);c=sqlite3.connect(root/"broker-state.sqlite3",timeout=30,isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL");c.execute("PRAGMA synchronous=FULL")
    c.execute("CREATE TABLE IF NOT EXISTS consumes(authority_key TEXT PRIMARY KEY,consume_id TEXT NOT NULL,request_sha TEXT NOT NULL,attestation_id TEXT NOT NULL,consumed_at REAL NOT NULL,status TEXT NOT NULL)")
    return c

def _consume(view,request_sha,attestation_id):
    key=_digest({k:view[k] for k in ("taskId","runId","ownerEpoch","envelopeSha256")});cid=secrets.token_hex(16);c=_db()
    try:
        c.execute("BEGIN IMMEDIATE")
        if c.execute("SELECT 1 FROM consumes WHERE authority_key=?",(key,)).fetchone():raise BrokerServerError("protected paid authority already consumed/replay")
        c.execute("INSERT INTO consumes VALUES(?,?,?,?,?,?)",(key,cid,request_sha,attestation_id,time.time(),"consumed"));c.execute("COMMIT")
    except Exception:
        try:c.execute("ROLLBACK")
        except Exception:pass
        raise
    finally:c.close()
    return key,cid

def _finish(key,status):
    c=_db()
    try:c.execute("BEGIN IMMEDIATE");c.execute("UPDATE consumes SET status=? WHERE authority_key=?",(status,key));c.execute("COMMIT")
    except Exception:
        try:c.execute("ROLLBACK")
        except Exception:pass
    finally:c.close()

def _authority_reply(view):return {k:view[k] for k in ("taskId","runId","ownerEpoch","envelopeSha256","budgetUsd")}
def _failure_receipt(request_sha,request,view,protected,consume_id,error,cost,calls):
    authority=_authority_reply(view)
    r={"schema":3,"requestSha256":request_sha,"preAuthoritySha256":request["preAuthoritySha256"],"preTargetsSha256":request["preTargetsSha256"],"authoritySha256":_digest(authority),"protectedAuthorityAttestationId":protected.attestation_id,"paidConsumeId":consume_id,"baseCommit":view["baseSha"],"resultCommit":None,"resultTree":None,"appliedPaths":[],"allowedPathsSha256":_digest(view["allowedPaths"]),"diffSha256":None,"resultRef":None,"expectedOldOid":None,"committedNewOid":None,"handoffRepoId":None,"hostWorktreeAuthoritative":False,"receiptId":secrets.token_hex(16),"failedBeforeResult":True}
    return {"schema":3,"ok":True,"isolated":True,"paidConsumed":True,"reintegrated":False,"reintegrationProtected":True,"ordinaryWorkersDeniedDirectWrite":True,"preopenedWritableHandlesExcluded":True,"hostWorkspaceMounted":False,"workerHasRuntimeControl":False,"localCopybackRequired":False,"changes":[],"authority":authority,"reintegrationReceipt":r,"completed":False,"cost_usd":cost,"calls":calls,"error":error}

class BrokerServer:
    def __init__(self,authority_verifier=None,signer=None,materializer=materialize_base,runner=run_mini_swe,handoff=build_and_handoff):self.authority_verifier=authority_verifier or ProtectedAuthorityVerifier();self.signer=signer or ReceiptSigner();self.materializer=materializer;self.runner=runner;self.handoff=handoff
    def handle(self,request):
        if not isinstance(request,dict):raise BrokerServerError("request must be object")
        request_sha=_digest(request);view=_authority_view(request);expected_ref=result_ref(view["taskId"],view["runId"])
        protected=self.authority_verifier.verify({"envelopeSha256":view["envelopeSha256"],"taskId":view["taskId"],"runId":view["runId"],"ownerEpoch":view["ownerEpoch"],"baseSha":view["baseSha"],"worktreePath":view["worktreePath"],"budgetUsd":view["budgetUsd"],"expiresAt":view["expiresAt"],"allowedPaths":view["allowedPaths"],"runtime":view["runtime"],"resultRef":expected_ref})
        if getattr(protected,"result_ref",expected_ref)!=expected_ref:raise BrokerServerError("protected controller result ref mismatch")
        key,consume_id=_consume(view,request_sha,protected.attestation_id);repo=None;rr=None
        try:
            repo=self.materializer(Path(view["worktreePath"]),view["baseSha"],view["runId"]);rr=self.runner(repo,view["packet"],view["budgetUsd"],view["model"],view["image"])
            if rr.completed is not True:raise BrokerServerError("paid Mini-SWE run failed after protected consume: "+str(rr.error or "unknown error"))
            result=self.handoff(repo,view["baseSha"],view["allowedPaths"],view["taskId"],view["runId"])
            if result.result_ref!=expected_ref:raise BrokerServerError("handoff result ref differs from protected controller authority")
            authority=_authority_reply(view)
            r={"schema":3,"requestSha256":request_sha,"preAuthoritySha256":request["preAuthoritySha256"],"preTargetsSha256":request["preTargetsSha256"],"authoritySha256":_digest(authority),"protectedAuthorityAttestationId":protected.attestation_id,"paidConsumeId":consume_id,"baseCommit":result.base_commit,"resultCommit":result.result_commit,"resultTree":result.result_tree,"appliedPaths":list(result.applied_paths),"allowedPathsSha256":_digest(view["allowedPaths"]),"diffSha256":result.diff_sha256,"resultRef":result.result_ref,"expectedOldOid":result.old_oid,"committedNewOid":result.new_oid,"handoffRepoId":result.handoff_repo_id,"hostWorktreeAuthoritative":False,"receiptId":secrets.token_hex(16)}
            signed={"schema":3,"ok":True,"isolated":True,"paidConsumed":True,"reintegrated":True,"reintegrationProtected":True,"ordinaryWorkersDeniedDirectWrite":True,"preopenedWritableHandlesExcluded":True,"hostWorkspaceMounted":False,"workerHasRuntimeControl":False,"localCopybackRequired":False,"changes":[],"authority":authority,"reintegrationReceipt":r,"completed":True,"cost_usd":rr.cost_usd,"calls":rr.calls,"error":None}
            _finish(key,"completed");return self.signer.sign(signed)
        except Exception as ex:
            _finish(key,"failed")
            if repo is not None:quarantine_run(repo)
            cost=getattr(rr,"cost_usd",None) if rr is not None else None;calls=getattr(rr,"calls",None) if rr is not None else None
            return self.signer.sign(_failure_receipt(request_sha,request,view,protected,consume_id,f"{type(ex).__name__}: {ex}",cost,calls))

def _read_sock(c,n):
    out=b""
    while len(out)<n:
        x=c.recv(n-len(out))
        if not x:raise BrokerServerError("client closed early")
        out+=x
    return out

def serve_linux(server):
    parent=LINUX_SOCKET.parent
    if not parent.exists():raise BrokerServerError("protected runtime directory missing; service setup prerequisite not satisfied")
    st=parent.stat()
    if st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)&0o022:raise BrokerServerError("broker runtime directory owner/mode invalid")
    try:
        old=LINUX_SOCKET.lstat()
        if not stat.S_ISSOCK(old.st_mode) or old.st_uid!=os.geteuid():raise BrokerServerError("unsafe object occupies broker socket path")
        LINUX_SOCKET.unlink()
    except FileNotFoundError:pass
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.bind(str(LINUX_SOCKET));os.chmod(LINUX_SOCKET,0o660);s.listen(16)
        while True:
            c,_=s.accept()
            with c:
                try:
                    ln=struct.unpack("!I",_read_sock(c,4))[0]
                    if ln<=0 or ln>MAX_REQUEST:raise BrokerServerError("request length invalid")
                    resp=server.handle(json.loads(_read_sock(c,ln).decode()))
                except Exception as e:resp={"error":f"{type(e).__name__}: {e}"}
                raw=_canonical(resp);c.sendall(struct.pack("!I",len(raw))+raw)

def _win_read(k,h,n):
    from ctypes import wintypes
    out=bytearray()
    while len(out)<n:
        b=ctypes.create_string_buffer(n-len(out));got=wintypes.DWORD()
        if not k.ReadFile(h,b,n-len(out),ctypes.byref(got),None) or got.value<=0:raise BrokerServerError("pipe read failed")
        out.extend(b.raw[:got.value])
    return bytes(out)
def _win_write(k,h,data):
    from ctypes import wintypes
    off=0
    while off<len(data):
        b=ctypes.create_string_buffer(data[off:]);n=wintypes.DWORD()
        if not k.WriteFile(h,b,len(data)-off,ctypes.byref(n),None) or n.value<=0:raise BrokerServerError("pipe write failed")
        off+=n.value

def serve_windows(server):
    from ctypes import wintypes
    k=ctypes.WinDLL("kernel32",use_last_error=True);a=ctypes.WinDLL("advapi32",use_last_error=True);LPVOID=wintypes.LPVOID;DWORD=wintypes.DWORD;HANDLE=wintypes.HANDLE;BOOL=wintypes.BOOL;PD=ctypes.POINTER(DWORD)
    k.CreateNamedPipeW.argtypes=[wintypes.LPCWSTR,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,LPVOID];k.CreateNamedPipeW.restype=HANDLE;k.ConnectNamedPipe.argtypes=[HANDLE,LPVOID];k.ConnectNamedPipe.restype=BOOL;k.DisconnectNamedPipe.argtypes=[HANDLE];k.DisconnectNamedPipe.restype=BOOL;k.ReadFile.argtypes=[HANDLE,LPVOID,DWORD,PD,LPVOID];k.ReadFile.restype=BOOL;k.WriteFile.argtypes=[HANDLE,LPVOID,DWORD,PD,LPVOID];k.WriteFile.restype=BOOL;k.CloseHandle.argtypes=[HANDLE];k.CloseHandle.restype=BOOL;k.LocalFree.argtypes=[LPVOID];k.LocalFree.restype=LPVOID
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,DWORD,ctypes.POINTER(LPVOID),ctypes.POINTER(DWORD)];a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=BOOL;sd=LPVOID()
    if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)(A;;GRGW;;;AU)",1,ctypes.byref(sd),None):raise BrokerServerError("cannot create protected broker pipe DACL")
    class SA(ctypes.Structure):_fields_=[("nLength",DWORD),("lpSecurityDescriptor",LPVOID),("bInheritHandle",BOOL)]
    sa=SA(ctypes.sizeof(SA),sd,False)
    try:
        while True:
            h=k.CreateNamedPipeW(WIN_PIPE,0x00000003|0x00080000,0,16,MAX_REQUEST,MAX_REQUEST,0,ctypes.byref(sa))
            if ctypes.cast(h,ctypes.c_void_p).value in (None,ctypes.c_void_p(-1).value):raise BrokerServerError("cannot create first-instance protected broker named pipe")
            try:
                ok=k.ConnectNamedPipe(h,None)
                if not ok and ctypes.get_last_error()!=535:raise BrokerServerError("broker named-pipe connect failed")
                try:
                    ln=struct.unpack("!I",_win_read(k,h,4))[0]
                    if ln<=0 or ln>MAX_REQUEST:raise BrokerServerError("request length invalid")
                    resp=server.handle(json.loads(_win_read(k,h,ln).decode()))
                except Exception as e:resp={"error":f"{type(e).__name__}: {e}"}
                raw=_canonical(resp);_win_write(k,h,struct.pack("!I",len(raw))+raw)
            finally:k.DisconnectNamedPipe(h);k.CloseHandle(h)
    finally:k.LocalFree(sd)

def wake_windows_pipe():
    if os.name!="nt":return
    try:
        from ctypes import wintypes
        k=ctypes.WinDLL("kernel32",use_last_error=True);k.CreateFileW.restype=wintypes.HANDLE;h=k.CreateFileW(WIN_PIPE,0x80000000,0,None,3,0,None)
        if ctypes.cast(h,ctypes.c_void_p).value not in (None,ctypes.c_void_p(-1).value):k.CloseHandle(h)
    except Exception:pass

def serve_forever():
    server=BrokerServer();serve_windows(server) if os.name=="nt" else serve_linux(server)
