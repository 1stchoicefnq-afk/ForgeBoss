from __future__ import annotations
import base64,ctypes,hashlib,json,math,os,socket,stat,struct
from pathlib import Path
from forgeboss.security import executor_guard as guard
class IsolationBrokerError(guard.SecurityError):pass
_MAX_REPLY=16*1024*1024;_WIN_PIPE=r"\\.\pipe\ForgeBossIsolationBroker.v3";_LINUX_SOCKET=Path("/run/forgeboss/isolation-broker-v3.sock");_LINUX_TRUST=Path("/etc/forgeboss/isolation-broker-trust.json");_WIN_TRUST_KEY=r"SOFTWARE\ForgeBoss\IsolationBroker";_TRUST_VALUE_KEY="Ed25519PublicKeyBase64";_TRUST_VALUE_SID="ServiceSid";_TRUST_VALUE_SERVICE="ServiceName";_TRUST_VALUE_IMAGE="ImagePath";_SE_GROUP_ENABLED=4;_SE_GROUP_USE_FOR_DENY_ONLY=16;_ZERO_OID="0"*40
def _positive_budget(raw):
    if isinstance(raw,bool):raise IsolationBrokerError("paid budget must be a finite positive number")
    try:v=float(raw)
    except Exception as e:raise IsolationBrokerError("paid budget must be a finite positive number") from e
    if not math.isfinite(v) or v<=0:raise IsolationBrokerError("paid budget must be a finite positive number")
    return v
def _canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def _digest(v):return hashlib.sha256(_canonical(v)).hexdigest()
def _decode_public_key(raw):
    try:k=base64.b64decode(raw,validate=True)
    except Exception as e:raise IsolationBrokerError("broker trust public key is invalid base64") from e
    if len(k)!=32:raise IsolationBrokerError("broker trust public key must be Ed25519/32-byte")
    return k
def _windows_trust():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,_WIN_TRUST_KEY,0,winreg.KEY_READ) as k:
            pub,t1=winreg.QueryValueEx(k,_TRUST_VALUE_KEY);sid,t2=winreg.QueryValueEx(k,_TRUST_VALUE_SID);service,t3=winreg.QueryValueEx(k,_TRUST_VALUE_SERVICE);image,t4=winreg.QueryValueEx(k,_TRUST_VALUE_IMAGE)
        if any(t!=winreg.REG_SZ for t in (t1,t2,t3,t4)):raise IsolationBrokerError("broker HKLM trust values have invalid type")
        if not isinstance(sid,str) or not sid.startswith("S-1-5-80-"):raise IsolationBrokerError("broker ServiceSid must be a Windows per-service SID")
        if not isinstance(service,str) or service.strip()!=service or not service:raise IsolationBrokerError("broker ServiceName trust value is invalid")
        if not isinstance(image,str) or not image.strip() or not os.path.isabs(image):raise IsolationBrokerError("broker ImagePath trust value must be absolute")
        return {"publicKey":_decode_public_key(pub),"serviceSid":sid,"serviceName":service,"imagePath":os.path.normcase(os.path.normpath(image))}
    except IsolationBrokerError:raise
    except Exception as e:raise IsolationBrokerError("OS-pinned broker trust is unavailable in HKLM") from e
def _linux_trust():
    try:
        st=_LINUX_TRUST.stat()
        if st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o022:raise IsolationBrokerError("broker trust file is not root-owned/write-protected")
        obj=json.loads(_LINUX_TRUST.read_text());uid=int(obj.get("serviceUid"));gid=int(obj.get("serviceGid"))
        if uid<0 or gid<0:raise ValueError("uid/gid")
        return {"publicKey":_decode_public_key(str(obj.get("ed25519PublicKeyBase64") or "")),"serviceUid":uid,"serviceGid":gid}
    except IsolationBrokerError:raise
    except Exception as e:raise IsolationBrokerError("OS-pinned broker trust file is unavailable") from e
def _trust_anchor():return _windows_trust() if os.name=="nt" else _linux_trust()
def _verify_signed_reply(env,pub):
    signed=env.get("signedReceipt") if isinstance(env,dict) else None;signature=env.get("receiptSignature") if isinstance(env,dict) else None
    if not isinstance(signed,dict) or not isinstance(signature,str):raise IsolationBrokerError("broker response is missing signed receipt")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(signature,validate=True),_canonical(signed))
    except ImportError as e:raise IsolationBrokerError("protected host prerequisite missing: pinned cryptography package for Ed25519 verification") from e
    except Exception as e:raise IsolationBrokerError("broker receipt signature verification failed") from e
    return signed
def _recv_exact(sock,n):
    out=b""
    while len(out)<n:
        c=sock.recv(n-len(out))
        if not c:raise IsolationBrokerError("broker IPC closed early")
        out+=c
    return out
def _linux_exchange(req,trust):
    try:
        st=_LINUX_SOCKET.stat();mode=stat.S_IMODE(st.st_mode)
        if st.st_uid!=trust["serviceUid"] or st.st_gid!=trust["serviceGid"] or (mode&0o007) or (mode&0o660)!=0o660 or not stat.S_ISSOCK(st.st_mode):raise IsolationBrokerError("broker socket owner/group/mode differs from pinned service identity")
        raw=_canonical(req)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(3600);s.connect(str(_LINUX_SOCKET))
            if not hasattr(socket,"SO_PEERCRED"):raise IsolationBrokerError("kernel peer credentials unavailable for broker socket")
            _pid,uid,_gid=struct.unpack("3i",s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
            if uid!=trust["serviceUid"]:raise IsolationBrokerError("broker Unix peer UID differs from pinned service identity")
            s.sendall(struct.pack("!I",len(raw))+raw);ln=struct.unpack("!I",_recv_exact(s,4))[0]
            if ln<=0 or ln>_MAX_REPLY:raise IsolationBrokerError("broker reply length is invalid")
            return json.loads(_recv_exact(s,ln).decode())
    except IsolationBrokerError:raise
    except Exception as e:raise IsolationBrokerError("protected Unix broker IPC failed") from e
def _win_libs():
    from ctypes import wintypes
    k=ctypes.WinDLL("kernel32",use_last_error=True);a=ctypes.WinDLL("advapi32",use_last_error=True);H=wintypes.HANDLE;D=wintypes.DWORD;B=wintypes.BOOL;V=wintypes.LPVOID;PD=ctypes.POINTER(D)
    k.CreateFileW.argtypes=[wintypes.LPCWSTR,D,D,V,D,D,H];k.CreateFileW.restype=H;k.GetNamedPipeServerProcessId.argtypes=[H,PD];k.GetNamedPipeServerProcessId.restype=B;k.OpenProcess.argtypes=[D,B,D];k.OpenProcess.restype=H;k.QueryFullProcessImageNameW.argtypes=[H,D,wintypes.LPWSTR,PD];k.QueryFullProcessImageNameW.restype=B;k.ReadFile.argtypes=[H,V,D,PD,V];k.ReadFile.restype=B;k.WriteFile.argtypes=[H,V,D,PD,V];k.WriteFile.restype=B;k.CloseHandle.argtypes=[H];k.CloseHandle.restype=B;k.LocalFree.argtypes=[V];k.LocalFree.restype=V
    a.OpenProcessToken.argtypes=[H,D,ctypes.POINTER(H)];a.OpenProcessToken.restype=B;a.GetTokenInformation.argtypes=[H,ctypes.c_int,V,D,PD];a.GetTokenInformation.restype=B;a.ConvertSidToStringSidW.argtypes=[V,ctypes.POINTER(wintypes.LPWSTR)];a.ConvertSidToStringSidW.restype=B;a.OpenSCManagerW.argtypes=[wintypes.LPCWSTR,wintypes.LPCWSTR,D];a.OpenSCManagerW.restype=H;a.OpenServiceW.argtypes=[H,wintypes.LPCWSTR,D];a.OpenServiceW.restype=H;a.QueryServiceStatusEx.argtypes=[H,ctypes.c_int,ctypes.POINTER(ctypes.c_ubyte),D,PD];a.QueryServiceStatusEx.restype=B;a.CloseServiceHandle.argtypes=[H];a.CloseServiceHandle.restype=B
    return k,a,wintypes
def _sid_to_text(a,k,p):
    from ctypes import wintypes
    text=wintypes.LPWSTR()
    if not a.ConvertSidToStringSidW(p,ctypes.byref(text)):raise IsolationBrokerError("cannot stringify broker token SID")
    try:return ctypes.wstring_at(text)
    finally:k.LocalFree(text)
def _token_group_sids(ph):
    k,a,w=_win_libs();TOKEN_QUERY=8;TokenGroups=2
    class SAA(ctypes.Structure):_fields_=[("Sid",w.LPVOID),("Attributes",w.DWORD)]
    class TG(ctypes.Structure):_fields_=[("GroupCount",w.DWORD),("Groups",SAA*1)]
    tok=w.HANDLE()
    if not a.OpenProcessToken(ph,TOKEN_QUERY,ctypes.byref(tok)):raise IsolationBrokerError("cannot query broker process token")
    try:
        need=w.DWORD();a.GetTokenInformation(tok,TokenGroups,None,0,ctypes.byref(need))
        if need.value<=0:raise IsolationBrokerError("cannot size broker token groups")
        buf=ctypes.create_string_buffer(need.value)
        if not a.GetTokenInformation(tok,TokenGroups,buf,need,ctypes.byref(need)):raise IsolationBrokerError("cannot read broker token groups")
        count=ctypes.cast(buf,ctypes.POINTER(w.DWORD)).contents.value
        if count>65536:raise IsolationBrokerError("broker token group count is unreasonable")
        groups=(SAA*count).from_address(ctypes.addressof(buf)+TG.Groups.offset);return [(_sid_to_text(a,k,g.Sid),int(g.Attributes)) for g in groups]
    finally:k.CloseHandle(tok)
def _has_enabled_service_sid(groups,expected):
    wanted=expected.casefold();return any(s.casefold()==wanted and (attrs&_SE_GROUP_ENABLED) and not(attrs&_SE_GROUP_USE_FOR_DENY_ONLY) for s,attrs in groups)
def _pipe_server_pid(k,h):
    from ctypes import wintypes
    p=wintypes.DWORD()
    if not k.GetNamedPipeServerProcessId(h,ctypes.byref(p)) or p.value<=0:raise IsolationBrokerError("cannot authenticate named-pipe server PID")
    return int(p.value)
def _process_image(k,ph):
    from ctypes import wintypes
    n=wintypes.DWORD(32768);b=ctypes.create_unicode_buffer(n.value)
    if not k.QueryFullProcessImageNameW(ph,0,b,ctypes.byref(n)):raise IsolationBrokerError("cannot query broker server process image")
    return os.path.normcase(os.path.normpath(b.value))
def _registered_service_pid(a,name):
    from ctypes import wintypes
    class SSP(ctypes.Structure):_fields_=[("dwServiceType",wintypes.DWORD),("dwCurrentState",wintypes.DWORD),("dwControlsAccepted",wintypes.DWORD),("dwWin32ExitCode",wintypes.DWORD),("dwServiceSpecificExitCode",wintypes.DWORD),("dwCheckPoint",wintypes.DWORD),("dwWaitHint",wintypes.DWORD),("dwProcessId",wintypes.DWORD),("dwServiceFlags",wintypes.DWORD)]
    scm=a.OpenSCManagerW(None,None,1)
    if not scm:raise IsolationBrokerError("cannot open Windows service control manager")
    try:
        svc=a.OpenServiceW(scm,name,4)
        if not svc:raise IsolationBrokerError("pinned ForgeBoss broker service is not registered")
        try:
            s=SSP();need=wintypes.DWORD();ok=a.QueryServiceStatusEx(svc,0,ctypes.cast(ctypes.byref(s),ctypes.POINTER(ctypes.c_ubyte)),ctypes.sizeof(s),ctypes.byref(need))
            if not ok or s.dwProcessId<=0:raise IsolationBrokerError("cannot authenticate pinned broker service process")
            return int(s.dwProcessId)
        finally:a.CloseServiceHandle(svc)
    finally:a.CloseServiceHandle(scm)
def _authenticate_windows_server(h,trust):
    k,a,_=_win_libs();pid=_pipe_server_pid(k,h)
    if pid!=_registered_service_pid(a,trust["serviceName"]):raise IsolationBrokerError("named-pipe server PID is not the pinned broker service instance")
    ph=k.OpenProcess(0x1000,False,pid)
    if not ph:raise IsolationBrokerError("cannot open broker server process")
    try:
        if _process_image(k,ph)!=trust["imagePath"]:raise IsolationBrokerError("broker process image differs from HKLM-pinned service image")
        if not _has_enabled_service_sid(_token_group_sids(ph),trust["serviceSid"]):raise IsolationBrokerError("broker process lacks enabled HKLM-pinned Windows service SID")
        if _pipe_server_pid(k,h)!=pid or _registered_service_pid(a,trust["serviceName"])!=pid or _process_image(k,ph)!=trust["imagePath"]:raise IsolationBrokerError("broker process identity changed during authentication")
    finally:k.CloseHandle(ph)
def _win_write_all(k,h,data):
    from ctypes import wintypes
    off=0
    while off<len(data):
        b=ctypes.create_string_buffer(data[off:]);n=wintypes.DWORD()
        if not k.WriteFile(h,b,len(data)-off,ctypes.byref(n),None) or n.value<=0:raise IsolationBrokerError("broker named-pipe write failed")
        off+=n.value
def _win_read_exact(k,h,n):
    from ctypes import wintypes
    out=bytearray()
    while len(out)<n:
        b=ctypes.create_string_buffer(n-len(out));got=wintypes.DWORD()
        if not k.ReadFile(h,b,n-len(out),ctypes.byref(got),None) or got.value<=0:raise IsolationBrokerError("broker named-pipe read failed")
        out.extend(b.raw[:got.value])
    return bytes(out)
def _windows_exchange(req,trust):
    k,_,_=_win_libs();h=k.CreateFileW(_WIN_PIPE,0xC0000000,0,None,3,0x80000000,None);bad=ctypes.c_void_p(-1).value
    if ctypes.cast(h,ctypes.c_void_p).value in (None,bad):raise IsolationBrokerError("fixed protected broker named pipe is unavailable")
    try:
        _authenticate_windows_server(h,trust);raw=_canonical(req);_win_write_all(k,h,struct.pack("!I",len(raw))+raw);ln=struct.unpack("!I",_win_read_exact(k,h,4))[0]
        if ln<=0 or ln>_MAX_REPLY:raise IsolationBrokerError("broker reply length is invalid")
        return json.loads(_win_read_exact(k,h,ln).decode())
    finally:k.CloseHandle(h)
def _file_state(path):
    p=Path(path)
    if not p.exists():return {"kind":"missing"}
    if guard.is_linklike(p) or not p.is_file():return {"kind":"unsafe"}
    d=p.read_bytes();return {"kind":"file","sha256":hashlib.sha256(d).hexdigest(),"size":len(d)}
def _capture_targets(host,packet):
    allowed,_=guard.validate_packet(packet);out={}
    for rel in allowed:
        guard.assert_paths_contained(host,[rel]);state=_file_state(Path(host)/rel)
        if state.get("kind")=="unsafe":raise IsolationBrokerError("host target is unsafe before broker run: "+rel)
        out[rel]=state
    return out
def _capture_authority(host):return {"ordinary":guard.snapshot(host),"git":guard.git_metadata_snapshot(host),"head":guard.git(host,"rev-parse","HEAD"),"worktree":guard.git(host,"rev-parse","--show-toplevel")}
def _expected_authority(lease_path,control_envelope,workspace,executor,cli_budget):
    lease=json.loads(Path(lease_path).read_text());a=guard._control_authority(control_envelope,lease,Path(workspace).resolve(),executor);budget=_positive_budget(cli_budget)
    if budget!=float(a["budgetUsd"]):raise IsolationBrokerError("runner budget differs from signed control authority")
    try:raw=json.loads(control_envelope);base=str(raw["baseSha"])
    except Exception as e:raise IsolationBrokerError("control envelope baseSha missing") from e
    if len(base)!=40 or not all(c in "0123456789abcdefABCDEF" for c in base):raise IsolationBrokerError("control envelope baseSha invalid")
    a["baseSha"]=base.lower();return a
def _call_broker(req):
    trust=_trust_anchor();env=_windows_exchange(req,trust) if os.name=="nt" else _linux_exchange(req,trust);reply=_verify_signed_reply(env,trust["publicKey"])
    if reply.get("schema")!=3 or reply.get("ok") is not True:raise IsolationBrokerError("broker returned invalid authenticated result")
    for f in ("isolated","paidConsumed","reintegrationProtected","ordinaryWorkersDeniedDirectWrite","preopenedWritableHandlesExcluded"):
        if reply.get(f) is not True:raise IsolationBrokerError("broker did not prove protected boundary: "+f)
    if reply.get("hostWorkspaceMounted") is not False or reply.get("workerHasRuntimeControl") is not False or reply.get("localCopybackRequired") is not False:raise IsolationBrokerError("broker boundary exposed or delegated protected state")
    if reply.get("changes") not in (None,[]):raise IsolationBrokerError("authenticated broker returned local file payloads")
    completed=reply.get("completed") is True
    if completed and reply.get("reintegrated") is not True:raise IsolationBrokerError("completed broker run lacks protected result handoff")
    if not completed and reply.get("reintegrated") is not False:raise IsolationBrokerError("failed broker run falsely claims protected result handoff")
    return reply
def _validate_reply_authority(reply,expected):
    a=reply.get("authority")
    if not isinstance(a,dict):raise IsolationBrokerError("broker result is missing exact authority binding")
    for k in ("taskId","runId","ownerEpoch","envelopeSha256"):
        if a.get(k)!=expected.get(k):raise IsolationBrokerError("broker authority mismatch: "+k)
    if _positive_budget(a.get("budgetUsd"))!=float(expected["budgetUsd"]):raise IsolationBrokerError("broker authority mismatch: budgetUsd")
def _casefold_allowed(allowed):
    out={}
    for raw in allowed:
        rel=guard.norm(raw);k=rel.casefold()
        if k in out:raise IsolationBrokerError("allowed paths contain Windows case collision: "+rel)
        out[k]=rel
    return out
def _safe_ref_component(raw):return hashlib.sha256(raw.encode()).hexdigest()[:24]
def _result_ref(task,run):return f"refs/forgeboss/results/{_safe_ref_component(task)}/{_safe_ref_component(run)}"
def _hex(raw,n):return isinstance(raw,str) and len(raw)==n and all(c in "0123456789abcdef" for c in raw.lower())
def _receipt_bindings(reply,request,pre_authority,pre_targets):return {"requestSha256":_digest(request),"preAuthoritySha256":_digest(pre_authority),"preTargetsSha256":_digest(pre_targets),"authoritySha256":_digest(reply.get("authority"))}
def _verify_failure_receipt(reply,request,pre_authority,pre_targets):
    r=reply.get("reintegrationReceipt")
    if not isinstance(r,dict) or r.get("schema")!=3 or r.get("failedBeforeResult") is not True:raise IsolationBrokerError("authenticated broker failure lacks protected consume receipt")
    for k,v in _receipt_bindings(reply,request,pre_authority,pre_targets).items():
        if r.get(k)!=v:raise IsolationBrokerError("failure receipt binding mismatch: "+k)
    if r.get("baseCommit")!=request["expectedAuthority"].get("baseSha") or r.get("hostWorktreeAuthoritative") is not False:raise IsolationBrokerError("failure receipt base/result authority invalid")
    if any(r.get(k) is not None for k in ("resultCommit","resultTree","resultRef","expectedOldOid","committedNewOid","handoffRepoId")):raise IsolationBrokerError("failed run fabricated result identity")
    if not str(r.get("paidConsumeId") or "") or not str(r.get("protectedAuthorityAttestationId") or ""):raise IsolationBrokerError("failure receipt lacks protected consume/authority identity")
    if not str(reply.get("error") or ""):raise IsolationBrokerError("failed paid run lacks authenticated error")
    return r
def _verify_receipt(reply,request,host,packet,pre_authority,pre_targets):
    r=reply.get("reintegrationReceipt")
    if not isinstance(r,dict) or r.get("schema")!=3:raise IsolationBrokerError("authenticated broker result lacks protected result receipt")
    for k,v in _receipt_bindings(reply,request,pre_authority,pre_targets).items():
        if r.get(k)!=v:raise IsolationBrokerError("result receipt binding mismatch: "+k)
    allowed,_=guard.validate_packet(packet);amap=_casefold_allowed(allowed)
    if r.get("allowedPathsSha256")!=_digest(allowed):raise IsolationBrokerError("result receipt allowed-path digest mismatch")
    if r.get("baseCommit")!=pre_authority.get("head") or r.get("baseCommit")!=request["expectedAuthority"].get("baseSha"):raise IsolationBrokerError("result receipt base commit mismatch")
    result=r.get("resultCommit");tree=r.get("resultTree")
    if not _hex(result,40) or not _hex(tree,40) or r.get("committedNewOid")!=result or r.get("expectedOldOid")!=_ZERO_OID:raise IsolationBrokerError("result commit/tree/CAS identity invalid")
    if r.get("resultRef")!=_result_ref(reply["authority"]["taskId"],reply["authority"]["runId"]):raise IsolationBrokerError("result ref identity mismatch")
    if r.get("hostWorktreeAuthoritative") is not False:raise IsolationBrokerError("ordinary host worktree cannot be authoritative result state")
    if not _hex(r.get("diffSha256"),64) or not _hex(r.get("handoffRepoId"),64) or not str(r.get("paidConsumeId") or "") or not str(r.get("protectedAuthorityAttestationId") or ""):raise IsolationBrokerError("protected result receipt incomplete")
    applied=r.get("appliedPaths")
    if not isinstance(applied,list):raise IsolationBrokerError("result applied path set invalid")
    seen=set();canonical=[]
    for raw in applied:
        rel=guard.norm(raw);k=rel.casefold()
        if k not in amap or k in seen:raise IsolationBrokerError("result applied path set invalid")
        seen.add(k);canonical.append(amap[k])
    current=_capture_authority(host)
    if current["git"]!=pre_authority["git"] or current["head"]!=pre_authority["head"] or current["worktree"]!=pre_authority["worktree"]:raise IsolationBrokerError("host Git authority changed across protected result handoff")
    return canonical,r
def run_isolated_mini_swe(lease_path,token,packet_path,workspace,control_envelope,cli_budget,model_name,image):
    host=Path(workspace).resolve();pp=Path(packet_path);packet=json.loads(pp.read_text());guard.validate_packet(packet);guard.assert_no_link_escape(host);authority=_expected_authority(lease_path,control_envelope,host,"mini-swe",cli_budget);pre_authority=_capture_authority(host);pre_targets=_capture_targets(host,packet)
    request={"schema":3,"operation":"run-mini-swe-v3","workspace":str(host),"packetPath":str(pp.resolve()),"packet":packet,"leasePath":str(Path(lease_path).resolve()),"leaseToken":str(token),"controlEnvelope":control_envelope,"budgetUsd":float(authority["budgetUsd"]),"model":str(model_name),"image":str(image),"expectedAuthority":{"taskId":authority["taskId"],"runId":authority["runId"],"ownerEpoch":authority["ownerEpoch"],"envelopeSha256":authority["envelopeSha256"],"budgetUsd":authority["budgetUsd"],"worktreePath":authority["worktreePath"],"baseSha":authority["baseSha"],"allowedPaths":authority["allowedPaths"],"expiresAt":authority["expiresAt"]},"preAuthority":pre_authority,"preAuthoritySha256":_digest(pre_authority),"preTargets":pre_targets,"preTargetsSha256":_digest(pre_targets)}
    reply=_call_broker(request);_validate_reply_authority(reply,authority)
    if reply.get("completed") is not True:
        receipt=_verify_failure_receipt(reply,request,pre_authority,pre_targets);return {"completed":False,"cost_usd":reply.get("cost_usd"),"calls":reply.get("calls"),"error":reply.get("error"),"applied":[],"authority":authority,"receipt":receipt}
    applied,receipt=_verify_receipt(reply,request,host,packet,pre_authority,pre_targets);return {"completed":True,"cost_usd":reply.get("cost_usd"),"calls":reply.get("calls"),"error":reply.get("error"),"applied":applied,"authority":authority,"result_commit":receipt["resultCommit"],"result_tree":receipt["resultTree"],"result_ref":receipt["resultRef"],"receipt":receipt}
