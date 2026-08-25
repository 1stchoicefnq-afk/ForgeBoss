from __future__ import annotations
import base64,ctypes,json,os,socket,stat,struct
from dataclasses import dataclass
from pathlib import Path
from forgeboss.executors.isolation_broker import _canonical
class BrokerCryptoError(RuntimeError):pass
WIN_ROOT=Path(r"C:\ProgramData\ForgeBoss\IsolationBroker");LINUX_ROOT=Path("/var/lib/forgeboss/isolation-broker");WIN_TRUST_KEY=r"SOFTWARE\ForgeBoss\IsolationBroker";WIN_AUTH_PIPE=r"\\.\pipe\ForgeBossControllerAuthority.v1";LINUX_AUTH_SOCKET=Path("/run/forgeboss/controller-authority-v1.sock");LINUX_AUTH_TRUST=Path("/etc/forgeboss/controller-authority.json");LINUX_BROKER_TRUST=Path("/etc/forgeboss/isolation-broker-trust.json")
def _linklike(p:Path):
    try:return p.is_symlink() or bool(hasattr(p,"is_junction") and p.is_junction())
    except OSError:return True
def broker_root()->Path:
    p=WIN_ROOT if os.name=="nt" else LINUX_ROOT
    try:
        if not p.exists() or _linklike(p) or not p.is_dir():raise BrokerCryptoError("protected broker root missing/unsafe; service setup prerequisite not satisfied")
        if os.name!="nt":
            st=p.stat()
            if st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o022:raise BrokerCryptoError("protected broker root is not root-owned/write-protected")
        return p.resolve()
    except BrokerCryptoError:raise
    except Exception as e:raise BrokerCryptoError("cannot validate protected broker root") from e
def _b64key(raw,label):
    try:v=base64.b64decode(str(raw),validate=True)
    except Exception as e:raise BrokerCryptoError(label+" invalid base64") from e
    if len(v)!=32:raise BrokerCryptoError(label+" must be 32-byte Ed25519 key")
    return v
def _read_protected(path:Path,root_owned=False)->bytes:
    try:
        if _linklike(path) or not path.is_file():raise BrokerCryptoError("protected file is not regular: "+str(path))
        st=path.stat()
        if root_owned and st.st_uid!=0:raise BrokerCryptoError("protected file is not root-owned: "+str(path))
        if stat.S_IMODE(st.st_mode)&0o022:raise BrokerCryptoError("protected file is writable by group/world: "+str(path))
        return path.read_bytes()
    except BrokerCryptoError:raise
    except Exception as e:raise BrokerCryptoError("cannot read protected file: "+str(path)) from e
def _protected_json(path:Path):
    try:
        obj=json.loads(_read_protected(path,root_owned=True).decode("utf-8"))
        if not isinstance(obj,dict):raise ValueError("object")
        return obj
    except BrokerCryptoError:raise
    except Exception as e:raise BrokerCryptoError("protected trust JSON invalid: "+str(path)) from e
def load_receipt_private_key()->bytes:
    raw=_read_protected(broker_root()/"receipt-ed25519-private.key",root_owned=(os.name!="nt"))
    if len(raw)!=32:raise BrokerCryptoError("receipt private key must be exactly 32 raw bytes")
    return raw
def load_controller_public_key()->bytes:
    if os.name=="nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,WIN_TRUST_KEY,0,winreg.KEY_READ) as k:raw,typ=winreg.QueryValueEx(k,"ControllerEd25519PublicKeyBase64")
            if typ!=winreg.REG_SZ:raise BrokerCryptoError("controller public key trust has invalid type")
            return _b64key(raw,"controller public key")
        except BrokerCryptoError:raise
        except Exception as e:raise BrokerCryptoError("controller public key trust unavailable in HKLM") from e
    return _b64key(_protected_json(LINUX_AUTH_TRUST).get("ed25519PublicKeyBase64") or "","controller public key")
def load_service_gid()->int:
    if os.name=="nt":raise BrokerCryptoError("service GID is Linux-only")
    try:gid=int(_protected_json(LINUX_BROKER_TRUST).get("serviceGid"))
    except BrokerCryptoError:raise
    except Exception as e:raise BrokerCryptoError("broker serviceGid trust unavailable") from e
    if gid<0:raise BrokerCryptoError("broker serviceGid trust invalid")
    return gid
class ReceiptSigner:
    def __init__(self,private_key=None):self.private_key=private_key
    def sign(self,receipt):
        key=self.private_key if self.private_key is not None else load_receipt_private_key()
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            sig=Ed25519PrivateKey.from_private_bytes(key).sign(_canonical(receipt))
        except ImportError as e:raise BrokerCryptoError("protected host prerequisite missing: cryptography Ed25519 support") from e
        except Exception as e:raise BrokerCryptoError("broker receipt signing failed") from e
        return {"signedReceipt":receipt,"receiptSignature":base64.b64encode(sig).decode("ascii")}
def _verify_attestation(env,pub):
    signed=env.get("signedAuthority") if isinstance(env,dict) else None;sig=env.get("authoritySignature") if isinstance(env,dict) else None
    if not isinstance(signed,dict) or not isinstance(sig,str):raise BrokerCryptoError("protected controller authority response is unsigned")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(sig,validate=True),_canonical(signed))
    except ImportError as e:raise BrokerCryptoError("protected host prerequisite missing: cryptography Ed25519 support") from e
    except Exception as e:raise BrokerCryptoError("protected controller authority signature verification failed") from e
    return signed
def _recv(sock,n):
    out=b""
    while len(out)<n:
        c=sock.recv(n-len(out))
        if not c:raise BrokerCryptoError("protected authority IPC closed early")
        out+=c
    return out
def _linux_exchange(req):
    try:
        st=LINUX_AUTH_SOCKET.stat()
        if st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o022 or not stat.S_ISSOCK(st.st_mode):raise BrokerCryptoError("controller authority socket trust invalid")
        raw=_canonical(req)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(10);s.connect(str(LINUX_AUTH_SOCKET))
            if not hasattr(socket,"SO_PEERCRED"):raise BrokerCryptoError("SO_PEERCRED unavailable")
            _pid,uid,_gid=struct.unpack("3i",s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
            if uid!=0:raise BrokerCryptoError("controller authority peer is not protected root service")
            s.sendall(struct.pack("!I",len(raw))+raw);ln=struct.unpack("!I",_recv(s,4))[0]
            if ln<=0 or ln>1024*1024:raise BrokerCryptoError("controller authority response length invalid")
            return json.loads(_recv(s,ln).decode())
    except BrokerCryptoError:raise
    except Exception as e:raise BrokerCryptoError("protected controller authority IPC failed") from e
def _windows_exchange(req):
    from ctypes import wintypes
    k=ctypes.WinDLL("kernel32",use_last_error=True);H=wintypes.HANDLE;D=wintypes.DWORD;B=wintypes.BOOL;V=wintypes.LPVOID;PD=ctypes.POINTER(D)
    k.CreateFileW.argtypes=[wintypes.LPCWSTR,D,D,V,D,D,H];k.CreateFileW.restype=H;k.ReadFile.argtypes=[H,V,D,PD,V];k.ReadFile.restype=B;k.WriteFile.argtypes=[H,V,D,PD,V];k.WriteFile.restype=B;k.CloseHandle.argtypes=[H]
    h=k.CreateFileW(WIN_AUTH_PIPE,0xC0000000,0,None,3,0,None);bad=ctypes.c_void_p(-1).value
    if ctypes.cast(h,ctypes.c_void_p).value in (None,bad):raise BrokerCryptoError("protected controller authority named pipe unavailable")
    def write(data):
        off=0
        while off<len(data):
            n=D();b=ctypes.create_string_buffer(data[off:])
            if not k.WriteFile(h,b,len(data)-off,ctypes.byref(n),None) or n.value<=0:raise BrokerCryptoError("authority pipe write failed")
            off+=n.value
    def read(n):
        out=bytearray()
        while len(out)<n:
            b=ctypes.create_string_buffer(n-len(out));got=D()
            if not k.ReadFile(h,b,n-len(out),ctypes.byref(got),None) or got.value<=0:raise BrokerCryptoError("authority pipe read failed")
            out.extend(b.raw[:got.value])
        return bytes(out)
    try:
        raw=_canonical(req);write(struct.pack("!I",len(raw))+raw);ln=struct.unpack("!I",read(4))[0]
        if ln<=0 or ln>1024*1024:raise BrokerCryptoError("authority response length invalid")
        return json.loads(read(ln).decode())
    finally:k.CloseHandle(h)
@dataclass(frozen=True)
class ProtectedAuthority:
    envelope_sha256:str;task_id:str;run_id:str;owner_epoch:int;base_sha:str;worktree_path:str;budget_usd:float;expires_at:float;allowed_paths:tuple[str,...];runtime:dict;result_ref:str;attestation_id:str
class ProtectedAuthorityVerifier:
    """FB-078 gate: legacy same-user HMAC is never sufficient."""
    def __init__(self,exchange=None,public_key=None):self.exchange=exchange;self.public_key=public_key
    def verify(self,req):
        q={"schema":1,"operation":"verify-forgeboss-authority","envelopeSha256":req["envelopeSha256"],"taskId":req["taskId"],"runId":req["runId"],"ownerEpoch":req["ownerEpoch"],"baseSha":req["baseSha"],"worktreePath":req["worktreePath"],"budgetUsd":req["budgetUsd"],"expiresAt":req["expiresAt"],"allowedPaths":req["allowedPaths"],"runtime":req["runtime"],"resultRef":req["resultRef"]}
        env=self.exchange(q) if self.exchange else (_windows_exchange(q) if os.name=="nt" else _linux_exchange(q));signed=_verify_attestation(env,self.public_key or load_controller_public_key())
        for k,v in q.items():
            if k not in ("schema","operation") and signed.get(k)!=v:raise BrokerCryptoError("protected controller authority mismatch: "+k)
        aid=str(signed.get("attestationId") or "")
        if not aid or signed.get("protected") is not True:raise BrokerCryptoError("protected controller authority prerequisite not satisfied")
        return ProtectedAuthority(q["envelopeSha256"],q["taskId"],q["runId"],int(q["ownerEpoch"]),q["baseSha"],q["worktreePath"],float(q["budgetUsd"]),float(q["expiresAt"]),tuple(q["allowedPaths"]),dict(q["runtime"]),q["resultRef"],aid)
