from __future__ import annotations
import hashlib,hmac,os,secrets,time
from pathlib import Path
from .envelope import canonical
from forgeboss.security.local_acl import harden_private_dir,harden_private_path
AUTH_WINDOW_SECONDS=30
NONCE_HEX_LEN=32

def client_auth_file(root:Path):
    p=Path(root)/"state"/"forgebossd"/"client-auth-secret.bin"
    harden_private_dir(p.parent)
    if not p.exists():
        try:
            fd=os.open(str(p),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            try: os.write(fd,secrets.token_bytes(32));os.fsync(fd)
            finally: os.close(fd)
        except FileExistsError: pass
    harden_private_path(p)
    data=p.read_bytes()
    if len(data)!=32: raise RuntimeError("client auth credential is invalid")
    return p,data

def material(p):
    caps=p.get("capabilities") or []
    if not isinstance(caps,list) or any(not isinstance(x,str) or not x for x in caps): raise ValueError("connect capabilities invalid")
    nonce=str(p.get("nonce") or "")
    if len(nonce)!=NONCE_HEX_LEN or any(c not in "0123456789abcdef" for c in nonce): raise PermissionError("connect nonce invalid")
    return {"protocolVersion":int(p.get("protocolVersion",0)),"client":str(p.get("client") or ""),"capabilities":caps,"timestamp":int(p.get("timestamp",0)),"nonce":nonce}
def make_connect_proof(p,secret): return "client-hmac-sha256:"+hmac.new(secret,canonical(material(p)),hashlib.sha256).hexdigest()
def verify_connect_proof(p,secret,now=None):
    now=time.time() if now is None else float(now);ts=int(p.get("timestamp",0));proof=str(p.get("authProof") or "")
    material(p)
    if abs(now-ts)>AUTH_WINDOW_SECONDS: raise PermissionError("connect authentication timestamp expired")
    if not proof.startswith("client-hmac-sha256:"): raise PermissionError("connect authentication proof missing")
    if not hmac.compare_digest(proof,make_connect_proof(p,secret)): raise PermissionError("connect authentication proof mismatch")
    return True
