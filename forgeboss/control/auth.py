from __future__ import annotations
import hashlib,hmac,time
from .envelope import canonical
AUTH_WINDOW_SECONDS=30
def material(p):
    return {"protocolVersion":int(p.get("protocolVersion",0)),"client":str(p.get("client") or ""),"capabilities":p.get("capabilities") or [],
            "timestamp":int(p.get("timestamp",0)),"nonce":str(p.get("nonce") or "")}
def make_connect_proof(p,secret):return "hmac-sha256:"+hmac.new(secret,canonical(material(p)),hashlib.sha256).hexdigest()
def verify_connect_proof(p,secret,now=None):
    now=time.time() if now is None else float(now);ts=int(p.get("timestamp",0));nonce=str(p.get("nonce") or "");proof=str(p.get("authProof") or "")
    if len(nonce)<24:raise PermissionError("connect nonce missing/too short")
    if abs(now-ts)>AUTH_WINDOW_SECONDS:raise PermissionError("connect authentication timestamp expired")
    if not proof.startswith("hmac-sha256:"):raise PermissionError("connect authentication proof missing")
    if not hmac.compare_digest(proof,make_connect_proof(p,secret)):raise PermissionError("connect authentication proof mismatch")
    return True
