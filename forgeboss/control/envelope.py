from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, time
from pathlib import Path
from forgeboss.security.local_acl import harden_private_dir,harden_private_path

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")

def _secret_file(root:Path,filename:str,label:str):
    p=Path(root)/"state"/"forgebossd"/filename
    harden_private_dir(p.parent)
    if not p.exists():
        try:
            fd=os.open(str(p),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            try:os.write(fd,secrets.token_bytes(32));os.fsync(fd)
            finally:os.close(fd)
        except FileExistsError:pass
    harden_private_path(p)
    data=p.read_bytes()
    if len(data)<32:raise RuntimeError(f"{label} secret is invalid")
    return p,data

def secret_file(root:Path):
    return _secret_file(root,"daemon-secret.bin","forgebossd")

def policy_secret_file(root:Path):
    return _secret_file(root,"policy-approval-secret.bin","forgeboss policy approval")

def launch_secret_file(root:Path):
    return _secret_file(root,"governed-launch-secret.bin","forgeboss governed launch")

def sign_envelope(payload,secret:bytes):
    body=dict(payload)
    body.pop("signature",None)
    sig=hmac.new(secret,canonical(body),hashlib.sha256).hexdigest()
    body["signature"]="hmac-sha256:"+sig
    return body

def verify_envelope(payload,secret:bytes,now=None):
    now=time.time() if now is None else float(now)
    if not isinstance(payload,dict):raise ValueError("envelope must be object")
    allowed={"envelopeVersion","taskId","repository","baseSha","branch","worktreePath","runId","attempt","ownerEpoch","runtime",
             "allowedPaths","deniedPaths","allowedTools","contextBundleHash","transcript","events","budgetUsd","expiresAt","protocolVersion","signature"}
    extra=set(payload)-allowed
    if extra:raise ValueError("unexpected envelope keys: "+",".join(sorted(extra)))
    required={"envelopeVersion","taskId","repository","baseSha","worktreePath","runId","ownerEpoch","runtime","allowedPaths","allowedTools","expiresAt","protocolVersion","signature"}
    missing=required-set(payload)
    if missing:raise ValueError("missing envelope keys: "+",".join(sorted(missing)))
    if int(payload["envelopeVersion"])!=1:raise ValueError("unsupported envelope version")
    if int(payload["protocolVersion"])!=1:raise ValueError("unsupported protocol version")
    exp=float(payload["expiresAt"])
    if exp<=now:raise PermissionError("worker launch envelope expired")
    sig=str(payload["signature"])
    if not sig.startswith("hmac-sha256:"):raise PermissionError("unsupported signature")
    unsigned=dict(payload);unsigned.pop("signature",None)
    want=hmac.new(secret,canonical(unsigned),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig.split(":",1)[1],want):raise PermissionError("worker launch envelope signature mismatch")
    return unsigned