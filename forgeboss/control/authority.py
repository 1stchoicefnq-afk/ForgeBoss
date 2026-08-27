from __future__ import annotations
import base64,json,math,re
from dataclasses import dataclass
from .envelope import canonical

AUTHORITY_VERSION=1
ALGORITHM="ed25519"
PURPOSE="worker-launch"
_SHA256=re.compile(r"^[0-9a-f]{64}$")
_ID=re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    Ed25519PublicKey=None

@dataclass(frozen=True)
class AuthorityKey:
    key_id:str
    public_key_b64:str
    not_before:float
    retire_after:float|None=None

@dataclass(frozen=True)
class PinnedAuthorityTrust:
    generation:int
    keys:tuple[AuthorityKey,...]
    minimum_generation:int=1

    def key_for(self,key_id:str,now:float):
        if self.generation < self.minimum_generation: raise PermissionError("stale authority trust generation")
        matches=[k for k in self.keys if k.key_id==key_id]
        if len(matches)!=1: raise PermissionError("unknown authority key id")
        k=matches[0]
        if now < float(k.not_before): raise PermissionError("authority key not active")
        if k.retire_after is not None and now >= float(k.retire_after): raise PermissionError("authority key retired")
        return k

_REQUIRED={"authorityVersion","algorithm","keyId","purpose","authorityId","taskId","runId","ownerEpoch","attempt","repository","baseSha","branch","worktreePath","runtime","allowedPaths","deniedPaths","allowedTools","contextBundleHash","budgetUsd","issuedAt","expiresAt","controllerKnownGood","assignmentId"}

def _finite(v,name,positive=False):
    if isinstance(v,bool): raise ValueError(name+" invalid")
    x=float(v)
    if not math.isfinite(x) or (positive and x<=0): raise ValueError(name+" invalid")
    return x

def _ident(v,name):
    s=str(v)
    if not _ID.fullmatch(s): raise ValueError(name+" invalid")
    return s

def _paths(v,name):
    if not isinstance(v,list): raise ValueError(name+" must be list")
    out=[];seen=set()
    for p in v:
        s=str(p).replace("\\","/").strip()
        if not s or s.startswith("/") or ".." in s.split("/"): raise ValueError(name+" invalid path")
        key=s.rstrip(" .").casefold()
        if key in seen: raise ValueError(name+" duplicate/colliding path")
        seen.add(key);out.append(s)
    return out

def validate_authority(a,now=None):
    if not isinstance(a,dict): raise ValueError("authority must be object")
    if set(a)!=_REQUIRED: raise ValueError("authority schema mismatch")
    if a["authorityVersion"]!=AUTHORITY_VERSION or a["algorithm"]!=ALGORITHM or a["purpose"]!=PURPOSE: raise ValueError("unsupported authority domain")
    _ident(a["keyId"],"keyId");_ident(a["authorityId"],"authorityId");_ident(a["taskId"],"taskId");_ident(a["runId"],"runId");_ident(a["assignmentId"],"assignmentId")
    if not isinstance(a["ownerEpoch"],int) or isinstance(a["ownerEpoch"],bool) or a["ownerEpoch"]<1: raise ValueError("ownerEpoch invalid")
    if not isinstance(a["attempt"],int) or isinstance(a["attempt"],bool) or a["attempt"]<1: raise ValueError("attempt invalid")
    repo=str(a["repository"]);parts=repo.replace("\\","/").split("/")
    if len(parts)!=2 or not all(parts) or any(x in {".",".."} for x in parts): raise ValueError("repository invalid")
    if not _SHA256.fullmatch(str(a["baseSha"]).lower()): raise ValueError("baseSha invalid")
    _paths(a["allowedPaths"],"allowedPaths");_paths(a["deniedPaths"],"deniedPaths")
    if not isinstance(a["allowedTools"],list) or len({str(x).casefold() for x in a["allowedTools"]})!=len(a["allowedTools"]): raise ValueError("allowedTools invalid")
    if not isinstance(a["runtime"],dict) or set(a["runtime"])!={"adapter","provider","model"} or not all(str(a["runtime"][k]) for k in a["runtime"]): raise ValueError("runtime invalid")
    kg=a["controllerKnownGood"]
    if not isinstance(kg,dict) or set(kg)!={"revision","manifestSha256","identitySha256"} or not isinstance(kg["revision"],int) or kg["revision"]<1 or not _SHA256.fullmatch(str(kg["manifestSha256"]).lower()) or not _SHA256.fullmatch(str(kg["identitySha256"]).lower()): raise ValueError("controllerKnownGood invalid")
    budget=_finite(a["budgetUsd"],"budgetUsd",True);issued=_finite(a["issuedAt"],"issuedAt");expires=_finite(a["expiresAt"],"expiresAt")
    if expires<=issued: raise ValueError("authority time window invalid")
    if now is not None:
        n=float(now)
        if n<issued: raise PermissionError("authority not yet valid")
        if n>=expires: raise PermissionError("authority expired")
    return a

class ControllerAuthorityVerifier:
    def __init__(self,trust:PinnedAuthorityTrust): self._trust=trust
    def verify(self,packet,now):
        if not isinstance(packet,dict) or set(packet)!={"authority","signature"}: raise ValueError("signed authority schema mismatch")
        a=validate_authority(packet["authority"],now)
        k=self._trust.key_for(a["keyId"],float(now))
        sig=str(packet["signature"])
        if not sig.startswith("ed25519:"): raise PermissionError("protected authority requires ed25519")
        if Ed25519PublicKey is None: raise RuntimeError("cryptography Ed25519 support unavailable")
        try:
            pub=base64.b64decode(k.public_key_b64,validate=True);raw=base64.b64decode(sig.split(":",1)[1],validate=True)
            Ed25519PublicKey.from_public_bytes(pub).verify(raw,canonical(a))
        except Exception as e: raise PermissionError("authority signature mismatch") from e
        return a

class ControllerAuthoritySignerClient:
    def __init__(self,transport,controller_identity:str): self._transport=transport;self._controller_identity=_ident(controller_identity,"controller identity")
    def sign_worker_launch(self,authority):
        a=validate_authority(dict(authority))
        req={"type":"sign-worker-launch","controllerIdentity":self._controller_identity,"authority":a}
        res=self._transport(req)
        if not isinstance(res,dict) or set(res)!={"authority","signature"} or res["authority"]!=a: raise PermissionError("protected signer returned mismatched authority")
        if not str(res["signature"]).startswith("ed25519:"): raise PermissionError("protected signer returned unsupported signature")
        return res
