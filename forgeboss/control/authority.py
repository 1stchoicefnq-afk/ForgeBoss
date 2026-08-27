from __future__ import annotations
import base64, math, time
from dataclasses import dataclass
from typing import Callable, Mapping
from .envelope import canonical

AUTHORITY_VERSION=1
AUTHORITY_ALGORITHM="Ed25519"
AUTHORITY_PURPOSE="worker-launch"
CLOCK_SKEW_SECONDS=5.0

_TOP_KEYS={"authorityVersion","algorithm","keyId","purpose","authority","signature"}
_AUTH_KEYS={"authorityId","assignmentId","taskId","runId","ownerEpoch","repository","baseSha","branch","worktreePath","runtime","allowedPaths","deniedPaths","allowedTools","contextBundleHash","budgetUsd","issuedAt","expiresAt","controllerKnownGood"}
_RUNTIME_KEYS={"adapter","provider","model"}

class AuthorityError(PermissionError):pass

@dataclass(frozen=True)
class PinnedAuthorityTrust:
    generation:int
    keys:Mapping[str,bytes]
    def __post_init__(self):
        if isinstance(self.generation,bool) or int(self.generation)<1:raise ValueError("trust generation must be positive")
        clean={}
        for key_id,raw in dict(self.keys).items():
            if not isinstance(key_id,str) or not key_id.strip():raise ValueError("trust keyId required")
            if not isinstance(raw,(bytes,bytearray)) or len(raw)!=32:raise ValueError("Ed25519 public key must be 32 bytes")
            clean[key_id]=bytes(raw)
        if not clean:raise ValueError("at least one pinned authority key required")
        object.__setattr__(self,"keys",clean)


def _crypto_public(raw:bytes):
    try:from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as ex:raise RuntimeError("cryptography Ed25519 support is required for protected authority") from ex
    return Ed25519PublicKey.from_public_bytes(raw)

def _b64decode(value:str)->bytes:
    if not isinstance(value,str) or not value.startswith("ed25519:"):raise AuthorityError("protected authority requires ed25519 signature")
    s=value.split(":",1)[1]
    try:return base64.urlsafe_b64decode(s+"="*((4-len(s)%4)%4))
    except Exception as ex:raise AuthorityError("invalid Ed25519 signature encoding") from ex

def _finite(value,name):
    if isinstance(value,bool):raise AuthorityError(f"{name} must be finite")
    try:x=float(value)
    except Exception as ex:raise AuthorityError(f"{name} must be finite") from ex
    if not math.isfinite(x):raise AuthorityError(f"{name} must be finite")
    return x

def _required_text(obj,key):
    value=obj.get(key)
    if not isinstance(value,str) or not value.strip():raise AuthorityError(f"{key} required")
    if any(ord(ch)<32 for ch in value):raise AuthorityError(f"{key} contains control characters")
    return value

def _path_key(value):return str(value).replace("\\","/").casefold()
def _validate_paths(values,name):
    if not isinstance(values,list):raise AuthorityError(f"{name} must be an array")
    seen=set()
    for value in values:
        if not isinstance(value,str) or not value.strip():raise AuthorityError(f"{name} contains invalid path")
        key=_path_key(value)
        if key in seen:raise AuthorityError(f"{name} contains duplicate/case-colliding path")
        seen.add(key)
    return seen

def validate_unsigned_authority(authority,now=None):
    if not isinstance(authority,dict):raise AuthorityError("authority must be object")
    extra=set(authority)-_AUTH_KEYS;missing=_AUTH_KEYS-set(authority)
    if extra:raise AuthorityError("unexpected authority keys: "+",".join(sorted(extra)))
    if missing:raise AuthorityError("missing authority keys: "+",".join(sorted(missing)))
    for key in ("authorityId","assignmentId","taskId","runId","repository","baseSha","branch","worktreePath","contextBundleHash","controllerKnownGood"):_required_text(authority,key)
    epoch=authority["ownerEpoch"]
    if isinstance(epoch,bool) or not isinstance(epoch,int) or epoch<1:raise AuthorityError("ownerEpoch must be positive integer")
    runtime=authority["runtime"]
    if not isinstance(runtime,dict) or set(runtime)!=_RUNTIME_KEYS:raise AuthorityError("runtime schema invalid")
    for key in _RUNTIME_KEYS:_required_text(runtime,key)
    allowed=_validate_paths(authority["allowedPaths"],"allowedPaths")
    denied=_validate_paths(authority["deniedPaths"],"deniedPaths")
    if allowed & denied:raise AuthorityError("allowedPaths and deniedPaths overlap")
    tools=authority["allowedTools"]
    if not isinstance(tools,list) or any(not isinstance(x,str) or not x.strip() for x in tools):raise AuthorityError("allowedTools must contain non-empty strings")
    if len({x.casefold() for x in tools})!=len(tools):raise AuthorityError("allowedTools contains duplicates")
    budget=_finite(authority["budgetUsd"],"budgetUsd")
    if budget<0:raise AuthorityError("budgetUsd must be non-negative")
    issued=_finite(authority["issuedAt"],"issuedAt");expires=_finite(authority["expiresAt"],"expiresAt")
    if expires<=issued:raise AuthorityError("expiresAt must be after issuedAt")
    current=time.time() if now is None else float(now)
    if issued>current+CLOCK_SKEW_SECONDS:raise AuthorityError("authority not yet valid")
    if expires<=current:raise AuthorityError("authority expired")
    return authority

def verify_protected_authority(document,trust:PinnedAuthorityTrust,now=None,required_generation=None):
    if not isinstance(trust,PinnedAuthorityTrust):raise TypeError("pinned trust object required")
    if required_generation is not None and int(required_generation)!=trust.generation:raise AuthorityError("authority trust generation mismatch")
    if not isinstance(document,dict):raise AuthorityError("protected authority document must be object")
    extra=set(document)-_TOP_KEYS;missing=_TOP_KEYS-set(document)
    if extra:raise AuthorityError("unexpected protected authority keys: "+",".join(sorted(extra)))
    if missing:raise AuthorityError("missing protected authority keys: "+",".join(sorted(missing)))
    if document["authorityVersion"]!=AUTHORITY_VERSION:raise AuthorityError("unsupported authorityVersion")
    if document["algorithm"]!=AUTHORITY_ALGORITHM:raise AuthorityError("unsupported authority algorithm")
    if document["purpose"]!=AUTHORITY_PURPOSE:raise AuthorityError("unsupported authority purpose")
    key_id=_required_text(document,"keyId")
    raw=trust.keys.get(key_id)
    if raw is None:raise AuthorityError("untrusted authority keyId")
    authority=validate_unsigned_authority(document["authority"],now=now)
    unsigned={k:document[k] for k in ("authorityVersion","algorithm","keyId","purpose","authority")}
    sig=_b64decode(document["signature"])
    if len(sig)!=64:raise AuthorityError("invalid Ed25519 signature length")
    try:_crypto_public(raw).verify(sig,canonical(unsigned))
    except AuthorityError:raise
    except Exception as ex:raise AuthorityError("protected authority signature mismatch") from ex
    return authority

class WorkerLaunchSignerClient:
    """Narrow client for a protected signer. It never accepts or exposes private key bytes."""
    def __init__(self,transport:Callable[[dict],dict],trust:PinnedAuthorityTrust,required_generation=None):
        if not callable(transport):raise TypeError("signer transport must be callable")
        self._transport=transport;self._trust=trust;self._generation=required_generation
    def request_worker_launch(self,authority,now=None):
        validated=validate_unsigned_authority(dict(authority),now=now)
        request={"operation":"sign-worker-launch","purpose":AUTHORITY_PURPOSE,"authorityVersion":AUTHORITY_VERSION,"authority":validated}
        result=self._transport(request)
        verified=verify_protected_authority(result,self._trust,now=now,required_generation=self._generation)
        if canonical(verified)!=canonical(validated):raise AuthorityError("protected signer changed requested authority")
        return result
