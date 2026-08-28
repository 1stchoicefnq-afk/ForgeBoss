from __future__ import annotations
import base64, copy, json, math, os, re, stat, uuid
from dataclasses import dataclass
from pathlib import Path
from .envelope import canonical

AUTHORITY_VERSION=1
PROTOCOL_VERSION=1
ALGORITHM="ed25519"
PURPOSE="worker-launch"
_ID=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OWNER=re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO=re.compile(r"^[A-Za-z0-9._-]+$")
_GIT_OID=re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256=re.compile(r"^[0-9a-f]{64}$")
_DOS_RESERVED=re.compile(r"^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$",re.I)
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    Ed25519PublicKey=None

def _strict_str(value,name,max_len=1024,pattern=None):
    if not isinstance(value,str) or not value or len(value)>max_len: raise ValueError(f"{name} invalid")
    if any(ord(ch)<32 or ord(ch)==127 for ch in value): raise ValueError(f"{name} invalid")
    if pattern is not None and not pattern.fullmatch(value): raise ValueError(f"{name} invalid")
    return value

def _strict_int(value,name,minimum=1):
    if not isinstance(value,int) or isinstance(value,bool) or value<minimum: raise ValueError(f"{name} invalid")
    return value

def _finite(value,name,positive=False):
    if isinstance(value,bool) or not isinstance(value,(int,float)): raise ValueError(f"{name} invalid")
    x=float(value)
    if not math.isfinite(x) or (positive and x<=0): raise ValueError(f"{name} invalid")
    return x

def _git_oid(value,name): return _strict_str(value,name,64,_GIT_OID)
def _sha256(value,name): return _strict_str(value,name,64,_SHA256)

def _repository(value):
    raw=_strict_str(value,"repository",201)
    if raw!=raw.strip() or "\\" in raw or raw.startswith("/") or ":" in raw: raise ValueError("repository invalid")
    parts=raw.split("/")
    if len(parts)!=2 or any(p in ("",".","..") for p in parts): raise ValueError("repository invalid")
    owner,repo=parts
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(repo): raise ValueError("repository invalid")
    canon=f"{owner.casefold()}/{repo.casefold()}"
    if raw!=canon: raise ValueError("repository must be canonical owner/name")
    return canon

def _branch(value):
    b=_strict_str(value,"branch",240)
    if b!=b.strip() or b.startswith(("/", ".", "-")) or b.endswith(("/",".")) or "\\" in b or ".." in b or "//" in b or "@{" in b or any(ch.isspace() for ch in b) or any(ch in b for ch in "~^:?*["):
        raise ValueError("branch invalid")
    parts=b.split("/")
    if any(not part or part.startswith(".") or part.casefold().endswith(".lock") for part in parts):
        raise ValueError("branch invalid")
    return b

def _path_parts(raw,name,absolute=False):
    value=_strict_str(raw,name,2048 if absolute else 1024)
    if value!=value.strip() or "\\" in value: raise ValueError(f"{name} must be canonical")
    if value.startswith("//"): raise ValueError(f"{name} device/UNC path denied")
    drive=None; rest=value
    if re.match(r"^[A-Za-z]:/",value):
        drive=value[:2]
        if drive[0]!=drive[0].upper(): raise ValueError(f"{name} drive must be uppercase canonical")
        rest=value[3:]
        if not absolute: raise ValueError(f"{name} drive path denied")
    elif value.startswith("/"):
        if not absolute: raise ValueError(f"{name} rooted path denied")
        rest=value[1:]
    elif absolute:
        raise ValueError(f"{name} must be absolute")
    parts=[]
    for part in rest.split("/"):
        if part in ("",".",".."): raise ValueError(f"{name} invalid component")
        if part!=part.rstrip(" ."): raise ValueError(f"{name} Windows alias component denied")
        if any(ch in part for ch in ':*?<>|"'): raise ValueError(f"{name} invalid component")
        if _DOS_RESERVED.fullmatch(part): raise ValueError(f"{name} reserved component denied")
        parts.append(part)
    if not parts: raise ValueError(f"{name} invalid")
    return drive,tuple(parts)

def _canonical_relative(value,name):
    _,parts=_path_parts(value,name,False)
    norm="/".join(parts); return norm,norm.casefold()

def _canonical_absolute(value,name="worktreePath"):
    drive,parts=_path_parts(value,name,True)
    return (f"{drive}/" if drive else "/")+"/".join(parts)

def _absolute_contains(root,child):
    rd,rp=_path_parts(root,"worktreeRoot",True); cd,cp=_path_parts(child,"worktreePath",True)
    if (rd or "").casefold()!=(cd or "").casefold() or len(cp)<len(rp): return False
    if rd: return tuple(x.casefold() for x in cp[:len(rp)])==tuple(x.casefold() for x in rp)
    return cp[:len(rp)]==rp

def _is_reparse(path):
    try: st=path.lstat()
    except OSError: return False
    return bool(getattr(st,"st_file_attributes",0)&getattr(stat,"FILE_ATTRIBUTE_REPARSE_POINT",0))

def _assert_no_link_components(path):
    current=Path(path.anchor) if path.anchor else Path()
    parts=path.parts[1:] if path.anchor else path.parts
    for part in parts:
        current=current/part
        if not current.exists(): continue
        try: st=current.lstat()
        except OSError as exc: raise ValueError("worktreePath component unreadable") from exc
        if stat.S_ISLNK(st.st_mode) or _is_reparse(current): raise ValueError("worktreePath symlink/reparse component denied")

def _worktree(value,worktree_root=None,inspect_existing=False):
    path=_canonical_absolute(value)
    if worktree_root is not None:
        root=_canonical_absolute(worktree_root,"worktreeRoot")
        if not _absolute_contains(root,path): raise ValueError("worktreePath escapes assigned root")
    if inspect_existing:
        if worktree_root is None: raise ValueError("protected worktree verification requires assigned root")
        p=Path(path); _assert_no_link_components(p)
        if not p.exists() or not p.is_dir(): raise ValueError("worktreePath must be existing directory")
        if str(p.resolve(strict=True)).replace("\\","/")!=path: raise ValueError("worktreePath is not canonical resolved path")
    return path

def _paths(value,name):
    if not isinstance(value,list): raise ValueError(f"{name} must be list")
    out=[]; seen=set()
    for item in value:
        norm,key=_canonical_relative(item,name)
        if key in seen: raise ValueError(f"{name} duplicate/colliding path")
        seen.add(key); out.append(norm)
    return out,seen

def _contains(a,b): return a==b or b.startswith(a+"/")

def _tools(value):
    if not isinstance(value,list): raise ValueError("allowedTools must be list")
    out=[]; seen=set()
    for item in value:
        tool=_strict_str(item,"allowedTools item",128,_ID); key=tool.casefold()
        if key in seen: raise ValueError("allowedTools duplicate/colliding tool")
        seen.add(key); out.append(tool)
    return out

def _runtime(value):
    if not isinstance(value,dict) or set(value)!={"adapter","provider","model"}: raise ValueError("runtime invalid")
    return {"adapter":_strict_str(value["adapter"],"runtime.adapter",128,_ID),"provider":_strict_str(value["provider"],"runtime.provider",128,_ID),"model":_strict_str(value["model"],"runtime.model",256)}

def _known_good(value):
    if not isinstance(value,dict) or set(value)!={"revision","manifestSha256","identitySha256"}: raise ValueError("controllerKnownGood invalid")
    return {"revision":_git_oid(value["revision"],"controllerKnownGood.revision"),"manifestSha256":_sha256(value["manifestSha256"],"controllerKnownGood.manifestSha256"),"identitySha256":_sha256(value["identitySha256"],"controllerKnownGood.identitySha256")}

def _review_policy(value):
    expected={"independentReviewRequired","authorMayReview","reviewerId"}
    if not isinstance(value,dict) or set(value)!=expected: raise ValueError("reviewPolicy invalid")
    if value["independentReviewRequired"] is not True or value["authorMayReview"] is not False: raise ValueError("reviewPolicy independence invalid")
    return {"independentReviewRequired":True,"authorMayReview":False,"reviewerId":_strict_str(value["reviewerId"],"reviewPolicy.reviewerId",128,_ID)}

@dataclass(frozen=True)
class AuthorityKey:
    key_id:str
    public_key_b64:str
    activation_at:float
    retirement_at:float|None=None
    cutoff_at:float|None=None
    def __post_init__(self):
        _strict_str(self.key_id,"keyId",128,_ID); _strict_str(self.public_key_b64,"public key",128)
        try: raw=base64.b64decode(self.public_key_b64,validate=True)
        except Exception as exc: raise ValueError("authority public key encoding invalid") from exc
        if len(raw)!=32: raise ValueError("authority public key length invalid")
        a=_finite(self.activation_at,"activationAt"); r=None if self.retirement_at is None else _finite(self.retirement_at,"retirementAt"); c=None if self.cutoff_at is None else _finite(self.cutoff_at,"cutoffAt")
        if r is not None and r<a: raise ValueError("authority key retirement precedes activation")
        if c is not None and c<a: raise ValueError("authority key cutoff precedes activation")
        if r is not None and c is not None and c<r: raise ValueError("authority key cutoff precedes retirement")
    def to_record(self): return {"keyId":self.key_id,"publicKey":self.public_key_b64,"activationAt":self.activation_at,"retirementAt":self.retirement_at,"cutoffAt":self.cutoff_at}
    @classmethod
    def from_record(cls,r):
        if not isinstance(r,dict) or set(r)!={"keyId","publicKey","activationAt","retirementAt","cutoffAt"}: raise ValueError("authority key record invalid")
        return cls(r["keyId"],r["publicKey"],r["activationAt"],r["retirementAt"],r["cutoffAt"])

@dataclass(frozen=True)
class PinnedAuthorityTrust:
    generation:int
    keys:tuple[AuthorityKey,...]
    current_key_id:str
    next_key_id:str|None=None
    minimum_generation:int=1
    authority_version:int=AUTHORITY_VERSION
    algorithm:str=ALGORITHM
    def __post_init__(self):
        _strict_int(self.authority_version,"trust authorityVersion")
        if self.authority_version!=AUTHORITY_VERSION or self.algorithm!=ALGORITHM: raise ValueError("unsupported authority trust domain")
        _strict_int(self.generation,"trust generation"); _strict_int(self.minimum_generation,"minimum trust generation")
        if self.generation<self.minimum_generation: raise PermissionError("stale authority trust generation")
        if not isinstance(self.keys,tuple) or not self.keys or any(not isinstance(k,AuthorityKey) for k in self.keys): raise ValueError("authority trust keys invalid")
        ids=[k.key_id for k in self.keys]
        if len({x.casefold() for x in ids})!=len(ids): raise ValueError("duplicate authority key id")
        cur=_strict_str(self.current_key_id,"currentKeyId",128,_ID); by={k.key_id:k for k in self.keys}
        if cur not in by: raise ValueError("current authority key missing")
        if self.next_key_id is not None:
            nxtid=_strict_str(self.next_key_id,"nextKeyId",128,_ID)
            if nxtid==cur or nxtid not in by: raise ValueError("next authority key invalid")
            current,nxt=by[cur],by[nxtid]
            if current.cutoff_at is None: raise ValueError("current authority key needs cutoff for rotation")
            end=float(current.cutoff_at)
            if nxt.cutoff_at is not None: end=min(end,float(nxt.cutoff_at))
            if max(float(current.activation_at),float(nxt.activation_at))>=end: raise ValueError("current/next authority key windows do not overlap")
        active={cur}; active.add(self.next_key_id) if self.next_key_id is not None else None
        for k in self.keys:
            if k.key_id not in active and k.cutoff_at is None: raise ValueError("retired authority key requires cutoff")
    def key_for(self,key_id,now):
        _strict_str(key_id,"keyId",128,_ID); current=_finite(now,"verification time")
        if self.generation<self.minimum_generation: raise PermissionError("stale authority trust generation")
        matches=[k for k in self.keys if k.key_id==key_id]
        if len(matches)!=1: raise PermissionError("unknown authority key id")
        k=matches[0]
        if current<float(k.activation_at): raise PermissionError("authority key not active")
        if k.cutoff_at is not None and current>=float(k.cutoff_at): raise PermissionError("authority key cutoff reached")
        return k
    def to_record(self): return {"authorityVersion":self.authority_version,"algorithm":self.algorithm,"generation":self.generation,"currentKeyId":self.current_key_id,"nextKeyId":self.next_key_id,"keys":[k.to_record() for k in self.keys]}
    @classmethod
    def from_record(cls,r,minimum_generation=1):
        if not isinstance(r,dict) or set(r)!={"authorityVersion","algorithm","generation","currentKeyId","nextKeyId","keys"} or not isinstance(r["keys"],list): raise ValueError("authority trust record invalid")
        return cls(r["generation"],tuple(AuthorityKey.from_record(x) for x in r["keys"]),r["currentKeyId"],r["nextKeyId"],minimum_generation,r["authorityVersion"],r["algorithm"])

def _reject_constant(value): raise ValueError(f"non-finite JSON constant rejected: {value}")
def _unique_object(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise ValueError(f"duplicate JSON key rejected: {k}")
        out[k]=v
    return out

def _read_trust_record(path):
    target=Path(path)
    if target.is_symlink() or _is_reparse(target): raise ValueError("authority trust path is link/reparse")
    return json.loads(target.read_text(encoding="utf-8"),object_pairs_hook=_unique_object,parse_constant=_reject_constant)

def load_pinned_trust(path,minimum_generation=1): return PinnedAuthorityTrust.from_record(_read_trust_record(path),minimum_generation)

def _trust_lock_path(target): return target.parent/f".{target.name}.update.lock"
def _acquire_trust_lock(target):
    lock=_trust_lock_path(target)
    flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY
    if hasattr(os,"O_NOFOLLOW"): flags|=os.O_NOFOLLOW
    try: fd=os.open(str(lock),flags,0o600)
    except FileExistsError as exc: raise RuntimeError("authority trust update already locked") from exc
    try: os.write(fd,(str(os.getpid())+"\n").encode()); os.fsync(fd)
    except Exception:
        os.close(fd)
        try: lock.unlink()
        except FileNotFoundError: pass
        raise
    return fd,lock

def write_pinned_trust(path,trust):
    if not isinstance(trust,PinnedAuthorityTrust): raise TypeError("pinned authority trust required")
    target=Path(path); target.parent.mkdir(parents=True,exist_ok=True)
    lock_fd,lock=_acquire_trust_lock(target)
    try:
        if target.is_symlink() or _is_reparse(target): raise ValueError("authority trust path is link/reparse")
        if target.exists():
            existing=PinnedAuthorityTrust.from_record(_read_trust_record(target),1)
            if trust.generation<existing.generation: raise PermissionError("authority trust generation rollback denied")
            if trust.generation==existing.generation:
                if trust.to_record()==existing.to_record(): return target
                raise PermissionError("authority trust same-generation mutation denied")
        payload=json.dumps(trust.to_record(),sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
        temp=target.parent/f".{target.name}.tmp-{uuid.uuid4().hex}"
        flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY
        if hasattr(os,"O_NOFOLLOW"): flags|=os.O_NOFOLLOW
        fd=os.open(str(temp),flags,0o600)
        try: os.write(fd,payload); os.fsync(fd)
        finally: os.close(fd)
        try:
            os.replace(temp,target)
            try:
                dfd=os.open(str(target.parent),os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
                try: os.fsync(dfd)
                finally: os.close(dfd)
            except OSError: pass
        except Exception:
            try: temp.unlink()
            except FileNotFoundError: pass
            raise
        return target
    finally:
        os.close(lock_fd)
        try: lock.unlink()
        except FileNotFoundError: pass

_REQUIRED={"authorityVersion","protocolVersion","algorithm","keyId","purpose","authorityId","assignmentId","assignmentSha256","builderId","taskId","runId","ownerEpoch","attempt","repository","baseSha","currentHead","worktreePath","runtime","allowedPaths","deniedPaths","allowedTools","contextBundleHash","budgetUsd","issuedAt","expiresAt","controllerKnownGood","reviewPolicy"}
_OPTIONAL={"branch"}

def validate_authority(a,now=None,worktree_root=None,inspect_worktree=False):
    if not isinstance(a,dict): raise ValueError("authority must be object")
    keys=set(a)
    if not _REQUIRED.issubset(keys) or keys-(_REQUIRED|_OPTIONAL): raise ValueError("authority schema mismatch")
    _strict_int(a["authorityVersion"],"authorityVersion"); _strict_int(a["protocolVersion"],"protocolVersion")
    if a["authorityVersion"]!=AUTHORITY_VERSION or a["protocolVersion"]!=PROTOCOL_VERSION: raise ValueError("unsupported authority version")
    if a["algorithm"]!=ALGORITHM or a["purpose"]!=PURPOSE: raise ValueError("unsupported authority domain")
    _strict_str(a["keyId"],"keyId",128,_ID); _strict_str(a["authorityId"],"authorityId",128,_ID); _strict_str(a["assignmentId"],"assignmentId",128,_ID)
    _sha256(a["assignmentSha256"],"assignmentSha256"); _strict_str(a["builderId"],"builderId",128,_ID); _strict_str(a["taskId"],"taskId",128,_ID); _strict_str(a["runId"],"runId",128,_ID)
    _strict_int(a["ownerEpoch"],"ownerEpoch"); _strict_int(a["attempt"],"attempt"); _repository(a["repository"]); _git_oid(a["baseSha"],"baseSha"); _git_oid(a["currentHead"],"currentHead")
    if "branch" in a: _branch(a["branch"])
    _worktree(a["worktreePath"],worktree_root,inspect_worktree); _runtime(a["runtime"])
    _,allowed=_paths(a["allowedPaths"],"allowedPaths"); _,denied=_paths(a["deniedPaths"],"deniedPaths")
    if any(_contains(x,y) or _contains(y,x) for x in allowed for y in denied): raise ValueError("allowedPaths and deniedPaths overlap")
    _tools(a["allowedTools"]); _sha256(a["contextBundleHash"],"contextBundleHash"); _known_good(a["controllerKnownGood"]); policy=_review_policy(a["reviewPolicy"])
    if policy["reviewerId"].casefold()==a["builderId"].casefold(): raise ValueError("reviewer must be independent from builder")
    _finite(a["budgetUsd"],"budgetUsd",True); issued=_finite(a["issuedAt"],"issuedAt"); expires=_finite(a["expiresAt"],"expiresAt")
    if expires<=issued: raise ValueError("authority time window invalid")
    if now is not None:
        cur=_finite(now,"verification time")
        if cur<issued: raise PermissionError("authority not yet valid")
        if cur>=expires: raise PermissionError("authority expired")
    return a

class ControllerAuthorityVerifier:
    def __init__(self,trust,worktree_root):
        if not isinstance(trust,PinnedAuthorityTrust): raise TypeError("pinned authority trust required")
        self._trust=trust; self._worktree_root=_canonical_absolute(worktree_root,"worktreeRoot")
    def verify(self,packet,now):
        if not isinstance(packet,dict) or set(packet)!={"authority","signature"}: raise ValueError("signed authority schema mismatch")
        a=copy.deepcopy(packet["authority"]); validate_authority(a,now,self._worktree_root,inspect_worktree=True)
        key=self._trust.key_for(a["keyId"],now); sig=packet["signature"]
        if not isinstance(sig,str) or not sig.startswith("ed25519:"): raise PermissionError("protected authority requires ed25519")
        if Ed25519PublicKey is None: raise RuntimeError("cryptography Ed25519 support unavailable")
        try:
            pub=base64.b64decode(key.public_key_b64,validate=True); raw=base64.b64decode(sig.split(":",1)[1],validate=True)
            if len(raw)!=64: raise ValueError("invalid Ed25519 signature length")
            Ed25519PublicKey.from_public_bytes(pub).verify(raw,canonical(a))
        except Exception as exc: raise PermissionError("authority signature mismatch") from exc
        return a

class ControllerAuthoritySignerClient:
    def __init__(self,transport,controller_identity,worktree_root):
        if not callable(transport): raise TypeError("signer transport must be callable")
        self._transport=transport; self._controller_identity=_strict_str(controller_identity,"controller identity",128,_ID); self._worktree_root=_canonical_absolute(worktree_root,"worktreeRoot")
    def sign_worker_launch(self,authority):
        if not isinstance(authority,dict): raise ValueError("authority must be object")
        checked=copy.deepcopy(authority); validate_authority(checked,worktree_root=self._worktree_root,inspect_worktree=True); expected=canonical(checked)
        req={"type":"sign-worker-launch","controllerIdentity":self._controller_identity,"authority":copy.deepcopy(checked)}
        res=self._transport(req)
        if not isinstance(res,dict) or set(res)!={"authority","signature"} or not isinstance(res["authority"],dict): raise PermissionError("protected signer returned malformed authority")
        try:
            returned=copy.deepcopy(res["authority"]); validate_authority(returned,worktree_root=self._worktree_root,inspect_worktree=True)
            if canonical(returned)!=expected: raise PermissionError("protected signer returned mismatched authority")
        except PermissionError: raise
        except Exception as exc: raise PermissionError("protected signer returned invalid authority") from exc
        sig=res["signature"]
        if not isinstance(sig,str) or not sig.startswith("ed25519:"): raise PermissionError("protected signer returned unsupported signature")
        return {"authority":returned,"signature":sig}
