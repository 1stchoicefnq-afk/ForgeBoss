from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple

SCHEMA_VERSION = 3
POLICY_PATH_KEY_VERSION = "win-git-v1"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_RESERVED = {"con","prn","aux","nul","clock$","conin$","conout$",*(f"com{i}" for i in range(1,10)),*(f"lpt{i}" for i in range(1,10))}
_SUPERSCRIPT_RESERVED = re.compile(r"^(?:com|lpt)[¹²³](?:\..*)?$", re.I)

class ReceiptError(ValueError): pass

def _closed(obj: Mapping[str, Any], allowed: Iterable[str], *, required: Iterable[str]=()) -> dict:
    if not isinstance(obj, Mapping): raise ReceiptError("record must be an object")
    allowed=set(allowed); required=set(required); extra=set(obj)-allowed; missing=required-set(obj)
    if extra: raise ReceiptError("unknown keys: "+",".join(sorted(extra)))
    if missing: raise ReceiptError("missing keys: "+",".join(sorted(missing)))
    return dict(obj)

def _text(value: Any, name: str, *, pattern=None, lower=False) -> str:
    if not isinstance(value,str) or not value or value!=value.strip(): raise ReceiptError(f"{name} must be non-empty canonical text")
    if any(ord(c)<32 or ord(c)==127 for c in value): raise ReceiptError(f"{name} contains forbidden control characters")
    out=value.lower() if lower else value
    if pattern is not None and not pattern.fullmatch(out): raise ReceiptError(f"{name} is invalid")
    return out

def _positive_int(value: Any,name: str,*,allow_zero=False)->int:
    if isinstance(value,bool) or not isinstance(value,int): raise ReceiptError(f"{name} must be an integer")
    if value < (0 if allow_zero else 1) or value > 2**63-1: raise ReceiptError(f"{name} is out of range")
    return value

def _git_oid(value: Any,name: str)->str:
    out=_text(value,name,lower=True)
    if not (_HEX40.fullmatch(out) or _HEX64.fullmatch(out)): raise ReceiptError(f"{name} must be a Git SHA-1/SHA-256 object id")
    return out

def _same_git_format(*oids: str)->None:
    lengths={len(x) for x in oids}
    if len(lengths)!=1: raise ReceiptError("mixed Git object formats are denied")

def _digest(value:Any,name:str)->str: return _text(value,name,pattern=_HEX64,lower=True)

def canonical_money(value:Any,name:str="money")->str:
    if not isinstance(value,str) or value!=value.strip() or not _DECIMAL.fullmatch(value): raise ReceiptError(f"{name} must be a non-negative decimal string without exponent/whitespace")
    try:d=Decimal(value)
    except InvalidOperation as ex: raise ReceiptError(f"{name} is invalid") from ex
    if not d.is_finite() or d<0: raise ReceiptError(f"{name} must be finite and non-negative")
    out=format(d,"f")
    if "." in out: out=out.rstrip("0").rstrip(".")
    return out or "0"

def _jsonable(value:Any)->Any:
    if isinstance(value,MappingProxyType): value=dict(value)
    if isinstance(value,Mapping): return {str(k):_jsonable(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)): return [_jsonable(v) for v in value]
    if isinstance(value,frozenset): return sorted(_jsonable(v) for v in value)
    if isinstance(value,(str,int,bool)) or value is None:return value
    raise ReceiptError(f"non-canonical value type: {type(value).__name__}")

def canonical_bytes(value:Any)->bytes:
    try:return json.dumps(_jsonable(value),sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
    except (TypeError,ValueError) as ex: raise ReceiptError("record is not canonical JSON") from ex

def receipt_digest(value:Any)->str:return hashlib.sha256(canonical_bytes(value)).hexdigest()

def strict_loads(text:Any)->Any:
    if not isinstance(text,str): raise ReceiptError("JSON input must be text")
    def pairs(items):
        out={}
        for k,v in items:
            if k in out: raise ReceiptError(f"duplicate JSON key: {k}")
            out[k]=v
        return out
    def constant(name): raise ReceiptError(f"non-finite JSON constant denied: {name}")
    try:return json.loads(text,object_pairs_hook=pairs,parse_constant=constant)
    except ReceiptError:raise
    except Exception as ex: raise ReceiptError("invalid JSON") from ex

def _git_component_policy_key(component:str)->str:
    if component in ("",".",".."): raise ReceiptError("empty/dot/traversal Git path component denied")
    if component[-1:] in (" ","."): raise ReceiptError("Windows trailing-dot/space alias denied")
    if ":" in component: raise ReceiptError("Windows ADS/colon path denied")
    if any(ord(c)<32 for c in component): raise ReceiptError("control character in Git path denied")
    folded=component.casefold();base=folded.split(".",1)[0]
    if base in _RESERVED or _SUPERSCRIPT_RESERVED.fullmatch(folded): raise ReceiptError("Windows reserved device path denied")
    if "~" in component: raise ReceiptError("Windows 8.3 alias candidate denied")
    return folded.replace("%","%25").replace("\\","%5c")

def policy_path_key(path:Any)->str:
    p=_text(path,"gitPath")
    if p.startswith(("/","//","\\\\","\\\\?\\","\\\\.\\")): raise ReceiptError("rooted/UNC/device Git path denied")
    if len(p)>=2 and p[0].isalpha() and p[1]==":": raise ReceiptError("drive-absolute Git path denied")
    return POLICY_PATH_KEY_VERSION+":"+"/".join(_git_component_policy_key(c) for c in p.split("/"))

def exact_git_paths(values:Sequence[Any],name:str="paths")->Tuple[Tuple[str,str],...]:
    if not isinstance(values,(list,tuple)): raise ReceiptError(f"{name} must be an array")
    seen_exact=set();seen_policy={};out=[]
    for raw in values:
        r=_closed(raw,{"gitPath","policyPathKey","policyVersion"},required={"gitPath","policyPathKey","policyVersion"})
        exact=_text(r["gitPath"],f"{name}[].gitPath"); version=_text(r["policyVersion"],f"{name}[].policyVersion")
        if version!=POLICY_PATH_KEY_VERSION: raise ReceiptError("unsupported policy path key version")
        derived=policy_path_key(exact); supplied=_text(r["policyPathKey"],f"{name}[].policyPathKey")
        if supplied!=derived: raise ReceiptError("policyPathKey does not match exact Git path")
        if exact in seen_exact: raise ReceiptError(f"duplicate exact Git path: {exact}")
        other=seen_policy.get(derived)
        if other is not None and other!=exact: raise ReceiptError(f"policy path collision: {other!r} vs {exact!r}")
        seen_exact.add(exact);seen_policy[derived]=exact;out.append((exact,derived))
    return tuple(out)

def _ids(values:Sequence[Any],name:str)->Tuple[str,...]:
    if not isinstance(values,(list,tuple)): raise ReceiptError(f"{name} must be an array")
    out=[];seen=set()
    for value in values:
        item=_text(value,f"{name}[]",pattern=_ID);folded=item.casefold()
        if folded in seen: raise ReceiptError(f"duplicate {name} identity")
        seen.add(folded);out.append(item)
    return tuple(out)

@dataclass(frozen=True)
class AssignmentIdentityReference:
    identity_sha256:str; task_id:str; run_id:str; attempt:int; owner_epoch:int; builder_principal:str
    assignment_generation:int; assignment_policy_sha256:str; repository:str; base_sha:str; branch:str
    worktree_path:str; workspace_generation:int; workspace_content_identity:str; budget_run_id:str

    @classmethod
    def from_store_packet(cls,raw:Mapping[str,Any])->"AssignmentIdentityReference":
        outer=_closed(raw,{"identity","assignmentIdentitySha256"},required={"identity","assignmentIdentitySha256"})
        ident=_closed(outer["identity"],{
            "taskId","runId","attempt","ownerEpoch","builderPrincipal","assignmentGeneration","assignmentPolicySha256",
            "repository","baseSha","branch","worktreePath","workspaceGeneration","workspaceContentIdentity","budgetRunId"
        },required={"taskId","runId","attempt","ownerEpoch","builderPrincipal","assignmentGeneration","assignmentPolicySha256",
            "repository","baseSha","branch","worktreePath","workspaceGeneration","workspaceContentIdentity","budgetRunId"})
        supplied=_digest(outer["assignmentIdentitySha256"],"assignmentIdentitySha256")
        actual=hashlib.sha256(json.dumps(ident,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
        if supplied!=actual: raise ReceiptError("Store assignment identity digest mismatch")
        repo=_text(ident["repository"],"repository",pattern=_REPO,lower=True)
        base=_git_oid(ident["baseSha"],"baseSha"); content=_git_oid(ident["workspaceContentIdentity"],"workspaceContentIdentity")
        _same_git_format(base,content)
        return cls(supplied,_text(ident["taskId"],"taskId",pattern=_ID),_text(ident["runId"],"runId",pattern=_ID),
            _positive_int(ident["attempt"],"attempt"),_positive_int(ident["ownerEpoch"],"ownerEpoch"),
            _text(ident["builderPrincipal"],"builderPrincipal",pattern=_ID),_positive_int(ident["assignmentGeneration"],"assignmentGeneration"),
            _digest(ident["assignmentPolicySha256"],"assignmentPolicySha256"),repo,base,
            _text(ident["branch"],"branch",pattern=_ID),_text(ident["worktreePath"],"worktreePath"),
            _positive_int(ident["workspaceGeneration"],"workspaceGeneration"),content,_text(ident["budgetRunId"],"budgetRunId",pattern=_ID))

    @classmethod
    def from_store(cls,store,task_id,run_id,owner_epoch):
        return cls.from_store_packet(store.assignment_identity(task_id,run_id,owner_epoch))

    @classmethod
    def from_packet_verified_by_store(cls, raw, store):
        if not isinstance(raw, Mapping) or not isinstance(raw.get("identity"), Mapping):
            raise ReceiptError("assignment must be a Store identity packet")
        ident = raw["identity"]
        try:
            task_id=ident["taskId"]; run_id=ident["runId"]; owner_epoch=ident["ownerEpoch"]
        except KeyError as ex:
            raise ReceiptError("assignment identity lookup fields missing") from ex
        authoritative=store.assignment_identity(task_id,run_id,owner_epoch)
        if canonical_bytes(raw) != canonical_bytes(authoritative):
            raise ReceiptError("assignment packet does not match durable Store authority")
        return cls.from_store_packet(authoritative)

    def to_store_packet(self)->dict:
        ident={"taskId":self.task_id,"runId":self.run_id,"attempt":self.attempt,"ownerEpoch":self.owner_epoch,
            "builderPrincipal":self.builder_principal,"assignmentGeneration":self.assignment_generation,
            "assignmentPolicySha256":self.assignment_policy_sha256,"repository":self.repository,"baseSha":self.base_sha,
            "branch":self.branch,"worktreePath":self.worktree_path,"workspaceGeneration":self.workspace_generation,
            "workspaceContentIdentity":self.workspace_content_identity,"budgetRunId":self.budget_run_id}
        return {"identity":ident,"assignmentIdentitySha256":self.identity_sha256}

@dataclass(frozen=True)
class CandidateHandoff:
    assignment:AssignmentIdentityReference; candidate_sha:str; candidate_tree_sha:str; changed_paths:Tuple[Tuple[str,str],...]
    required_test_receipts:Tuple[str,...]; scope_diff_sha256:str; additions:int; deletions:int
    measured_cost_usd:Optional[str]; reserved_cost_usd:str; contributors:Tuple[str,...]; known_uncertainty:Tuple[str,...]

    @classmethod
    def from_dict(cls,raw:Mapping[str,Any],*,store)->"CandidateHandoff":
        req={"assignment","candidateSha","candidateTreeSha","changedPaths","requiredTestReceipts","scopeDiffSha256","additions","deletions","measuredCostUsd","reservedCostUsd","contributors","knownUncertainty"}
        r=_closed(raw,req,required=req);a=AssignmentIdentityReference.from_packet_verified_by_store(r["assignment"],store)
        c=_git_oid(r["candidateSha"],"candidateSha");t=_git_oid(r["candidateTreeSha"],"candidateTreeSha");_same_git_format(a.base_sha,a.workspace_content_identity,c,t)
        paths=exact_git_paths(r["changedPaths"],"changedPaths");tests=tuple(_digest(x,"requiredTestReceipts[]") for x in r["requiredTestReceipts"])
        if len(set(tests))!=len(tests):raise ReceiptError("duplicate required test receipt")
        measured=None if r["measuredCostUsd"] is None else canonical_money(r["measuredCostUsd"],"measuredCostUsd")
        reserved=canonical_money(r["reservedCostUsd"],"reservedCostUsd")
        unc_raw=r["knownUncertainty"]
        if not isinstance(unc_raw,(list,tuple)):raise ReceiptError("knownUncertainty must be an array")
        contributors=_ids(r["contributors"],"contributors")
        if not contributors:raise ReceiptError("candidate handoff requires at least one contributor")
        return cls(a,c,t,paths,tests,_digest(r["scopeDiffSha256"],"scopeDiffSha256"),_positive_int(r["additions"],"additions",allow_zero=True),
            _positive_int(r["deletions"],"deletions",allow_zero=True),measured,reserved,contributors,tuple(_text(x,"knownUncertainty[]") for x in unc_raw))

    def to_dict(self)->dict:
        return {"assignment":self.assignment.to_store_packet(),"candidateSha":self.candidate_sha,"candidateTreeSha":self.candidate_tree_sha,
            "changedPaths":[{"gitPath":p,"policyPathKey":k,"policyVersion":POLICY_PATH_KEY_VERSION} for p,k in self.changed_paths],
            "requiredTestReceipts":list(self.required_test_receipts),"scopeDiffSha256":self.scope_diff_sha256,"additions":self.additions,
            "deletions":self.deletions,"measuredCostUsd":self.measured_cost_usd,"reservedCostUsd":self.reserved_cost_usd,
            "contributors":list(self.contributors),"knownUncertainty":list(self.known_uncertainty)}
    @property
    def digest(self)->str:return receipt_digest({"type":"candidate-handoff","schemaVersion":SCHEMA_VERSION,**self.to_dict()})

@dataclass(frozen=True)
class ReviewerReceipt:
    assignment:AssignmentIdentityReference;handoff_sha256:str;candidate_sha:str;candidate_tree_sha:str;reviewer_id:str;verdict:str;evidence_sha256:str;reviewer_test_receipts:Tuple[str,...]
    @classmethod
    def from_dict(cls,raw:Mapping[str,Any],*,store,handoff:Optional[CandidateHandoff]=None)->"ReviewerReceipt":
        req={"assignment","handoffSha256","candidateSha","candidateTreeSha","reviewerId","verdict","evidenceSha256","reviewerTestReceipts"};r=_closed(raw,req,required=req)
        a=AssignmentIdentityReference.from_packet_verified_by_store(r["assignment"],store); verdict=_text(r["verdict"],"verdict",lower=True)
        if verdict not in ("pass","fail","blocked"):raise ReceiptError("invalid review verdict")
        c=_git_oid(r["candidateSha"],"candidateSha");t=_git_oid(r["candidateTreeSha"],"candidateTreeSha");_same_git_format(a.base_sha,c,t)
        obj=cls(a,_digest(r["handoffSha256"],"handoffSha256"),c,t,_text(r["reviewerId"],"reviewerId",pattern=_ID),verdict,
            _digest(r["evidenceSha256"],"evidenceSha256"),tuple(_digest(x,"reviewerTestReceipts[]") for x in r["reviewerTestReceipts"]))
        if handoff is not None:obj.assert_matches_handoff(handoff)
        return obj
    def assert_matches_handoff(self,handoff:CandidateHandoff)->None:
        if self.assignment!=handoff.assignment:raise ReceiptError("review assignment identity mismatch")
        if self.handoff_sha256!=handoff.digest:raise ReceiptError("review handoff digest mismatch")
        if self.candidate_sha!=handoff.candidate_sha or self.candidate_tree_sha!=handoff.candidate_tree_sha:raise ReceiptError("review candidate identity mismatch")
        if self.reviewer_id.casefold() in {x.casefold() for x in handoff.contributors}:raise ReceiptError("reviewer is a candidate contributor")
    def to_dict(self)->dict:return {"assignment":self.assignment.to_store_packet(),"handoffSha256":self.handoff_sha256,"candidateSha":self.candidate_sha,"candidateTreeSha":self.candidate_tree_sha,"reviewerId":self.reviewer_id,"verdict":self.verdict,"evidenceSha256":self.evidence_sha256,"reviewerTestReceipts":list(self.reviewer_test_receipts)}
    @property
    def digest(self)->str:return receipt_digest({"type":"reviewer-receipt","schemaVersion":SCHEMA_VERSION,**self.to_dict()})

@dataclass(frozen=True)
class ControllerAcceptanceReference:
    assignment:AssignmentIdentityReference;handoff_sha256:str;review_sha256:str;candidate_sha:str;candidate_tree_sha:str;controller_id:str;accepted:bool
    @classmethod
    def from_records(cls,*,controller_id:str,handoff:CandidateHandoff,review:ReviewerReceipt)->"ControllerAcceptanceReference":
        review.assert_matches_handoff(handoff)
        if review.verdict!="pass":raise ReceiptError("controller acceptance requires PASS review")
        return cls(handoff.assignment,handoff.digest,review.digest,handoff.candidate_sha,handoff.candidate_tree_sha,_text(controller_id,"controllerId",pattern=_ID),True)
    def to_dict(self)->dict:return {"assignment":self.assignment.to_store_packet(),"handoffSha256":self.handoff_sha256,"reviewSha256":self.review_sha256,"candidateSha":self.candidate_sha,"candidateTreeSha":self.candidate_tree_sha,"controllerId":self.controller_id,"accepted":True}
    @property
    def digest(self)->str:return receipt_digest({"type":"controller-acceptance","schemaVersion":SCHEMA_VERSION,**self.to_dict()})
