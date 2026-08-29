from __future__ import annotations

import hashlib, json, re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Sequence

VERSION=3
PATH_POLICY="win-git-v1"
_ID=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_REPO=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_HEX40=re.compile(r"^[0-9a-f]{40}$")
_HEX64=re.compile(r"^[0-9a-f]{64}$")
_MONEY=re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_DEVICE=re.compile(r"^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$",re.I)

class ReceiptError(ValueError): pass

def _obj(v,keys):
    if not isinstance(v,Mapping) or set(v)!=set(keys): raise ReceiptError("record keys invalid")
    return dict(v)

def _text(v,name,pattern=None,lower=False):
    if not isinstance(v,str) or not v or v!=v.strip() or any(ord(c)<32 or ord(c)==127 for c in v):
        raise ReceiptError(f"{name} invalid")
    out=v.lower() if lower else v
    if pattern and not pattern.fullmatch(out): raise ReceiptError(f"{name} invalid")
    return out

def _int(v,name):
    if isinstance(v,bool) or not isinstance(v,int) or v<1 or v>2**63-1: raise ReceiptError(f"{name} invalid")
    return v

def _sha(v,name,fmt):
    return _text(v,name,_HEX40 if fmt=="sha1" else _HEX64 if fmt=="sha256" else re.compile(r"$^"),True)

def _digest(v,name): return _text(v,name,_HEX64,True)

def money(v,name):
    if not isinstance(v,str) or v!=v.strip() or not _MONEY.fullmatch(v): raise ReceiptError(f"{name} invalid")
    try:d=Decimal(v)
    except InvalidOperation as e: raise ReceiptError(f"{name} invalid") from e
    if not d.is_finite() or d<0: raise ReceiptError(f"{name} invalid")
    s=format(d,"f")
    if "." in s:s=s.rstrip("0").rstrip(".")
    return s or "0"

def _jsonable(v):
    if isinstance(v,Mapping): return {str(k):_jsonable(x) for k,x in v.items()}
    if isinstance(v,(list,tuple)): return [_jsonable(x) for x in v]
    if isinstance(v,(str,int,bool)) or v is None:return v
    raise ReceiptError("non-canonical value")

def canonical(v):
    return json.dumps(_jsonable(v),sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()

def digest(v): return hashlib.sha256(canonical(v)).hexdigest()

def strict_loads(raw):
    if not isinstance(raw,str): raise ReceiptError("json must be text")
    def pairs(xs):
        out={}
        for k,v in xs:
            if k in out: raise ReceiptError("duplicate json key")
            out[k]=v
        return out
    def constant(_): raise ReceiptError("nonfinite json")
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
    except ReceiptError: raise
    except Exception as e: raise ReceiptError("invalid json") from e

def policy_path_key(raw):
    p=_text(raw,"gitPath")
    if p.startswith(("/",r"\\")) or (len(p)>=2 and p[0].isalpha() and p[1]==":"): raise ReceiptError("rooted path")
    parts=p.split("/")
    out=[]
    for x in parts:
        if x in ("",".","..") or x!=x.rstrip(" .") or ":" in x or "~" in x or any(c in x for c in '*?<>"|') or _DEVICE.fullmatch(x):
            raise ReceiptError("unsafe git path")
        out.append(x.casefold().replace("%","%25").replace("\\","%5c"))
    return PATH_POLICY+":"+"/".join(out)

def exact_paths(values):
    if not isinstance(values,(list,tuple)): raise ReceiptError("paths invalid")
    exact=set(); policy={}; out=[]
    for rec in values:
        r=_obj(rec,("gitPath","policyVersion","policyPathKey"))
        p=_text(r["gitPath"],"gitPath")
        if r["policyVersion"]!=PATH_POLICY: raise ReceiptError("path policy version")
        k=policy_path_key(p)
        if r["policyPathKey"]!=k: raise ReceiptError("path policy mismatch")
        if p in exact: raise ReceiptError("duplicate exact path")
        if k in policy and policy[k]!=p: raise ReceiptError("path alias collision")
        exact.add(p); policy[k]=p; out.append((p,k))
    return tuple(out)

@dataclass(frozen=True)
class Assignment:
    assignment_id:str
    assignment_sha256:str
    task_id:str
    run_id:str
    attempt:int
    owner_epoch:int
    builder_id:str
    assignment_generation:int
    repository:str
    object_format:str
    base_sha:str
    workspace_generation:int
    workspace_content_sha256:str

    @classmethod
    def parse(cls,raw):
        keys=("assignmentId","assignmentSha256","taskId","runId","attempt","ownerEpoch","builderId","assignmentGeneration",
              "repository","objectFormat","baseSha","workspaceGeneration","workspaceContentSha256")
        r=_obj(raw,keys); fmt=_text(r["objectFormat"],"objectFormat",lower=True)
        if fmt not in ("sha1","sha256"): raise ReceiptError("object format")
        return cls(_text(r["assignmentId"],"assignmentId",_ID),_digest(r["assignmentSha256"],"assignmentSha256"),
                   _text(r["taskId"],"taskId",_ID),_text(r["runId"],"runId",_ID),_int(r["attempt"],"attempt"),
                   _int(r["ownerEpoch"],"ownerEpoch"),_text(r["builderId"],"builderId",_ID),
                   _int(r["assignmentGeneration"],"assignmentGeneration"),
                   _text(r["repository"],"repository",_REPO,True),fmt,_sha(r["baseSha"],"baseSha",fmt),
                   _int(r["workspaceGeneration"],"workspaceGeneration"),_digest(r["workspaceContentSha256"],"workspaceContentSha256"))
    def data(self):
        return {"assignmentId":self.assignment_id,"assignmentSha256":self.assignment_sha256,"taskId":self.task_id,
                "runId":self.run_id,"attempt":self.attempt,"ownerEpoch":self.owner_epoch,"builderId":self.builder_id,
                "assignmentGeneration":self.assignment_generation,"repository":self.repository,"objectFormat":self.object_format,
                "baseSha":self.base_sha,"workspaceGeneration":self.workspace_generation,"workspaceContentSha256":self.workspace_content_sha256}

@dataclass(frozen=True)
class Handoff:
    assignment:Assignment
    candidate_sha:str
    candidate_tree_sha:str
    changed_paths:tuple
    tests:tuple
    diff_sha256:str
    measured_cost_usd:str|None
    reserved_cost_usd:str
    @classmethod
    def parse(cls,raw):
        keys=("assignment","candidateSha","candidateTreeSha","changedPaths","requiredTestReceipts","scopeDiffSha256","measuredCostUsd","reservedCostUsd")
        r=_obj(raw,keys); a=Assignment.parse(r["assignment"])
        tests=tuple(_digest(x,"test receipt") for x in r["requiredTestReceipts"])
        if len(tests)!=len(set(tests)): raise ReceiptError("duplicate test receipt")
        measured=None if r["measuredCostUsd"] is None else money(r["measuredCostUsd"],"measuredCostUsd")
        reserved=money(r["reservedCostUsd"],"reservedCostUsd")
        if measured is not None and Decimal(measured)>Decimal(reserved): raise ReceiptError("measured > reserved")
        return cls(a,_sha(r["candidateSha"],"candidateSha",a.object_format),_sha(r["candidateTreeSha"],"candidateTreeSha",a.object_format),
                   exact_paths(r["changedPaths"]),tests,_digest(r["scopeDiffSha256"],"scopeDiffSha256"),measured,reserved)
    def data(self):
        return {"assignment":self.assignment.data(),"candidateSha":self.candidate_sha,"candidateTreeSha":self.candidate_tree_sha,
                "changedPaths":[{"gitPath":p,"policyVersion":PATH_POLICY,"policyPathKey":k} for p,k in self.changed_paths],
                "requiredTestReceipts":list(self.tests),"scopeDiffSha256":self.diff_sha256,
                "measuredCostUsd":self.measured_cost_usd,"reservedCostUsd":self.reserved_cost_usd}
    @property
    def sha256(self): return digest({"type":"handoff","version":VERSION,**self.data()})

@dataclass(frozen=True)
class Review:
    assignment:Assignment
    handoff_sha256:str
    candidate_sha:str
    candidate_tree_sha:str
    reviewer_id:str
    verdict:str
    evidence_sha256:str
    @classmethod
    def parse(cls,raw,handoff:Handoff):
        keys=("assignment","handoffSha256","candidateSha","candidateTreeSha","reviewerId","verdict","evidenceSha256")
        r=_obj(raw,keys); a=Assignment.parse(r["assignment"])
        verdict=_text(r["verdict"],"verdict",lower=True)
        if verdict not in ("pass","fail","blocked"): raise ReceiptError("verdict")
        obj=cls(a,_digest(r["handoffSha256"],"handoffSha256"),_sha(r["candidateSha"],"candidateSha",a.object_format),
                _sha(r["candidateTreeSha"],"candidateTreeSha",a.object_format),_text(r["reviewerId"],"reviewerId",_ID),
                verdict,_digest(r["evidenceSha256"],"evidenceSha256"))
        obj.match(handoff); return obj
    def match(self,handoff):
        if self.assignment!=handoff.assignment or self.handoff_sha256!=handoff.sha256 or self.candidate_sha!=handoff.candidate_sha or self.candidate_tree_sha!=handoff.candidate_tree_sha:
            raise ReceiptError("review does not bind handoff")
        if self.reviewer_id.casefold()==handoff.assignment.builder_id.casefold(): raise ReceiptError("builder cannot review own candidate")
    def data(self):
        return {"assignment":self.assignment.data(),"handoffSha256":self.handoff_sha256,"candidateSha":self.candidate_sha,
                "candidateTreeSha":self.candidate_tree_sha,"reviewerId":self.reviewer_id,"verdict":self.verdict,"evidenceSha256":self.evidence_sha256}
    @property
    def sha256(self): return digest({"type":"review","version":VERSION,**self.data()})

@dataclass(frozen=True)
class Acceptance:
    assignment:Assignment
    handoff_sha256:str
    review_sha256:str
    candidate_sha:str
    controller_id:str
    @classmethod
    def create(cls,controller_id,handoff:Handoff,review:Review):
        review.match(handoff)
        if review.verdict!="pass": raise ReceiptError("PASS review required")
        controller=_text(controller_id,"controllerId",_ID)
        if controller.casefold() in (handoff.assignment.builder_id.casefold(),review.reviewer_id.casefold()):
            raise ReceiptError("controller acceptance principal must be independent")
        return cls(handoff.assignment,handoff.sha256,review.sha256,handoff.candidate_sha,controller)
    def data(self):
        return {"assignment":self.assignment.data(),"handoffSha256":self.handoff_sha256,"reviewSha256":self.review_sha256,
                "candidateSha":self.candidate_sha,"controllerId":self.controller_id,"accepted":True}
    @property
    def sha256(self): return digest({"type":"acceptance","version":VERSION,**self.data()})
