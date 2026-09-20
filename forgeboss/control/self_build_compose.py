from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Callable

from .known_good import verify_build_manifest
from .receipts import POLICY_PATH_KEY_VERSION, SCHEMA_VERSION, policy_path_key, receipt_digest
from .self_build_freeze import (
    _canonical_digest, _clean_test_env, _git, _git_bytes, _inside, _is_linklike, _rel, _run,
)

_SHA=re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RUN_ID=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TEST=re.compile(r"^python -m unittest ([A-Za-z_][A-Za-z0-9_.]*) -v$")
_ENTRYPOINT="forgeboss/control/daemon.py"
_INVENTORY_MODE="forgeboss-package-v2-git-bound"


class SelfBuildComposeError(RuntimeError):
    def __init__(self,code:str,message:str):
        super().__init__(message);self.code=code


def _fail(code,message):raise SelfBuildComposeError(code,message)

def _sha(value,code="SHA_INVALID"):
    out=str(value or "").lower()
    if not _SHA.fullmatch(out):_fail(code,"exact Git object id required")
    return out

def _path(value):
    raw=str(value or "").replace("\\","/");out=_rel(raw)
    if raw!=out:_fail("COMPOSITION_PATH_INVALID","non-canonical repository path")
    return out

def _digest(kind,value):return receipt_digest({"type":kind,"schemaVersion":SCHEMA_VERSION,**value})

def _entries(record,key,task):return [x for x in (record.get(key) or []) if x.get("taskId")==task]

def _paths_collide(paths):
    rows=[tuple(x.casefold() for x in PurePosixPath(p).parts) for p in paths]
    for i,a in enumerate(rows):
        for b in rows[i+1:]:
            n=min(len(a),len(b))
            if a[:n]==b[:n]:return True
    return False

def _git_text(git,root,*args):
    try:return _git(git,root,*args)
    except Exception as ex:raise SelfBuildComposeError(getattr(ex,"code","GIT_COMMAND_FAILED"),str(ex)) from ex

def _git_bin(git,root,*args):
    try:return _git_bytes(git,root,*args)
    except Exception as ex:raise SelfBuildComposeError(getattr(ex,"code","GIT_COMMAND_FAILED"),str(ex)) from ex

def _atomic_json(path,value):
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as f:
            json.dump(value,f,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False);f.write("\n");f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        try:
            if os.path.exists(tmp):os.unlink(tmp)
        except OSError:pass

def _worker_set(record):
    prepared=record.get("prepared")
    initial=list((prepared or {}).get("builders") or []);replacement=record.get("replacement")
    if len(initial)!=2 or not isinstance(replacement,dict):_fail("COMPOSITION_PLAN_INVALID","Finish Line 1 requires two initial workers and one replacement")
    replaced=str(replacement.get("replacement_for") or (replacement.get("packet") or {}).get("replacement_for") or "")
    original=next((x for x in initial if str(x.get("task_id") or "")==replaced),None)
    survivor=next((x for x in initial if str(x.get("task_id") or "")!=replaced),None)
    if not replaced or original is None or survivor is None or not replacement.get("task_id"):_fail("COMPOSITION_PLAN_INVALID","replacement lineage invalid")
    rev=[x for x in (record.get("revocations") or []) if x.get("taskId")==replaced]
    authority=original.get("authority") or {}
    if len(rev)!=1 or str(rev[0].get("workerRunId") or "")!=str(authority.get("run_id") or "") or int(rev[0].get("ownerEpoch") or 0)!=int(original.get("owner_epoch") or 0):
        _fail("REPLACED_WRITER_NOT_REVOKED","original writer lacks exact revocation")
    return survivor,original,replacement,replaced

def _validate_chain(record,item,base):
    task=str(item.get("task_id") or "")
    hs,rs,acs=_entries(record,"handoffs",task),_entries(record,"reviews",task),_entries(record,"accepted",task)
    if len(hs)!=1 or len(rs)!=1 or len(acs)!=1:_fail("ACCEPTED_CHAIN_INCOMPLETE",f"one exact receipt chain required for {task}")
    he,re,ac=hs[0],rs[0],acs[0]
    h,r,a=he.get("handoff"),re.get("review"),ac.get("acceptance")
    if not all(isinstance(x,dict) for x in (h,r,a)) or re.get("status")!="PASS" or ac.get("status")!="ACCEPTED":_fail("ACCEPTED_CHAIN_INVALID",f"candidate {task} is not independently accepted")
    hd,rd,ad=_digest("candidate-handoff",h),_digest("reviewer-receipt",r),_digest("controller-acceptance",a)
    if hd!=str(he.get("handoffDigest") or "").lower() or hd!=str(ac.get("handoffDigest") or "").lower():_fail("HANDOFF_DIGEST_MISMATCH","handoff digest mismatch")
    if rd!=str(re.get("reviewDigest") or "").lower() or rd!=str(ac.get("reviewDigest") or "").lower():_fail("REVIEW_DIGEST_MISMATCH","review digest mismatch")
    if ad!=str(ac.get("acceptanceDigest") or "").lower():_fail("ACCEPTANCE_DIGEST_MISMATCH","acceptance digest mismatch")
    assignment=h.get("assignment");ident=(assignment or {}).get("identity") if isinstance(assignment,dict) else None
    if not isinstance(ident,dict) or r.get("assignment")!=assignment or a.get("assignment")!=assignment:_fail("ASSIGNMENT_BINDING_MISMATCH","assignment changed across receipt chain")
    if str(assignment.get("assignmentIdentitySha256") or "").lower()!=_canonical_digest(ident):_fail("ASSIGNMENT_BINDING_MISMATCH","assignment identity digest invalid")
    authority=item.get("authority") or {}
    try:iw=Path(str(item.get("worktree") or "")).resolve(strict=True);aw=Path(str(ident.get("worktreePath") or "")).resolve(strict=True)
    except Exception as ex:raise SelfBuildComposeError("ASSIGNMENT_BINDING_MISMATCH","assignment worktree invalid") from ex
    if any((
        str(ident.get("taskId") or "")!=task,
        str(ident.get("baseSha") or "").lower()!=base,
        str(ident.get("builderPrincipal") or "")!=str(item.get("builder_id") or ""),
        str(ident.get("runId") or "")!=str(authority.get("run_id") or ""),
        int(ident.get("ownerEpoch") or 0)!=int(item.get("owner_epoch") or 0),
        aw!=iw,str(ident.get("workspaceContentIdentity") or "").lower()!=base,
        str(ac.get("workerRunId") or "")!=str(authority.get("run_id") or ""),
        int(ac.get("ownerEpoch") or 0)!=int(item.get("owner_epoch") or 0),
    )):_fail("ASSIGNMENT_BINDING_MISMATCH","accepted chain does not bind exact worker authority/base")
    if str(r.get("verdict") or "").lower()!="pass" or a.get("accepted") is not True:_fail("ACCEPTED_CHAIN_INVALID","PASS review and controller acceptance required")
    if str(r.get("reviewerId") or "").casefold() in {str(x).casefold() for x in (h.get("contributors") or [])}:_fail("SELF_REVIEW_DENIED","candidate reviewer is a contributor")
    candidate,tree=_sha(ac.get("candidateSha"),"CANDIDATE_SHA_INVALID"),_sha(ac.get("candidateTreeSha"),"CANDIDATE_TREE_INVALID")
    if len(candidate)!=len(base) or len(tree)!=len(base):_fail("GIT_FORMAT_MISMATCH","mixed Git object formats denied")
    if any(str(x or "").lower()!=candidate for x in (h.get("candidateSha"),r.get("candidateSha"),a.get("candidateSha"))):_fail("CANDIDATE_BINDING_MISMATCH","candidate SHA mismatch")
    if any(str(x or "").lower()!=tree for x in (h.get("candidateTreeSha"),r.get("candidateTreeSha"),a.get("candidateTreeSha"))):_fail("CANDIDATE_BINDING_MISMATCH","candidate tree mismatch")
    if str(a.get("handoffSha256") or "").lower()!=hd or str(a.get("reviewSha256") or "").lower()!=rd:_fail("ACCEPTANCE_BINDING_MISMATCH","acceptance does not bind exact handoff/review")
    paths=[];keys=[]
    for row in h.get("changedPaths") or []:
        if not isinstance(row,dict) or row.get("policyVersion")!=POLICY_PATH_KEY_VERSION:_fail("COMPOSITION_PATH_INVALID","changed path receipt invalid")
        p=_path(row.get("gitPath"));k=policy_path_key(p)
        if row.get("policyPathKey")!=k:_fail("COMPOSITION_PATH_INVALID","policy path key mismatch")
        paths.append(p);keys.append(k)
    if not paths or len(paths)!=len(set(paths)) or len(keys)!=len(set(keys)) or _paths_collide(paths):_fail("COMPOSITION_PATH_INVALID","candidate changed paths invalid")
    allowed={policy_path_key(_path(x)) for x in ((item.get("packet") or {}).get("allowed_files") or [])}
    if not allowed or any(k not in allowed for k in keys):_fail("COMPOSITION_SCOPE_INVALID","accepted paths exceed original worker scope")
    return {"task":task,"candidate":candidate,"tree":tree,"paths":paths,"keys":keys,"handoff":h,"hd":hd,"rd":rd,"ad":ad}

def _verify_candidate(git,workspace_root,item,row,base):
    raw=Path(str(item.get("worktree") or ""))
    if not raw.is_absolute() or _is_linklike(raw):_fail("CANDIDATE_WORKSPACE_INVALID","candidate workspace must be a plain absolute path")
    try:work=raw.resolve(strict=True)
    except Exception as ex:raise SelfBuildComposeError("CANDIDATE_WORKSPACE_INVALID","candidate workspace missing") from ex
    if work==workspace_root or not _inside(work,workspace_root):_fail("CANDIDATE_WORKSPACE_ESCAPE","candidate workspace escapes protected root")
    if _git_text(git,work,"rev-parse","HEAD").lower()!=row["candidate"]:_fail("CANDIDATE_HEAD_MISMATCH","candidate HEAD mismatch")
    if _git_text(git,work,"status","--porcelain=v1","--untracked-files=all"):_fail("CANDIDATE_WORKSPACE_DIRTY","accepted workspace is not pristine")
    if _git_text(git,work,"remote"):_fail("CANDIDATE_REMOTE_PRESENT","accepted workspace has a remote")
    parents=_git_text(git,work,"rev-list","--parents","-n","1",row["candidate"]).split()
    if len(parents)!=2 or parents[1].lower()!=base:_fail("CANDIDATE_PARENT_MISMATCH","accepted candidate is not one direct child of base")
    if _git_text(git,work,"rev-parse",f"{row['candidate']}^{{tree}}").lower()!=row["tree"]:_fail("CANDIDATE_TREE_MISMATCH","candidate tree mismatch")
    changed=[_path(x) for x in _git_text(git,work,"diff","--name-only",base,row["candidate"],"--").splitlines() if x.strip()]
    if sorted(x.casefold() for x in changed)!=sorted(x.casefold() for x in row["paths"]):_fail("CANDIDATE_SCOPE_MISMATCH","candidate diff does not match handoff")
    if hashlib.sha256(_git_bin(git,work,"diff","--binary",base,row["candidate"],"--")).hexdigest()!=str(row["handoff"].get("scopeDiffSha256") or "").lower():_fail("CANDIDATE_DIFF_MISMATCH","candidate patch digest mismatch")
    blobs={}
    for p in row["paths"]:
        rows=[x for x in _git_bin(git,work,"ls-tree","-z",row["candidate"],"--",p).split(b"\0") if x]
        if len(rows)!=1:_fail("CANDIDATE_BLOB_MISSING","accepted path is not one candidate blob")
        try:meta,name=rows[0].split(b"\t",1);mode,kind,oid=meta.decode("ascii").split(" ");name=name.decode("utf-8","strict").replace("\\","/")
        except Exception as ex:raise SelfBuildComposeError("CANDIDATE_BLOB_INVALID","candidate tree row malformed") from ex
        if name!=p or kind!="blob" or mode not in {"100644","100755"}:_fail("CANDIDATE_BLOB_INVALID","candidate path must be a regular blob")
        blobs[p]=(mode,oid.lower())
    return work,blobs

def _target(root,rel):
    target=root.joinpath(*PurePosixPath(rel).parts);current=root
    for part in PurePosixPath(rel).parts[:-1]:
        current/=part
        if current.exists() or _is_linklike(current):
            if _is_linklike(current) or not current.is_dir():_fail("SUCCESSOR_PATH_ALIAS","non-directory/link in successor path")
        else:current.mkdir()
    if not _inside(target.parent.resolve(strict=True),root):_fail("SUCCESSOR_PATH_ESCAPE","successor target escapes workspace")
    if target.exists() or _is_linklike(target):
        if _is_linklike(target) or not target.is_file():_fail("SUCCESSOR_PATH_ALIAS","non-file/link target denied")
    return target

def _apply(git,work,successor,rel,mode,oid):
    target=_target(successor,rel);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(_git_bin(git,work,"cat-file","blob",oid))
    current=target.stat().st_mode;target.chmod((current|stat.S_IXUSR|stat.S_IXGRP|stat.S_IXOTH) if mode=="100755" else (current&~(stat.S_IXUSR|stat.S_IXGRP|stat.S_IXOTH)))

def _tests(successor,items):
    out=[];seen=set();python=Path(sys.executable).resolve(strict=True)
    for item in items:
        for command in ((item.get("packet") or {}).get("required_tests") or []):
            command=str(command).strip()
            if command in seen:continue
            seen.add(command);m=_TEST.fullmatch(command)
            if not m:_fail("TEST_COMMAND_DENIED","unsupported successor focused test")
            p=_run([python,"-m","unittest",m.group(1),"-v"],cwd=successor,env=_clean_test_env(),timeout=240)
            output=(p.stdout or "")+"\n"+(p.stderr or "");row={"command":command,"exit_code":p.returncode,"output_sha256":hashlib.sha256(output.encode()).hexdigest()};row["receipt_digest"]=_canonical_digest(row);out.append(row)
            if p.returncode:_fail("SUCCESSOR_TEST_FAILED",output[-5000:])
    if not out:_fail("SUCCESSOR_TEST_REQUIRED","successor requires focused tests")
    return out

def build_manifest(*,git,root,revision,manifest_path,entrypoint=_ENTRYPOINT):
    root=Path(root).resolve(strict=True);revision=_sha(revision,"MANIFEST_REVISION_INVALID")
    if _git_text(git,root,"rev-parse","HEAD").lower()!=revision:_fail("MANIFEST_HEAD_MISMATCH","manifest revision is not successor HEAD")
    files={};folded={}
    for row in [x for x in _git_bin(git,root,"ls-tree","-r","-z","--full-tree",revision,"--","forgeboss").split(b"\0") if x]:
        try:meta,name=row.split(b"\t",1);mode,kind,oid=meta.decode("ascii").split(" ");name=name.decode("utf-8","strict").replace("\\","/")
        except Exception as ex:raise SelfBuildComposeError("MANIFEST_TREE_INVALID","Git tree row malformed") from ex
        if kind!="blob" or mode not in {"100644","100755"}:_fail("MANIFEST_TREE_INVALID","unsupported authoritative package entry")
        name=_path(name)
        if "__pycache__" in PurePosixPath(name).parts:continue
        key=name.casefold()
        if key in folded and folded[key]!=name:_fail("MANIFEST_PATH_COLLISION","case-colliding package paths")
        folded[key]=name;files[name]=hashlib.sha256(_git_bin(git,root,"cat-file","blob",oid)).hexdigest()
    if not files or entrypoint not in files:_fail("MANIFEST_INCOMPLETE","authoritative entrypoint missing")
    tree=hashlib.sha256(json.dumps([[k,files[k]] for k in sorted(files)],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    manifest={"schema":1,"inventoryMode":_INVENTORY_MODE,"revision":revision,"codeRoot":str(root),"entrypoint":entrypoint,"treeSha256":tree,"files":files}
    _atomic_json(Path(manifest_path),manifest);digest=hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest();identity=verify_build_manifest(manifest_path,root,revision,digest)
    return digest,identity

def compose_successor(*,record,run_id,source_root,workspace_root,protected_state,git_executable,manifest_path,provision_workspace_fn:Callable|None=None):
    if not isinstance(record,dict) or record.get("schema")!=1:_fail("RUN_STATE_INVALID","self-build run state invalid")
    if not isinstance(run_id,str) or not _RUN_ID.fullmatch(run_id):_fail("RUN_ID_INVALID","self-build run id invalid")
    prepared=record.get("prepared") or {};base=_sha(prepared.get("base_sha"),"BASE_SHA_INVALID")
    if str(prepared.get("run_id") or "")!=run_id:_fail("RUN_ID_MISMATCH","run id differs from protected preparation")
    source=Path(source_root).resolve(strict=True);workspaces=Path(workspace_root).resolve(strict=True);git=Path(git_executable).resolve(strict=True)
    if source!=Path(str(prepared.get("source_root") or "")).resolve(strict=True):_fail("SOURCE_ROOT_MISMATCH","source root differs from protected preparation")
    survivor,original,replacement,replaced=_worker_set(record);items=[survivor,replacement];required={str(x.get("task_id") or "") for x in items};accepted=list(record.get("accepted") or [])
    if len(accepted)!=2 or {str(x.get("taskId") or "") for x in accepted}!=required or replaced in required:_fail("ACCEPTED_SET_INVALID","successor must contain exactly survivor + replacement")
    rows=[_validate_chain(record,item,base) for item in items];all_paths=[p for row in rows for p in row["paths"]]
    if len({k for row in rows for k in row["keys"]})!=len(all_paths) or _paths_collide(all_paths):_fail("COMPOSITION_SCOPE_COLLISION","accepted candidate paths overlap/alias")
    verified=[(*_verify_candidate(git,workspaces,item,row,base),item,row) for item,row in zip(items,rows)]
    manifest=Path(manifest_path)
    if not manifest.is_absolute() or _is_linklike(manifest) or not manifest.parent.exists() or _is_linklike(manifest.parent):_fail("MANIFEST_PATH_INVALID","manifest must be a plain external protected-state path")
    mp=manifest.parent.resolve(strict=True)
    if _inside(mp,source) or _inside(mp,workspaces):_fail("MANIFEST_PATH_INVALID","manifest cannot live in source/worker/successor workspaces")
    successor=workspaces/f"{run_id}-successor";branch=f"forgeboss/fl1-successor-{run_id}"
    if successor.exists() or _is_linklike(successor):_fail("SUCCESSOR_ALREADY_EXISTS","successor workspace already exists")
    if provision_workspace_fn is None:
        from .workspace import provision_workspace as provision_workspace_fn
    try:provision_workspace_fn(source,successor,workspaces,base,branch,git,protected_state=protected_state)
    except Exception as ex:raise SelfBuildComposeError(getattr(ex,"code","SUCCESSOR_PROVISION_FAILED"),str(ex)) from ex
    successor=successor.resolve(strict=True)
    if successor==source or not _inside(successor,workspaces) or _git_text(git,successor,"rev-parse","HEAD").lower()!=base:_fail("SUCCESSOR_BASE_MISMATCH","successor did not start as isolated exact base")
    if _git_text(git,successor,"remote"):_fail("SUCCESSOR_REMOTE_PRESENT","successor workspace has a remote")
    for work,blobs,item,row in verified:
        for rel in row["paths"]:_apply(git,work,successor,rel,*blobs[rel]);_git_text(git,successor,"add","--",rel)
    staged=[_path(x) for x in _git_text(git,successor,"diff","--cached","--name-only","--").splitlines() if x.strip()]
    if sorted(x.casefold() for x in staged)!=sorted(x.casefold() for x in all_paths):_fail("SUCCESSOR_SCOPE_MISMATCH","staged successor differs from accepted union")
    tests=_tests(successor,items)
    _git_text(git,successor,"-c","user.name=ForgeBoss Self-Build","-c","user.email=forgeboss@localhost","commit","--no-gpg-sign","--no-verify","-m",f"self-build compose: {run_id}","--")
    sha=_sha(_git_text(git,successor,"rev-parse","HEAD"),"SUCCESSOR_SHA_INVALID");tree=_sha(_git_text(git,successor,"rev-parse",f"{sha}^{{tree}}"),"SUCCESSOR_TREE_INVALID")
    if sha==base or _git_text(git,successor,"status","--porcelain=v1","--untracked-files=all"):_fail("SUCCESSOR_FREEZE_INVALID","successor is not pristine")
    parents=_git_text(git,successor,"rev-list","--parents","-n","1",sha).split();changed=[_path(x) for x in _git_text(git,successor,"diff","--name-only",base,sha,"--").splitlines() if x.strip()]
    if len(parents)!=2 or parents[1].lower()!=base:_fail("SUCCESSOR_PARENT_MISMATCH","successor must be one direct child of exact base")
    if sorted(x.casefold() for x in changed)!=sorted(x.casefold() for x in all_paths):_fail("SUCCESSOR_DIFF_MISMATCH","frozen successor differs from accepted union")
    md,identity=build_manifest(git=git,root=successor,revision=sha,manifest_path=manifest)
    result={"schema":1,"run_id":run_id,"base_sha":base,"successor_sha":sha,"successor_tree_sha":tree,"workspace":str(successor),"branch":branch,"composed_task_ids":[str(x.get("task_id") or "") for x in items],"replaced_task_id":str(original.get("task_id") or ""),"source_candidates":[{"task_id":r["task"],"candidate_sha":r["candidate"],"candidate_tree_sha":r["tree"],"handoff_digest":r["hd"],"review_digest":r["rd"],"acceptance_digest":r["ad"]} for r in rows],"changed_files":sorted(all_paths,key=str.casefold),"focused_tests":tests,"manifest_path":str(manifest.resolve(strict=True)),"manifest_sha256":md,"identity_sha256":identity["identitySha256"],"tree_sha256":identity["treeSha256"]}
    result["composition_digest"]=_canonical_digest(result);return result
