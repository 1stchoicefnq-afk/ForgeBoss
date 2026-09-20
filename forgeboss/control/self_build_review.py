from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

from .self_build_freeze import _TEST_RE,_canonical_digest,_clean_test_env,_git,_git_bytes,_inside,_is_linklike,_rel,_run
from .workspace import cleanup_workspace,provision_workspace


class SelfBuildReviewError(RuntimeError):
    def __init__(self,code:str,message:str):
        super().__init__(message);self.code=code


def _fail(code,message):
    raise SelfBuildReviewError(code,message)


def _git_text(git:Path,root:Path,*args)->str:
    try:return _git(git,root,*args)
    except Exception as ex:raise SelfBuildReviewError(getattr(ex,"code","REVIEW_GIT_FAILED"),str(ex)) from ex


def _git_bin(git:Path,root:Path,*args)->bytes:
    try:return _git_bytes(git,root,*args)
    except Exception as ex:raise SelfBuildReviewError(getattr(ex,"code","REVIEW_GIT_FAILED"),str(ex)) from ex


def review_frozen_candidate(*,item:dict,handoff,workspace_root,protected_state,git_executable,
                            python_executable=None,reviewer_id:str="reviewer-independent")->dict:
    """Independently re-prove and re-test one exact frozen candidate.

    The reviewer never edits the builder workspace. It provisions a fresh isolated
    checkout from the frozen candidate, runs only the packet's allowlisted unittest
    commands with paid/GitHub/protected credentials stripped, proves the review
    checkout stayed pristine, then destroys that checkout before returning evidence.
    """
    if not isinstance(reviewer_id,str) or not reviewer_id or reviewer_id!=reviewer_id.strip():
        _fail("REVIEWER_ID_INVALID","reviewer identity invalid")
    contributors={str(x).casefold() for x in getattr(handoff,"contributors",())}
    if reviewer_id.casefold() in contributors:
        _fail("SELF_REVIEW_DENIED","independent reviewer cannot be a candidate contributor")

    root=Path(workspace_root).resolve(strict=True)
    raw=Path(str(item.get("worktree") or ""))
    if not raw.is_absolute() or _is_linklike(raw):
        _fail("REVIEW_SOURCE_INVALID","frozen candidate workspace must be a plain absolute path")
    try:source=raw.resolve(strict=True)
    except Exception as ex:raise SelfBuildReviewError("REVIEW_SOURCE_INVALID","frozen candidate workspace missing") from ex
    if source==root or not _inside(source,root):
        _fail("REVIEW_SOURCE_ESCAPE","frozen candidate workspace escapes protected workspace root")

    assignment=getattr(handoff,"assignment",None)
    base=str(getattr(assignment,"base_sha","") or "").lower()
    candidate=str(getattr(handoff,"candidate_sha","") or "").lower()
    tree=str(getattr(handoff,"candidate_tree_sha","") or "").lower()
    if not base or not candidate or not tree:
        _fail("REVIEW_IDENTITY_INVALID","handoff Git identity missing")
    if Path(str(getattr(assignment,"worktree_path","") or "")).resolve(strict=True)!=source:
        _fail("REVIEW_ASSIGNMENT_MISMATCH","handoff worktree differs from protected candidate workspace")
    if str(item.get("task_id") or "")!=str(getattr(assignment,"task_id","") or ""):
        _fail("REVIEW_ASSIGNMENT_MISMATCH","task identity differs from handoff")
    if str(item.get("builder_id") or "")!=str(getattr(assignment,"builder_principal","") or ""):
        _fail("REVIEW_ASSIGNMENT_MISMATCH","builder identity differs from handoff")

    git=Path(git_executable).resolve(strict=True)
    python=Path(python_executable or sys.executable).resolve(strict=True)
    if _git_text(git,source,"rev-parse","HEAD").lower()!=candidate:
        _fail("REVIEW_SOURCE_HEAD_MISMATCH","frozen candidate HEAD changed before review")
    if _git_text(git,source,"status","--porcelain=v1","--untracked-files=all"):
        _fail("REVIEW_SOURCE_DIRTY","frozen candidate workspace changed before review")
    if _git_text(git,source,"remote"):
        _fail("REVIEW_SOURCE_REMOTE_PRESENT","frozen candidate workspace has a remote")

    expected_paths=[_rel(p) for p,_key in getattr(handoff,"changed_paths",())]
    actual_paths=[_rel(x) for x in _git_text(git,source,"diff","--name-only",base,candidate,"--").splitlines() if x.strip()]
    if sorted(x.casefold() for x in actual_paths)!=sorted(x.casefold() for x in expected_paths):
        _fail("REVIEW_SCOPE_MISMATCH","frozen candidate paths differ from handoff")
    if _git_text(git,source,"rev-parse",f"{candidate}^{{tree}}").lower()!=tree:
        _fail("REVIEW_TREE_MISMATCH","frozen candidate tree differs from handoff")
    parents=_git_text(git,source,"rev-list","--parents","-n","1",candidate).split()
    if len(parents)!=2 or parents[1].lower()!=base:
        _fail("REVIEW_PARENT_MISMATCH","candidate must be one direct child of exact base")
    diff_digest=hashlib.sha256(_git_bin(git,source,"diff","--no-ext-diff","--binary",base,candidate,"--")).hexdigest()
    if diff_digest!=str(getattr(handoff,"scope_diff_sha256","") or "").lower():
        _fail("REVIEW_DIFF_MISMATCH","candidate diff digest differs from handoff")

    packet=item.get("packet") or {}
    commands=list(packet.get("required_tests") or [])
    if not commands:
        _fail("REVIEW_TESTS_REQUIRED","independent review requires focused tests")
    tag=hashlib.sha256((str(item.get("task_id") or "")+"\0"+candidate).encode("utf-8")).hexdigest()[:16]
    review_path=root/f"review-{tag}"
    branch=f"forgeboss/fl1-review-{tag}"
    if review_path.exists() or review_path.is_symlink():
        _fail("REVIEW_WORKSPACE_EXISTS","independent review workspace already exists")

    tests=[]
    provisioned=False
    try:
        try:
            provision_workspace(source,review_path,root,candidate,branch,git,protected_state=protected_state)
            provisioned=True
        except Exception as ex:
            raise SelfBuildReviewError(getattr(ex,"code","REVIEW_WORKSPACE_PROVISION_FAILED"),str(ex)) from ex
        review=review_path.resolve(strict=True)
        if _git_text(git,review,"rev-parse","HEAD").lower()!=candidate:
            _fail("REVIEW_WORKSPACE_HEAD_MISMATCH","independent review checkout HEAD mismatch")
        if _git_text(git,review,"remote"):
            _fail("REVIEW_WORKSPACE_REMOTE_PRESENT","independent review checkout has a remote")
        if _git_text(git,review,"status","--porcelain=v1","--untracked-files=all"):
            _fail("REVIEW_WORKSPACE_DIRTY","independent review checkout is not pristine before tests")

        verdict="pass"
        for command in commands:
            command=str(command).strip();m=_TEST_RE.fullmatch(command)
            if not m:_fail("REVIEW_TEST_COMMAND_DENIED","unsupported independent review test command")
            p=_run([python,"-m","unittest",m.group(1),"-v"],cwd=review,env=_clean_test_env(),timeout=240)
            output=(p.stdout or "")+"\n"+(p.stderr or "")
            row={"command":command,"exit_code":int(p.returncode),"output_sha256":hashlib.sha256(output.encode("utf-8")).hexdigest()}
            row["receipt_digest"]=_canonical_digest(row)
            tests.append(row)
            if p.returncode:verdict="fail"

        if _git_text(git,review,"status","--porcelain=v1","--untracked-files=all"):
            _fail("REVIEW_WORKSPACE_MUTATED","review/test execution mutated the independent checkout")
        if _git_text(git,review,"rev-parse","HEAD").lower()!=candidate:
            _fail("REVIEW_WORKSPACE_HEAD_CHANGED","review/test execution changed candidate HEAD")
    finally:
        if provisioned:
            try:
                cleanup_workspace(review_path,root,protected_state=protected_state)
            except Exception as ex:
                raise SelfBuildReviewError(getattr(ex,"code","REVIEW_WORKSPACE_CLEANUP_FAILED"),str(ex)) from ex
    if review_path.exists() or review_path.is_symlink():
        _fail("REVIEW_WORKSPACE_CLEANUP_FAILED","independent review workspace remains after review")
    if _git_text(git,source,"rev-parse","HEAD").lower()!=candidate or _git_text(git,source,"status","--porcelain=v1","--untracked-files=all"):
        _fail("REVIEW_SOURCE_CHANGED","frozen builder candidate changed during independent review")
    if _git_text(git,source,"remote"):
        _fail("REVIEW_SOURCE_CHANGED","frozen builder candidate gained a remote during independent review")

    evidence={
        "schema":1,
        "reviewer_id":reviewer_id,
        "task_id":str(item.get("task_id") or ""),
        "builder_id":str(item.get("builder_id") or ""),
        "base_sha":base,
        "candidate_sha":candidate,
        "candidate_tree_sha":tree,
        "handoff_sha256":str(getattr(handoff,"digest","") or ""),
        "changed_files":expected_paths,
        "scope_diff_sha256":diff_digest,
        "tests":tests,
        "verdict":verdict,
        "workspace_pristine":True,
        "workspace_cleanup_proven":True,
    }
    evidence["evidence_digest"]=_canonical_digest(evidence)
    return evidence
