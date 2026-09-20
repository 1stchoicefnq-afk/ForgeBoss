from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .activation import ActivationError
from .self_build_compose import SelfBuildComposeError,build_manifest
from .self_build_freeze import _git
from .workspace import cleanup_workspace,provision_workspace
from .workspace_state import ProtectedWorkspaceState

_RUN_ID=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DAEMON_REL="forgeboss/control/daemon.py"
_NEEDLE=b"RUNTIME_IDENTITY=runtime_identity_from_env(ROOT)"
_BROKEN=b'RUNTIME_IDENTITY={**runtime_identity_from_env(ROOT),"revision":"0"*40}'


class SelfBuildRollbackProofError(RuntimeError):
    def __init__(self,code:str,message:str):
        super().__init__(message);self.code=code


def _fail(code,message):
    raise SelfBuildRollbackProofError(code,message)


def _digest(value)->str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")).hexdigest()


def _git_text(git,root,*args):
    try:return _git(git,root,*args)
    except Exception as ex:raise SelfBuildRollbackProofError(getattr(ex,"code","ROLLBACK_PROOF_GIT_FAILED"),str(ex)) from ex


def run_rollback_proof(*,run_id:str,current_identity:dict,activation_root,workspace_root,
                       protected_state,git_executable,manifest_path,activation_manager_factory)->dict:
    if not isinstance(run_id,str) or not _RUN_ID.fullmatch(run_id):
        _fail("RUN_ID_INVALID","rollback proof run id invalid")
    if not isinstance(current_identity,dict) or current_identity.get("verified") is not True:
        _fail("ROLLBACK_PROOF_IDENTITY_INVALID","rollback proof requires verified current known-good identity")
    try:
        source=Path(str(current_identity.get("codeRoot") or "")).resolve(strict=True)
        revision=str(current_identity.get("revision") or "").lower()
        current_manifest=Path(str(current_identity.get("manifestPath") or "")).resolve(strict=True)
        current_manifest_sha=str(current_identity.get("manifestSha256") or "").lower()
        root=Path(workspace_root).resolve(strict=True)
        git=Path(git_executable).resolve(strict=True)
        manifest=Path(manifest_path)
    except Exception as ex:
        raise SelfBuildRollbackProofError("ROLLBACK_PROOF_IDENTITY_INVALID","rollback proof current identity paths invalid") from ex
    if len(revision) not in (40,64) or any(c not in "0123456789abcdef" for c in revision):
        _fail("ROLLBACK_PROOF_IDENTITY_INVALID","rollback proof current revision invalid")
    if not manifest.is_absolute() or not manifest.parent.is_dir():
        _fail("ROLLBACK_PROOF_MANIFEST_INVALID","rollback proof manifest path invalid")

    drill=root/f"{run_id}-rollback-drill"
    branch=f"forgeboss/fl1-rollback-drill-{run_id}"
    if drill.exists() or drill.is_symlink() or manifest.exists() or manifest.is_symlink():
        _fail("ROLLBACK_PROOF_ALREADY_EXISTS","rollback proof artifacts already exist")

    try:
        state=ProtectedWorkspaceState(protected_root=protected_state.root,boundary=protected_state.boundary)
    except Exception as ex:
        raise SelfBuildRollbackProofError(getattr(ex,"code","ROLLBACK_PROOF_STATE_INVALID"),str(ex)) from ex

    provisioned=False
    candidate_sha=None
    manifest_sha=None
    activation_generation=None
    expected_failure=None
    final_state=None
    pointer=None
    try:
        try:
            provision_workspace(source,drill,root,revision,branch,git,protected_state=state)
            provisioned=True
        except Exception as ex:
            raise SelfBuildRollbackProofError(getattr(ex,"code","ROLLBACK_PROOF_PROVISION_FAILED"),str(ex)) from ex
        drill=drill.resolve(strict=True)
        if _git_text(git,drill,"rev-parse","HEAD").lower()!=revision:
            _fail("ROLLBACK_PROOF_BASE_MISMATCH","rollback proof workspace did not start at exact known-good")
        if _git_text(git,drill,"remote"):
            _fail("ROLLBACK_PROOF_REMOTE_PRESENT","rollback proof workspace has a remote")
        daemon=drill.joinpath(*_DAEMON_REL.split("/"))
        raw=daemon.read_bytes()
        if raw.count(_NEEDLE)!=1:
            _fail("ROLLBACK_PROOF_ANCHOR_INVALID","daemon runtime identity anchor is not unique")
        daemon.write_bytes(raw.replace(_NEEDLE,_BROKEN,1))
        _git_text(git,drill,"add","--",_DAEMON_REL)
        _git_text(git,drill,"-c","user.name=ForgeBoss Rollback Proof","-c","user.email=forgeboss@localhost",
                  "commit","--no-gpg-sign","--no-verify","-m",f"rollback proof: {run_id}","--")
        candidate_sha=_git_text(git,drill,"rev-parse","HEAD").lower()
        if candidate_sha==revision:
            _fail("ROLLBACK_PROOF_CANDIDATE_INVALID","rollback proof candidate did not change")
        changed=[x.strip().replace("\\","/") for x in _git_text(git,drill,"diff","--name-only",revision,candidate_sha,"--").splitlines() if x.strip()]
        if changed!=[_DAEMON_REL]:
            _fail("ROLLBACK_PROOF_SCOPE_INVALID","rollback proof candidate changed unexpected files")
        if _git_text(git,drill,"status","--porcelain=v1","--untracked-files=all"):
            _fail("ROLLBACK_PROOF_CANDIDATE_DIRTY","rollback proof candidate is not pristine")
        try:manifest_sha,_identity=build_manifest(git=git,root=drill,revision=candidate_sha,manifest_path=manifest)
        except SelfBuildComposeError as ex:raise SelfBuildRollbackProofError(ex.code,str(ex)) from ex

        manager=activation_manager_factory(Path(activation_root),current_identity)
        manager.initialize_known_good()
        before=manager.status()
        if before.get("phase")!="READY":
            _fail("ROLLBACK_PROOF_NOT_READY","rollback proof requires sealed READY known-good activation state")
        activation_generation=int(before.get("generation",0))+1
        staged=manager.stage(drill,manifest,candidate_sha,manifest_sha,expected_generation=int(before.get("generation",0)))
        if int(staged.get("generation",0))!=activation_generation or staged.get("phase")!="STAGED":
            _fail("ROLLBACK_PROOF_STAGE_INVALID","rollback proof candidate did not stage as exact next generation")
        manager.start_candidate(expected_generation=activation_generation)
        try:
            manager.authoritative_probe(expected_generation=activation_generation,timeout=20.0)
        except ActivationError as ex:
            expected_failure=str(ex)
        else:
            try:manager.rollback("rollback proof unexpectedly passed",expected_generation=activation_generation)
            except Exception:pass
            _fail("ROLLBACK_PROOF_UNEXPECTED_PASS","deliberately broken candidate unexpectedly passed authoritative probe")

        final_state=manager.status()
        pointer=manager.known_good_pointer() or {}
        if final_state.get("phase")!="ROLLED_BACK":
            _fail("ROLLBACK_PROOF_NOT_ROLLED_BACK","broken candidate did not finish in ROLLED_BACK state")
        if final_state.get("processIdentity") is not None:
            _fail("ROLLBACK_PROOF_PROCESS_LIVE","broken candidate process identity remains after rollback")
        current=(pointer.get("current") or {})
        for key,want in (("revision",revision),("codeRoot",str(source)),("manifestPath",str(current_manifest)),("manifestSha256",current_manifest_sha)):
            if current.get(key)!=want:
                _fail("ROLLBACK_PROOF_POINTER_MISMATCH","known-good pointer was not restored exactly: "+key)
    finally:
        cleanup_error=None
        if provisioned:
            try:cleanup_workspace(drill,root,protected_state=state)
            except Exception as ex:cleanup_error=ex
        try:state.close()
        except Exception as ex:
            if cleanup_error is None:cleanup_error=ex
        if cleanup_error is not None:
            raise SelfBuildRollbackProofError(getattr(cleanup_error,"code","ROLLBACK_PROOF_CLEANUP_FAILED"),str(cleanup_error)) from cleanup_error

    if drill.exists() or drill.is_symlink():
        _fail("ROLLBACK_PROOF_CLEANUP_FAILED","rollback proof workspace remains")
    evidence={
        "schema":1,"status":"ROLLBACK_PROVEN","run_id":run_id,
        "known_good_revision":revision,"broken_candidate_sha":candidate_sha,
        "changed_files":[_DAEMON_REL],"manifest_sha256":manifest_sha,
        "activation_generation":activation_generation,"final_phase":(final_state or {}).get("phase"),
        "pointer_revision":((pointer or {}).get("current") or {}).get("revision"),
        "expected_probe_failure":expected_failure,"candidate_process_dead":True,
        "workspace_cleaned":True,
    }
    evidence["evidence_digest"]=_digest(evidence)
    return evidence
