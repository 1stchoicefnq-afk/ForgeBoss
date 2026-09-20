from __future__ import annotations

import hashlib
import json
import os
import tempfile
import re
import subprocess
from decimal import Decimal, InvalidOperation
from pathlib import Path

from forgeboss.control.self_build_coordinator import SelfBuildCoordinator,SelfBuildCoordinatorError
from forgeboss.control.store import ControlStore
from forgeboss.control.workspace_state import ProtectedWorkspaceState
from forgeboss.security.executor_guard import _resolve_git_executable
from forgeboss.control.receipts import CandidateHandoff,ReviewerReceipt,ControllerAcceptanceReference,POLICY_PATH_KEY_VERSION,policy_path_key,receipt_digest
from forgeboss.control.self_build_review import SelfBuildReviewError,review_frozen_candidate
from forgeboss.control.self_build_compose import SelfBuildComposeError,compose_successor as compose_reviewed_successor,verify_composed_successor


class SelfBuildRuntimeError(RuntimeError):
    def __init__(self,code:str,message:str):
        super().__init__(message);self.code=code


def _fsync_dir(path:Path)->None:
    if os.name=="nt":return
    fd=os.open(str(path),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def _atomic_json(path:Path,value:dict)->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as f:
            json.dump(value,f,sort_keys=True,indent=2)
            f.write("\n");f.flush();os.fsync(f.fileno())
        os.replace(tmp,path);_fsync_dir(path.parent)
    finally:
        try:
            if os.path.exists(tmp):os.unlink(tmp)
        except OSError:pass


class SelfBuildRuntime:
    """Service-principal runtime for ForgeBoss self-build preparation.

    This class performs NO model/API call. It only creates protected task,
    workspace and budget authority. Paid launch remains separately attested.
    """
    def __init__(self,*,protected_root:Path,boundary,receipt_public_key_b64:str,
                 git_resolver=_resolve_git_executable,compose_fn=compose_reviewed_successor,
                 verify_compose_fn=verify_composed_successor,review_fn=review_frozen_candidate):
        root=Path(protected_root)
        if not root.is_absolute():
            raise SelfBuildRuntimeError("PROTECTED_ROOT_INVALID","protected root must be absolute")
        self.root=root.resolve(strict=True)
        boundary.assert_service_principal(self.root)
        self.boundary=boundary
        self.git_resolver=git_resolver
        self.compose_fn=compose_fn
        self.verify_compose_fn=verify_compose_fn
        self.review_fn=review_fn

        self.workspace_root=self.root/"self-build-workspaces"
        self.run_root=self.root/"self-build-runs"
        self.activation_root=self.root/"activation"
        for p in (self.workspace_root,self.run_root,self.activation_root):
            p.mkdir(mode=0o700,exist_ok=True)
            boundary.assert_protected_path(p,protected_root=self.root)

        self.workspace_state=ProtectedWorkspaceState(protected_root=self.root,boundary=boundary)
        self.store=ControlStore(self.root/"self-build-control.sqlite3")
        boundary.assert_protected_path(self.root/"self-build-control.sqlite3",protected_root=self.root)
        self.coordinator=SelfBuildCoordinator(
            store=self.store,receipt_public_key_b64=receipt_public_key_b64
        )

    def close(self):
        try:self.workspace_state.close()
        finally:
            try:self.store.db.close()
            except Exception:pass

    def _assert_service(self)->None:
        try:self.boundary.assert_service_principal(self.root)
        except Exception as ex:raise SelfBuildRuntimeError("SERVICE_PRINCIPAL_DENIED","protected self-build service principal denied") from ex

    def _assert_path(self,path:Path)->None:
        self._assert_service()
        try:self.boundary.assert_protected_path(path,protected_root=self.root)
        except Exception as ex:raise SelfBuildRuntimeError("PROTECTED_STATE_DENIED","protected self-build state path denied") from ex

    def _pointer(self)->dict:
        path=self.activation_root/"known-good.json"
        self._assert_service()
        if not path.is_file():
            raise SelfBuildRuntimeError("KNOWN_GOOD_POINTER_MISSING","protected activation known-good pointer is missing")
        self._assert_path(path)
        try:value=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("KNOWN_GOOD_POINTER_INVALID","protected known-good pointer is unreadable") from ex
        if not isinstance(value,dict):
            raise SelfBuildRuntimeError("KNOWN_GOOD_POINTER_INVALID","protected known-good pointer is invalid")
        return value

    def _run_path(self,run_id:str)->Path:
        if not isinstance(run_id,str) or not run_id or len(run_id)>64 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for c in run_id):
            raise SelfBuildRuntimeError("RUN_ID_INVALID","self-build run id invalid")
        return self.run_root/(run_id+".json")

    def prepare(self,payload:dict)->dict:
        try:
            source=Path(payload["sourceRoot"]).resolve(strict=True)
            base=str(payload["baseSha"]).lower()
            run_id=str(payload["runId"])
        except Exception as ex:
            raise SelfBuildRuntimeError("SELF_BUILD_PAYLOAD_INVALID","self-build prepare payload invalid") from ex
        path=self._run_path(run_id)
        if path.exists():
            raise SelfBuildRuntimeError("RUN_ALREADY_EXISTS","self-build run id already exists")
        git=self.git_resolver()
        try:
            result=self.coordinator.prepare_initial_run(
                source_root=source,
                known_good_pointer=self._pointer(),
                base_sha=base,
                run_id=run_id,
                workspace_root=self.workspace_root,
                git_executable=git,
                protected_state=self.workspace_state,
            )
        except SelfBuildCoordinatorError as ex:
            raise SelfBuildRuntimeError(ex.code,str(ex)) from ex
        record={"schema":1,"phase":"PREPARED","prepared":result,"replacement":None}
        _atomic_json(path,record)
        self._assert_path(path)
        return result

    def prepare_replacement(self,payload:dict)->dict:
        run_id=str(payload.get("runId") or "")
        path=self._run_path(run_id)
        if not path.is_file():
            raise SelfBuildRuntimeError("RUN_NOT_FOUND","self-build run not found")
        self._assert_path(path)
        try:record=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state unreadable") from ex
        if not isinstance(record,dict) or record.get("schema")!=1 or record.get("phase")!="PREPARED" or not isinstance(record.get("prepared"),dict):
            raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run is not replacement-ready")
        if record.get("replacement") is not None:
            raise SelfBuildRuntimeError("REPLACEMENT_ALREADY_PREPARED","replacement authority already exists")
        prepared=record["prepared"]
        git=self.git_resolver()
        try:
            replacement=self.coordinator.prepare_replacement(
                prepared_run=prepared,
                source_root=prepared["source_root"],
                workspace_root=self.workspace_root,
                git_executable=git,
                protected_state=self.workspace_state,
            )
        except SelfBuildCoordinatorError as ex:
            raise SelfBuildRuntimeError(ex.code,str(ex)) from ex
        record["replacement"]=replacement
        record["phase"]="REPLACEMENT_PREPARED"
        _atomic_json(path,record)
        return replacement

    def revoke_worker(self,payload:dict)->dict:
        run_id=str(payload.get("runId") or "")
        path=self._run_path(run_id)
        if not path.is_file():
            raise SelfBuildRuntimeError("RUN_NOT_FOUND","self-build run not found")
        self._assert_path(path)
        try:record=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state unreadable") from ex
        prepared=record.get("prepared") if isinstance(record,dict) else None
        if not isinstance(prepared,dict):
            raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run preparation missing")
        candidates=list(prepared.get("builders") or [])
        if isinstance(record.get("replacement"),dict):candidates.append(record["replacement"])
        task_id=str(payload.get("taskId") or "")
        worker_run_id=str(payload.get("workerRunId") or "")
        try:owner_epoch=int(payload.get("ownerEpoch"))
        except Exception as ex:raise SelfBuildRuntimeError("OWNER_EPOCH_INVALID","owner epoch invalid") from ex
        item=next((x for x in candidates if x.get("task_id")==task_id),None)
        if item is None:
            raise SelfBuildRuntimeError("WORKER_NOT_IN_RUN","worker task is not part of protected run")
        authority=item.get("authority") or {}
        if authority.get("run_id")!=worker_run_id or int(item.get("owner_epoch") or 0)!=owner_epoch:
            raise SelfBuildRuntimeError("WORKER_AUTHORITY_STALE","worker run/epoch does not match protected run")
        reason=str(payload.get("reason") or "").strip()
        if not reason:raise SelfBuildRuntimeError("REVOKE_REASON_REQUIRED","revoke reason required")
        try:
            out=self.store.revoke_writer(task_id,worker_run_id,owner_epoch,reason)
        except Exception as ex:
            code=getattr(ex,"code","WORKER_REVOKE_FAILED")
            raise SelfBuildRuntimeError(code,str(ex)) from ex
        revocations=record.setdefault("revocations",[])
        revocations.append({"taskId":task_id,"workerRunId":worker_run_id,"ownerEpoch":owner_epoch,"reason":reason})
        _atomic_json(path,record)
        return {"revoked":True,"taskId":task_id,"workerRunId":worker_run_id,"ownerEpoch":owner_epoch,"status":out.get("status")}

    def _git(self,root:Path,*args,binary=False):
        git=Path(self.git_resolver()).resolve(strict=True)
        env={k:v for k,v in os.environ.items() if not k.upper().startswith("GIT_")}
        env.update({"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,"GIT_TERMINAL_PROMPT":"0","GIT_ASKPASS":"","GIT_ALLOW_PROTOCOL":"file","GIT_PROTOCOL_FROM_USER":"0"})
        try:
            p=subprocess.run([str(git),"-C",str(root),*map(str,args)],env=env,stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=not binary,
                             encoding=None if binary else "utf-8",errors=None if binary else "strict",
                             timeout=60,check=False)
        except Exception as ex:raise SelfBuildRuntimeError("HANDOFF_GIT_FAILED","candidate Git verification failed") from ex
        if p.returncode:
            detail=p.stderr if not binary else p.stderr.decode("utf-8","replace")
            raise SelfBuildRuntimeError("HANDOFF_GIT_FAILED",str(detail)[-1200:])
        return p.stdout

    def _handoff_item(self,record:dict,payload:dict):
        prepared=record.get("prepared") if isinstance(record,dict) else None
        if not isinstance(prepared,dict):raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run preparation missing")
        candidates=list(prepared.get("builders") or [])
        if isinstance(record.get("replacement"),dict):candidates.append(record["replacement"])
        task_id=str(payload.get("taskId") or "");worker_run_id=str(payload.get("workerRunId") or "")
        try:owner_epoch=int(payload.get("ownerEpoch"))
        except Exception as ex:raise SelfBuildRuntimeError("OWNER_EPOCH_INVALID","owner epoch invalid") from ex
        item=next((x for x in candidates if x.get("task_id")==task_id),None)
        if item is None:raise SelfBuildRuntimeError("WORKER_NOT_IN_RUN","worker task is not part of protected run")
        authority=item.get("authority") or {}
        if authority.get("run_id")!=worker_run_id or int(item.get("owner_epoch") or 0)!=owner_epoch:
            raise SelfBuildRuntimeError("WORKER_AUTHORITY_STALE","worker run/epoch does not match protected run")
        return prepared,item,task_id,worker_run_id,owner_epoch

    def record_handoff(self,payload:dict)->dict:
        run_id=str(payload.get("runId") or "");path=self._run_path(run_id)
        if not path.is_file():raise SelfBuildRuntimeError("RUN_NOT_FOUND","self-build run not found")
        self._assert_path(path)
        try:record=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state unreadable") from ex
        prepared,item,task_id,worker_run_id,owner_epoch=self._handoff_item(record,payload)
        evidence=payload.get("evidence")
        if not isinstance(evidence,dict) or evidence.get("schema")!=1:
            raise SelfBuildRuntimeError("HANDOFF_EVIDENCE_INVALID","candidate evidence invalid")
        source_digest=receipt_digest(evidence)
        existing=next((x for x in (record.get("handoffs") or []) if x.get("taskId")==task_id),None)
        if existing is not None:
            if existing.get("sourceEvidenceDigest")!=source_digest:
                raise SelfBuildRuntimeError("HANDOFF_CONFLICT","candidate handoff already recorded differently")
            return existing

        assignment=self.store.assignment_identity(task_id,worker_run_id,owner_epoch)
        work=Path(item.get("worktree") or "").resolve(strict=True)
        workspace_root=self.workspace_root.resolve(strict=True)
        try:
            if Path(os.path.commonpath([str(workspace_root),str(work)]))!=workspace_root or work==workspace_root:
                raise SelfBuildRuntimeError("HANDOFF_WORKSPACE_INVALID","candidate workspace escapes protected root")
        except ValueError as ex:raise SelfBuildRuntimeError("HANDOFF_WORKSPACE_INVALID","candidate workspace escapes protected root") from ex
        self._assert_path(work)

        base=str(prepared.get("base_sha") or "").lower();candidate=str(evidence.get("candidate_sha") or "").lower()
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})",base) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})",candidate) or len(base)!=len(candidate):
            raise SelfBuildRuntimeError("HANDOFF_SHA_INVALID","candidate/base Git identity invalid")
        head=str(self._git(work,"rev-parse","HEAD")).strip().lower()
        if head!=candidate:raise SelfBuildRuntimeError("HANDOFF_HEAD_MISMATCH","workspace HEAD is not frozen candidate")
        if str(self._git(work,"status","--porcelain=v1","--untracked-files=all")).strip():
            raise SelfBuildRuntimeError("HANDOFF_WORKSPACE_DIRTY","frozen candidate workspace is not pristine")
        if str(self._git(work,"remote")).strip():
            raise SelfBuildRuntimeError("HANDOFF_REMOTE_PRESENT","frozen candidate workspace has a remote")
        tree=str(self._git(work,"rev-parse",f"{candidate}^{{tree}}")).strip().lower()
        changed=[x for x in str(self._git(work,"diff","--name-only",base,candidate,"--")).splitlines() if x.strip()]
        allowed={str(x).replace("\\","/").casefold() for x in ((item.get("packet") or {}).get("allowed_files") or [])}
        if not changed or any(x.replace("\\","/").casefold() not in allowed for x in changed):
            raise SelfBuildRuntimeError("HANDOFF_SCOPE_INVALID","frozen candidate changed scope is invalid")
        claimed=[str(x).replace("\\","/") for x in (evidence.get("changed_files") or [])]
        if sorted(x.casefold() for x in changed)!=sorted(x.casefold() for x in claimed):
            raise SelfBuildRuntimeError("HANDOFF_SCOPE_MISMATCH","candidate evidence changed files mismatch")

        patch=bytes(self._git(work,"diff","--binary",base,candidate,"--",binary=True))
        scope_digest=hashlib.sha256(patch).hexdigest()
        additions=0;deletions=0
        for line in str(self._git(work,"diff","--numstat",base,candidate,"--")).splitlines():
            if not line.strip():continue
            parts=line.split("\t",2)
            if len(parts)!=3 or parts[0]=="-" or parts[1]=="-":
                raise SelfBuildRuntimeError("HANDOFF_CHURN_INVALID","binary/malformed candidate diff denied")
            additions+=int(parts[0]);deletions+=int(parts[1])
        if tree!=str(evidence.get("candidate_tree_sha") or "").lower() or scope_digest!=str(evidence.get("scope_diff_sha256") or "").lower():
            raise SelfBuildRuntimeError("HANDOFF_IDENTITY_MISMATCH","candidate tree/diff digest mismatch")
        if additions!=evidence.get("additions") or deletions!=evidence.get("deletions"):
            raise SelfBuildRuntimeError("HANDOFF_CHURN_MISMATCH","candidate churn evidence mismatch")

        tests=evidence.get("focused_tests") or []
        if not isinstance(tests,list) or not tests:raise SelfBuildRuntimeError("HANDOFF_TEST_EVIDENCE_MISSING","focused test receipts missing")
        test_receipts=[]
        for row in tests:
            if not isinstance(row,dict) or row.get("exit_code")!=0:
                raise SelfBuildRuntimeError("HANDOFF_TEST_EVIDENCE_INVALID","focused test did not pass")
            supplied=str(row.get("receipt_digest") or "").lower()
            core={k:v for k,v in row.items() if k!="receipt_digest"}
            if supplied!=receipt_digest(core):
                raise SelfBuildRuntimeError("HANDOFF_TEST_EVIDENCE_INVALID","focused test receipt digest mismatch")
            test_receipts.append(supplied)

        try:
            measured=Decimal(str(evidence.get("measured_cost_usd")));reserved=Decimal(str((item.get("authority") or {}).get("budget_usd")))
        except (InvalidOperation,ValueError,TypeError) as ex:
            raise SelfBuildRuntimeError("HANDOFF_COST_INVALID","candidate cost evidence invalid") from ex
        if not measured.is_finite() or measured<0 or not reserved.is_finite() or reserved<=0 or measured>reserved:
            raise SelfBuildRuntimeError("HANDOFF_COST_INVALID","candidate cost exceeds protected reservation")
        if str(evidence.get("reserved_cost_usd") or "")!=str((item.get("authority") or {}).get("budget_usd") or ""):
            raise SelfBuildRuntimeError("HANDOFF_COST_BINDING_MISMATCH","candidate reserved cost binding mismatch")
        process_digest=str(evidence.get("process_evidence_digest") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}",process_digest):
            raise SelfBuildRuntimeError("HANDOFF_PROCESS_EVIDENCE_INVALID","process completion digest missing")

        raw={
            "assignment":assignment,
            "candidateSha":candidate,
            "candidateTreeSha":tree,
            "changedPaths":[{"gitPath":x,"policyPathKey":policy_path_key(x),"policyVersion":POLICY_PATH_KEY_VERSION} for x in changed],
            "requiredTestReceipts":test_receipts,
            "scopeDiffSha256":scope_digest,
            "additions":additions,
            "deletions":deletions,
            "measuredCostUsd":format(measured,"f"),
            "reservedCostUsd":str((item.get("authority") or {}).get("budget_usd") or ""),
            "contributors":[str(item.get("builder_id") or "")],
            "knownUncertainty":[str(x) for x in (evidence.get("known_uncertainty") or [])],
        }
        try:handoff=CandidateHandoff.from_dict(raw,store=self.store)
        except Exception as ex:raise SelfBuildRuntimeError("HANDOFF_RECEIPT_INVALID",str(ex)) from ex
        entry={"taskId":task_id,"workerRunId":worker_run_id,"ownerEpoch":owner_epoch,
               "handoff":handoff.to_dict(),"handoffDigest":handoff.digest,
               "sourceEvidenceDigest":source_digest,"processEvidenceDigest":process_digest,
               "status":"FROZEN_AWAITING_INDEPENDENT_REVIEW"}
        record.setdefault("handoffs",[]).append(entry)
        _atomic_json(path,record);self._assert_path(path)
        return entry

    @staticmethod
    def _entry_for_task(record:dict,key:str,task_id:str):
        return next((x for x in (record.get(key) or []) if x.get("taskId")==task_id),None)

    def record_review(self,payload:dict)->dict:
        run_id=str(payload.get("runId") or "");path=self._run_path(run_id)
        if not path.is_file():raise SelfBuildRuntimeError("RUN_NOT_FOUND","self-build run not found")
        self._assert_path(path)
        try:record=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state unreadable") from ex
        _prepared,item,task_id,worker_run_id,owner_epoch=self._handoff_item(record,payload)
        handoff_entry=self._entry_for_task(record,"handoffs",task_id)
        if handoff_entry is None:raise SelfBuildRuntimeError("HANDOFF_REQUIRED","candidate handoff must freeze before review")
        existing=self._entry_for_task(record,"reviews",task_id)
        if existing is not None:
            try:
                handoff=CandidateHandoff.from_dict(handoff_entry["handoff"],store=self.store)
                ReviewerReceipt.from_dict(existing["review"],store=self.store,handoff=handoff)
            except Exception as ex:raise SelfBuildRuntimeError("REVIEW_RECEIPT_INVALID",str(ex)) from ex
            evidence=existing.get("reviewEvidence")
            evidence_digest=existing.get("reviewEvidenceDigest")
            if not isinstance(evidence,dict) or receipt_digest(evidence)!=evidence_digest:
                raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","persisted independent review evidence digest mismatch")
            stored_review=existing.get("review") or {}
            if stored_review.get("evidenceSha256")!=evidence_digest:
                raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","persisted review receipt is not bound to stored evidence")
            evidence_tests=evidence.get("tests") or []
            expected_test_receipts=[x.get("receipt_digest") for x in evidence_tests if isinstance(x,dict)]
            if stored_review.get("reviewerTestReceipts")!=expected_test_receipts:
                raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","persisted review receipt test bindings mismatch")
            return existing
        try:
            handoff=CandidateHandoff.from_dict(handoff_entry["handoff"],store=self.store)
        except Exception as ex:raise SelfBuildRuntimeError("HANDOFF_RECEIPT_INVALID",str(ex)) from ex
        try:
            evidence=self.review_fn(
                item=item,handoff=handoff,workspace_root=self.workspace_root,
                protected_state=self.workspace_state,git_executable=self.git_resolver(),
                reviewer_id="reviewer-independent",
            )
        except SelfBuildReviewError as ex:raise SelfBuildRuntimeError(ex.code,str(ex)) from ex
        except Exception as ex:raise SelfBuildRuntimeError("INDEPENDENT_REVIEW_FAILED",str(ex)) from ex
        if not isinstance(evidence,dict) or set(evidence)!={
            "schema","reviewer_id","task_id","builder_id","base_sha","candidate_sha","candidate_tree_sha",
            "handoff_sha256","changed_files","scope_diff_sha256","tests","verdict",
            "workspace_pristine","workspace_cleanup_proven","evidence_digest",
        }:
            raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","independent review evidence shape invalid")
        core={k:v for k,v in evidence.items() if k!="evidence_digest"}
        if evidence.get("schema")!=1 or evidence.get("evidence_digest")!=receipt_digest(core):
            raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","independent review evidence digest invalid")
        if evidence.get("reviewer_id")!="reviewer-independent":
            raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","unexpected independent reviewer identity")
        if evidence.get("task_id")!=task_id or evidence.get("builder_id")!=item.get("builder_id"):
            raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","independent review task/builder mismatch")
        if str(evidence.get("base_sha") or "").lower()!=handoff.assignment.base_sha:
            raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","independent review base mismatch")
        if str(evidence.get("candidate_sha") or "").lower()!=handoff.candidate_sha or str(evidence.get("candidate_tree_sha") or "").lower()!=handoff.candidate_tree_sha:
            raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","independent review candidate identity mismatch")
        if str(evidence.get("handoff_sha256") or "").lower()!=handoff.digest or str(evidence.get("scope_diff_sha256") or "").lower()!=handoff.scope_diff_sha256:
            raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","independent review handoff/diff binding mismatch")
        expected_paths=[p for p,_ in handoff.changed_paths]
        if sorted(str(x).casefold() for x in (evidence.get("changed_files") or []))!=sorted(x.casefold() for x in expected_paths):
            raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","independent review changed-file set mismatch")
        if evidence.get("workspace_pristine") is not True or evidence.get("workspace_cleanup_proven") is not True:
            raise SelfBuildRuntimeError("REVIEW_EVIDENCE_INVALID","independent review workspace proof missing")
        tests=evidence.get("tests")
        if not isinstance(tests,list) or not tests:
            raise SelfBuildRuntimeError("REVIEW_TEST_EVIDENCE_REQUIRED","independent review test receipts missing")
        reviewer_tests=[]
        any_failed=False
        for row in tests:
            if not isinstance(row,dict) or set(row)!={"command","exit_code","output_sha256","receipt_digest"}:
                raise SelfBuildRuntimeError("REVIEW_TEST_EVIDENCE_INVALID","independent review test receipt shape invalid")
            supplied=str(row.get("receipt_digest") or "").lower()
            tcore={k:v for k,v in row.items() if k!="receipt_digest"}
            if supplied!=receipt_digest(tcore):
                raise SelfBuildRuntimeError("REVIEW_TEST_EVIDENCE_INVALID","independent review test receipt digest mismatch")
            if isinstance(row.get("exit_code"),bool) or not isinstance(row.get("exit_code"),int):
                raise SelfBuildRuntimeError("REVIEW_TEST_EVIDENCE_INVALID","independent review test exit code invalid")
            any_failed=any_failed or row["exit_code"]!=0
            reviewer_tests.append(supplied)
        verdict=str(evidence.get("verdict") or "").lower()
        if verdict not in {"pass","fail"} or (verdict=="pass" and any_failed) or (verdict=="fail" and not any_failed):
            raise SelfBuildRuntimeError("REVIEW_VERDICT_INVALID","independent review verdict does not match rerun tests")
        raw={
            "assignment":handoff.assignment.to_store_packet(),
            "handoffSha256":handoff.digest,
            "candidateSha":handoff.candidate_sha,
            "candidateTreeSha":handoff.candidate_tree_sha,
            "reviewerId":evidence["reviewer_id"],
            "verdict":verdict,
            "evidenceSha256":receipt_digest(evidence),
            "reviewerTestReceipts":reviewer_tests,
        }
        try:review=ReviewerReceipt.from_dict(raw,store=self.store,handoff=handoff)
        except Exception as ex:raise SelfBuildRuntimeError("REVIEW_RECEIPT_INVALID",str(ex)) from ex
        entry={"taskId":task_id,"workerRunId":worker_run_id,"ownerEpoch":owner_epoch,
               "review":review.to_dict(),"reviewDigest":review.digest,
               "reviewEvidence":evidence,"reviewEvidenceDigest":receipt_digest(evidence),
               "status":review.verdict.upper()}
        record.setdefault("reviews",[]).append(entry)
        _atomic_json(path,record);self._assert_path(path)
        return entry

    def _finalize_acceptance(self,path:Path,record:dict,pending:dict)->dict:
        task_id=pending["taskId"]
        accepted=self._entry_for_task(record,"accepted",task_id)
        if accepted is not None:return accepted
        record.setdefault("accepted",[]).append(pending)
        record.pop("acceptancePending",None)
        _atomic_json(path,record);self._assert_path(path)
        return pending

    def accept_candidate(self,payload:dict,*,controller_id:str)->dict:
        run_id=str(payload.get("runId") or "");path=self._run_path(run_id)
        if not path.is_file():raise SelfBuildRuntimeError("RUN_NOT_FOUND","self-build run not found")
        self._assert_path(path)
        try:record=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state unreadable") from ex
        prepared,item,task_id,worker_run_id,owner_epoch=self._handoff_item(record,payload)
        accepted=self._entry_for_task(record,"accepted",task_id)
        if accepted is not None:return accepted

        pending=record.get("acceptancePending")
        if pending is not None:
            if not isinstance(pending,dict) or pending.get("taskId")!=task_id or pending.get("workerRunId")!=worker_run_id or int(pending.get("ownerEpoch") or 0)!=owner_epoch:
                raise SelfBuildRuntimeError("ACCEPTANCE_PENDING_CONFLICT","another acceptance is pending")
            task=self.store.get_task(task_id)
            if not isinstance(task,dict):raise SelfBuildRuntimeError("ACCEPTANCE_TASK_MISSING","task state unavailable")
            status=str(task.get("status") or "")
            if status=="released":
                if str(task.get("result_head") or "").lower()!=str(pending.get("candidateSha") or "").lower():
                    raise SelfBuildRuntimeError("ACCEPTANCE_RELEASE_MISMATCH","released task head differs from pending acceptance")
                return self._finalize_acceptance(path,record,pending)
            if status!="running":
                raise SelfBuildRuntimeError("ACCEPTANCE_TASK_STATE_INVALID","pending acceptance task is not releasable")
            try:self.store.release(task_id,worker_run_id,owner_epoch,result_head=pending["candidateSha"],outcome="released",expected_head=str(prepared.get("base_sha") or ""))
            except Exception as ex:
                code=getattr(ex,"code","ACCEPTANCE_RELEASE_FAILED")
                raise SelfBuildRuntimeError(code,str(ex)) from ex
            return self._finalize_acceptance(path,record,pending)

        handoff_entry=self._entry_for_task(record,"handoffs",task_id)
        review_entry=self._entry_for_task(record,"reviews",task_id)
        if handoff_entry is None or review_entry is None:
            raise SelfBuildRuntimeError("REVIEW_REQUIRED","candidate requires frozen handoff and independent review")
        try:
            handoff=CandidateHandoff.from_dict(handoff_entry["handoff"],store=self.store)
            review=ReviewerReceipt.from_dict(review_entry["review"],store=self.store,handoff=handoff)
            acceptance=ControllerAcceptanceReference.from_records(controller_id=controller_id,handoff=handoff,review=review)
        except Exception as ex:raise SelfBuildRuntimeError("CONTROLLER_ACCEPTANCE_DENIED",str(ex)) from ex
        pending={"taskId":task_id,"workerRunId":worker_run_id,"ownerEpoch":owner_epoch,
                 "candidateSha":handoff.candidate_sha,"candidateTreeSha":handoff.candidate_tree_sha,
                 "acceptance":acceptance.to_dict(),"acceptanceDigest":acceptance.digest,
                 "handoffDigest":handoff.digest,"reviewDigest":review.digest,"status":"ACCEPTED"}
        record["acceptancePending"]=pending
        _atomic_json(path,record);self._assert_path(path)
        try:self.store.release(task_id,worker_run_id,owner_epoch,result_head=handoff.candidate_sha,outcome="released",expected_head=str(prepared.get("base_sha") or ""))
        except Exception as ex:
            code=getattr(ex,"code","ACCEPTANCE_RELEASE_FAILED")
            raise SelfBuildRuntimeError(code,str(ex)) from ex
        return self._finalize_acceptance(path,record,pending)

    def compose_successor(self,payload:dict)->dict:
        run_id=str(payload.get("runId") or "");path=self._run_path(run_id)
        if not path.is_file():raise SelfBuildRuntimeError("RUN_NOT_FOUND","self-build run not found")
        self._assert_path(path)
        try:record=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state unreadable") from ex
        if not isinstance(record,dict) or record.get("schema")!=1 or not isinstance(record.get("prepared"),dict):
            raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run preparation missing")
        if record.get("phase") not in {"REPLACEMENT_PREPARED","SUCCESSOR_COMPOSED"}:
            raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run is not composition-ready")
        prepared=record["prepared"];manifest=self.run_root/f"{run_id}-successor-manifest.json";git=self.git_resolver()
        kwargs={"record":record,"run_id":run_id,"source_root":prepared.get("source_root"),"workspace_root":self.workspace_root,"git_executable":git,"manifest_path":manifest}
        existing=record.get("successor")
        if existing is not None:
            if record.get("phase")!="SUCCESSOR_COMPOSED" or not isinstance(existing,dict):
                raise SelfBuildRuntimeError("SUCCESSOR_RECORD_INVALID","persisted successor phase/record mismatch")
            try:self.verify_compose_fn(**kwargs,expected=existing)
            except SelfBuildComposeError as ex:raise SelfBuildRuntimeError(ex.code,str(ex)) from ex
            return existing
        if record.get("phase")!="REPLACEMENT_PREPARED":
            raise SelfBuildRuntimeError("RUN_STATE_INVALID","successor record missing from composed run")
        successor_path=self.workspace_root/f"{run_id}-successor"
        if successor_path.exists() or successor_path.is_symlink() or manifest.exists() or manifest.is_symlink():
            raise SelfBuildRuntimeError("SUCCESSOR_RECOVERY_REQUIRED","unrecorded successor artifacts require explicit reconciliation")
        try:
            result=self.compose_fn(**kwargs,protected_state=self.workspace_state)
        except SelfBuildComposeError as ex:raise SelfBuildRuntimeError(ex.code,str(ex)) from ex
        if not isinstance(result,dict) or result.get("schema")!=1:
            raise SelfBuildRuntimeError("SUCCESSOR_RESULT_INVALID","composer returned invalid successor evidence")
        entry={**result,"status":"COMPOSED_AWAITING_ACTIVATION"}
        try:self.verify_compose_fn(**kwargs,expected=entry)
        except SelfBuildComposeError as ex:raise SelfBuildRuntimeError(ex.code,str(ex)) from ex
        try:
            workspace=Path(str(entry.get("workspace") or "")).resolve(strict=True)
            manifest_observed=Path(str(entry.get("manifest_path") or "")).resolve(strict=True)
        except Exception as ex:raise SelfBuildRuntimeError("SUCCESSOR_RESULT_INVALID","successor paths invalid") from ex
        if workspace!=(self.workspace_root/f"{run_id}-successor").resolve(strict=True) or manifest_observed!=manifest.resolve(strict=True):
            raise SelfBuildRuntimeError("SUCCESSOR_RESULT_INVALID","successor paths differ from protected runtime authority")
        self._assert_path(manifest_observed)
        record["successor"]=entry;record["phase"]="SUCCESSOR_COMPOSED";_atomic_json(path,record);self._assert_path(path)
        return entry

    def status(self,payload:dict)->dict:
        run_id=str(payload.get("runId") or "")
        path=self._run_path(run_id)
        if not path.is_file():raise SelfBuildRuntimeError("RUN_NOT_FOUND","self-build run not found")
        self._assert_path(path)
        try:value=json.loads(path.read_text(encoding="utf-8"))
        except Exception as ex:raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state unreadable") from ex
        if not isinstance(value,dict) or value.get("schema")!=1:
            raise SelfBuildRuntimeError("RUN_STATE_INVALID","self-build run state invalid")
        return value
