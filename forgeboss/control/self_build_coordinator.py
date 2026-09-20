from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from forgeboss.control.self_build import SelfBuildRunPlan, WorkerPlan, finish_line_one_plan
from forgeboss.control.store import ControlStore
from forgeboss.control.workspace import cleanup_workspace, inspect_source, provision_workspace

_OID=re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class SelfBuildCoordinatorError(RuntimeError):
    def __init__(self,code:str,message:str):
        super().__init__(message);self.code=code


def _exact_sha(value)->str:
    raw=str(value or "").lower()
    if not _OID.fullmatch(raw):raise SelfBuildCoordinatorError("BASE_SHA_INVALID","exact Git object id required")
    return raw


def _pointer_current(pointer:dict)->dict:
    if not isinstance(pointer,dict) or pointer.get("schema")!=2:
        raise SelfBuildCoordinatorError("KNOWN_GOOD_POINTER_INVALID","activation known-good pointer missing or invalid")
    current=pointer.get("current")
    if not isinstance(current,dict) or current.get("verified") is not True:
        raise SelfBuildCoordinatorError("KNOWN_GOOD_UNVERIFIED","current known-good identity is not verified")
    return current


def _public_worker_record(value:dict)->dict:
    blocked=("assignmentToken","assignment_token","token","privateKey","private_key","secret")
    text=json.dumps(value,sort_keys=True)
    if any(x.lower() in text.lower() for x in blocked):
        raise SelfBuildCoordinatorError("SECRET_LEAK","worker preparation record contains secret-bearing fields")
    return value


class SelfBuildCoordinator:
    """
    Service-principal preparation authority for the first real ForgeBoss-on-ForgeBoss run.

    This class does NOT call a model. It creates durable Store assignments, provisions
    isolated workspaces from the exact known-good Git object, reserves the Store-backed
    global budget, and returns public launch metadata. Paid launch is a later gate.
    """

    def __init__(self,*,store:ControlStore,receipt_public_key_b64:str,
                 inspect_source_fn:Callable=inspect_source,
                 provision_workspace_fn:Callable=provision_workspace,
                 cleanup_workspace_fn:Callable=cleanup_workspace):
        if not isinstance(store,ControlStore):
            raise SelfBuildCoordinatorError("STORE_REQUIRED","ControlStore authority required")
        if not isinstance(receipt_public_key_b64,str) or not receipt_public_key_b64.strip():
            raise SelfBuildCoordinatorError("RECEIPT_PIN_REQUIRED","protected authority receipt key pin required")
        self.store=store
        self.receipt_public_key_b64=receipt_public_key_b64.strip()
        self.inspect_source_fn=inspect_source_fn
        self.provision_workspace_fn=provision_workspace_fn
        self.cleanup_workspace_fn=cleanup_workspace_fn

    def verify_known_good(self,*,source_root,known_good_pointer,base_sha,git_executable)->dict:
        base=_exact_sha(base_sha)
        source=Path(source_root).resolve(strict=True)
        current=_pointer_current(known_good_pointer)
        if str(current.get("revision") or "").lower()!=base:
            raise SelfBuildCoordinatorError("KNOWN_GOOD_SHA_MISMATCH","selected base is not the activation known-good revision")
        try:code_root=Path(str(current.get("codeRoot") or "")).resolve(strict=True)
        except Exception as ex:raise SelfBuildCoordinatorError("KNOWN_GOOD_ROOT_INVALID","activation known-good code root is invalid") from ex
        if source!=code_root:
            raise SelfBuildCoordinatorError("KNOWN_GOOD_ROOT_MISMATCH","selected ForgeBoss folder is not the activation known-good code root")
        observed=self.inspect_source_fn(source,base,git_executable)
        if str(observed.get("source_head") or "").lower()!=base:
            raise SelfBuildCoordinatorError("SOURCE_HEAD_MISMATCH","selected ForgeBoss HEAD differs from known-good")
        return {"source_root":source,"base_sha":base,"source_identity":observed}

    def _task(self,plan:SelfBuildRunPlan,worker:WorkerPlan)->dict:
        return self.store.create_task({
            "taskId":worker.task_id,
            "repository":plan.repository,
            "purpose":"finish-line-1-self-build",
            "baseSha":plan.known_good_sha,
            "branch":worker.branch,
            "allowedPaths":list(worker.allowed_files),
            "requiredTests":list(worker.required_tests),
            "budgetUsd":worker.budget_usd,
        })

    def _prepare_worker(self,*,plan:SelfBuildRunPlan,worker:WorkerPlan,source:Path,
                        workspace_root:Path,git_executable,protected_state,index:int)->dict:
        task=self._task(plan,worker)
        assignment=self.store.assign_builder(
            worker.task_id,worker.builder_id,plan.run_id,
            expected_task_revision=task["revision"],
        )
        worktree=workspace_root/f"{plan.run_id}-{worker.builder_id}"
        identity=self.provision_workspace_fn(
            source,worktree,workspace_root,plan.known_good_sha,worker.branch,git_executable,
            protected_state=protected_state,
        )
        budget=self.store.get_budget_run(plan.run_id)
        lease=self.store.claim_workspace(
            worker.task_id,f"{plan.run_id}-run-{index}",str(worktree),worker.branch,plan.known_good_sha,
            ttl_seconds=1200,runtime_id="mini-swe",worktree_root=workspace_root,
            budget_reserved=worker.budget_usd,
            builder_id=worker.builder_id,
            assignment_token=assignment["assignmentToken"],
            assignment_generation=assignment["assignmentGeneration"],
            assignment_sha256=assignment["assignmentSha256"],
            budget_run_revision=budget["revision"],
        )
        durable=self.store.assignment_identity(worker.task_id,lease["owner_run_id"],lease["owner_epoch"])
        public_authority={
            "repository":plan.repository,
            "control_revision":1,
            "task_id":worker.task_id,
            "run_id":lease["owner_run_id"],
            "owner_epoch":int(lease["owner_epoch"]),
            "builder_id":worker.builder_id,
            "assignment_generation":int(durable["identity"]["assignmentGeneration"]),
            "assignment_sha256":durable["identity"]["assignmentPolicySha256"],
            "branch":worker.branch,
            "budget_usd":worker.budget_usd,
            "global_budget_run_id":plan.run_id,
            "global_budget_reservation_id":worker.task_id,
            "receipt_public_key_b64":self.receipt_public_key_b64,
        }
        packet=worker.packet(known_good_sha=plan.known_good_sha,run_id=plan.run_id)
        packet["self_build_authority"]=dict(public_authority)
        record={
            "task_id":worker.task_id,
            "builder_id":worker.builder_id,
            "worktree":str(worktree.resolve()),
            "owner_epoch":int(lease["owner_epoch"]),
            "assignment_identity_sha256":durable["assignmentIdentitySha256"],
            "workspace_identity":identity.as_dict() if hasattr(identity,"as_dict") else dict(identity),
            "packet":packet,
            "authority":public_authority,
        }
        return _public_worker_record(record)

    def prepare_initial_run(self,*,source_root,known_good_pointer,base_sha,run_id,
                            workspace_root,git_executable,protected_state)->dict:
        verified=self.verify_known_good(
            source_root=source_root,known_good_pointer=known_good_pointer,
            base_sha=base_sha,git_executable=git_executable,
        )
        plan=finish_line_one_plan(verified["base_sha"],run_id)
        root=Path(workspace_root).resolve(strict=True)
        source=verified["source_root"]
        self.store.create_budget_run(plan.run_id,plan.global_budget_usd)
        prepared=[]
        try:
            for index,worker in enumerate(plan.initial_workers,start=1):
                prepared.append(self._prepare_worker(
                    plan=plan,worker=worker,source=source,workspace_root=root,
                    git_executable=git_executable,protected_state=protected_state,index=index,
                ))
            budget=self.store.get_budget_run(plan.run_id)
            # Initial workers reserve $1.50, leaving exactly $0.50 for mandatory B2 reassignment.
            if str(budget.get("reserved_exact")) not in {"1.5","1.50"} or str(budget.get("remaining_exact")) not in {"0.5","0.50"}:
                raise SelfBuildCoordinatorError("GLOBAL_BUDGET_RESERVATION_INVALID","initial run must reserve $1.50 and retain $0.50 B2 headroom")
            return _public_worker_record({
                "schema":1,"run_id":plan.run_id,"base_sha":plan.known_good_sha,
                "source_root":str(source),"global_budget_cap_usd":plan.global_budget_usd,
                "global_budget_reserved_usd":"1.50","reassignment_headroom_usd":"0.50",
                "builders":prepared,
                "replacement_plan":plan.replacement_workers[0].packet(known_good_sha=plan.known_good_sha,run_id=plan.run_id),
            })
        except BaseException:
            for item in reversed(prepared):
                try:self.store.revoke_writer(item["task_id"],item["authority"]["run_id"],item["owner_epoch"],"prepare-failed")
                except Exception:pass
                try:self.cleanup_workspace_fn(item["worktree"],root,protected_state=protected_state)
                except Exception:pass
            try:
                budget=self.store.get_budget_run(plan.run_id)
                if budget and budget.get("status")=="active":
                    self.store.close_budget_run(plan.run_id,budget.get("revision"))
            except Exception:pass
            raise

    def prepare_replacement(self,*,prepared_run:dict,source_root,workspace_root,git_executable,protected_state)->dict:
        plan=finish_line_one_plan(prepared_run["base_sha"],prepared_run["run_id"])
        replacement=plan.replacement_workers[0]
        original=plan.initial_workers[1]
        old=next((x for x in prepared_run.get("builders",[]) if x.get("task_id")==original.task_id),None)
        if old is None:
            raise SelfBuildCoordinatorError("REPLACEMENT_SOURCE_MISSING","Builder B preparation record missing")

        # Fence the old writer first. revoke_writer rotates/clears its durable assignment
        # authority so stale builder/token/generation cannot become valid again.
        self.store.revoke_writer(
            original.task_id,old["authority"]["run_id"],old["owner_epoch"],
            "mandatory FL1 stop/reassign proof",
        )

        # Store task branch authority is intentionally immutable. Therefore the fresh
        # B2 attempt is a NEW replacement task record, linked by the plan's
        # replacement_for field, with a new builder, branch and workspace.
        task=self._task(plan,replacement)
        assignment=self.store.assign_builder(
            replacement.task_id,replacement.builder_id,plan.run_id,
            expected_task_revision=task["revision"],
        )

        root=Path(workspace_root).resolve(strict=True)
        source=Path(source_root).resolve(strict=True)
        worktree=root/f"{plan.run_id}-{replacement.builder_id}"
        identity=self.provision_workspace_fn(
            source,worktree,root,plan.known_good_sha,replacement.branch,git_executable,
            protected_state=protected_state,
        )
        budget=self.store.get_budget_run(plan.run_id)
        lease=self.store.claim_workspace(
            replacement.task_id,f"{plan.run_id}-run-b2",str(worktree),replacement.branch,plan.known_good_sha,
            ttl_seconds=1200,runtime_id="mini-swe",worktree_root=root,budget_reserved=replacement.budget_usd,
            builder_id=replacement.builder_id,assignment_token=assignment["assignmentToken"],
            assignment_generation=assignment["assignmentGeneration"],
            assignment_sha256=assignment["assignmentSha256"],
            budget_run_revision=budget["revision"],
        )
        durable=self.store.assignment_identity(replacement.task_id,lease["owner_run_id"],lease["owner_epoch"])
        authority={
            "repository":plan.repository,
            "control_revision":1,
            "task_id":replacement.task_id,
            "run_id":lease["owner_run_id"],
            "owner_epoch":int(lease["owner_epoch"]),
            "builder_id":replacement.builder_id,
            "assignment_generation":int(durable["identity"]["assignmentGeneration"]),
            "assignment_sha256":durable["identity"]["assignmentPolicySha256"],
            "branch":replacement.branch,
            "budget_usd":replacement.budget_usd,
            "global_budget_run_id":plan.run_id,
            "global_budget_reservation_id":replacement.task_id,
            "receipt_public_key_b64":self.receipt_public_key_b64,
        }
        packet=replacement.packet(known_good_sha=plan.known_good_sha,run_id=plan.run_id)
        packet["self_build_authority"]=dict(authority)
        budget_after=self.store.get_budget_run(plan.run_id)
        if str(budget_after.get("remaining_exact")) not in {"0","0.0","0.00"}:
            raise SelfBuildCoordinatorError("GLOBAL_BUDGET_REASSIGNMENT_INVALID","B2 must consume the final $0.50 global headroom")
        return _public_worker_record({
            "task_id":replacement.task_id,
            "replacement_for":original.task_id,
            "builder_id":replacement.builder_id,
            "worktree":str(worktree.resolve()),
            "owner_epoch":int(lease["owner_epoch"]),
            "assignment_identity_sha256":durable["assignmentIdentitySha256"],
            "workspace_identity":identity.as_dict() if hasattr(identity,"as_dict") else dict(identity),
            "packet":packet,
            "authority":authority,
        })
