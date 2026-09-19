from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, asdict
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath
from typing import Iterable

_SHA=re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_ID=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MONEY=Decimal("0.01")


class SelfBuildPlanError(RuntimeError):
    pass


def _money(value)->Decimal:
    if isinstance(value,bool):
        raise SelfBuildPlanError("budget must be a finite positive amount")
    try:
        out=Decimal(str(value))
    except (InvalidOperation,ValueError,TypeError) as ex:
        raise SelfBuildPlanError("budget must be a finite positive amount") from ex
    if not out.is_finite() or out<=0 or out!=out.quantize(_MONEY):
        raise SelfBuildPlanError("budget must be a finite positive cent amount")
    return out


def _sha(value:str)->str:
    raw=str(value or "").lower()
    if not _SHA.fullmatch(raw):
        raise SelfBuildPlanError("exact known-good Git object id required")
    return raw


def _relpath(value:str)->str:
    raw=str(value or "").replace("\\","/")
    p=PurePosixPath(raw)
    if not raw or p.is_absolute() or ".." in p.parts or "." in p.parts:
        raise SelfBuildPlanError("canonical repository-relative path required")
    if raw.startswith(".git/") or raw==".git":
        raise SelfBuildPlanError("Git metadata cannot be worker scope")
    return p.as_posix()


def _scope(values:Iterable[str])->tuple[str,...]:
    out=tuple(_relpath(x) for x in values)
    if not out:
        raise SelfBuildPlanError("worker scope cannot be empty")
    folded=[x.casefold() for x in out]
    if len(folded)!=len(set(folded)):
        raise SelfBuildPlanError("duplicate worker scope")
    return out


def _overlap(a:Iterable[str],b:Iterable[str])->bool:
    aa=[PurePosixPath(x).parts for x in a]
    bb=[PurePosixPath(x).parts for x in b]
    for left in aa:
        for right in bb:
            n=min(len(left),len(right))
            if tuple(x.casefold() for x in left[:n])==tuple(x.casefold() for x in right[:n]):
                return True
    return False


@dataclass(frozen=True)
class WorkerPlan:
    task_id:str
    builder_id:str
    branch:str
    allowed_files:tuple[str,...]
    context_files:tuple[str,...]
    required_tests:tuple[str,...]
    acceptance_criteria:tuple[str,...]
    budget_usd:str
    max_changed_files:int
    max_changed_lines:int
    replacement_for:str|None=None

    def packet(self,*,known_good_sha:str,run_id:str)->dict:
        return {
            "schema":1,
            "product":"ForgeBoss",
            "project_id":"forgeboss",
            "task_id":self.task_id,
            "builder_id":self.builder_id,
            "run_id":run_id,
            "objective":self.acceptance_criteria[0],
            "expected_head_revision":known_good_sha,
            "branch":self.branch,
            "allowed_files":list(self.allowed_files),
            "context_files":list(self.context_files),
            "required_tests":list(self.required_tests),
            "acceptance_criteria":list(self.acceptance_criteria),
            "budget_usd":self.budget_usd,
            "max_changed_files":self.max_changed_files,
            "max_changed_lines":self.max_changed_lines,
            "replacement_for":self.replacement_for,
            "publish":False,
            "merge":False,
            "deploy":False,
        }


@dataclass(frozen=True)
class SelfBuildRunPlan:
    schema:int
    run_id:str
    repository:str
    known_good_sha:str
    global_budget_usd:str
    initial_workers:tuple[WorkerPlan,...]
    replacement_workers:tuple[WorkerPlan,...]
    reviewer_mode:str

    def validate(self)->"SelfBuildRunPlan":
        if self.schema!=1: raise SelfBuildPlanError("unsupported self-build plan schema")
        if not _ID.fullmatch(self.run_id): raise SelfBuildPlanError("invalid run id")
        if self.repository.casefold()!="1stchoicefnq-afk/forgeboss": raise SelfBuildPlanError("Finish Line 1 repository mismatch")
        _sha(self.known_good_sha)
        global_cap=_money(self.global_budget_usd)
        workers=self.initial_workers+self.replacement_workers
        ids=[w.task_id for w in workers]
        builders=[w.builder_id for w in workers]
        if len(ids)!=len(set(ids)) or len(builders)!=len(set(builders)):
            raise SelfBuildPlanError("task/builder identities must be unique")
        total=Decimal("0")
        for w in workers:
            if not _ID.fullmatch(w.task_id) or not _ID.fullmatch(w.builder_id):
                raise SelfBuildPlanError("invalid worker identity")
            if not w.branch.startswith("forgeboss/fl1-selfbuild-"):
                raise SelfBuildPlanError("self-build branch namespace required")
            _scope(w.allowed_files);_scope(w.context_files)
            if not w.required_tests or not all(isinstance(x,str) and x.strip() for x in w.required_tests):
                raise SelfBuildPlanError("focused tests required")
            if w.max_changed_files<1 or w.max_changed_files>2 or w.max_changed_lines<1 or w.max_changed_lines>250:
                raise SelfBuildPlanError("worker churn ceiling exceeds FL1 packet")
            total+=_money(w.budget_usd)
        if total>global_cap:
            raise SelfBuildPlanError("worker + replacement authority exceeds global cap")
        for i,left in enumerate(self.initial_workers):
            for right in self.initial_workers[i+1:]:
                if _overlap(left.allowed_files,right.allowed_files):
                    raise SelfBuildPlanError("initial worker scopes overlap")
        initial_ids={x.task_id for x in self.initial_workers}
        for replacement in self.replacement_workers:
            if not replacement.replacement_for or replacement.replacement_for not in initial_ids:
                raise SelfBuildPlanError("replacement must name an initial task")
            original=next(x for x in self.initial_workers if x.task_id==replacement.replacement_for)
            if tuple(x.casefold() for x in original.allowed_files)!=tuple(x.casefold() for x in replacement.allowed_files):
                raise SelfBuildPlanError("replacement scope must equal revoked task scope")
            if replacement.branch==original.branch or replacement.builder_id==original.builder_id:
                raise SelfBuildPlanError("replacement needs fresh branch and builder identity")
        if self.reviewer_mode!="zero-paid-independent":
            raise SelfBuildPlanError("first FL1 proof uses zero-paid independent review")
        return self

    def as_dict(self)->dict:
        self.validate()
        value=asdict(self)
        value["initial_workers"]=[asdict(x) for x in self.initial_workers]
        value["replacement_workers"]=[asdict(x) for x in self.replacement_workers]
        return value

    def canonical_json(self)->str:
        return json.dumps(self.as_dict(),sort_keys=True,separators=(",",":"),ensure_ascii=False)


def finish_line_one_plan(known_good_sha:str,run_id:str|None=None)->SelfBuildRunPlan:
    kg=_sha(known_good_sha)
    rid=run_id or ("fl1-"+uuid.uuid4().hex[:12])
    a=WorkerPlan(
        task_id="fl1-a-learning",
        builder_id="builder-a",
        branch=f"forgeboss/fl1-selfbuild-a-{rid}",
        allowed_files=("forgeboss/learning/test_fl1_reuse_regression.py",),
        context_files=("forgeboss/learning/policy.py","forgeboss/learning/store.py"),
        required_tests=("python -m unittest forgeboss.learning.test_fl1_reuse_regression -v",),
        acceptance_criteria=(
            "Add deterministic regressions proving failed, superseded, or non-promotable learning evidence cannot become reusable while valid verified lessons remain reusable across restart.",
            "Do not modify production learning code in the first canary.",
        ),
        budget_usd="1.00",max_changed_files=1,max_changed_lines=250,
    )
    b=WorkerPlan(
        task_id="fl1-b-packet",
        builder_id="builder-b",
        branch=f"forgeboss/fl1-selfbuild-b-{rid}",
        allowed_files=("forgeboss/security/test_fl1_packet_validation.py",),
        context_files=("forgeboss/security/executor_guard.py",),
        required_tests=("python -m unittest forgeboss.security.test_fl1_packet_validation -v",),
        acceptance_criteria=(
            "Add deterministic fail-closed regressions for malformed worker packets: missing identity/base, unsafe writable paths, non-finite budget, and unexpected authority structure.",
            "Do not modify production security/control code in the first canary.",
        ),
        budget_usd="0.50",max_changed_files=1,max_changed_lines=250,
    )
    b2=WorkerPlan(
        task_id="fl1-b2-packet",
        builder_id="builder-b2",
        branch=f"forgeboss/fl1-selfbuild-b2-{rid}",
        allowed_files=b.allowed_files,
        context_files=b.context_files,
        required_tests=b.required_tests,
        acceptance_criteria=b.acceptance_criteria,
        budget_usd="0.50",max_changed_files=1,max_changed_lines=250,
        replacement_for=b.task_id,
    )
    return SelfBuildRunPlan(
        schema=1,run_id=rid,repository="1stchoicefnq-afk/ForgeBoss",
        known_good_sha=kg,global_budget_usd="2.00",
        initial_workers=(a,b),replacement_workers=(b2,),
        reviewer_mode="zero-paid-independent",
    ).validate()
