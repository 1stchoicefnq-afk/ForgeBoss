from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import re

from forgeboss.control.envelope import canonical
from forgeboss.control.store import _git_object_id, _repository_identity, _scope_authorities


class TaskGovernanceAuthorityError(RuntimeError):
    pass


_SCHEMA=1
_TYPE="governed-task-authority"
_SHA256=re.compile(r"^[0-9a-f]{64}$")


def _secret(value):
    if not isinstance(value,(bytes,bytearray)) or len(value)<32:
        raise TaskGovernanceAuthorityError("policy secret must be at least 32 bytes")
    return bytes(value)


def _text(value,label):
    if not isinstance(value,str) or not value.strip() or value!=value.strip():
        raise TaskGovernanceAuthorityError(f"{label} is invalid")
    if any(ord(ch)<32 or ord(ch)==127 for ch in value):
        raise TaskGovernanceAuthorityError(f"{label} contains control characters")
    return value


def _digest(value,label):
    if value is None:return None
    if not isinstance(value,str) or not _SHA256.fullmatch(value):
        raise TaskGovernanceAuthorityError(f"{label} must be lowercase SHA-256")
    return value


def _budget(value):
    if isinstance(value,bool):raise TaskGovernanceAuthorityError("budget must be finite non-negative")
    try:v=Decimal(str(value))
    except (InvalidOperation,TypeError,ValueError) as ex:raise TaskGovernanceAuthorityError("budget must be finite non-negative") from ex
    if not v.is_finite() or v<0:raise TaskGovernanceAuthorityError("budget must be finite non-negative")
    t=format(v.normalize(),"f")
    return "0" if Decimal(t)==0 else t


def _tests_digest(value):
    if not isinstance(value,list) or any(not isinstance(x,str) for x in value):
        raise TaskGovernanceAuthorityError("requiredTests must be a string array")
    return hashlib.sha256(canonical(value)).hexdigest()


def _body_from_create(task):
    mode=task.get("governanceMode")
    if mode!="reuse-v1":raise TaskGovernanceAuthorityError("governanceMode must be reuse-v1")
    work=task.get("workKind")
    if work not in ("small-repair","substantial-subsystem"):raise TaskGovernanceAuthorityError("workKind invalid")
    paths=list(_scope_authorities(task.get("allowedPaths",[])))
    if not paths:raise TaskGovernanceAuthorityError("allowedPaths required")
    branch=task.get("branch")
    if branch is not None:
        branch=_text(branch,"branch")
    return {
        "schema":_SCHEMA,
        "type":_TYPE,
        "taskId":_text(task.get("taskId"),"taskId"),
        "repository":_repository_identity(task.get("repository")),
        "baseSha":_git_object_id(task.get("baseSha")),
        "purposeSha256":hashlib.sha256(_text(task.get("purpose"),"purpose").encode("utf-8")).hexdigest(),
        "allowedPaths":paths,
        "subsystem":_text(task.get("subsystem"),"subsystem"),
        "workKind":work,
        "reuseReviewSha256":_digest(task.get("reuseReviewSha256"),"reuseReviewSha256"),
        "reuseReviewReceiptSha256":_digest(task.get("reuseReviewReceiptSha256"),"reuseReviewReceiptSha256"),
        "smallRepairExemptionSha256":_digest(task.get("smallRepairExemptionSha256"),"smallRepairExemptionSha256"),
        "branch":branch,
        "budgetUsd":_budget(task.get("budgetUsd",0)),
        "requiredTestsSha256":_tests_digest(task.get("requiredTests",[])),
    }


def sign_governed_task_authority(task,secret):
    key=_secret(secret);body=_body_from_create(task)
    sig=hmac.new(key,canonical(body),hashlib.sha256).hexdigest()
    return "hmac-sha256:"+sig


def _body_from_row(row):
    try:
        allowed=json.loads(row.get("allowed_paths_json") or "[]")
        tests=json.loads(row.get("required_tests_json") or "[]")
    except json.JSONDecodeError as ex:
        raise TaskGovernanceAuthorityError("stored governed JSON is invalid") from ex
    return _body_from_create({
        "governanceMode":row.get("governance_mode"),
        "workKind":row.get("work_kind"),
        "taskId":row.get("task_id"),
        "repository":row.get("repository"),
        "baseSha":row.get("base_sha"),
        "purpose":row.get("purpose"),
        "allowedPaths":allowed,
        "subsystem":row.get("subsystem"),
        "reuseReviewSha256":row.get("reuse_review_sha256"),
        "reuseReviewReceiptSha256":row.get("reuse_review_receipt_sha256"),
        "smallRepairExemptionSha256":row.get("small_repair_exemption_sha256"),
        "branch":row.get("branch"),
        "budgetUsd":row.get("budget_allocated"),
        "requiredTests":tests,
    })


def verify_governed_task_authority_row(row,secret):
    if not isinstance(row,dict):raise TaskGovernanceAuthorityError("task row must be a mapping")
    receipt=row.get("governance_authority_receipt")
    if not isinstance(receipt,str) or not receipt.startswith("hmac-sha256:"):
        raise TaskGovernanceAuthorityError("governed task authority receipt missing")
    supplied=receipt.split(":",1)[1]
    if not _SHA256.fullmatch(supplied):
        raise TaskGovernanceAuthorityError("governed task authority receipt malformed")
    body=_body_from_row(row)
    wanted=hmac.new(_secret(secret),canonical(body),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied,wanted):
        raise TaskGovernanceAuthorityError("governed task authority receipt mismatch")
    return body
