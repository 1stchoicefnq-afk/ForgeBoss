from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from forgeboss.control.scheduler import _canonical_path

ASSIGNMENT_VERSION = 1
SUPPORTED_TOOL_IDS = frozenset({"git", "node", "npm", "python", "pytest", "docker"})
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class AssignmentError(RuntimeError):
    code = "ASSIGNMENT_INVALID"


def _opaque(value: object, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise AssignmentError(
            f"{name} must be 1..128 characters using letters, digits, '.', '_', ':', or '-'"
        )
    return value


def _text(value: object, name: str, *, max_len: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise AssignmentError(f"{name} must be a non-empty bounded string")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise AssignmentError(f"{name} contains control characters")
    return value


def _repository(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AssignmentError("repository must be GitHub owner/name")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise AssignmentError("repository contains control characters")
    raw = value.replace("\\", "/")
    lowered = raw.casefold()
    if "://" in lowered or lowered.startswith("git@") or ":" in raw or raw.startswith("//"):
        raise AssignmentError("repository must be GitHub owner/name")
    parts = raw.split("/")
    if len(parts) != 2 or any(part in ("", ".", "..") for part in parts):
        raise AssignmentError("repository must be GitHub owner/name")
    owner, repo = parts
    if not _OWNER_RE.fullmatch(owner) or not _REPO_RE.fullmatch(repo):
        raise AssignmentError("repository must be GitHub owner/name")
    return f"{owner.casefold()}/{repo.casefold()}"


def _branch(value: object) -> str:
    branch = _text(value, "branch", max_len=240)
    if (
        branch.startswith(("/", "."))
        or branch.endswith(("/", "."))
        or branch.endswith(".lock")
        or "\\" in branch
        or ".." in branch
        or "//" in branch
        or "@{" in branch
        or any(ch.isspace() for ch in branch)
    ):
        raise AssignmentError("branch is not a safe named Git branch")
    return branch


def _sha40(value: object, name: str = "baseSha") -> str:
    if not isinstance(value, str) or not _SHA40_RE.fullmatch(value):
        raise AssignmentError(f"{name} must be exact 40-hex sha")
    return value.lower()


def _sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise AssignmentError(f"{name} must be exact sha256 hex")
    return value.lower()


def _finite_decimal(value: object, name: str) -> str:
    if isinstance(value, bool):
        raise AssignmentError(f"{name} must be finite non-negative")
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise AssignmentError(f"{name} must be finite non-negative") from exc
    if not amount.is_finite() or amount < 0:
        raise AssignmentError(f"{name} must be finite non-negative")
    text = format(amount.normalize(), "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _positive_int(value: object, name: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AssignmentError(f"{name} must be an integer")
    if value < (0 if allow_zero else 1):
        raise AssignmentError(f"{name} is below minimum")
    return value


def _paths(values: object, name: str) -> list[str]:
    if not isinstance(values, list):
        raise AssignmentError(f"{name} must be an array")
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str) or not raw.strip():
            raise AssignmentError(f"{name} contains invalid path")
        canonical = _canonical_path(raw)
        if not canonical:
            raise AssignmentError(f"{name} contains empty/root path authority")
        if canonical in seen:
            raise AssignmentError(f"{name} contains duplicate/equivalent path authority")
        seen.add(canonical)
        out.append(canonical)
    return sorted(out)


def _scope_overlap(left: list[str], right: list[str]) -> bool:
    return any(
        a == b or a.startswith(b + "/") or b.startswith(a + "/")
        for a in left
        for b in right
    )


def _tools(values: object) -> list[str]:
    if not isinstance(values, list) or not values:
        raise AssignmentError("allowedTools must be a non-empty array")
    out = []
    seen = set()
    for raw in values:
        if not isinstance(raw, str) or raw not in SUPPORTED_TOOL_IDS:
            raise AssignmentError(f"unsupported tool id: {raw!r}")
        if raw in seen:
            raise AssignmentError("allowedTools contains duplicate tool")
        seen.add(raw)
        out.append(raw)
    return sorted(out)


def _tests(values: object) -> list[str]:
    if not isinstance(values, list) or not values:
        raise AssignmentError("requiredTests must be a non-empty ordered array")
    out = []
    seen = set()
    for raw in values:
        test = _text(raw, "requiredTests item", max_len=2048)
        if test in seen:
            raise AssignmentError("requiredTests contains duplicate command")
        seen.add(test)
        out.append(test)
    return out


def _runtime(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"adapter", "provider", "model"}:
        raise AssignmentError("runtime must contain exactly adapter/provider/model")
    return {
        "adapter": _opaque(value["adapter"], "runtime.adapter"),
        "provider": _opaque(value["provider"], "runtime.provider"),
        "model": _opaque(value["model"], "runtime.model"),
    }


def _context(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"artefactId", "sha256"}:
        raise AssignmentError("contextBundle must be null or exact artefactId/sha256 object")
    return {
        "artefactId": _opaque(value["artefactId"], "contextBundle.artefactId"),
        "sha256": _sha256(value["sha256"], "contextBundle.sha256"),
    }


def _strict_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AssignmentError("assignment contains non-strict JSON material") from exc


def build_assignment(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise AssignmentError("assignment must be an object")

    expected = {
        "assignmentVersion",
        "taskId",
        "purpose",
        "controllerIdentity",
        "controllerRevision",
        "builderId",
        "reviewerId",
        "repository",
        "baseSha",
        "branch",
        "allowedPaths",
        "deniedPaths",
        "allowedTools",
        "runtime",
        "contextBundle",
        "requiredTests",
        "churn",
        "budget",
        "stopReassign",
    }
    if set(raw) != expected:
        missing = sorted(expected - set(raw))
        extra = sorted(set(raw) - expected)
        raise AssignmentError(f"assignment keys mismatch missing={missing} extra={extra}")

    if raw["assignmentVersion"] != ASSIGNMENT_VERSION:
        raise AssignmentError("unsupported assignmentVersion")

    builder = _opaque(raw["builderId"], "builderId")
    reviewer = _opaque(raw["reviewerId"], "reviewerId")
    if builder.casefold() == reviewer.casefold():
        raise AssignmentError("reviewer must be independent from builder")

    allowed = _paths(raw["allowedPaths"], "allowedPaths")
    denied = _paths(raw["deniedPaths"], "deniedPaths")
    if not allowed:
        raise AssignmentError("allowedPaths must not be empty")
    if _scope_overlap(allowed, denied):
        raise AssignmentError("allowedPaths and deniedPaths contain contradictory overlap")

    churn = raw["churn"]
    if not isinstance(churn, dict) or set(churn) != {"maxFiles", "maxChangedLines", "maxChangedBytes"}:
        raise AssignmentError("churn must contain exactly maxFiles/maxChangedLines/maxChangedBytes")
    churn_obj = {
        "maxFiles": _positive_int(churn["maxFiles"], "churn.maxFiles"),
        "maxChangedLines": _positive_int(churn["maxChangedLines"], "churn.maxChangedLines"),
        "maxChangedBytes": _positive_int(churn["maxChangedBytes"], "churn.maxChangedBytes"),
    }

    budget = raw["budget"]
    if not isinstance(budget, dict) or set(budget) != {"workerUsd", "runId", "runContributionUsd"}:
        raise AssignmentError("budget must contain exactly workerUsd/runId/runContributionUsd")
    worker_usd = _finite_decimal(budget["workerUsd"], "budget.workerUsd")
    contribution = _finite_decimal(budget["runContributionUsd"], "budget.runContributionUsd")
    if Decimal(contribution) > Decimal(worker_usd):
        raise AssignmentError("global run contribution cannot exceed worker budget")
    budget_obj = {
        "workerUsd": worker_usd,
        "runId": _opaque(budget["runId"], "budget.runId"),
        "runContributionUsd": contribution,
    }

    stop = raw["stopReassign"]
    if not isinstance(stop, dict) or set(stop) != {
        "controllerRevokeRequired",
        "freshWorktreeRequired",
        "maxAttempts",
    }:
        raise AssignmentError(
            "stopReassign must contain exactly controllerRevokeRequired/freshWorktreeRequired/maxAttempts"
        )
    if stop["controllerRevokeRequired"] is not True or stop["freshWorktreeRequired"] is not True:
        raise AssignmentError("Finish-Line-1 reassignment must require revoke + fresh worktree")
    stop_obj = {
        "controllerRevokeRequired": True,
        "freshWorktreeRequired": True,
        "maxAttempts": _positive_int(stop["maxAttempts"], "stopReassign.maxAttempts"),
    }

    canonical = {
        "assignmentVersion": ASSIGNMENT_VERSION,
        "taskId": _opaque(raw["taskId"], "taskId"),
        "purpose": _text(raw["purpose"], "purpose"),
        "controllerIdentity": _opaque(raw["controllerIdentity"], "controllerIdentity"),
        "controllerRevision": _positive_int(
            raw["controllerRevision"], "controllerRevision", allow_zero=True
        ),
        "builderId": builder,
        "reviewerId": reviewer,
        "repository": _repository(raw["repository"]),
        "baseSha": _sha40(raw["baseSha"]),
        "branch": _branch(raw["branch"]),
        "allowedPaths": allowed,
        "deniedPaths": denied,
        "allowedTools": _tools(raw["allowedTools"]),
        "runtime": _runtime(raw["runtime"]),
        "contextBundle": _context(raw["contextBundle"]),
        "requiredTests": _tests(raw["requiredTests"]),
        "churn": churn_obj,
        "budget": budget_obj,
        "stopReassign": stop_obj,
    }
    digest = hashlib.sha256(_strict_json(canonical)).hexdigest()
    return {**canonical, "assignmentSha256": digest}


def verify_assignment(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AssignmentError("assignment must be an object")
    supplied = value.get("assignmentSha256")
    if not isinstance(supplied, str) or not _SHA256_RE.fullmatch(supplied):
        raise AssignmentError("assignmentSha256 must be exact sha256 hex")
    raw = dict(value)
    raw.pop("assignmentSha256", None)
    rebuilt = build_assignment(raw)
    if rebuilt["assignmentSha256"] != supplied.lower():
        raise AssignmentError("assignmentSha256 mismatch")
    return rebuilt
