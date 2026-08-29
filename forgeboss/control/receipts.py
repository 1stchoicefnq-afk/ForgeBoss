from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RECEIPT_KINDS = frozenset({
    "required-test",
    "scope-diff",
    "independent-review",
    "measured-cost",
    "candidate-freeze",
})


class ReceiptValidationError(ValueError):
    """Raised when a receipt is malformed or violates a fail-closed invariant."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReceiptValidationError(f"{name} must be an object")
    return value


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ReceiptValidationError(f"{name} must be a non-empty normalized string")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ReceiptValidationError(f"{name} contains forbidden control characters")
    return value


def _require_sha(value: Any, name: str, *, length: int = 40) -> str:
    text = _require_str(value, name)
    rx = _GIT_SHA_RE if length == 40 else _SHA256_RE
    if not rx.fullmatch(text):
        raise ReceiptValidationError(f"{name} must be lowercase {length}-hex")
    return text


def _require_nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReceiptValidationError(f"{name} must be a non-negative integer")
    return value


def _require_finite_nonnegative(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReceiptValidationError(f"{name} must be a finite non-negative number")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ReceiptValidationError(f"{name} must be a finite non-negative number")
    return number


def _normalize_paths(paths: Any, name: str) -> tuple[str, ...]:
    if not isinstance(paths, Sequence) or isinstance(paths, (str, bytes, bytearray)):
        raise ReceiptValidationError(f"{name} must be an array")
    out: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        path = _require_str(raw, f"{name}[]").replace("\\", "/")
        if path.startswith("/") or (len(path) >= 2 and path[1] == ":"):
            raise ReceiptValidationError(f"{name} contains absolute path")
        parts = path.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise ReceiptValidationError(f"{name} contains non-canonical path")
        key = path.casefold()
        if key in seen:
            raise ReceiptValidationError(f"{name} contains duplicate/case-colliding path")
        seen.add(key)
        out.append(path)
    if tuple(out) != tuple(sorted(out, key=lambda x: (x.casefold(), x))):
        raise ReceiptValidationError(f"{name} must be sorted canonically")
    return tuple(out)


@dataclass(frozen=True)
class ReceiptIdentity:
    task_id: str
    run_id: str
    owner_epoch: int
    base_sha: str
    candidate_sha: str
    contract_sha256: str

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ReceiptIdentity":
        return cls(
            task_id=_require_str(raw.get("taskId"), "taskId"),
            run_id=_require_str(raw.get("runId"), "runId"),
            owner_epoch=_require_nonnegative_int(raw.get("ownerEpoch"), "ownerEpoch"),
            base_sha=_require_sha(raw.get("baseSha"), "baseSha"),
            candidate_sha=_require_sha(raw.get("candidateSha"), "candidateSha"),
            contract_sha256=_require_sha(raw.get("contractSha256"), "contractSha256", length=64),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "taskId": self.task_id,
            "runId": self.run_id,
            "ownerEpoch": self.owner_epoch,
            "baseSha": self.base_sha,
            "candidateSha": self.candidate_sha,
            "contractSha256": self.contract_sha256,
        }


def validate_receipt(raw: Mapping[str, Any]) -> dict[str, Any]:
    raw = _require_mapping(raw, "receipt")
    if set(raw) != {"version", "kind", "identity", "evidence"}:
        raise ReceiptValidationError("receipt keys must be exactly version/kind/identity/evidence")
    version = raw["version"]
    if version != 1:
        raise ReceiptValidationError("unsupported receipt version")
    kind = _require_str(raw["kind"], "kind")
    if kind not in _RECEIPT_KINDS:
        raise ReceiptValidationError("unsupported receipt kind")
    identity = ReceiptIdentity.from_mapping(_require_mapping(raw["identity"], "identity"))
    evidence = _require_mapping(raw["evidence"], "evidence")

    validator = {
        "required-test": _validate_required_test,
        "scope-diff": _validate_scope_diff,
        "independent-review": _validate_independent_review,
        "measured-cost": _validate_measured_cost,
        "candidate-freeze": _validate_candidate_freeze,
    }[kind]
    clean_evidence = validator(evidence, identity)
    clean = {"version": 1, "kind": kind, "identity": identity.as_dict(), "evidence": clean_evidence}
    return json.loads(canonical_json(clean))


def receipt_sha256(raw: Mapping[str, Any]) -> str:
    return canonical_sha256(validate_receipt(raw))


def _validate_required_test(e: Mapping[str, Any], _: ReceiptIdentity) -> dict[str, Any]:
    expected = {"command", "oracleSha256", "exitCode", "passed", "changedOraclePaths"}
    if set(e) != expected:
        raise ReceiptValidationError("required-test evidence keys invalid")
    command = _require_str(e["command"], "command")
    oracle = _require_sha(e["oracleSha256"], "oracleSha256", length=64)
    exit_code = e["exitCode"]
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise ReceiptValidationError("exitCode must be an integer")
    if not isinstance(e["passed"], bool):
        raise ReceiptValidationError("passed must be boolean")
    changed = _normalize_paths(e["changedOraclePaths"], "changedOraclePaths")
    passed = bool(e["passed"])
    if passed != (exit_code == 0):
        raise ReceiptValidationError("passed must exactly match exitCode == 0")
    if passed and changed:
        raise ReceiptValidationError("passing required-test receipt cannot use changed oracle paths")
    return {
        "command": command,
        "oracleSha256": oracle,
        "exitCode": exit_code,
        "passed": passed,
        "changedOraclePaths": list(changed),
    }


def _validate_scope_diff(e: Mapping[str, Any], _: ReceiptIdentity) -> dict[str, Any]:
    expected = {
        "changedPaths", "changedFileCount", "additions", "deletions", "totalChurn",
        "maxChangedFiles", "maxChurnLines", "diffSha256",
    }
    if set(e) != expected:
        raise ReceiptValidationError("scope-diff evidence keys invalid")
    paths = _normalize_paths(e["changedPaths"], "changedPaths")
    count = _require_nonnegative_int(e["changedFileCount"], "changedFileCount")
    additions = _require_nonnegative_int(e["additions"], "additions")
    deletions = _require_nonnegative_int(e["deletions"], "deletions")
    total = _require_nonnegative_int(e["totalChurn"], "totalChurn")
    max_files = _require_nonnegative_int(e["maxChangedFiles"], "maxChangedFiles")
    max_churn = _require_nonnegative_int(e["maxChurnLines"], "maxChurnLines")
    diff_sha = _require_sha(e["diffSha256"], "diffSha256", length=64)
    if count != len(paths):
        raise ReceiptValidationError("changedFileCount does not match changedPaths")
    if total != additions + deletions:
        raise ReceiptValidationError("totalChurn must equal additions + deletions")
    if count > max_files or total > max_churn:
        raise ReceiptValidationError("scope/churn ceiling exceeded")
    return {
        "changedPaths": list(paths),
        "changedFileCount": count,
        "additions": additions,
        "deletions": deletions,
        "totalChurn": total,
        "maxChangedFiles": max_files,
        "maxChurnLines": max_churn,
        "diffSha256": diff_sha,
    }


def _validate_independent_review(e: Mapping[str, Any], _: ReceiptIdentity) -> dict[str, Any]:
    expected = {"builderPrincipal", "reviewerPrincipal", "reviewedCandidateSha", "verdict", "reviewEvidenceSha256"}
    if set(e) != expected:
        raise ReceiptValidationError("independent-review evidence keys invalid")
    builder = _require_str(e["builderPrincipal"], "builderPrincipal")
    reviewer = _require_str(e["reviewerPrincipal"], "reviewerPrincipal")
    if builder.casefold() == reviewer.casefold():
        raise ReceiptValidationError("builder and reviewer must be independent")
    reviewed = _require_sha(e["reviewedCandidateSha"], "reviewedCandidateSha")
    verdict = _require_str(e["verdict"], "verdict")
    if verdict not in {"PASS", "FAIL", "BLOCKED"}:
        raise ReceiptValidationError("review verdict invalid")
    evidence_sha = _require_sha(e["reviewEvidenceSha256"], "reviewEvidenceSha256", length=64)
    return {
        "builderPrincipal": builder,
        "reviewerPrincipal": reviewer,
        "reviewedCandidateSha": reviewed,
        "verdict": verdict,
        "reviewEvidenceSha256": evidence_sha,
    }


def _validate_measured_cost(e: Mapping[str, Any], _: ReceiptIdentity) -> dict[str, Any]:
    expected = {"reservedUsd", "measuredUsd", "settlementState", "measurementSha256"}
    if set(e) != expected:
        raise ReceiptValidationError("measured-cost evidence keys invalid")
    reserved = _require_finite_nonnegative(e["reservedUsd"], "reservedUsd")
    state = _require_str(e["settlementState"], "settlementState")
    if state not in {"settled", "unknown"}:
        raise ReceiptValidationError("settlementState invalid")
    measured_raw = e["measuredUsd"]
    if state == "unknown":
        if measured_raw is not None:
            raise ReceiptValidationError("unknown settlement must use measuredUsd=null")
        measured = None
    else:
        measured = _require_finite_nonnegative(measured_raw, "measuredUsd")
        if measured > reserved:
            raise ReceiptValidationError("measured cost exceeds reserved authority")
    measurement_sha = _require_sha(e["measurementSha256"], "measurementSha256", length=64)
    return {
        "reservedUsd": reserved,
        "measuredUsd": measured,
        "settlementState": state,
        "measurementSha256": measurement_sha,
    }


def _validate_candidate_freeze(e: Mapping[str, Any], identity: ReceiptIdentity) -> dict[str, Any]:
    expected = {"observedCandidateSha", "writerRevoked", "frozenAtUnixMs", "scopeDiffReceiptSha256"}
    if set(e) != expected:
        raise ReceiptValidationError("candidate-freeze evidence keys invalid")
    observed = _require_sha(e["observedCandidateSha"], "observedCandidateSha")
    if observed != identity.candidate_sha:
        raise ReceiptValidationError("freeze observed SHA does not match receipt candidate SHA")
    if e["writerRevoked"] is not True:
        raise ReceiptValidationError("candidate freeze requires writerRevoked=true")
    frozen_at = _require_nonnegative_int(e["frozenAtUnixMs"], "frozenAtUnixMs")
    scope_sha = _require_sha(e["scopeDiffReceiptSha256"], "scopeDiffReceiptSha256", length=64)
    return {
        "observedCandidateSha": observed,
        "writerRevoked": True,
        "frozenAtUnixMs": frozen_at,
        "scopeDiffReceiptSha256": scope_sha,
    }


def receipt_matches_identity(receipt: Mapping[str, Any], *, task_id: str, run_id: str, owner_epoch: int,
                             base_sha: str, candidate_sha: str, contract_sha256: str) -> bool:
    clean = validate_receipt(receipt)
    expected = ReceiptIdentity(
        task_id=_require_str(task_id, "task_id"),
        run_id=_require_str(run_id, "run_id"),
        owner_epoch=_require_nonnegative_int(owner_epoch, "owner_epoch"),
        base_sha=_require_sha(base_sha, "base_sha"),
        candidate_sha=_require_sha(candidate_sha, "candidate_sha"),
        contract_sha256=_require_sha(contract_sha256, "contract_sha256", length=64),
    ).as_dict()
    return clean["identity"] == expected


def require_acceptance_bundle(receipts: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    by_kind: dict[str, dict[str, Any]] = {}
    identity: dict[str, Any] | None = None
    for raw in receipts:
        clean = validate_receipt(raw)
        kind = clean["kind"]
        if kind in by_kind:
            raise ReceiptValidationError(f"duplicate receipt kind: {kind}")
        if identity is None:
            identity = clean["identity"]
        elif clean["identity"] != identity:
            raise ReceiptValidationError("receipt bundle identity mismatch")
        by_kind[kind] = clean
    required = {"required-test", "scope-diff", "independent-review", "measured-cost", "candidate-freeze"}
    missing = required - set(by_kind)
    if missing:
        raise ReceiptValidationError("missing acceptance receipts: " + ",".join(sorted(missing)))
    if by_kind["independent-review"]["evidence"]["reviewedCandidateSha"] != identity["candidateSha"]:
        raise ReceiptValidationError("review receipt is not bound to exact candidate SHA")
    if by_kind["independent-review"]["evidence"]["verdict"] != "PASS":
        raise ReceiptValidationError("acceptance requires independent REVIEW PASS")
    if not by_kind["required-test"]["evidence"]["passed"]:
        raise ReceiptValidationError("acceptance requires required-test PASS")
    return by_kind
