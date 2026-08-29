from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional, Sequence, Tuple

SCHEMA_VERSION = 2
POLICY_PATH_KEY_VERSION = "win-git-v1"

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_RESERVED = {
    "con", "prn", "aux", "nul", "clock$", "conin$", "conout$",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
_SUPERSCRIPT_RESERVED = re.compile(r"^(?:com|lpt)[¹²³](?:\..*)?$", re.I)


class ReceiptError(ValueError):
    pass


def _closed(obj: Mapping[str, Any], allowed: Iterable[str], *, required: Iterable[str] = ()) -> dict:
    if not isinstance(obj, Mapping):
        raise ReceiptError("record must be an object")
    allowed = set(allowed)
    required = set(required)
    extra = set(obj) - allowed
    missing = required - set(obj)
    if extra:
        raise ReceiptError("unknown keys: " + ",".join(sorted(extra)))
    if missing:
        raise ReceiptError("missing keys: " + ",".join(sorted(missing)))
    return dict(obj)


def _text(value: Any, name: str, *, pattern=None, lower=False) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ReceiptError(f"{name} must be non-empty canonical text")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise ReceiptError(f"{name} contains forbidden control characters")
    out = value.lower() if lower else value
    if pattern is not None and not pattern.fullmatch(out):
        raise ReceiptError(f"{name} is invalid")
    return out


def _positive_int(value: Any, name: str, *, allow_zero=False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReceiptError(f"{name} must be an integer")
    if value < (0 if allow_zero else 1) or value > 2**63 - 1:
        raise ReceiptError(f"{name} is out of range")
    return value


def _sha(value: Any, name: str, object_format: str = "sha1") -> str:
    pattern = _HEX40 if object_format == "sha1" else _HEX64 if object_format == "sha256" else None
    if pattern is None:
        raise ReceiptError("unsupported object format")
    return _text(value, name, pattern=pattern, lower=True)


def _digest(value: Any, name: str) -> str:
    return _text(value, name, pattern=_HEX64, lower=True)


def canonical_money(value: Any, name: str = "money") -> str:
    if not isinstance(value, str) or value != value.strip() or not _DECIMAL.fullmatch(value):
        raise ReceiptError(f"{name} must be a non-negative decimal string without exponent/whitespace")
    try:
        d = Decimal(value)
    except InvalidOperation as ex:
        raise ReceiptError(f"{name} is invalid") from ex
    if not d.is_finite() or d < 0:
        raise ReceiptError(f"{name} must be finite and non-negative")
    out = format(d, "f")
    if "." in out:
        out = out.rstrip("0").rstrip(".")
    if out == "-0":
        out = "0"
    return out or "0"


def _jsonable(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        value = dict(value)
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, frozenset):
        return sorted(_jsonable(v) for v in value)
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise ReceiptError(f"non-canonical value type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            _jsonable(value), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as ex:
        raise ReceiptError("record is not canonical JSON") from ex


def strict_loads(text: Any) -> Any:
    if not isinstance(text, str):
        raise ReceiptError("JSON input must be text")

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ReceiptError(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    def constant(name):
        raise ReceiptError(f"non-finite JSON constant denied: {name}")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except ReceiptError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as ex:
        raise ReceiptError("invalid JSON") from ex


def receipt_digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _git_component_policy_key(component: str) -> str:
    if component in ("", ".", ".."):
        raise ReceiptError("empty/dot/traversal Git path component denied")
    if component[-1:] in (" ", "."):
        raise ReceiptError("Windows trailing-dot/space alias denied")
    if ":" in component:
        raise ReceiptError("Windows ADS/colon path denied")
    if any(ord(c) < 32 for c in component):
        raise ReceiptError("control character in Git path denied")
    folded = component.casefold()
    base = folded.split(".", 1)[0]
    if base in _RESERVED or _SUPERSCRIPT_RESERVED.fullmatch(folded):
        raise ReceiptError("Windows reserved device path denied")
    if "~" in component:
        raise ReceiptError("Windows 8.3 alias candidate denied")
    return folded.replace("%", "%25").replace("\\", "%5c")


def policy_path_key(path: Any) -> str:
    p = _text(path, "gitPath")
    if p.startswith("/") or p.startswith("//") or p.startswith("\\\\") or p.startswith("\\\\?\\") or p.startswith("\\\\.\\"):
        raise ReceiptError("rooted/UNC/device Git path denied")
    if len(p) >= 2 and p[0].isalpha() and p[1] == ":":
        raise ReceiptError("drive-absolute Git path denied")
    return POLICY_PATH_KEY_VERSION + ":" + "/".join(_git_component_policy_key(c) for c in p.split("/"))


def exact_git_paths(values: Sequence[Any], name: str = "paths") -> Tuple[Tuple[str, str], ...]:
    if not isinstance(values, (list, tuple)):
        raise ReceiptError(f"{name} must be an array")
    seen_exact = set()
    seen_policy = {}
    out = []
    for raw in values:
        rec = _closed(raw, {"gitPath", "policyPathKey", "policyVersion"},
                      required={"gitPath", "policyPathKey", "policyVersion"})
        exact = _text(rec["gitPath"], f"{name}[].gitPath")
        version = _text(rec["policyVersion"], f"{name}[].policyVersion")
        if version != POLICY_PATH_KEY_VERSION:
            raise ReceiptError("unsupported policy path key version")
        derived = policy_path_key(exact)
        supplied = _text(rec["policyPathKey"], f"{name}[].policyPathKey")
        if supplied != derived:
            raise ReceiptError("policyPathKey does not match exact Git path")
        if exact in seen_exact:
            raise ReceiptError(f"duplicate exact Git path: {exact}")
        other = seen_policy.get(derived)
        if other is not None and other != exact:
            raise ReceiptError(f"policy path collision: {other!r} vs {exact!r}")
        seen_exact.add(exact)
        seen_policy[derived] = exact
        out.append((exact, derived))
    return tuple(out)


def _ids(values: Sequence[Any], name: str) -> Tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ReceiptError(f"{name} must be an array")
    out = []
    seen = set()
    for value in values:
        item = _text(value, f"{name}[]", pattern=_ID)
        folded = item.casefold()
        if folded in seen:
            raise ReceiptError(f"duplicate {name} identity")
        seen.add(folded)
        out.append(item)
    return tuple(out)


@dataclass(frozen=True)
class AssignmentIdentityReference:
    assignment_id: str
    assignment_sha256: str
    task_id: str
    run_id: str
    attempt: int
    owner_epoch: int
    repository: str
    object_format: str
    base_sha: str
    workspace_generation: int
    workspace_content_sha256: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AssignmentIdentityReference":
        required = {
            "assignmentId", "assignmentSha256", "taskId", "runId", "attempt", "ownerEpoch",
            "repository", "objectFormat", "baseSha", "workspaceGeneration", "workspaceContentSha256"
        }
        r = _closed(raw, required, required=required)
        fmt = _text(r["objectFormat"], "objectFormat", lower=True)
        if fmt not in ("sha1", "sha256"):
            raise ReceiptError("unsupported object format")
        return cls(
            _text(r["assignmentId"], "assignmentId", pattern=_ID),
            _digest(r["assignmentSha256"], "assignmentSha256"),
            _text(r["taskId"], "taskId", pattern=_ID),
            _text(r["runId"], "runId", pattern=_ID),
            _positive_int(r["attempt"], "attempt"),
            _positive_int(r["ownerEpoch"], "ownerEpoch"),
            _text(r["repository"], "repository", pattern=_REPO),
            fmt, _sha(r["baseSha"], "baseSha", fmt),
            _positive_int(r["workspaceGeneration"], "workspaceGeneration"),
            _digest(r["workspaceContentSha256"], "workspaceContentSha256"),
        )

    def to_dict(self) -> dict:
        return {
            "assignmentId": self.assignment_id, "assignmentSha256": self.assignment_sha256,
            "taskId": self.task_id, "runId": self.run_id, "attempt": self.attempt,
            "ownerEpoch": self.owner_epoch, "repository": self.repository,
            "objectFormat": self.object_format, "baseSha": self.base_sha,
            "workspaceGeneration": self.workspace_generation,
            "workspaceContentSha256": self.workspace_content_sha256,
        }

    @property
    def digest(self) -> str:
        return receipt_digest({"type": "assignment-identity", "schemaVersion": SCHEMA_VERSION, **self.to_dict()})


@dataclass(frozen=True)
class CandidateHandoff:
    assignment: AssignmentIdentityReference
    candidate_sha: str
    candidate_tree_sha: str
    changed_paths: Tuple[Tuple[str, str], ...]
    required_test_receipts: Tuple[str, ...]
    scope_diff_sha256: str
    additions: int
    deletions: int
    measured_cost_usd: Optional[str]
    reserved_cost_usd: str
    contributors: Tuple[str, ...]
    known_uncertainty: Tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CandidateHandoff":
        required = {
            "assignment", "candidateSha", "candidateTreeSha", "changedPaths", "requiredTestReceipts",
            "scopeDiffSha256", "additions", "deletions", "measuredCostUsd", "reservedCostUsd",
            "contributors", "knownUncertainty"
        }
        r = _closed(raw, required, required=required)
        assignment = AssignmentIdentityReference.from_dict(r["assignment"])
        paths = exact_git_paths(r["changedPaths"], "changedPaths")
        tests = tuple(_digest(x, "requiredTestReceipts[]") for x in r["requiredTestReceipts"])
        if len(set(tests)) != len(tests):
            raise ReceiptError("duplicate required test receipt")
        measured = r["measuredCostUsd"]
        if measured is not None:
            measured = canonical_money(measured, "measuredCostUsd")
        reserved = canonical_money(r["reservedCostUsd"], "reservedCostUsd")
        if measured is not None and Decimal(measured) > Decimal(reserved):
            raise ReceiptError("measured cost exceeds reserved authority")
        uncertainties = r["knownUncertainty"]
        if not isinstance(uncertainties, (list, tuple)):
            raise ReceiptError("knownUncertainty must be an array")
        unc = tuple(_text(x, "knownUncertainty[]") for x in uncertainties)
        contributors = _ids(r["contributors"], "contributors")
        if not contributors:
            raise ReceiptError("candidate handoff requires at least one contributor")
        return cls(
            assignment,
            _sha(r["candidateSha"], "candidateSha", assignment.object_format),
            _sha(r["candidateTreeSha"], "candidateTreeSha", assignment.object_format),
            paths, tests, _digest(r["scopeDiffSha256"], "scopeDiffSha256"),
            _positive_int(r["additions"], "additions", allow_zero=True),
            _positive_int(r["deletions"], "deletions", allow_zero=True),
            measured, reserved, contributors, unc
        )

    def to_dict(self) -> dict:
        return {
            "assignment": self.assignment.to_dict(),
            "candidateSha": self.candidate_sha, "candidateTreeSha": self.candidate_tree_sha,
            "changedPaths": [
                {"gitPath": p, "policyPathKey": k, "policyVersion": POLICY_PATH_KEY_VERSION}
                for p, k in self.changed_paths
            ],
            "requiredTestReceipts": list(self.required_test_receipts),
            "scopeDiffSha256": self.scope_diff_sha256,
            "additions": self.additions, "deletions": self.deletions,
            "measuredCostUsd": self.measured_cost_usd, "reservedCostUsd": self.reserved_cost_usd,
            "contributors": list(self.contributors), "knownUncertainty": list(self.known_uncertainty),
        }

    @property
    def digest(self) -> str:
        return receipt_digest({"type": "candidate-handoff", "schemaVersion": SCHEMA_VERSION, **self.to_dict()})


@dataclass(frozen=True)
class ReviewerReceipt:
    assignment: AssignmentIdentityReference
    handoff_sha256: str
    candidate_sha: str
    candidate_tree_sha: str
    reviewer_id: str
    verdict: str
    evidence_sha256: str
    reviewer_test_receipts: Tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], *, handoff: Optional[CandidateHandoff] = None) -> "ReviewerReceipt":
        required = {
            "assignment", "handoffSha256", "candidateSha", "candidateTreeSha", "reviewerId",
            "verdict", "evidenceSha256", "reviewerTestReceipts"
        }
        r = _closed(raw, required, required=required)
        assignment = AssignmentIdentityReference.from_dict(r["assignment"])
        verdict = _text(r["verdict"], "verdict", lower=True)
        if verdict not in ("pass", "fail", "blocked"):
            raise ReceiptError("invalid review verdict")
        obj = cls(
            assignment, _digest(r["handoffSha256"], "handoffSha256"),
            _sha(r["candidateSha"], "candidateSha", assignment.object_format),
            _sha(r["candidateTreeSha"], "candidateTreeSha", assignment.object_format),
            _text(r["reviewerId"], "reviewerId", pattern=_ID), verdict,
            _digest(r["evidenceSha256"], "evidenceSha256"),
            tuple(_digest(x, "reviewerTestReceipts[]") for x in r["reviewerTestReceipts"])
        )
        if handoff is not None:
            obj.assert_matches_handoff(handoff)
        return obj

    def assert_matches_handoff(self, handoff: CandidateHandoff) -> None:
        if self.assignment != handoff.assignment:
            raise ReceiptError("review assignment identity mismatch")
        if self.handoff_sha256 != handoff.digest:
            raise ReceiptError("review handoff digest mismatch")
        if self.candidate_sha != handoff.candidate_sha or self.candidate_tree_sha != handoff.candidate_tree_sha:
            raise ReceiptError("review candidate identity mismatch")
        if self.reviewer_id.casefold() in {x.casefold() for x in handoff.contributors}:
            raise ReceiptError("reviewer is a candidate contributor")

    def to_dict(self) -> dict:
        return {
            "assignment": self.assignment.to_dict(), "handoffSha256": self.handoff_sha256,
            "candidateSha": self.candidate_sha, "candidateTreeSha": self.candidate_tree_sha,
            "reviewerId": self.reviewer_id, "verdict": self.verdict,
            "evidenceSha256": self.evidence_sha256,
            "reviewerTestReceipts": list(self.reviewer_test_receipts),
        }

    @property
    def digest(self) -> str:
        return receipt_digest({"type": "reviewer-receipt", "schemaVersion": SCHEMA_VERSION, **self.to_dict()})


@dataclass(frozen=True)
class ControllerAcceptanceReference:
    assignment: AssignmentIdentityReference
    handoff_sha256: str
    review_sha256: str
    candidate_sha: str
    candidate_tree_sha: str
    controller_id: str
    accepted: bool

    @classmethod
    def from_records(cls, *, controller_id: str, handoff: CandidateHandoff,
                     review: ReviewerReceipt) -> "ControllerAcceptanceReference":
        review.assert_matches_handoff(handoff)
        if review.verdict != "pass":
            raise ReceiptError("controller acceptance requires PASS review")
        return cls(
            handoff.assignment, handoff.digest, review.digest,
            handoff.candidate_sha, handoff.candidate_tree_sha,
            _text(controller_id, "controllerId", pattern=_ID), True
        )

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], *, handoff: CandidateHandoff,
                  review: ReviewerReceipt) -> "ControllerAcceptanceReference":
        required = {
            "assignment", "handoffSha256", "reviewSha256", "candidateSha", "candidateTreeSha",
            "controllerId", "accepted"
        }
        r = _closed(raw, required, required=required)
        if r["accepted"] is not True:
            raise ReceiptError("acceptance record must represent accepted=true")
        obj = cls(
            AssignmentIdentityReference.from_dict(r["assignment"]),
            _digest(r["handoffSha256"], "handoffSha256"),
            _digest(r["reviewSha256"], "reviewSha256"),
            _sha(r["candidateSha"], "candidateSha", handoff.assignment.object_format),
            _sha(r["candidateTreeSha"], "candidateTreeSha", handoff.assignment.object_format),
            _text(r["controllerId"], "controllerId", pattern=_ID), True
        )
        expected = cls.from_records(controller_id=obj.controller_id, handoff=handoff, review=review)
        if obj != expected:
            raise ReceiptError("acceptance reference does not exactly bind handoff/review")
        return obj

    def to_dict(self) -> dict:
        return {
            "assignment": self.assignment.to_dict(), "handoffSha256": self.handoff_sha256,
            "reviewSha256": self.review_sha256, "candidateSha": self.candidate_sha,
            "candidateTreeSha": self.candidate_tree_sha, "controllerId": self.controller_id,
            "accepted": True,
        }

    @property
    def digest(self) -> str:
        return receipt_digest({"type": "controller-acceptance", "schemaVersion": SCHEMA_VERSION, **self.to_dict()})
