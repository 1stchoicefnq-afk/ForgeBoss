from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


class ReuseReviewError(RuntimeError):
    """Raised when substantial work lacks a valid upstream reuse decision."""


WORK_KINDS = frozenset({"small-repair", "substantial-subsystem"})
DECISIONS = frozenset({"reuse", "adapt", "custom"})
LICENSE_STATUSES = frozenset({"permissive", "compatible", "incompatible", "unknown"})
FIT_STATUSES = frozenset({"fit", "partial", "unfit", "unknown"})
DISPOSITIONS = frozenset({"selected", "rejected", "reference-only"})

_REQUIRED_REVIEW_KEYS = frozenset({
    "schema",
    "subsystem",
    "search_performed",
    "candidates",
    "decision",
    "custom_build_reason",
})
_REQUIRED_CANDIDATE_KEYS = frozenset({
    "name",
    "source",
    "exact_identity",
    "license",
    "license_status",
    "maintenance_status",
    "platform_fit",
    "security_fit",
    "disposition",
    "notes",
})


@dataclass(frozen=True)
class ReuseCandidate:
    name: str
    source: str
    exact_identity: str
    license: str
    license_status: str
    maintenance_status: str
    platform_fit: str
    security_fit: str
    disposition: str
    notes: str


@dataclass(frozen=True)
class ReuseReview:
    schema: int
    subsystem: str
    search_performed: tuple[str, ...]
    candidates: tuple[ReuseCandidate, ...]
    decision: str
    custom_build_reason: str
    selected: tuple[ReuseCandidate, ...]


@dataclass(frozen=True)
class BuildReadiness:
    ready: bool
    work_kind: str
    blocker: str | None
    review: ReuseReview | None


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ReuseReviewError(f"{label} must be a string")
    clean = value.strip()
    if not allow_empty and not clean:
        raise ReuseReviewError(f"{label} is required")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
        raise ReuseReviewError(f"{label} contains control characters")
    return clean


def _strict_keys(value: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ReuseReviewError(f"{label} field mismatch: missing={missing!r} extra={extra!r}")


def _searches(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ReuseReviewError("search_performed must be an array")
    out = tuple(_text(item, "search_performed item") for item in value)
    if not out:
        raise ReuseReviewError("search_performed must record at least one search")
    if len(set(out)) != len(out):
        raise ReuseReviewError("search_performed contains duplicates")
    return out


def _candidate(value: object) -> ReuseCandidate:
    if not isinstance(value, dict):
        raise ReuseReviewError("candidate must be an object")
    _strict_keys(value, _REQUIRED_CANDIDATE_KEYS, "candidate")
    candidate = ReuseCandidate(
        name=_text(value["name"], "candidate.name"),
        source=_text(value["source"], "candidate.source"),
        exact_identity=_text(value["exact_identity"], "candidate.exact_identity", allow_empty=True),
        license=_text(value["license"], "candidate.license"),
        license_status=_text(value["license_status"], "candidate.license_status"),
        maintenance_status=_text(value["maintenance_status"], "candidate.maintenance_status"),
        platform_fit=_text(value["platform_fit"], "candidate.platform_fit"),
        security_fit=_text(value["security_fit"], "candidate.security_fit"),
        disposition=_text(value["disposition"], "candidate.disposition"),
        notes=_text(value["notes"], "candidate.notes", allow_empty=True),
    )
    if candidate.license_status not in LICENSE_STATUSES:
        raise ReuseReviewError(f"unknown license_status: {candidate.license_status}")
    if candidate.platform_fit not in FIT_STATUSES:
        raise ReuseReviewError(f"unknown platform_fit: {candidate.platform_fit}")
    if candidate.security_fit not in FIT_STATUSES:
        raise ReuseReviewError(f"unknown security_fit: {candidate.security_fit}")
    if candidate.disposition not in DISPOSITIONS:
        raise ReuseReviewError(f"unknown disposition: {candidate.disposition}")
    if candidate.disposition == "selected":
        if not candidate.exact_identity:
            raise ReuseReviewError("selected candidate requires exact_identity")
        if candidate.license_status not in {"permissive", "compatible"}:
            raise ReuseReviewError("selected candidate must have compatible license status")
        if candidate.platform_fit not in {"fit", "partial"}:
            raise ReuseReviewError("selected candidate requires known acceptable platform fit")
        if candidate.security_fit not in {"fit", "partial"}:
            raise ReuseReviewError("selected candidate requires known acceptable security fit")
    return candidate


def validate_reuse_review(
    document: object,
    *,
    expected_subsystem: str | None = None,
) -> ReuseReview:
    if not isinstance(document, dict):
        raise ReuseReviewError("UPSTREAM_REUSE_REVIEW must be an object")
    _strict_keys(document, _REQUIRED_REVIEW_KEYS, "UPSTREAM_REUSE_REVIEW")
    if type(document.get("schema")) is not int or document["schema"] != 1:
        raise ReuseReviewError("UPSTREAM_REUSE_REVIEW schema must be integer 1")

    subsystem = _text(document["subsystem"], "subsystem")
    if expected_subsystem is not None and subsystem != _text(expected_subsystem, "expected_subsystem"):
        raise ReuseReviewError(
            f"reuse review subsystem mismatch: expected {expected_subsystem!r}, got {subsystem!r}"
        )

    searches = _searches(document["search_performed"])
    raw_candidates = document["candidates"]
    if not isinstance(raw_candidates, list):
        raise ReuseReviewError("candidates must be an array")
    candidates = tuple(_candidate(item) for item in raw_candidates)
    names = [item.name for item in candidates]
    if len(set(names)) != len(names):
        raise ReuseReviewError("candidate names must be unique")

    decision = _text(document["decision"], "decision")
    if decision not in DECISIONS:
        raise ReuseReviewError(f"unknown decision: {decision}")

    custom_reason = _text(
        document["custom_build_reason"],
        "custom_build_reason",
        allow_empty=True,
    )
    selected = tuple(item for item in candidates if item.disposition == "selected")

    if decision in {"reuse", "adapt"}:
        if not selected:
            raise ReuseReviewError(f"{decision} decision requires at least one selected candidate")
        if custom_reason:
            raise ReuseReviewError("custom_build_reason must be empty for reuse/adapt decisions")
    else:
        if selected:
            raise ReuseReviewError("custom decision cannot also select an upstream component")
        if not custom_reason:
            raise ReuseReviewError("custom decision requires an explicit custom_build_reason")
        if not candidates:
            raise ReuseReviewError("custom decision requires recorded candidates that were considered")

    return ReuseReview(
        schema=1,
        subsystem=subsystem,
        search_performed=searches,
        candidates=candidates,
        decision=decision,
        custom_build_reason=custom_reason,
        selected=selected,
    )


def evaluate_build_readiness(
    *,
    work_kind: str,
    subsystem: str,
    reuse_review: object | None,
) -> BuildReadiness:
    """Fail closed for substantial work and allow small repairs without broad OSS research.

    work_kind must ultimately come from an authoritative ForgeBoss planning/control
    record. This primitive deliberately does not trust or create that classification.
    """
    kind = _text(work_kind, "work_kind")
    if kind not in WORK_KINDS:
        raise ReuseReviewError(f"unknown work_kind: {kind}")
    subsystem = _text(subsystem, "subsystem")

    if kind == "small-repair" and reuse_review is None:
        return BuildReadiness(True, kind, None, None)

    if reuse_review is None:
        return BuildReadiness(
            False,
            kind,
            "UPSTREAM_REUSE_REVIEW_REQUIRED",
            None,
        )

    try:
        review = validate_reuse_review(reuse_review, expected_subsystem=subsystem)
    except ReuseReviewError as ex:
        return BuildReadiness(False, kind, f"UPSTREAM_REUSE_REVIEW_INVALID: {ex}", None)

    return BuildReadiness(True, kind, None, review)


def review_summary(review: ReuseReview) -> Mapping[str, object]:
    return MappingProxyType({
        "subsystem": review.subsystem,
        "decision": review.decision,
        "searches": review.search_performed,
        "selected": tuple(
            MappingProxyType({
                "name": item.name,
                "source": item.source,
                "exact_identity": item.exact_identity,
                "license": item.license,
            })
            for item in review.selected
        ),
        "custom_build_reason": review.custom_build_reason,
    })