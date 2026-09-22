from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Callable, Iterable, Mapping, Sequence


class WorkforceContractError(ValueError):
    """Raised when a worker/routine contract is invalid or authority is ambiguous."""


OUTBOUND_ACTIONS = frozenset({
    "send",
    "submit",
    "publish",
    "post",
    "spend",
    "deploy",
    "migrate",
    "delete",
    "push",
    "merge",
    "approve",
})

RUN_STATES = frozenset({
    "ok",
    "partial",
    "failed",
    "blocked",
    "needs-approval",
    "skipped-out-of-window",
    "skipped-already-ran",
    "paused",
})

_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def _clean_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise WorkforceContractError(f"{label} must be a string")
    text = value.strip()
    if not text:
        raise WorkforceContractError(f"{label} is required")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise WorkforceContractError(f"{label} contains control characters")
    return text


def _clean_tuple(values: Iterable[object], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise WorkforceContractError(f"{label} values must be a sequence, not a string")
    try:
        raw = tuple(values)
    except TypeError as ex:
        raise WorkforceContractError(f"{label} values must be iterable") from ex
    cleaned = tuple(_clean_text(value, label) for value in raw)
    if len(set(cleaned)) != len(cleaned):
        raise WorkforceContractError(f"{label} values must be unique")
    return cleaned


def _utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise WorkforceContractError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class RoutineContract:
    routine_id: str
    period_kind: str
    capabilities: tuple[str, ...]
    budget_seconds: int
    outbound_actions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        routine_id = _clean_text(self.routine_id, "routine_id")
        period_kind = _clean_text(self.period_kind, "period_kind")
        if isinstance(self.budget_seconds, bool) or not isinstance(self.budget_seconds, int) or self.budget_seconds <= 0:
            raise WorkforceContractError("budget_seconds must be a positive integer")
        capabilities = _clean_tuple(self.capabilities, "capability")
        if not capabilities:
            raise WorkforceContractError("at least one named capability is required")
        outbound_actions = _clean_tuple(self.outbound_actions, "outbound action")
        unknown_outbound = set(outbound_actions) - OUTBOUND_ACTIONS
        if unknown_outbound:
            raise WorkforceContractError(f"unknown outbound actions: {sorted(unknown_outbound)}")
        object.__setattr__(self, "routine_id", routine_id)
        object.__setattr__(self, "period_kind", period_kind)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "outbound_actions", outbound_actions)


@dataclass(frozen=True)
class WorkerContract:
    worker_id: str
    role: str
    version: str
    routines: tuple[RoutineContract, ...]
    authority_grant: str = "NONE"

    def __post_init__(self) -> None:
        worker_id = _clean_text(self.worker_id, "worker_id")
        role = _clean_text(self.role, "role")
        version = _clean_text(self.version, "version")
        if isinstance(self.routines, (str, bytes)):
            raise WorkforceContractError("routines must be a sequence of RoutineContract values")
        try:
            routines = tuple(self.routines)
        except TypeError as ex:
            raise WorkforceContractError("routines must be iterable") from ex
        if not _SEMVER.fullmatch(version):
            raise WorkforceContractError("version must be strict major.minor.patch semver")
        if self.authority_grant != "NONE":
            raise WorkforceContractError("worker contracts are descriptive and cannot grant runtime authority")
        if not routines:
            raise WorkforceContractError("at least one routine is required")
        if any(not isinstance(routine, RoutineContract) for routine in routines):
            raise WorkforceContractError("routines must contain RoutineContract values")
        ids = [routine.routine_id for routine in routines]
        if len(set(ids)) != len(ids):
            raise WorkforceContractError("routine_id values must be unique within a worker")
        object.__setattr__(self, "worker_id", worker_id)
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "routines", routines)


@dataclass(frozen=True)
class RunRecord:
    worker_id: str
    routine_id: str
    period_key: str
    state: str
    started_at: datetime
    finished_at: datetime
    evidence_ref: str
    blockers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        worker_id = _clean_text(self.worker_id, "worker_id")
        routine_id = _clean_text(self.routine_id, "routine_id")
        period_key = _clean_text(self.period_key, "period_key")
        evidence_ref = _clean_text(self.evidence_ref, "evidence_ref")
        state = _clean_text(self.state, "state")
        if state not in RUN_STATES:
            raise WorkforceContractError(f"unknown run state: {state}")
        started_at = _utc(self.started_at, "started_at")
        finished_at = _utc(self.finished_at, "finished_at")
        if finished_at < started_at:
            raise WorkforceContractError("finished_at cannot be before started_at")
        blockers = _clean_tuple(self.blockers, "blocker")
        object.__setattr__(self, "worker_id", worker_id)
        object.__setattr__(self, "routine_id", routine_id)
        object.__setattr__(self, "period_key", period_key)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "finished_at", finished_at)
        object.__setattr__(self, "evidence_ref", evidence_ref)
        object.__setattr__(self, "blockers", blockers)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.worker_id, self.routine_id, self.period_key)


def should_run_period(records: Iterable[RunRecord], worker_id: str, routine_id: str, period_key: str) -> bool:
    """Return False once evidence exists for the exact worker/routine/period key."""
    wanted = (
        _clean_text(worker_id, "worker_id"),
        _clean_text(routine_id, "routine_id"),
        _clean_text(period_key, "period_key"),
    )
    return not any(record.key == wanted for record in records)


def outbound_action_allowed(
    action: str,
    *,
    released_actions: Iterable[str] = (),
    authority_check: Callable[[str], bool] | None,
) -> bool:
    """Require both an explicit release and a separate runtime authority verifier."""
    action = _clean_text(action, "action").lower()
    if action not in OUTBOUND_ACTIONS:
        raise WorkforceContractError(f"unknown outbound action: {action}")
    released = {value.lower() for value in _clean_tuple(released_actions, "released action")}
    unknown = released - OUTBOUND_ACTIONS
    if unknown:
        raise WorkforceContractError(f"unknown released actions: {sorted(unknown)}")
    if action not in released:
        return False
    if authority_check is None or not callable(authority_check):
        raise WorkforceContractError("authoritative runtime verifier is required")
    decision = authority_check(action)
    if decision is not True and decision is not False:
        raise WorkforceContractError("authoritative runtime verifier must return bool")
    return decision is True


def validate_capability_routes(
    required_capabilities: Sequence[str],
    routes: Mapping[str, str | None],
) -> dict[str, str]:
    """Resolve named capabilities to concrete routes without letting routes redefine policy."""
    capabilities = _clean_tuple(required_capabilities, "capability")
    if not capabilities:
        raise WorkforceContractError("at least one capability is required")
    resolved: dict[str, str] = {}
    for capability in capabilities:
        if capability not in routes or not routes[capability]:
            raise WorkforceContractError(f"missing capability route: {capability}")
        resolved[capability] = _clean_text(routes[capability], f"route for {capability}")
    return resolved
