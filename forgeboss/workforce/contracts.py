from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Iterable, Mapping, Sequence


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

_SEMVER = re.compile(r"^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$")


@dataclass(frozen=True)
class RoutineContract:
    routine_id: str
    period_kind: str
    capabilities: tuple[str, ...]
    budget_seconds: int
    outbound_actions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        routine_id = self.routine_id.strip()
        period_kind = self.period_kind.strip()
        if not routine_id:
            raise WorkforceContractError("routine_id is required")
        if not period_kind:
            raise WorkforceContractError("period_kind is required")
        if self.budget_seconds <= 0:
            raise WorkforceContractError("budget_seconds must be positive")
        if not self.capabilities or any(not value.strip() for value in self.capabilities):
            raise WorkforceContractError("at least one named capability is required")
        if len(set(self.capabilities)) != len(self.capabilities):
            raise WorkforceContractError("capabilities must be unique")
        if len(set(self.outbound_actions)) != len(self.outbound_actions):
            raise WorkforceContractError("outbound_actions must be unique")
        unknown_outbound = set(self.outbound_actions) - OUTBOUND_ACTIONS
        if unknown_outbound:
            raise WorkforceContractError(f"unknown outbound actions: {sorted(unknown_outbound)}")
        object.__setattr__(self, "routine_id", routine_id)
        object.__setattr__(self, "period_kind", period_kind)


@dataclass(frozen=True)
class WorkerContract:
    worker_id: str
    role: str
    version: str
    routines: tuple[RoutineContract, ...]
    authority_grant: str = "NONE"

    def __post_init__(self) -> None:
        worker_id = self.worker_id.strip()
        role = self.role.strip()
        version = self.version.strip()
        if not worker_id or not role or not version:
            raise WorkforceContractError("worker_id, role and version are required")
        if not _SEMVER.fullmatch(version):
            raise WorkforceContractError("version must be strict major.minor.patch semver")
        if self.authority_grant != "NONE":
            raise WorkforceContractError("worker contracts are descriptive and cannot grant runtime authority")
        if not self.routines:
            raise WorkforceContractError("at least one routine is required")
        ids = [routine.routine_id for routine in self.routines]
        if len(set(ids)) != len(ids):
            raise WorkforceContractError("routine_id values must be unique within a worker")
        object.__setattr__(self, "worker_id", worker_id)
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "version", version)


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
        for label, value in (
            ("worker_id", self.worker_id),
            ("routine_id", self.routine_id),
            ("period_key", self.period_key),
            ("evidence_ref", self.evidence_ref),
        ):
            if not str(value).strip():
                raise WorkforceContractError(f"{label} is required")
        if self.state not in RUN_STATES:
            raise WorkforceContractError(f"unknown run state: {self.state}")
        if self.finished_at < self.started_at:
            raise WorkforceContractError("finished_at cannot be before started_at")

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.worker_id, self.routine_id, self.period_key)


def should_run_period(records: Iterable[RunRecord], worker_id: str, routine_id: str, period_key: str) -> bool:
    """Return False once evidence exists for the exact worker/routine/period key."""
    wanted = (worker_id, routine_id, period_key)
    return not any(record.key == wanted for record in records)


def outbound_action_allowed(
    action: str,
    *,
    released_actions: Iterable[str] = (),
    runtime_authority: bool = False,
) -> bool:
    """A release never grants authority by itself; both gates must explicitly allow the action."""
    action = str(action).strip().lower()
    if action not in OUTBOUND_ACTIONS:
        raise WorkforceContractError(f"unknown outbound action: {action}")
    released = {str(value).strip().lower() for value in released_actions}
    unknown = released - OUTBOUND_ACTIONS
    if unknown:
        raise WorkforceContractError(f"unknown released actions: {sorted(unknown)}")
    return runtime_authority and action in released


def validate_capability_routes(
    required_capabilities: Sequence[str],
    routes: Mapping[str, str | None],
) -> dict[str, str]:
    """Resolve named capabilities to concrete routes without letting routes redefine policy."""
    resolved: dict[str, str] = {}
    for capability in required_capabilities:
        if capability not in routes or not routes[capability]:
            raise WorkforceContractError(f"missing capability route: {capability}")
        resolved[capability] = str(routes[capability])
    return resolved
