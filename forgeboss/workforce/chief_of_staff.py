from __future__ import annotations

from dataclasses import dataclass
import math
from types import MappingProxyType
from typing import Iterable, Mapping

from .contracts import RunRecord, RoutineContract, WorkerContract, WorkforceContractError


CHIEF_OF_STAFF_CONTRACT = WorkerContract(
    worker_id="chief-of-staff",
    role="Chief of Staff",
    version="1.0.0",
    routines=(
        RoutineContract("fleet-reconcile", "period-key", ("control.read", "evidence.read"), 300),
        RoutineContract("owner-brief", "period-key", ("control.read", "evidence.read", "approval.read"), 300),
    ),
)


@dataclass(frozen=True)
class ExpectedRoutine:
    worker_id: str
    routine_id: str
    period_key: str
    paused: bool = False

    def __post_init__(self) -> None:
        values = []
        for label, value in (("worker_id", self.worker_id), ("routine_id", self.routine_id), ("period_key", self.period_key)):
            if not isinstance(value, str):
                raise WorkforceContractError(f"{label} must be a string")
            text = value.strip()
            if not text:
                raise WorkforceContractError(f"{label} is required")
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
                raise WorkforceContractError(f"{label} contains control characters")
            values.append(text)
        object.__setattr__(self, "worker_id", values[0])
        object.__setattr__(self, "routine_id", values[1])
        object.__setattr__(self, "period_key", values[2])
        if not isinstance(self.paused, bool):
            raise WorkforceContractError("paused must be bool")

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.worker_id, self.routine_id, self.period_key)


@dataclass(frozen=True)
class RoutineObservation:
    worker_id: str
    routine_id: str
    period_key: str
    status: str
    evidence_ref: str | None
    blockers: tuple[str, ...] = ()


_HEALTHY = frozenset({"ok", "skipped-out-of-window", "skipped-already-ran"})
_ATTENTION = frozenset({"partial", "blocked", "failed", "silent", "paused", "needs-approval", "unexpected-run"})


def _freeze_brief_value(value: object) -> object:
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise WorkforceContractError("approval brief mapping keys must be strings")
            clean = key.strip()
            if not clean or any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
                raise WorkforceContractError("approval brief mapping keys are invalid")
            if clean in frozen:
                raise WorkforceContractError("approval brief mapping contains duplicate normalized keys")
            frozen[clean] = _freeze_brief_value(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_brief_value(item) for item in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise WorkforceContractError("approval brief contains non-finite number")
        return value
    raise WorkforceContractError(f"unsupported approval brief value type: {type(value).__name__}")


def _observation_from_record(item: ExpectedRoutine, record: RunRecord) -> RoutineObservation:
    if record.state in _HEALTHY:
        status = "healthy"
    elif record.state == "partial":
        status = "partial"
    elif record.state == "paused":
        status = "paused"
    elif record.state == "blocked":
        status = "blocked"
    elif record.state == "needs-approval":
        status = "needs-approval"
    else:
        status = "failed"
    return RoutineObservation(
        item.worker_id,
        item.routine_id,
        item.period_key,
        status,
        record.evidence_ref,
        record.blockers,
    )


def reconcile_fleet(expected: Iterable[ExpectedRoutine], records: Iterable[RunRecord]) -> tuple[RoutineObservation, ...]:
    """Compare expected routines with run evidence, including silent and unexpected work."""
    by_key: dict[tuple[str, str, str], RunRecord] = {}
    for record in records:
        if not isinstance(record, RunRecord):
            raise WorkforceContractError("records must contain RunRecord values")
        if record.key in by_key:
            raise WorkforceContractError(f"conflicting duplicate run evidence for {record.key}")
        by_key[record.key] = record

    seen_expected: set[tuple[str, str, str]] = set()
    observations: list[RoutineObservation] = []
    for item in expected:
        if not isinstance(item, ExpectedRoutine):
            raise WorkforceContractError("expected must contain ExpectedRoutine values")
        if item.key in seen_expected:
            raise WorkforceContractError(f"duplicate expected routine: {item.key}")
        seen_expected.add(item.key)

        record = by_key.get(item.key)
        if item.paused:
            if record is None:
                observations.append(RoutineObservation(item.worker_id, item.routine_id, item.period_key, "paused", None))
            else:
                observations.append(
                    RoutineObservation(
                        item.worker_id,
                        item.routine_id,
                        item.period_key,
                        "unexpected-run",
                        record.evidence_ref,
                        record.blockers,
                    )
                )
            continue

        if record is None:
            observations.append(RoutineObservation(item.worker_id, item.routine_id, item.period_key, "silent", None))
            continue

        observations.append(_observation_from_record(item, record))

    for key in sorted(set(by_key) - seen_expected):
        record = by_key[key]
        observations.append(
            RoutineObservation(
                record.worker_id,
                record.routine_id,
                record.period_key,
                "unexpected-run",
                record.evidence_ref,
                record.blockers,
            )
        )

    return tuple(observations)


def build_brief(
    expected: Iterable[ExpectedRoutine],
    records: Iterable[RunRecord],
    *,
    pending_approvals: Iterable[Mapping[str, object]] = (),
) -> Mapping[str, object]:
    """Produce a deeply read-only brief from supplied evidence. It owns no mutation path."""
    observations = reconcile_fleet(expected, records)
    approvals: list[Mapping[str, object]] = []
    for item in pending_approvals:
        if not isinstance(item, Mapping):
            raise WorkforceContractError("pending approvals must contain mappings")
        frozen = _freeze_brief_value(item)
        if not isinstance(frozen, Mapping):
            raise WorkforceContractError("pending approval normalization failed")
        approvals.append(frozen)
    states = ("healthy", "partial", "blocked", "failed", "silent", "paused", "needs-approval", "unexpected-run")
    counts = {state: sum(1 for item in observations if item.status == state) for state in states}
    attention = tuple(item for item in observations if item.status in _ATTENTION)
    return MappingProxyType({
        "counts": MappingProxyType(counts),
        "attention": attention,
        "pending_approvals": tuple(approvals),
        "observations": observations,
    })
