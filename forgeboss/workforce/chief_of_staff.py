from __future__ import annotations

from dataclasses import dataclass
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


def reconcile_fleet(expected: Iterable[ExpectedRoutine], records: Iterable[RunRecord]) -> tuple[RoutineObservation, ...]:
    """Compare expected routines with immutable run evidence and expose silent absence."""
    by_key: dict[tuple[str, str, str], RunRecord] = {}
    for record in records:
        if record.key in by_key:
            raise WorkforceContractError(f"conflicting duplicate run evidence for {record.key}")
        by_key[record.key] = record

    seen_expected: set[tuple[str, str, str]] = set()
    observations: list[RoutineObservation] = []
    for item in expected:
        if item.key in seen_expected:
            raise WorkforceContractError(f"duplicate expected routine: {item.key}")
        seen_expected.add(item.key)

        if item.paused:
            observations.append(RoutineObservation(item.worker_id, item.routine_id, item.period_key, "paused", None))
            continue

        record = by_key.get(item.key)
        if record is None:
            observations.append(RoutineObservation(item.worker_id, item.routine_id, item.period_key, "silent", None))
            continue

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
        observations.append(
            RoutineObservation(
                item.worker_id,
                item.routine_id,
                item.period_key,
                status,
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
    """Produce a read-only brief from supplied evidence. It owns no mutation path."""
    observations = reconcile_fleet(expected, records)
    approvals = tuple(MappingProxyType(dict(item)) for item in pending_approvals)
    states = ("healthy", "partial", "blocked", "failed", "silent", "paused", "needs-approval")
    counts = {state: sum(1 for item in observations if item.status == state) for state in states}
    attention = tuple(
        item for item in observations if item.status in {"partial", "blocked", "failed", "silent", "needs-approval"}
    )
    return MappingProxyType({
        "counts": MappingProxyType(counts),
        "attention": attention,
        "pending_approvals": approvals,
        "observations": observations,
    })
