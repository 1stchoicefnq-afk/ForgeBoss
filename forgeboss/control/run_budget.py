"""FB-050: hard GLOBAL self-build run spend authority.

Aggregate, cross-worker spend authority for one ForgeBoss self-build run. The
primitive is deliberately standalone: no persistence, no daemon wiring, no
imports from the rest of ForgeBoss. Integration with ``daemon.py``/``store.py``
is explicitly out of scope for this packet.

Model
-----
A run is created with a finite, non-negative global cap. Every paid unit of work
must obtain authority *before* spending::

    budget = GlobalRunBudget("25.00")
    rec = budget.reserve("run-1:worker-a:call-7", "0.40", worker_id="worker-a")
    ...                                       # paid work happens here
    budget.settle(rec.reservation_id, "0.31") # unused 0.09 returns to the pool

Deterministic state machine (per reservation id)::

    (absent) --reserve--> RESERVED --settle(measured <= reserved)--> SETTLED
                          RESERVED --settle_unknown-----------------> SETTLED (cost_known=False)
                          RESERVED --release-----------------------> RELEASED
                          RESERVED --settle(measured >  reserved)--> OVERRUN + hard failure

Terminal states are final. Reservation ids are never recycled.

Fail-closed rules
-----------------
* cap and every amount must be a finite, non-negative decimal; ``NaN``,
  ``Infinity``, negatives, booleans, ``None``, overflowing exponents and
  malformed strings are rejected and change no state;
* a rejected reservation consumes no authority;
* an unknown/unmeasured cost can never silently release authority: ``settle``
  with a non-numeric cost is rejected and the reservation stays ``RESERVED``;
  the only way to close a reservation with an unknown cost is
  ``settle_unknown``, which conservatively commits the *whole* reserved amount;
* a measured settlement above the reserved amount is a hard failure: the full
  reserved amount is committed, the excess is recorded as ``unbilled_overrun``,
  the budget latches into a breached state (no further reservations may be
  granted) and ``RunBudgetError('SETTLEMENT_EXCEEDS_RESERVATION')`` is raised;
* ``release`` only ever returns *unused* reserved authority, and only from
  ``RESERVED``; it can never mint budget.

Idempotency / duplicate operations
----------------------------------
Replaying an operation that already succeeded with identical arguments returns
the same record and moves no money. Any other repeat fails closed with
``RESERVATION_CONFLICT``:

===========================  ==========================================
operation                    repeat behaviour
===========================  ==========================================
reserve, same id+amount+wid  idempotent while ``RESERVED``
reserve, id in any other way conflict (different amount/worker, or terminal)
settle, same measured cost   idempotent while ``SETTLED`` with known cost
settle_unknown               idempotent while ``SETTLED`` with unknown cost
release                      idempotent while ``RELEASED``
any op on ``OVERRUN``        conflict
===========================  ==========================================

All operations are atomic under a single re-entrant lock, so concurrent workers
can never jointly reserve more than the global cap.
"""
from __future__ import annotations
import math, threading
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation

MAX_IDENTIFIER_BYTES = 256

STATE_RESERVED = "RESERVED"
STATE_SETTLED = "SETTLED"
STATE_RELEASED = "RELEASED"
STATE_OVERRUN = "OVERRUN"
TERMINAL_STATES = frozenset({STATE_SETTLED, STATE_RELEASED, STATE_OVERRUN})

ZERO = Decimal(0)


class RunBudgetError(RuntimeError):
    """Coded spend-authority failure. ``code`` is stable and machine-readable."""

    def __init__(self, code, message):
        super().__init__(message);self.code = code


def _amount(value, code, message) -> Decimal:
    """Coerce ``value`` to a finite, non-negative Decimal or fail closed."""
    if isinstance(value, bool):raise RunBudgetError(code, message)
    # Decimal() tolerates surrounding whitespace and PEP 515 underscores; money does not.
    if isinstance(value, str) and (value.strip() != value or "_" in value):raise RunBudgetError(code, message)
    if not isinstance(value, (int, str, Decimal, float)):raise RunBudgetError(code, message)
    try:amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as ex:raise RunBudgetError(code, message) from ex
    if not amount.is_finite() or amount < 0:raise RunBudgetError(code, message)
    try:as_float = float(amount)
    except (OverflowError, ValueError) as ex:raise RunBudgetError(code, message) from ex
    if not math.isfinite(as_float):raise RunBudgetError(code, message)
    return amount


def _identifier(value, field) -> str:
    if not isinstance(value, str) or not value:
        raise RunBudgetError("IDENTIFIER_INVALID", f"{field} must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
        raise RunBudgetError("IDENTIFIER_INVALID", f"{field} exceeds {MAX_IDENTIFIER_BYTES} bytes")
    if value.strip() != value:
        raise RunBudgetError("IDENTIFIER_INVALID", f"{field} must not have surrounding whitespace")
    return value


@dataclass(frozen=True)
class Reservation:
    """Immutable snapshot of one reservation's authority accounting."""
    reservation_id: str
    worker_id: str | None
    state: str
    reserved: Decimal
    committed: Decimal
    released: Decimal
    measured: Decimal | None
    cost_known: bool
    unbilled_overrun: Decimal

    @property
    def outstanding(self) -> Decimal:
        """Authority still held by this reservation (non-zero only when RESERVED)."""
        return self.reserved if self.state == STATE_RESERVED else ZERO

    def as_dict(self) -> dict:
        return {
            "reservationId": self.reservation_id,
            "workerId": self.worker_id,
            "state": self.state,
            "reservedUsd": str(self.reserved),
            "committedUsd": str(self.committed),
            "releasedUsd": str(self.released),
            "measuredUsd": None if self.measured is None else str(self.measured),
            "costKnown": self.cost_known,
            "unbilledOverrunUsd": str(self.unbilled_overrun),
        }


class GlobalRunBudget:
    """Hard global spend authority shared by every worker in one run.

    Integration API (intentionally small, all thread-safe):
    ``reserve``, ``settle``, ``settle_unknown``, ``release``, ``get``,
    ``reservations``, ``reserved_for_worker``, ``snapshot`` and the
    ``cap``/``committed``/``outstanding``/``remaining``/``breached`` properties.
    """

    def __init__(self, cap_usd):
        self._lock = threading.RLock()
        self._cap = _amount(cap_usd, "BUDGET_CAP_INVALID", "global run cap must be a finite non-negative number")
        self._committed = ZERO
        self._outstanding = ZERO
        self._records: dict[str, Reservation] = {}
        self._breach_reason: str | None = None

    # ---- read-only views -------------------------------------------------
    @property
    def cap(self) -> Decimal:
        return self._cap

    @property
    def committed(self) -> Decimal:
        with self._lock:return self._committed

    @property
    def outstanding(self) -> Decimal:
        with self._lock:return self._outstanding

    @property
    def remaining(self) -> Decimal:
        with self._lock:return self._remaining_locked()

    @property
    def breached(self) -> bool:
        with self._lock:return self._breach_reason is not None

    @property
    def breach_reason(self) -> str | None:
        with self._lock:return self._breach_reason

    def get(self, reservation_id) -> Reservation | None:
        rid = _identifier(reservation_id, "reservationId")
        with self._lock:return self._records.get(rid)

    def reservations(self) -> tuple[Reservation, ...]:
        with self._lock:return tuple(self._records.values())

    def reserved_for_worker(self, worker_id) -> Decimal:
        wid = _identifier(worker_id, "workerId")
        with self._lock:
            return sum((r.outstanding for r in self._records.values() if r.worker_id == wid), ZERO)

    def snapshot(self) -> dict:
        """JSON-ready aggregate state; amounts are exact decimal strings."""
        with self._lock:
            return {
                "capUsd": str(self._cap),
                "committedUsd": str(self._committed),
                "outstandingUsd": str(self._outstanding),
                "remainingUsd": str(self._remaining_locked()),
                "reservationCount": len(self._records),
                "outstandingCount": sum(1 for r in self._records.values() if r.state == STATE_RESERVED),
                "breached": self._breach_reason is not None,
                "breachReason": self._breach_reason,
            }

    # ---- authority transitions -------------------------------------------
    def reserve(self, reservation_id, amount_usd, worker_id=None) -> Reservation:
        """Grant ``amount_usd`` of global authority to ``reservation_id``.

        Raises ``BUDGET_EXCEEDED`` when the request would exceed the remaining
        global authority, and consumes nothing when it does.
        """
        rid = _identifier(reservation_id, "reservationId")
        wid = None if worker_id is None else _identifier(worker_id, "workerId")
        amount = _amount(amount_usd, "BUDGET_INVALID", "reservation amount must be a finite non-negative number")
        with self._lock:
            existing = self._records.get(rid)
            if existing is not None:
                if existing.state == STATE_RESERVED and existing.reserved == amount and existing.worker_id == wid:
                    return existing
                raise RunBudgetError("RESERVATION_CONFLICT",
                                     f"reservation {rid} already exists in state {existing.state}")
            if self._breach_reason is not None:
                raise RunBudgetError("BUDGET_BREACHED", self._breach_reason)
            remaining = self._remaining_locked()
            if amount > remaining:
                raise RunBudgetError("BUDGET_EXCEEDED",
                                     f"reservation {amount} exceeds remaining global authority {remaining}")
            record = Reservation(rid, wid, STATE_RESERVED, amount, ZERO, ZERO, None, True, ZERO)
            self._records[rid] = record
            self._outstanding += amount
            self._check_locked()
            return record

    def settle(self, reservation_id, measured_cost_usd) -> Reservation:
        """Close a reservation with a measured cost, releasing only the unused part.

        A non-numeric/unknown cost is rejected and leaves the reservation
        ``RESERVED``. A measured cost above the reserved amount commits the full
        reserved amount, latches the budget as breached and raises
        ``SETTLEMENT_EXCEEDS_RESERVATION``.
        """
        rid = _identifier(reservation_id, "reservationId")
        measured = _amount(measured_cost_usd, "BUDGET_INVALID", "measured cost must be a finite non-negative number")
        with self._lock:
            record = self._require_locked(rid)
            if record.state == STATE_SETTLED:
                if record.cost_known and record.measured == measured:return record
                raise RunBudgetError("RESERVATION_CONFLICT",
                                     f"reservation {rid} already settled with a different cost")
            if record.state != STATE_RESERVED:
                raise RunBudgetError("RESERVATION_CONFLICT",
                                     f"reservation {rid} cannot be settled from state {record.state}")
            if measured > record.reserved:
                reason = (f"reservation {rid} measured {measured} exceeds reserved authority {record.reserved}")
                updated = replace(record, state=STATE_OVERRUN, committed=record.reserved, released=ZERO,
                                  measured=measured, cost_known=True, unbilled_overrun=measured - record.reserved)
                self._apply_locked(updated, record.reserved)
                self._breach_reason = reason
                raise RunBudgetError("SETTLEMENT_EXCEEDS_RESERVATION", reason)
            updated = replace(record, state=STATE_SETTLED, committed=measured,
                              released=record.reserved - measured, measured=measured, cost_known=True)
            self._apply_locked(updated, measured)
            return updated

    def settle_unknown(self, reservation_id) -> Reservation:
        """Close a reservation whose real cost is unknown by committing all of it."""
        rid = _identifier(reservation_id, "reservationId")
        with self._lock:
            record = self._require_locked(rid)
            if record.state == STATE_SETTLED:
                if not record.cost_known:return record
                raise RunBudgetError("RESERVATION_CONFLICT",
                                     f"reservation {rid} already settled with a measured cost")
            if record.state != STATE_RESERVED:
                raise RunBudgetError("RESERVATION_CONFLICT",
                                     f"reservation {rid} cannot be settled from state {record.state}")
            updated = replace(record, state=STATE_SETTLED, committed=record.reserved, released=ZERO,
                              measured=None, cost_known=False)
            self._apply_locked(updated, record.reserved)
            return updated

    def release(self, reservation_id) -> Reservation:
        """Cancel a reservation, returning only its unused authority to the pool."""
        rid = _identifier(reservation_id, "reservationId")
        with self._lock:
            record = self._require_locked(rid)
            if record.state == STATE_RELEASED:return record
            if record.state != STATE_RESERVED:
                raise RunBudgetError("RESERVATION_CONFLICT",
                                     f"reservation {rid} cannot be released from state {record.state}")
            updated = replace(record, state=STATE_RELEASED, committed=ZERO, released=record.reserved,
                              measured=None, cost_known=True)
            self._apply_locked(updated, ZERO)
            return updated

    # ---- internals -------------------------------------------------------
    def _remaining_locked(self) -> Decimal:
        return self._cap - self._committed - self._outstanding

    def _require_locked(self, rid) -> Reservation:
        record = self._records.get(rid)
        if record is None:raise RunBudgetError("RESERVATION_UNKNOWN", f"reservation {rid} is unknown")
        return record

    def _apply_locked(self, updated, commit_amount):
        """Move ``updated.reserved`` out of outstanding, committing ``commit_amount``."""
        previous = self._records[updated.reservation_id]
        self._records[updated.reservation_id] = updated
        self._outstanding -= previous.reserved
        self._committed += commit_amount
        self._check_locked()

    def _check_locked(self):
        if self._committed < 0 or self._outstanding < 0 or self._committed + self._outstanding > self._cap:
            reason = (f"global budget invariant violated: committed={self._committed} "
                      f"outstanding={self._outstanding} cap={self._cap}")
            self._breach_reason = reason
            raise RunBudgetError("BUDGET_STATE_INVALID", reason)
