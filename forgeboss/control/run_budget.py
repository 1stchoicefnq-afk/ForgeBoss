from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from typing import Callable

MAX_IDENTIFIER_BYTES = 256
ZERO = Decimal(0)

STATE_RESERVED = "RESERVED"
STATE_PAID_STARTED = "PAID_STARTED"
STATE_SETTLED = "SETTLED"
STATE_RELEASED = "RELEASED"
STATE_FAILED = "FAILED"
STATE_CANCELLED = "CANCELLED"
STATE_UNKNOWN = "UNKNOWN"
TERMINAL_STATES = frozenset({STATE_SETTLED, STATE_RELEASED, STATE_FAILED, STATE_CANCELLED, STATE_UNKNOWN})


class RunBudgetError(RuntimeError):
    def __init__(self, code: str, message: str, *, state: str | None = None):
        super().__init__(message)
        self.code = code
        self.state = state


def _amount(value, code="BUDGET_INVALID", message="amount must be finite and non-negative") -> Decimal:
    if isinstance(value, bool):
        raise RunBudgetError(code, message)
    if isinstance(value, str) and (value.strip() != value or "_" in value or value == ""):
        raise RunBudgetError(code, message)
    if not isinstance(value, (int, float, str, Decimal)):
        raise RunBudgetError(code, message)
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as ex:
        raise RunBudgetError(code, message) from ex
    if not result.is_finite() or result < 0:
        raise RunBudgetError(code, message)
    try:
        as_float = float(result)
    except (OverflowError, ValueError) as ex:
        raise RunBudgetError(code, message) from ex
    if not math.isfinite(as_float):
        raise RunBudgetError(code, message)
    return result


def _identifier(value, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise RunBudgetError("IDENTIFIER_INVALID", f"{field} must be a non-empty trimmed string")
    if len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
        raise RunBudgetError("IDENTIFIER_INVALID", f"{field} is too long")
    return value


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Reservation:
    reservation_id: str
    worker_id: str | None
    state: str
    reserved: Decimal
    committed: Decimal = ZERO
    measured: Decimal | None = None
    cost_known: bool = True
    authority_token_sha256: str | None = None
    reason: str | None = None

    @property
    def outstanding(self) -> Decimal:
        return self.reserved if self.state in {STATE_RESERVED, STATE_PAID_STARTED} else ZERO

    def as_dict(self) -> dict:
        return {
            "reservationId": self.reservation_id,
            "workerId": self.worker_id,
            "state": self.state,
            "reservedUsd": str(self.reserved),
            "committedUsd": str(self.committed),
            "measuredUsd": None if self.measured is None else str(self.measured),
            "costKnown": self.cost_known,
            "authorityTokenSha256": self.authority_token_sha256,
            "reason": self.reason,
        }


class GlobalRunBudget:
    """In-process hard global paid-work authority for one ForgeBoss run.

    A reservation MUST transition through start_paid() before paid execution.
    release() is only legal before paid execution. Once paid work starts, every
    terminal path records cost (or conservatively records the reservation when
    cost is unknown). New paid work is latched off after an overrun/unknown
    authority condition, but already-started work may still be truthfully settled.
    """

    def __init__(self, cap_usd, *, journal: Callable[[dict], None] | None = None):
        self._lock = threading.RLock()
        self._cap = _amount(cap_usd, "BUDGET_CAP_INVALID", "global cap must be finite and non-negative")
        self._records: dict[str, Reservation] = {}
        self._latched = False
        self._latch_reason: str | None = None
        self._journal = journal

    @property
    def cap(self) -> Decimal:
        return self._cap

    @property
    def latched(self) -> bool:
        with self._lock:
            return self._latched

    @property
    def latch_reason(self) -> str | None:
        with self._lock:
            return self._latch_reason

    @property
    def committed(self) -> Decimal:
        with self._lock:
            return sum((r.committed for r in self._records.values()), ZERO)

    @property
    def outstanding(self) -> Decimal:
        with self._lock:
            return sum((r.outstanding for r in self._records.values()), ZERO)

    @property
    def remaining(self) -> Decimal:
        with self._lock:
            value = self._cap - self.committed - self.outstanding
            return value if value > ZERO else ZERO

    def get(self, reservation_id) -> Reservation | None:
        rid = _identifier(reservation_id, "reservationId")
        with self._lock:
            return self._records.get(rid)

    def reservations(self) -> tuple[Reservation, ...]:
        with self._lock:
            return tuple(self._records.values())

    def reserve(self, reservation_id, amount_usd, worker_id=None) -> Reservation:
        rid = _identifier(reservation_id, "reservationId")
        wid = None if worker_id is None else _identifier(worker_id, "workerId")
        amount = _amount(amount_usd)
        with self._lock:
            existing = self._records.get(rid)
            if existing is not None:
                if existing.state == STATE_RESERVED and existing.reserved == amount and existing.worker_id == wid:
                    return existing
                raise RunBudgetError("RESERVATION_CONFLICT", f"reservation {rid} already exists", state=existing.state)
            if self._latched:
                raise RunBudgetError("BUDGET_LATCHED", self._latch_reason or "budget is latched")
            if amount > self.remaining:
                raise RunBudgetError("BUDGET_EXCEEDED", f"reservation {amount} exceeds remaining {self.remaining}")
            record = Reservation(rid, wid, STATE_RESERVED, amount)
            self._transition(None, record, "reserve")
            return record

    def start_paid(self, reservation_id) -> tuple[Reservation, str]:
        rid = _identifier(reservation_id, "reservationId")
        with self._lock:
            current = self._require(rid)
            if current.state == STATE_PAID_STARTED:
                raise RunBudgetError("PAID_WORK_ALREADY_STARTED", "paid work already started", state=current.state)
            if current.state != STATE_RESERVED:
                raise RunBudgetError("RESERVATION_CONFLICT", "paid work cannot start from this state", state=current.state)
            if self._latched:
                raise RunBudgetError("BUDGET_LATCHED", self._latch_reason or "budget is latched")
            token = secrets.token_urlsafe(32)
            updated = replace(current, state=STATE_PAID_STARTED, authority_token_sha256=_token_digest(token))
            self._transition(current, updated, "start_paid")
            return updated, token

    def release(self, reservation_id) -> Reservation:
        rid = _identifier(reservation_id, "reservationId")
        with self._lock:
            current = self._require(rid)
            if current.state == STATE_RELEASED:
                return current
            if current.state == STATE_PAID_STARTED:
                raise RunBudgetError("PAID_WORK_STARTED", "cannot refund authority after paid work starts", state=current.state)
            if current.state != STATE_RESERVED:
                raise RunBudgetError("RESERVATION_CONFLICT", "reservation cannot be released", state=current.state)
            updated = replace(current, state=STATE_RELEASED, committed=ZERO, reason="released-before-paid-start")
            self._transition(current, updated, "release")
            return updated

    def settle(self, reservation_id, actual_usd, *, authority_token=None) -> Reservation:
        return self._finish(reservation_id, STATE_SETTLED, actual_usd, authority_token=authority_token, reason="settled")

    def fail(self, reservation_id, actual_usd=None, *, authority_token=None) -> Reservation:
        if actual_usd is None:
            return self._finish_unknown(reservation_id, STATE_FAILED, authority_token=authority_token, reason="failed-cost-unknown")
        return self._finish(reservation_id, STATE_FAILED, actual_usd, authority_token=authority_token, reason="failed")

    def cancel(self, reservation_id, actual_usd=None, *, authority_token=None) -> Reservation:
        rid = _identifier(reservation_id, "reservationId")
        with self._lock:
            current = self._require(rid)
            if current.state == STATE_RESERVED:
                updated = replace(current, state=STATE_CANCELLED, committed=ZERO, reason="cancelled-before-paid-start")
                self._transition(current, updated, "cancel")
                return updated
        if actual_usd is None:
            return self._finish_unknown(rid, STATE_CANCELLED, authority_token=authority_token, reason="cancelled-cost-unknown")
        return self._finish(rid, STATE_CANCELLED, actual_usd, authority_token=authority_token, reason="cancelled")

    def settle_unknown(self, reservation_id, *, authority_token=None) -> Reservation:
        return self._finish_unknown(reservation_id, STATE_UNKNOWN, authority_token=authority_token, reason="settled-cost-unknown")

    def latch(self, reason: str) -> None:
        if not isinstance(reason, str) or not reason.strip():
            raise RunBudgetError("LATCH_REASON_INVALID", "latch reason required")
        with self._lock:
            self._emit({"op": "latch", "reason": reason})
            self._latched = True
            self._latch_reason = reason

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "schema": 1,
                "capUsd": str(self._cap),
                "latched": self._latched,
                "latchReason": self._latch_reason,
                "records": [r.as_dict() for r in self._records.values()],
            }

    @classmethod
    def from_snapshot(cls, snapshot: dict, *, journal=None) -> "GlobalRunBudget":
        if not isinstance(snapshot, dict) or snapshot.get("schema") != 1:
            raise RunBudgetError("SNAPSHOT_INVALID", "unsupported snapshot")
        obj = cls(snapshot.get("capUsd"), journal=journal)
        records = snapshot.get("records")
        if not isinstance(records, list):
            raise RunBudgetError("SNAPSHOT_INVALID", "records must be a list")
        seen = set()
        for item in records:
            if not isinstance(item, dict):
                raise RunBudgetError("SNAPSHOT_INVALID", "record must be an object")
            rid = _identifier(item.get("reservationId"), "reservationId")
            if rid in seen:
                raise RunBudgetError("SNAPSHOT_INVALID", "duplicate reservation")
            seen.add(rid)
            state = item.get("state")
            if state not in {STATE_RESERVED, STATE_PAID_STARTED, *TERMINAL_STATES}:
                raise RunBudgetError("SNAPSHOT_INVALID", "invalid state")
            reserved = _amount(item.get("reservedUsd"), "SNAPSHOT_INVALID", "invalid reserved amount")
            committed = _amount(item.get("committedUsd"), "SNAPSHOT_INVALID", "invalid committed amount")
            measured_raw = item.get("measuredUsd")
            measured = None if measured_raw is None else _amount(measured_raw, "SNAPSHOT_INVALID", "invalid measured amount")
            if state in {STATE_RESERVED, STATE_PAID_STARTED} and committed != ZERO:
                raise RunBudgetError("SNAPSHOT_INVALID", "open reservation cannot be committed")
            if state == STATE_PAID_STARTED and not item.get("authorityTokenSha256"):
                raise RunBudgetError("SNAPSHOT_INVALID", "paid-started record missing authority digest")
            cost_known = bool(item.get("costKnown", True))
            token_digest = item.get("authorityTokenSha256")
            if token_digest is not None and (not isinstance(token_digest, str) or len(token_digest) != 64):
                raise RunBudgetError("SNAPSHOT_INVALID", "invalid authority token digest")
            if state == STATE_RELEASED and (committed != ZERO or measured is not None):
                raise RunBudgetError("SNAPSHOT_INVALID", "released record cannot contain spend")
            if state in {STATE_SETTLED, STATE_FAILED, STATE_CANCELLED} and cost_known and measured is None:
                raise RunBudgetError("SNAPSHOT_INVALID", "known-cost terminal missing measured cost")
            if state == STATE_UNKNOWN and (cost_known or measured is not None or committed != reserved):
                raise RunBudgetError("SNAPSHOT_INVALID", "unknown-cost terminal is inconsistent")
            if not cost_known and state != STATE_UNKNOWN and not (state in {STATE_FAILED, STATE_CANCELLED} and measured is None and committed == reserved):
                raise RunBudgetError("SNAPSHOT_INVALID", "unknown cost state is inconsistent")
            rec = Reservation(
                rid,
                None if item.get("workerId") is None else _identifier(item.get("workerId"), "workerId"),
                state,
                reserved,
                committed,
                measured,
                cost_known,
                token_digest,
                item.get("reason"),
            )
            obj._records[rid] = rec
        individual_overrun = any(r.measured is not None and r.measured > r.reserved for r in obj._records.values())
        if (obj.committed + obj.outstanding > obj.cap or individual_overrun) and not snapshot.get("latched"):
            raise RunBudgetError("SNAPSHOT_INVALID", "unlatched snapshot contains exceeded authority")
        obj._latched = bool(snapshot.get("latched"))
        obj._latch_reason = snapshot.get("latchReason")
        if obj._latched and (not isinstance(obj._latch_reason, str) or not obj._latch_reason):
            raise RunBudgetError("SNAPSHOT_INVALID", "latched snapshot missing reason")
        return obj

    def _require(self, rid: str) -> Reservation:
        current = self._records.get(rid)
        if current is None:
            raise RunBudgetError("RESERVATION_UNKNOWN", f"reservation {rid} is unknown")
        return current

    def _verify_authority_token(self, current: Reservation, token) -> None:
        digest = current.authority_token_sha256
        if not isinstance(digest, str) or len(digest) != 64:
            raise RunBudgetError("AUTHORITY_TOKEN_INVALID", "paid authority token is unavailable", state=current.state)
        if not isinstance(token, str) or not token:
            raise RunBudgetError("AUTHORITY_TOKEN_INVALID", "paid authority token required", state=current.state)
        if not hmac.compare_digest(_token_digest(token), digest):
            raise RunBudgetError("AUTHORITY_TOKEN_INVALID", "paid authority token invalid", state=current.state)

    def _verify_token(self, current: Reservation, token) -> None:
        if current.state != STATE_PAID_STARTED:
            raise RunBudgetError("PAID_WORK_NOT_STARTED", "paid work has not started", state=current.state)
        self._verify_authority_token(current, token)

    def _finish(self, reservation_id, terminal_state, actual_usd, *, authority_token, reason) -> Reservation:
        rid = _identifier(reservation_id, "reservationId")
        actual = _amount(actual_usd)
        with self._lock:
            current = self._require(rid)
            if current.state == terminal_state and current.cost_known and current.measured == actual:
                self._verify_authority_token(current, authority_token)
                return current
            self._verify_token(current, authority_token)
            updated = replace(current, state=terminal_state, committed=actual, measured=actual, cost_known=True, reason=reason)
            projected_committed = sum((r.committed for k, r in self._records.items() if k != rid), ZERO) + actual
            projected_outstanding = sum((r.outstanding for k, r in self._records.items() if k != rid), ZERO)
            latch_reason = None
            if actual > current.reserved:
                latch_reason = "reservation-overrun"
            elif projected_committed + projected_outstanding > self._cap:
                latch_reason = "cap-exceeded"
            event = {"op": "finish", "reservationId": rid, "from": current.state, "to": terminal_state, "actualUsd": str(actual), "latchReason": latch_reason}
            self._emit(event)
            self._records[rid] = updated
            if latch_reason is not None:
                self._latched = True
                self._latch_reason = latch_reason
            return updated

    def _finish_unknown(self, reservation_id, terminal_state, *, authority_token, reason) -> Reservation:
        rid = _identifier(reservation_id, "reservationId")
        with self._lock:
            current = self._require(rid)
            if current.state == terminal_state and not current.cost_known:
                self._verify_authority_token(current, authority_token)
                return current
            self._verify_token(current, authority_token)
            updated = replace(current, state=terminal_state, committed=current.reserved, measured=None, cost_known=False, reason=reason)
            event = {"op": "finish_unknown", "reservationId": rid, "from": current.state, "to": terminal_state, "reservedUsd": str(current.reserved), "latchReason": "unknown-cost"}
            self._emit(event)
            self._records[rid] = updated
            self._latched = True
            self._latch_reason = "unknown-cost"
            return updated

    def _transition(self, old: Reservation | None, new: Reservation, op: str) -> None:
        event = {
            "op": op,
            "reservationId": new.reservation_id,
            "from": None if old is None else old.state,
            "to": new.state,
            "reservedUsd": str(new.reserved),
        }
        self._emit(event)
        self._records[new.reservation_id] = new

    def _emit(self, event: dict) -> None:
        if self._journal is not None:
            self._journal(dict(event))