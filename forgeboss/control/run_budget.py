from __future__ import annotations

import math
import re
import sqlite3
import time
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class RunBudgetError(RuntimeError):
    code = "RUN_BUDGET_ERROR"


class RunBudgetInputError(RunBudgetError):
    code = "RUN_BUDGET_INPUT_INVALID"


class RunBudgetStateError(RunBudgetError):
    code = "RUN_BUDGET_STATE_INVALID"


class RunBudgetExceeded(RunBudgetError):
    code = "RUN_BUDGET_EXCEEDED"


class RunBudgetConflict(RunBudgetError):
    code = "RUN_BUDGET_CONFLICT"


@dataclass(frozen=True)
class RunBudgetSnapshot:
    run_id: str
    controller_identity: str
    cap_usd: str
    reserved_usd: str


def _opaque_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise RunBudgetInputError(
            f"{name} must be 1..128 characters using letters, digits, '.', '_', ':', or '-'"
        )
    return value


def _amount(value: object, name: str) -> Decimal:
    if isinstance(value, bool):
        raise RunBudgetInputError(f"{name} must be a finite non-negative number")
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise RunBudgetInputError(f"{name} must be a finite non-negative number") from exc
    if not amount.is_finite() or amount < 0:
        raise RunBudgetInputError(f"{name} must be a finite non-negative number")
    return amount


def _canon(amount: Decimal) -> str:
    if not amount.is_finite() or amount < 0:
        raise RunBudgetStateError("stored run budget amount is invalid")
    value = format(amount.normalize(), "f")
    if "." in value:
        value = value.rstrip("0").rstrip(".")
    return value or "0"


def _stored_amount(value: object, name: str) -> Decimal:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise RunBudgetStateError(f"stored {name} is invalid") from exc
    if not amount.is_finite() or amount < 0:
        raise RunBudgetStateError(f"stored {name} is invalid")
    return amount


def _require_transaction(conn: sqlite3.Connection) -> None:
    if not conn.in_transaction:
        raise RunBudgetStateError("run-budget mutation requires caller transaction")


def _finite_time(value: float | None) -> float:
    now = time.time() if value is None else float(value)
    if not math.isfinite(now):
        raise RunBudgetInputError("timestamp must be finite")
    return now


def install_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS run_budgets(
          run_id TEXT PRIMARY KEY,
          controller_identity TEXT NOT NULL,
          cap_usd TEXT NOT NULL,
          reserved_usd TEXT NOT NULL,
          created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS run_budget_reservations(
          reservation_id TEXT PRIMARY KEY,
          run_id TEXT NOT NULL REFERENCES run_budgets(run_id),
          task_id TEXT NOT NULL,
          worker_id TEXT NOT NULL,
          amount_usd TEXT NOT NULL,
          created_at REAL NOT NULL
        );
        """
    )


def create_run_budget(
    conn: sqlite3.Connection,
    run_id: object,
    controller_identity: object,
    cap_usd: object,
    *,
    now: float | None = None,
) -> RunBudgetSnapshot:
    _require_transaction(conn)
    run_id = _opaque_id(run_id, "run_id")
    controller_identity = _opaque_id(controller_identity, "controller_identity")
    cap = _amount(cap_usd, "cap_usd")
    now = _finite_time(now)

    row = conn.execute(
        "SELECT controller_identity,cap_usd,reserved_usd FROM run_budgets WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if row is not None:
        existing_identity, existing_cap, reserved = row
        existing_cap_dec = _stored_amount(existing_cap, "cap_usd")
        reserved_dec = _stored_amount(reserved, "reserved_usd")
        if existing_identity != controller_identity or existing_cap_dec != cap:
            raise RunBudgetConflict("run budget already exists with different authority")
        return RunBudgetSnapshot(run_id, existing_identity, _canon(existing_cap_dec), _canon(reserved_dec))

    conn.execute(
        """
        INSERT INTO run_budgets(run_id,controller_identity,cap_usd,reserved_usd,created_at)
        VALUES(?,?,?,?,?)
        """,
        (run_id, controller_identity, _canon(cap), "0", now),
    )
    return RunBudgetSnapshot(run_id, controller_identity, _canon(cap), "0")


def reserve(
    conn: sqlite3.Connection,
    run_id: object,
    controller_identity: object,
    reservation_id: object,
    task_id: object,
    worker_id: object,
    amount_usd: object,
    *,
    now: float | None = None,
) -> RunBudgetSnapshot:
    _require_transaction(conn)
    run_id = _opaque_id(run_id, "run_id")
    controller_identity = _opaque_id(controller_identity, "controller_identity")
    reservation_id = _opaque_id(reservation_id, "reservation_id")
    task_id = _opaque_id(task_id, "task_id")
    worker_id = _opaque_id(worker_id, "worker_id")
    amount = _amount(amount_usd, "amount_usd")
    now = _finite_time(now)

    budget = conn.execute(
        "SELECT controller_identity,cap_usd,reserved_usd FROM run_budgets WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if budget is None:
        raise RunBudgetStateError("run budget does not exist")
    stored_identity, cap_raw, reserved_raw = budget
    if stored_identity != controller_identity:
        raise RunBudgetConflict("controller identity does not own run budget")
    cap = _stored_amount(cap_raw, "cap_usd")
    reserved = _stored_amount(reserved_raw, "reserved_usd")
    if reserved > cap:
        raise RunBudgetStateError("run budget is already over-reserved")

    old = conn.execute(
        """
        SELECT run_id,task_id,worker_id,amount_usd
        FROM run_budget_reservations WHERE reservation_id=?
        """,
        (reservation_id,),
    ).fetchone()
    if old is not None:
        old_run, old_task, old_worker, old_amount_raw = old
        old_amount = _stored_amount(old_amount_raw, "reservation amount")
        if (
            old_run != run_id
            or old_task != task_id
            or old_worker != worker_id
            or old_amount != amount
        ):
            raise RunBudgetConflict("reservation id reused with different authority")
        return RunBudgetSnapshot(run_id, stored_identity, _canon(cap), _canon(reserved))

    new_reserved = reserved + amount
    if new_reserved > cap:
        raise RunBudgetExceeded(
            f"run reservation {_canon(amount)} exceeds remaining {_canon(cap - reserved)}"
        )

    conn.execute(
        """
        INSERT INTO run_budget_reservations(
          reservation_id,run_id,task_id,worker_id,amount_usd,created_at
        ) VALUES(?,?,?,?,?,?)
        """,
        (reservation_id, run_id, task_id, worker_id, _canon(amount), now),
    )
    cur = conn.execute(
        """
        UPDATE run_budgets SET reserved_usd=?
        WHERE run_id=? AND controller_identity=? AND reserved_usd=?
        """,
        (_canon(new_reserved), run_id, controller_identity, _canon(reserved)),
    )
    if cur.rowcount != 1:
        raise RunBudgetStateError("run budget authority changed during reservation")
    return RunBudgetSnapshot(run_id, stored_identity, _canon(cap), _canon(new_reserved))


def snapshot(conn: sqlite3.Connection, run_id: object) -> RunBudgetSnapshot:
    run_id = _opaque_id(run_id, "run_id")
    row = conn.execute(
        "SELECT controller_identity,cap_usd,reserved_usd FROM run_budgets WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if row is None:
        raise RunBudgetStateError("run budget does not exist")
    identity, cap_raw, reserved_raw = row
    cap = _stored_amount(cap_raw, "cap_usd")
    reserved = _stored_amount(reserved_raw, "reserved_usd")
    if reserved > cap:
        raise RunBudgetStateError("run budget is over-reserved")
    return RunBudgetSnapshot(run_id, identity, _canon(cap), _canon(reserved))
