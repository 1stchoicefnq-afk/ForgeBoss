from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ALLOWED_STATES = {"in_progress", "completed"}


class IdempotencyError(RuntimeError):
    code = "IDEMPOTENCY_ERROR"


class IdempotencyKeyError(IdempotencyError):
    code = "IDEMPOTENCY_KEY_INVALID"


class IdempotencyConflict(IdempotencyError):
    code = "IDEMPOTENCY_CONFLICT"


class IdempotencyInProgress(IdempotencyError):
    code = "IDEMPOTENCY_IN_PROGRESS"


class IdempotencyStateError(IdempotencyError):
    code = "IDEMPOTENCY_STATE_INVALID"


@dataclass(frozen=True)
class IdempotencyReservation:
    key: str
    request_digest: str
    replay: bool
    result: Any = None


def validate_idempotency_key(value: object) -> str:
    if not isinstance(value, str):
        raise IdempotencyKeyError("idempotency key must be a string")
    if not _KEY_RE.fullmatch(value):
        raise IdempotencyKeyError(
            "idempotency key must be 1..128 characters using letters, digits, '.', '_', ':', or '-'"
        )
    return value


def _strict_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise IdempotencyStateError("idempotency material must be strict JSON") from exc


def request_digest(method: object, params: object) -> str:
    if not isinstance(method, str) or not method:
        raise IdempotencyStateError("method must be a non-empty string")
    if not isinstance(params, dict):
        raise IdempotencyStateError("params must be an object")
    material = _strict_json({"method": method, "params": params})
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def install_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS idempotency_operations(
          idempotency_key TEXT PRIMARY KEY,
          request_digest TEXT NOT NULL,
          state TEXT NOT NULL,
          result_json TEXT,
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL
        )
        """
    )


def _validate_digest(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise IdempotencyStateError("request digest must be a 64-character sha256 hex string")
    try:
        int(value, 16)
    except ValueError as exc:
        raise IdempotencyStateError("request digest must be sha256 hex") from exc
    return value.lower()


def reserve(conn: sqlite3.Connection, key: object, digest: object, *, now: float | None = None) -> IdempotencyReservation:
    key = validate_idempotency_key(key)
    digest = _validate_digest(digest)
    now = time.time() if now is None else float(now)
    if not (now == now and abs(now) != float("inf")):
        raise IdempotencyStateError("reservation time must be finite")

    row = conn.execute(
        "SELECT request_digest,state,result_json FROM idempotency_operations WHERE idempotency_key=?",
        (key,),
    ).fetchone()
    if row is None:
        conn.execute(
            """
            INSERT INTO idempotency_operations(
              idempotency_key,request_digest,state,result_json,created_at,updated_at
            ) VALUES(?,?,'in_progress',NULL,?,?)
            """,
            (key, digest, now, now),
        )
        return IdempotencyReservation(key, digest, False, None)

    existing_digest, state, result_json = row
    existing_digest = _validate_digest(existing_digest)
    if existing_digest != digest:
        raise IdempotencyConflict("idempotency key reused with different request")
    if state not in _ALLOWED_STATES:
        raise IdempotencyStateError(f"unknown idempotency state: {state!r}")
    if state == "in_progress":
        raise IdempotencyInProgress("matching idempotent mutation is already in progress")
    if result_json is None:
        raise IdempotencyStateError("completed idempotency operation is missing result")
    try:
        result = json.loads(result_json)
    except Exception as exc:
        raise IdempotencyStateError("completed idempotency result is invalid JSON") from exc
    return IdempotencyReservation(key, digest, True, result)


def complete(
    conn: sqlite3.Connection,
    key: object,
    digest: object,
    result: object,
    *,
    now: float | None = None,
) -> None:
    key = validate_idempotency_key(key)
    digest = _validate_digest(digest)
    result_json = _strict_json(result)
    now = time.time() if now is None else float(now)
    if not (now == now and abs(now) != float("inf")):
        raise IdempotencyStateError("completion time must be finite")

    cur = conn.execute(
        """
        UPDATE idempotency_operations
        SET state='completed',result_json=?,updated_at=?
        WHERE idempotency_key=? AND request_digest=? AND state='in_progress'
        """,
        (result_json, now, key, digest),
    )
    if cur.rowcount != 1:
        row = conn.execute(
            "SELECT request_digest,state FROM idempotency_operations WHERE idempotency_key=?",
            (key,),
        ).fetchone()
        if row is None:
            raise IdempotencyStateError("idempotency reservation does not exist")
        existing_digest, state = row
        existing_digest = _validate_digest(existing_digest)
        if existing_digest != digest:
            raise IdempotencyConflict("idempotency completion digest mismatch")
        if state == "completed":
            raise IdempotencyStateError("idempotency operation is already completed")
        raise IdempotencyStateError(f"cannot complete idempotency state {state!r}")
