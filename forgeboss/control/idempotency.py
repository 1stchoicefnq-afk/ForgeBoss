from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_STATES = {"in_progress", "completed"}
_REDACTED = "[REDACTED]"
_SENSITIVE_KEYS = {
    "token", "accesstoken", "refreshtoken", "bearertoken", "authtoken",
    "secret", "clientsecret", "apisecret", "apikey", "password", "passwd",
    "credential", "credentials", "privatekey", "signingkey", "sessionkey",
    "authproof", "authorization",
}


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
    principal_id: str
    operation: str
    key: str
    request_digest: str
    replay: bool
    result: Any = None


def _identity(value: object, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise IdempotencyStateError(
            f"{name} must be 1..128 canonical characters using letters, digits, '.', '_', ':', or '-'"
        )
    return value


def validate_idempotency_key(value: object) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise IdempotencyKeyError(
            "idempotency key must be 1..128 canonical characters using letters, digits, '.', '_', ':', or '-'"
        )
    return value


def _reject_constant(value: str):
    raise IdempotencyStateError(f"non-finite JSON constant rejected: {value}")


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise IdempotencyStateError(f"duplicate JSON key rejected: {key}")
        out[key] = value
    return out


def _strict_json(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise IdempotencyStateError("idempotency material must be strict JSON") from exc


def _strict_loads(value: object) -> Any:
    if not isinstance(value, str) or not value:
        raise IdempotencyStateError("completed idempotency result is missing or invalid")
    try:
        return json.loads(value, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except IdempotencyStateError:
        raise
    except Exception as exc:
        raise IdempotencyStateError("completed idempotency result is invalid JSON") from exc


def request_digest(operation: object, params: object) -> str:
    operation = _identity(operation, "operation")
    if not isinstance(params, dict):
        raise IdempotencyStateError("params must be an object")
    material = _strict_json({"operation": operation, "params": params})
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def install_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS idempotency_operations(
          principal_id TEXT NOT NULL,
          operation TEXT NOT NULL,
          idempotency_key TEXT NOT NULL,
          request_digest TEXT NOT NULL,
          state TEXT NOT NULL,
          result_json TEXT,
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL,
          PRIMARY KEY(principal_id, operation, idempotency_key)
        )
        """
    )


def _validate_digest(value: object) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise IdempotencyStateError("request digest must be canonical lowercase sha256 hex")
    return value


def _finite_time(value: object, name: str) -> float:
    if isinstance(value, bool):
        raise IdempotencyStateError(f"{name} must be finite")
    try:
        current = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise IdempotencyStateError(f"{name} must be finite") from exc
    if not math.isfinite(current):
        raise IdempotencyStateError(f"{name} must be finite")
    return current


def _sensitive_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
    return normalized in _SENSITIVE_KEYS or normalized.endswith("token") or normalized.endswith("secret")


def _replay_safe(value: object) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise IdempotencyStateError("result contains non-finite number")
        return value
    if isinstance(value, list):
        return [_replay_safe(item) for item in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise IdempotencyStateError("result object keys must be strings")
            out[key] = _REDACTED if _sensitive_key(key) else _replay_safe(item)
        return out
    raise IdempotencyStateError("result contains unsupported replay value")


def _validate_persisted_safe(value: object) -> None:
    if value is None or isinstance(value, (str, int, bool)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise IdempotencyStateError("persisted result contains non-finite number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_persisted_safe(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IdempotencyStateError("persisted result object key invalid")
            if _sensitive_key(key) and item != _REDACTED:
                raise IdempotencyStateError("persisted result contains protected secret/token material")
            _validate_persisted_safe(item)
        return
    raise IdempotencyStateError("persisted result contains unsupported replay value")


def _read_existing(conn, principal_id, operation, key):
    return conn.execute(
        """SELECT request_digest,state,result_json FROM idempotency_operations
        WHERE principal_id=? AND operation=? AND idempotency_key=?""",
        (principal_id, operation, key),
    ).fetchone()


def reserve(conn: sqlite3.Connection, principal_id: object, operation: object, key: object, digest: object, *, now: float | None = None) -> IdempotencyReservation:
    principal_id = _identity(principal_id, "principalId")
    operation = _identity(operation, "operation")
    key = validate_idempotency_key(key)
    digest = _validate_digest(digest)
    current = _finite_time(time.time() if now is None else now, "reservation time")
    row = _read_existing(conn, principal_id, operation, key)
    if row is None:
        try:
            conn.execute(
                """INSERT INTO idempotency_operations(
                principal_id,operation,idempotency_key,request_digest,state,result_json,created_at,updated_at
                ) VALUES(?,?,?,?,'in_progress',NULL,?,?)""",
                (principal_id, operation, key, digest, current, current),
            )
            return IdempotencyReservation(principal_id, operation, key, digest, False, None)
        except sqlite3.IntegrityError:
            row = _read_existing(conn, principal_id, operation, key)
            if row is None:
                raise
    existing_digest, state, result_json = row
    existing_digest = _validate_digest(existing_digest)
    if existing_digest != digest:
        raise IdempotencyConflict("idempotency identity reused with different request")
    if state not in _ALLOWED_STATES:
        raise IdempotencyStateError(f"unknown idempotency state: {state!r}")
    if state == "in_progress":
        raise IdempotencyInProgress("matching idempotent mutation is already in progress")
    result = _strict_loads(result_json)
    _validate_persisted_safe(result)
    return IdempotencyReservation(principal_id, operation, key, digest, True, result)


def complete(conn: sqlite3.Connection, principal_id: object, operation: object, key: object, digest: object, result: object, *, now: float | None = None) -> None:
    principal_id = _identity(principal_id, "principalId")
    operation = _identity(operation, "operation")
    key = validate_idempotency_key(key)
    digest = _validate_digest(digest)
    result_json = _strict_json(_replay_safe(result))
    current = _finite_time(time.time() if now is None else now, "completion time")
    cur = conn.execute(
        """UPDATE idempotency_operations SET state='completed',result_json=?,updated_at=?
        WHERE principal_id=? AND operation=? AND idempotency_key=? AND request_digest=? AND state='in_progress'""",
        (result_json, current, principal_id, operation, key, digest),
    )
    if cur.rowcount == 1:
        return
    row = _read_existing(conn, principal_id, operation, key)
    if row is None:
        raise IdempotencyStateError("idempotency reservation does not exist")
    existing_digest, state, _ = row
    existing_digest = _validate_digest(existing_digest)
    if existing_digest != digest:
        raise IdempotencyConflict("idempotency completion digest mismatch")
    if state == "completed":
        raise IdempotencyStateError("idempotency operation is already completed")
    if state not in _ALLOWED_STATES:
        raise IdempotencyStateError(f"unknown idempotency state: {state!r}")
    raise IdempotencyStateError(f"cannot complete idempotency state {state!r}")
