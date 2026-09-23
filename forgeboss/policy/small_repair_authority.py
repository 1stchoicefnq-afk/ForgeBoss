from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
import time
from typing import Mapping, Sequence

from forgeboss.control.envelope import canonical
from forgeboss.policy.reuse_review import BuildReadiness, evaluate_build_readiness


class SmallRepairAuthorityError(RuntimeError):
    """Raised when a small-repair exemption is malformed, stale, or mismatched."""


TOKEN_SCHEMA = 1
TOKEN_TYPE = "small-repair-exemption"
MAX_TTL_SECONDS = 60 * 60
_GIT_OBJECT_ID = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO = re.compile(r"^[A-Za-z0-9._-]+$")
_TOKEN_KEYS = frozenset({
    "schema",
    "type",
    "taskId",
    "repository",
    "baseSha",
    "objectiveSha256",
    "allowedPaths",
    "issuedAt",
    "expiresAt",
    "signature",
})


@dataclass(frozen=True)
class VerifiedSmallRepairExemption:
    task_id: str
    repository: str
    base_sha: str
    objective_sha256: str
    allowed_paths: tuple[str, ...]
    issued_at: float
    expires_at: float


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise SmallRepairAuthorityError(f"{label} must be a string")
    clean = value.strip()
    if not clean:
        raise SmallRepairAuthorityError(f"{label} is required")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
        raise SmallRepairAuthorityError(f"{label} contains control characters")
    return clean


def _repository(value: object) -> str:
    raw = _text(value, "repository")
    if "://" in raw or raw.startswith(("git@", "\\\\", "//")) or ":" in raw or "\\" in raw:
        raise SmallRepairAuthorityError("repository must be owner/name")
    parts = raw.split("/")
    if len(parts) != 2:
        raise SmallRepairAuthorityError("repository must be owner/name")
    owner, name = parts
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(name):
        raise SmallRepairAuthorityError("repository must be owner/name")
    return f"{owner.casefold()}/{name.casefold()}"


def _base_sha(value: object) -> str:
    raw = _text(value, "baseSha")
    if not _GIT_OBJECT_ID.fullmatch(raw):
        raise SmallRepairAuthorityError("baseSha must be a 40- or 64-hex object id")
    return raw.lower()


def _objective_sha256(objective: object) -> str:
    if not isinstance(objective, str):
        raise SmallRepairAuthorityError("objective must be a string")
    if not objective:
        raise SmallRepairAuthorityError("objective is required")
    if "\x00" in objective:
        raise SmallRepairAuthorityError("objective contains NUL")
    encoded = objective.encode("utf-8")
    if len(encoded) > 128 * 1024:
        raise SmallRepairAuthorityError("objective is too large")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_path(value: object) -> str:
    raw = _text(value, "allowedPaths item").replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) or raw.startswith("//"):
        raise SmallRepairAuthorityError("allowedPaths must be repository-relative")
    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise SmallRepairAuthorityError("allowedPaths must not escape the repository")
        parts.append(part)
    if not parts:
        raise SmallRepairAuthorityError("allowedPaths contains an empty/root path")
    return "/".join(parts)


def _paths(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise SmallRepairAuthorityError("allowedPaths must be an array")
    out = tuple(sorted({_canonical_path(item) for item in value}))
    if not out:
        raise SmallRepairAuthorityError("allowedPaths must not be empty")
    return out


def _secret(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise SmallRepairAuthorityError("secret must be bytes")
    secret = bytes(value)
    if len(secret) < 32:
        raise SmallRepairAuthorityError("secret must be at least 32 bytes")
    return secret


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SmallRepairAuthorityError(f"{label} must be numeric")
    out = float(value)
    if not (out == out) or out in (float("inf"), float("-inf")):
        raise SmallRepairAuthorityError(f"{label} must be finite")
    return out


def _unsigned(payload: Mapping[str, object]) -> dict[str, object]:
    body = dict(payload)
    body.pop("signature", None)
    return body


def issue_small_repair_exemption(
    *,
    task_id: str,
    repository: str,
    base_sha: str,
    objective: str,
    allowed_paths: Sequence[str],
    secret: bytes,
    ttl_seconds: int = 900,
    now: float | None = None,
) -> dict[str, object]:
    secret_bytes = _secret(secret)
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise SmallRepairAuthorityError("ttl_seconds must be an integer")
    if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
        raise SmallRepairAuthorityError(
            f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"
        )
    issued = time.time() if now is None else _timestamp(now, "now")
    body: dict[str, object] = {
        "schema": TOKEN_SCHEMA,
        "type": TOKEN_TYPE,
        "taskId": _text(task_id, "taskId"),
        "repository": _repository(repository),
        "baseSha": _base_sha(base_sha),
        "objectiveSha256": _objective_sha256(objective),
        "allowedPaths": list(_paths(allowed_paths)),
        "issuedAt": issued,
        "expiresAt": issued + ttl_seconds,
    }
    digest = hmac.new(secret_bytes, canonical(body), hashlib.sha256).hexdigest()
    body["signature"] = "hmac-sha256:" + digest
    return body


def verify_small_repair_exemption(
    token: object,
    *,
    task_id: str,
    repository: str,
    base_sha: str,
    objective: str,
    allowed_paths: Sequence[str],
    secret: bytes,
    now: float | None = None,
) -> VerifiedSmallRepairExemption:
    secret_bytes = _secret(secret)
    if not isinstance(token, dict):
        raise SmallRepairAuthorityError("small-repair exemption must be an object")
    actual_keys = frozenset(token)
    if actual_keys != _TOKEN_KEYS:
        missing = sorted(_TOKEN_KEYS - actual_keys)
        extra = sorted(actual_keys - _TOKEN_KEYS)
        raise SmallRepairAuthorityError(
            f"small-repair exemption fields mismatch: missing={missing!r} extra={extra!r}"
        )
    if type(token.get("schema")) is not int or token["schema"] != TOKEN_SCHEMA:
        raise SmallRepairAuthorityError("unsupported small-repair exemption schema")
    if token.get("type") != TOKEN_TYPE:
        raise SmallRepairAuthorityError("unexpected small-repair exemption type")

    expected_task = _text(task_id, "taskId")
    expected_repository = _repository(repository)
    expected_base = _base_sha(base_sha)
    expected_objective = _objective_sha256(objective)
    expected_paths = _paths(allowed_paths)

    token_task = _text(token["taskId"], "token.taskId")
    token_repository = _repository(token["repository"])
    token_base = _base_sha(token["baseSha"])
    token_objective = _text(token["objectiveSha256"], "token.objectiveSha256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", token_objective):
        raise SmallRepairAuthorityError("token.objectiveSha256 must be 64 lowercase hex")
    token_paths = _paths(token["allowedPaths"])
    issued = _timestamp(token["issuedAt"], "issuedAt")
    expires = _timestamp(token["expiresAt"], "expiresAt")
    current = time.time() if now is None else _timestamp(now, "now")

    if expires <= issued or expires - issued > MAX_TTL_SECONDS:
        raise SmallRepairAuthorityError("small-repair exemption TTL is invalid")
    if current < issued - 30:
        raise SmallRepairAuthorityError("small-repair exemption is not yet valid")
    if current >= expires:
        raise SmallRepairAuthorityError("small-repair exemption expired")

    signature = token["signature"]
    if not isinstance(signature, str) or not signature.startswith("hmac-sha256:"):
        raise SmallRepairAuthorityError("small-repair exemption signature is invalid")
    supplied = signature.split(":", 1)[1]
    if not re.fullmatch(r"[0-9a-f]{64}", supplied):
        raise SmallRepairAuthorityError("small-repair exemption signature is invalid")
    wanted = hmac.new(
        secret_bytes,
        canonical(_unsigned(token)),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied, wanted):
        raise SmallRepairAuthorityError("small-repair exemption signature mismatch")

    mismatches = []
    if token_task != expected_task:
        mismatches.append("taskId")
    if token_repository != expected_repository:
        mismatches.append("repository")
    if token_base != expected_base:
        mismatches.append("baseSha")
    if token_objective != expected_objective:
        mismatches.append("objective")
    if token_paths != expected_paths:
        mismatches.append("allowedPaths")
    if mismatches:
        raise SmallRepairAuthorityError(
            "small-repair exemption binding mismatch: " + ",".join(mismatches)
        )

    return VerifiedSmallRepairExemption(
        task_id=token_task,
        repository=token_repository,
        base_sha=token_base,
        objective_sha256=token_objective,
        allowed_paths=token_paths,
        issued_at=issued,
        expires_at=expires,
    )


def classify_work_kind(
    *,
    task_id: str,
    repository: str,
    base_sha: str,
    objective: str,
    allowed_paths: Sequence[str],
    secret: bytes,
    exemption: object | None,
    now: float | None = None,
) -> str:
    if exemption is None:
        return "substantial-subsystem"
    verify_small_repair_exemption(
        exemption,
        task_id=task_id,
        repository=repository,
        base_sha=base_sha,
        objective=objective,
        allowed_paths=allowed_paths,
        secret=secret,
        now=now,
    )
    return "small-repair"


def evaluate_task_reuse_readiness(
    *,
    task_id: str,
    repository: str,
    base_sha: str,
    objective: str,
    allowed_paths: Sequence[str],
    secret: bytes,
    exemption: object | None,
    subsystem: str,
    reuse_review: object | None,
    now: float | None = None,
) -> BuildReadiness:
    work_kind = classify_work_kind(
        task_id=task_id,
        repository=repository,
        base_sha=base_sha,
        objective=objective,
        allowed_paths=allowed_paths,
        secret=secret,
        exemption=exemption,
        now=now,
    )
    return evaluate_build_readiness(
        work_kind=work_kind,
        subsystem=subsystem,
        reuse_review=reuse_review,
    )
