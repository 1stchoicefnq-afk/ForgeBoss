from __future__ import annotations

import hashlib
import hmac
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import time
from typing import Mapping

from forgeboss.control.envelope import canonical
from forgeboss.security.executor_guard import (
    SecurityError,
    git as trusted_git,
    git_metadata_snapshot,
    snapshot,
)


class ProjectAdmissionError(RuntimeError):
    """Raised when project-mode build admission is missing, stale, or invalid."""


SCHEMA = 1
WORK_KIND = "substantial-subsystem"
MAX_TTL_SECONDS = 30 * 60
MAX_CLOCK_SKEW_SECONDS = 5
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADMISSION_ID = re.compile(r"^[0-9a-f]{32}$")
_SUBSYSTEM = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,126}[A-Za-z0-9])?$")
_ALLOWED_KEYS = frozenset({
    "schema",
    "admissionId",
    "projectRoot",
    "baseSha",
    "subsystem",
    "workKind",
    "allowedPaths",
    "rulesCanonicalSha256",
    "reuseReviewSha256",
    "workspaceBaselineSha256",
    "issuedAt",
    "expiresAt",
    "signature",
})


def _secret(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ProjectAdmissionError("control-plane secret must be bytes")
    out = bytes(value)
    if len(out) < 32:
        raise ProjectAdmissionError("control-plane secret must be at least 32 bytes")
    return out


def _project_root(value: str | os.PathLike[str]) -> Path:
    try:
        root = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as ex:
        raise ProjectAdmissionError(f"project root is unavailable: {value}") from ex
    if not root.is_dir():
        raise ProjectAdmissionError(f"project root is not a directory: {root}")
    return root


def _sha1(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ProjectAdmissionError(f"{label} must be a 40-hex commit SHA")
    clean = value.strip().lower()
    if clean != value.lower() or not _SHA1.fullmatch(clean):
        raise ProjectAdmissionError(f"{label} must be an exact 40-hex commit SHA")
    return clean


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ProjectAdmissionError(f"{label} must be a SHA-256 digest")
    clean = value.strip().lower()
    if clean != value.lower() or not _SHA256.fullmatch(clean):
        raise ProjectAdmissionError(f"{label} must be exactly 64 hexadecimal characters")
    return clean


def _subsystem(value: object) -> str:
    if not isinstance(value, str):
        raise ProjectAdmissionError("subsystem must be a string")
    clean = value.strip()
    if clean != value or not _SUBSYSTEM.fullmatch(clean):
        raise ProjectAdmissionError("subsystem has invalid format")
    if "//" in clean or "/./" in f"/{clean}/" or "/../" in f"/{clean}/":
        raise ProjectAdmissionError("subsystem has invalid path-like segments")
    return clean


def _path(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ProjectAdmissionError("allowedPaths contains an invalid path")
    if "\x00" in value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ProjectAdmissionError("allowedPaths contains control characters")
    raw = value.replace("\\", "/")
    if raw.startswith(("/", "//", "~")) or (len(raw) >= 2 and raw[1] == ":"):
        raise ProjectAdmissionError("allowedPaths must be repository-relative")
    path = PurePosixPath(raw)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ProjectAdmissionError("allowedPaths contains traversal or empty segments")
    normalized = path.as_posix()
    if not normalized:
        raise ProjectAdmissionError("allowedPaths contains an empty path")
    if len(normalized.encode("utf-8")) > 1024:
        raise ProjectAdmissionError("allowedPaths contains an overlong path")
    return normalized


def _scope(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ProjectAdmissionError("allowedPaths must be an array")
    if not values:
        raise ProjectAdmissionError("allowedPaths must not be empty")
    if len(values) > 512:
        raise ProjectAdmissionError("allowedPaths exceeds the admission cap")
    out = tuple(_path(value) for value in values)
    keys = [value.casefold() for value in out]
    if len(set(keys)) != len(keys):
        raise ProjectAdmissionError("allowedPaths contains duplicate Windows-equivalent paths")
    if sum(len(value.encode("utf-8")) for value in out) > 64 * 1024:
        raise ProjectAdmissionError("allowedPaths exceeds the total byte cap")
    ordered = tuple(sorted(out, key=lambda value: value.casefold()))
    folded = [value.casefold() for value in ordered]
    for index, value in enumerate(folded):
        for other in folded[index + 1:]:
            if other.startswith(value + "/"):
                raise ProjectAdmissionError(
                    "allowedPaths contains overlapping ancestor/descendant authority"
                )
    return ordered


def _now(value: float | int | None) -> int:
    raw = time.time() if value is None else value
    if isinstance(raw, bool):
        raise ProjectAdmissionError("current time must be finite")
    try:
        numeric = float(raw)
    except (TypeError, ValueError, OverflowError) as ex:
        raise ProjectAdmissionError("current time must be finite") from ex
    if not math.isfinite(numeric) or numeric < 0:
        raise ProjectAdmissionError("current time must be finite")
    return int(numeric)


def _ttl(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProjectAdmissionError("ttl_seconds must be an integer")
    if value <= 0 or value > MAX_TTL_SECONDS:
        raise ProjectAdmissionError(
            f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"
        )
    return value


def _current_head(root: Path) -> str:
    try:
        top = Path(trusted_git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
        if os.path.normcase(str(top)) != os.path.normcase(str(root)):
            raise ProjectAdmissionError(
                f"project root differs from effective Git worktree: project={root} git={top}"
            )
        head = trusted_git(root, "rev-parse", "HEAD").strip().lower()
    except ProjectAdmissionError:
        raise
    except SecurityError as ex:
        raise ProjectAdmissionError(f"trusted Git HEAD verification failed: {ex}") from ex
    if not _SHA1.fullmatch(head):
        raise ProjectAdmissionError("project must have an exact 40-hex Git HEAD")
    return head


def _workspace_baseline_sha256(root: Path) -> str:
    try:
        material = {
            "files": snapshot(root),
            "gitMetadata": git_metadata_snapshot(root),
        }
        return hashlib.sha256(canonical(material)).hexdigest()
    except SecurityError as ex:
        raise ProjectAdmissionError(
            f"workspace baseline verification failed: {ex}"
        ) from ex
    except (OSError, ValueError, TypeError) as ex:
        raise ProjectAdmissionError(
            f"workspace baseline could not be captured: {ex}"
        ) from ex


def _signature(unsigned: Mapping[str, object], secret: bytes) -> str:
    digest = hmac.new(secret, canonical(dict(unsigned)), hashlib.sha256).hexdigest()
    return "hmac-sha256:" + digest


def _unsigned(receipt: Mapping[str, object]) -> dict[str, object]:
    return {key: receipt[key] for key in receipt if key != "signature"}


def issue_project_build_admission(
    *,
    project_root: str | os.PathLike[str],
    base_sha: str,
    subsystem: str,
    allowed_paths: list[str] | tuple[str, ...],
    rules_canonical_sha256: str,
    reuse_review_sha256: str,
    secret: bytes,
    ttl_seconds: int = 15 * 60,
    now: float | int | None = None,
) -> dict[str, object]:
    """Issue a signed admission for substantial project-mode work.

    There is deliberately no work_kind parameter. P0 project-mode builds are
    substantial by construction. A future small-repair exception needs its own
    owner-authority design rather than a caller-selectable flag.
    """
    control_secret = _secret(secret)
    root = _project_root(project_root)
    base = _sha1(base_sha, "base_sha")
    current = _current_head(root)
    if current != base:
        raise ProjectAdmissionError(
            f"project HEAD mismatch at admission: expected {base}, got {current}"
        )

    scope = _scope(allowed_paths)
    subsystem_name = _subsystem(subsystem)
    rules_digest = _sha256(rules_canonical_sha256, "rules_canonical_sha256")
    reuse_digest = _sha256(reuse_review_sha256, "reuse_review_sha256")
    issued = _now(now)
    ttl = _ttl(ttl_seconds)

    payload: dict[str, object] = {
        "schema": SCHEMA,
        "admissionId": secrets.token_hex(16),
        "projectRoot": str(root),
        "baseSha": base,
        "subsystem": subsystem_name,
        "workKind": WORK_KIND,
        "allowedPaths": list(scope),
        "rulesCanonicalSha256": rules_digest,
        "reuseReviewSha256": reuse_digest,
        "workspaceBaselineSha256": _workspace_baseline_sha256(root),
        "issuedAt": issued,
        "expiresAt": issued + ttl,
    }
    payload["signature"] = _signature(payload, control_secret)
    return payload


def verify_project_build_admission(
    receipt: object,
    *,
    secret: bytes,
    expected_project_root: str | os.PathLike[str],
    expected_base_sha: str,
    expected_subsystem: str,
    expected_allowed_paths: list[str] | tuple[str, ...],
    expected_rules_canonical_sha256: str,
    expected_reuse_review_sha256: str,
    now: float | int | None = None,
) -> dict[str, object]:
    if not isinstance(receipt, dict):
        raise ProjectAdmissionError("project admission receipt must be an object")
    actual_keys = frozenset(receipt)
    if actual_keys != _ALLOWED_KEYS:
        missing = sorted(_ALLOWED_KEYS - actual_keys)
        extra = sorted(actual_keys - _ALLOWED_KEYS)
        raise ProjectAdmissionError(
            f"project admission field mismatch: missing={missing!r} extra={extra!r}"
        )

    # Authenticate before any receipt-controlled filesystem or Git access.
    if type(receipt.get("schema")) is not int or receipt["schema"] != SCHEMA:
        raise ProjectAdmissionError("unsupported project admission schema")
    admission_id = receipt.get("admissionId")
    if not isinstance(admission_id, str) or not _ADMISSION_ID.fullmatch(admission_id):
        raise ProjectAdmissionError("invalid project admission ID")
    signature = receipt.get("signature")
    if not isinstance(signature, str) or not signature.startswith("hmac-sha256:"):
        raise ProjectAdmissionError("project admission signature is invalid")
    supplied = signature.split(":", 1)[1]
    if not re.fullmatch(r"[0-9a-f]{64}", supplied):
        raise ProjectAdmissionError("project admission signature is invalid")

    # Bound JSON-compatible field shapes before canonical HMAC computation.
    if not isinstance(receipt.get("projectRoot"), str):
        raise ProjectAdmissionError("project admission root must be a string")
    if not isinstance(receipt.get("baseSha"), str):
        raise ProjectAdmissionError("project admission base SHA must be a string")
    if not isinstance(receipt.get("subsystem"), str):
        raise ProjectAdmissionError("project admission subsystem must be a string")
    if receipt.get("workKind") != WORK_KIND:
        raise ProjectAdmissionError("project admission work kind is invalid")
    if not isinstance(receipt.get("allowedPaths"), list):
        raise ProjectAdmissionError("project admission allowedPaths must be an array")
    if not isinstance(receipt.get("rulesCanonicalSha256"), str):
        raise ProjectAdmissionError("project admission rules digest must be a string")
    if not isinstance(receipt.get("reuseReviewSha256"), str):
        raise ProjectAdmissionError("project admission reuse-review digest must be a string")
    if not isinstance(receipt.get("workspaceBaselineSha256"), str):
        raise ProjectAdmissionError("project admission workspace baseline digest must be a string")
    issued = receipt.get("issuedAt")
    expires = receipt.get("expiresAt")
    if type(issued) is not int or type(expires) is not int:
        raise ProjectAdmissionError("project admission timestamps must be integers")

    try:
        expected_signature = _signature(_unsigned(receipt), _secret(secret))
    except (TypeError, ValueError) as ex:
        raise ProjectAdmissionError("project admission canonical payload is invalid") from ex
    if not hmac.compare_digest(signature, expected_signature):
        raise ProjectAdmissionError("project admission signature mismatch")

    root = _project_root(receipt["projectRoot"])
    expected_root = _project_root(expected_project_root)
    if os.path.normcase(str(root)) != os.path.normcase(str(expected_root)):
        raise ProjectAdmissionError("project admission root mismatch")
    if str(root) != receipt["projectRoot"]:
        raise ProjectAdmissionError("project admission root is not canonical")

    base = _sha1(receipt["baseSha"], "receipt.baseSha")
    if base != _sha1(expected_base_sha, "expected_base_sha"):
        raise ProjectAdmissionError("project admission base SHA mismatch")
    current = _current_head(root)
    if current != base:
        raise ProjectAdmissionError(
            f"project HEAD changed after admission: expected {base}, got {current}"
        )
    baseline_digest = _sha256(
        receipt["workspaceBaselineSha256"],
        "receipt.workspaceBaselineSha256",
    )
    current_baseline = _workspace_baseline_sha256(root)
    if current_baseline != baseline_digest:
        raise ProjectAdmissionError(
            "project workspace baseline changed after admission"
        )

    subsystem_name = _subsystem(receipt["subsystem"])
    if subsystem_name != _subsystem(expected_subsystem):
        raise ProjectAdmissionError("project admission subsystem mismatch")

    scope = _scope(receipt["allowedPaths"])
    expected_scope = _scope(expected_allowed_paths)
    if scope != expected_scope or list(scope) != receipt["allowedPaths"]:
        raise ProjectAdmissionError("project admission write scope mismatch")

    rules_digest = _sha256(
        receipt["rulesCanonicalSha256"],
        "receipt.rulesCanonicalSha256",
    )
    if rules_digest != _sha256(
        expected_rules_canonical_sha256,
        "expected_rules_canonical_sha256",
    ):
        raise ProjectAdmissionError("project admission rules digest mismatch")

    reuse_digest = _sha256(
        receipt["reuseReviewSha256"],
        "receipt.reuseReviewSha256",
    )
    if reuse_digest != _sha256(
        expected_reuse_review_sha256,
        "expected_reuse_review_sha256",
    ):
        raise ProjectAdmissionError("project admission reuse-review digest mismatch")

    if issued < 0 or expires <= issued or expires - issued > MAX_TTL_SECONDS:
        raise ProjectAdmissionError("project admission timestamp range is invalid")
    current_time = _now(now)
    if issued > current_time + MAX_CLOCK_SKEW_SECONDS:
        raise ProjectAdmissionError("project admission was issued in the future")
    if expires <= current_time:
        raise ProjectAdmissionError("project admission has expired")

    return dict(receipt)