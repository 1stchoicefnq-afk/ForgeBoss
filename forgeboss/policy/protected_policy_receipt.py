from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import re
import time
from types import MappingProxyType
from typing import Mapping, Sequence

from forgeboss.control.scheduler import _canonical_path as _store_canonical_path
from forgeboss.control.store import (
    WorkspaceCollisionError,
    _git_object_id,
    _repository_identity,
)
from forgeboss.protected_authority.signing import verify_signed_receipt


class ProtectedPolicyReceiptError(RuntimeError):
    """Raised when a protected policy approval receipt is invalid or mismatched."""


MAX_POLICY_TTL_SECONDS = 3600
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class VerifiedProtectedPolicyApproval:
    operation: str
    policy: str
    task_id: str
    repository: str
    base_sha: str
    objective_sha256: str
    allowed_paths: tuple[str, ...]
    subsystem: str | None
    review_sha256: str | None
    issued_at: int
    expires_at: int
    peer_id: str
    control_revision: int
    service_principal: str
    receipt_digest: str
    receipt_public_key_id: str


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ProtectedPolicyReceiptError(f"{label} must be a string")
    clean = value.strip()
    if not clean:
        raise ProtectedPolicyReceiptError(f"{label} is required")
    if clean != value:
        raise ProtectedPolicyReceiptError(f"{label} must not have surrounding whitespace")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
        raise ProtectedPolicyReceiptError(f"{label} contains control characters")
    return clean


def _repository(value: object) -> str:
    try:
        return _repository_identity(value)
    except WorkspaceCollisionError as ex:
        raise ProtectedPolicyReceiptError("repository identity is invalid") from ex


def _base_sha(value: object) -> str:
    try:
        return _git_object_id(value)
    except WorkspaceCollisionError as ex:
        raise ProtectedPolicyReceiptError("base SHA identity is invalid") from ex


def _objective_sha256(objective: object) -> str:
    if not isinstance(objective, str) or not objective or "\x00" in objective:
        raise ProtectedPolicyReceiptError("objective is invalid")
    encoded = objective.encode("utf-8")
    if len(encoded) > 128 * 1024:
        raise ProtectedPolicyReceiptError("objective is too large")
    return hashlib.sha256(encoded).hexdigest()


def _digest(value: object, label: str) -> str:
    clean = _text(value, label).lower()
    if not _HEX64.fullmatch(clean):
        raise ProtectedPolicyReceiptError(f"{label} must be a lowercase SHA-256")
    return clean


def _path(value: object) -> str:
    raw = _text(value, "allowed path").replace("\\", "/")
    if raw.startswith("/") or raw.startswith("//") or re.match(r"^[A-Za-z]:/", raw):
        raise ProtectedPolicyReceiptError("allowed path must be repository-relative")
    if any(part == ".." for part in raw.split("/")):
        raise ProtectedPolicyReceiptError("allowed path contains parent traversal")
    out = _store_canonical_path(raw)
    if not out:
        raise ProtectedPolicyReceiptError("allowed path is empty/root")
    return out


def _paths(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ProtectedPolicyReceiptError("allowed paths must be an array")
    out = tuple(sorted(_path(item) for item in value))
    if not out:
        raise ProtectedPolicyReceiptError("allowed paths must not be empty")
    if len(set(out)) != len(out):
        raise ProtectedPolicyReceiptError("allowed paths contain duplicate canonical identities")
    return out


def _int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtectedPolicyReceiptError(f"{label} must be an integer")
    return value


def _exact(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ProtectedPolicyReceiptError(f"{label} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys)
        raise ProtectedPolicyReceiptError(
            f"{label} fields mismatch: missing={missing!r} extra={extra!r}"
        )
    return value


def _allowed_peer(peer: str, allowed_peer_ids: Sequence[str]) -> str:
    if not isinstance(allowed_peer_ids, Sequence) or isinstance(
        allowed_peer_ids, (str, bytes, bytearray)
    ):
        raise ProtectedPolicyReceiptError("allowed approver peers must be an array")
    peers = tuple(_text(item, "allowed approver peer") for item in allowed_peer_ids)
    if not peers or len(set(peers)) != len(peers):
        raise ProtectedPolicyReceiptError("allowed approver peer set is invalid")
    if peer not in peers:
        raise ProtectedPolicyReceiptError("protected policy approver peer is not allowed")
    return peer


def verify_protected_policy_approval(
    response: object,
    *,
    pinned_public_key_b64: str,
    expected_operation: str,
    task_id: str,
    repository: str,
    base_sha: str,
    objective: str,
    allowed_paths: Sequence[str],
    expected_control_revision: int,
    expected_service_principal: str,
    allowed_peer_ids: Sequence[str],
    subsystem: str | None = None,
    review_sha256: str | None = None,
    now: float | None = None,
) -> VerifiedProtectedPolicyApproval:
    if expected_operation not in {"approve_small_repair", "approve_reuse_review"}:
        raise ProtectedPolicyReceiptError("unsupported protected policy operation")
    if not isinstance(pinned_public_key_b64, str) or not pinned_public_key_b64.strip():
        raise ProtectedPolicyReceiptError("pinned public key is required")
    if not verify_signed_receipt(response, pinned_public_key_b64):
        raise ProtectedPolicyReceiptError("protected policy receipt signature/result verification failed")

    top = _exact(
        response,
        {"receipt", "receiptDigest", "receiptPublicKeyId", "receiptSignature", "result"},
        "protected policy response",
    )
    receipt = _exact(
        top["receipt"],
        {
            "schema",
            "operation",
            "requestId",
            "peerId",
            "peerPrincipal",
            "repository",
            "controlRevision",
            "requestDigest",
            "resultDigest",
            "servicePrincipal",
        },
        "protected policy receipt",
    )
    if receipt["schema"] != 3:
        raise ProtectedPolicyReceiptError("protected policy receipt schema mismatch")
    if receipt["operation"] != expected_operation:
        raise ProtectedPolicyReceiptError("protected policy operation mismatch")

    peer = _allowed_peer(_text(receipt["peerId"], "receipt.peerId"), allowed_peer_ids)
    control_revision = _int(receipt["controlRevision"], "receipt.controlRevision")
    if control_revision != _int(expected_control_revision, "expected_control_revision"):
        raise ProtectedPolicyReceiptError("protected policy control revision mismatch")
    service_principal = _text(receipt["servicePrincipal"], "receipt.servicePrincipal")
    if service_principal != _text(expected_service_principal, "expected_service_principal"):
        raise ProtectedPolicyReceiptError("protected policy service principal mismatch")

    expected_repo = _repository(repository)
    receipt_repo = _repository(receipt["repository"])
    if receipt_repo != expected_repo:
        raise ProtectedPolicyReceiptError("protected policy repository mismatch")

    common_keys = {
        "schema",
        "approved",
        "policy",
        "taskId",
        "repository",
        "baseSha",
        "objectiveSha256",
        "allowedPaths",
        "issuedAt",
        "expiresAt",
    }
    result_keys = (
        common_keys
        if expected_operation == "approve_small_repair"
        else common_keys | {"subsystem", "reviewSha256"}
    )
    result = _exact(top["result"], result_keys, "protected policy result")
    if result["schema"] != 1 or result["approved"] is not True:
        raise ProtectedPolicyReceiptError("protected policy result is not approved")
    expected_policy = "small-repair-v1" if expected_operation == "approve_small_repair" else "reuse-review-v1"
    if result["policy"] != expected_policy:
        raise ProtectedPolicyReceiptError("protected policy result type mismatch")

    expected_task = _text(task_id, "task_id")
    if _text(result["taskId"], "result.taskId") != expected_task:
        raise ProtectedPolicyReceiptError("protected policy task mismatch")
    if _repository(result["repository"]) != expected_repo:
        raise ProtectedPolicyReceiptError("protected policy result repository mismatch")
    if _base_sha(result["baseSha"]) != _base_sha(base_sha):
        raise ProtectedPolicyReceiptError("protected policy base SHA mismatch")
    if _digest(result["objectiveSha256"], "result.objectiveSha256") != _objective_sha256(objective):
        raise ProtectedPolicyReceiptError("protected policy objective mismatch")
    if _paths(result["allowedPaths"]) != _paths(allowed_paths):
        raise ProtectedPolicyReceiptError("protected policy writable scope mismatch")

    verified_subsystem = None
    verified_review = None
    if expected_operation == "approve_reuse_review":
        verified_subsystem = _text(result["subsystem"], "result.subsystem")
        if verified_subsystem != _text(subsystem, "subsystem"):
            raise ProtectedPolicyReceiptError("protected policy subsystem mismatch")
        verified_review = _digest(result["reviewSha256"], "result.reviewSha256")
        if verified_review != _digest(review_sha256, "review_sha256"):
            raise ProtectedPolicyReceiptError("protected policy reuse-review digest mismatch")
    elif subsystem is not None or review_sha256 is not None:
        raise ProtectedPolicyReceiptError("small-repair approval must not carry reuse-review expectations")

    issued = _int(result["issuedAt"], "result.issuedAt")
    expires = _int(result["expiresAt"], "result.expiresAt")
    if expires <= issued or expires - issued > MAX_POLICY_TTL_SECONDS:
        raise ProtectedPolicyReceiptError("protected policy approval TTL is invalid")
    try:
        current = time.time() if now is None else float(now)
    except (TypeError, ValueError, OverflowError) as ex:
        raise ProtectedPolicyReceiptError("current time is invalid") from ex
    if not math.isfinite(current):
        raise ProtectedPolicyReceiptError("current time is invalid")
    if current < issued - 30:
        raise ProtectedPolicyReceiptError("protected policy approval is not yet valid")
    if current >= expires:
        raise ProtectedPolicyReceiptError("protected policy approval expired")

    return VerifiedProtectedPolicyApproval(
        operation=expected_operation,
        policy=expected_policy,
        task_id=expected_task,
        repository=expected_repo,
        base_sha=_base_sha(base_sha),
        objective_sha256=_objective_sha256(objective),
        allowed_paths=_paths(allowed_paths),
        subsystem=verified_subsystem,
        review_sha256=verified_review,
        issued_at=issued,
        expires_at=expires,
        peer_id=peer,
        control_revision=control_revision,
        service_principal=service_principal,
        receipt_digest=_digest(top["receiptDigest"], "receiptDigest"),
        receipt_public_key_id=_digest(top["receiptPublicKeyId"], "receiptPublicKeyId"),
    )