from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
import time

from forgeboss.control.envelope import canonical
from forgeboss.policy.reuse_review import BuildReadiness, validate_reuse_review
from forgeboss.policy.small_repair_authority import (
    SmallRepairAuthorityError,
    _base_sha,
    _objective_sha256,
    _paths,
    _repository,
    _secret,
    _text,
    _timestamp,
    classify_work_kind,
)


class ReuseReviewAuthorityError(RuntimeError):
    """Raised when an approved reuse-review receipt is invalid or mismatched."""


RECEIPT_SCHEMA = 1
RECEIPT_TYPE = "upstream-reuse-review-receipt"
MAX_RECEIPT_TTL_SECONDS = 24 * 60 * 60
_RECEIPT_KEYS = frozenset({
    "schema",
    "type",
    "taskId",
    "repository",
    "baseSha",
    "objectiveSha256",
    "allowedPaths",
    "subsystem",
    "reviewSha256",
    "issuedAt",
    "expiresAt",
    "signature",
})


@dataclass(frozen=True)
class VerifiedReuseReviewReceipt:
    task_id: str
    repository: str
    base_sha: str
    objective_sha256: str
    allowed_paths: tuple[str, ...]
    subsystem: str
    review_sha256: str
    issued_at: float
    expires_at: float


def _review_digest(review: object, *, subsystem: str) -> str:
    clean_subsystem = _text(subsystem, "subsystem")
    if not isinstance(review, dict):
        raise ReuseReviewAuthorityError("UPSTREAM_REUSE_REVIEW must be an object")
    try:
        validate_reuse_review(review, expected_subsystem=clean_subsystem)
        encoded = canonical(review)
    except Exception as ex:
        raise ReuseReviewAuthorityError(
            f"UPSTREAM_REUSE_REVIEW is not valid for signing: {ex}"
        ) from ex
    return hashlib.sha256(encoded).hexdigest()


def issue_reuse_review_receipt(
    *,
    task_id: str,
    repository: str,
    base_sha: str,
    objective: str,
    allowed_paths,
    subsystem: str,
    reuse_review: object,
    secret: bytes,
    ttl_seconds: int = 3600,
    now: float | None = None,
) -> dict[str, object]:
    secret_bytes = _secret(secret)
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise ReuseReviewAuthorityError("ttl_seconds must be an integer")
    if ttl_seconds <= 0 or ttl_seconds > MAX_RECEIPT_TTL_SECONDS:
        raise ReuseReviewAuthorityError(
            f"ttl_seconds must be between 1 and {MAX_RECEIPT_TTL_SECONDS}"
        )
    issued = time.time() if now is None else _timestamp(now, "now")
    clean_subsystem = _text(subsystem, "subsystem")
    review_sha256 = _review_digest(reuse_review, subsystem=clean_subsystem)
    body: dict[str, object] = {
        "schema": RECEIPT_SCHEMA,
        "type": RECEIPT_TYPE,
        "taskId": _text(task_id, "taskId"),
        "repository": _repository(repository),
        "baseSha": _base_sha(base_sha),
        "objectiveSha256": _objective_sha256(objective),
        "allowedPaths": list(_paths(allowed_paths)),
        "subsystem": clean_subsystem,
        "reviewSha256": review_sha256,
        "issuedAt": issued,
        "expiresAt": issued + ttl_seconds,
    }
    digest = hmac.new(secret_bytes, canonical(body), hashlib.sha256).hexdigest()
    body["signature"] = "hmac-sha256:" + digest
    return body


def verify_reuse_review_receipt(
    receipt: object,
    *,
    task_id: str,
    repository: str,
    base_sha: str,
    objective: str,
    allowed_paths,
    subsystem: str,
    reuse_review: object,
    secret: bytes,
    now: float | None = None,
) -> VerifiedReuseReviewReceipt:
    secret_bytes = _secret(secret)
    if not isinstance(receipt, dict):
        raise ReuseReviewAuthorityError("reuse-review receipt must be an object")
    actual = frozenset(receipt)
    if actual != _RECEIPT_KEYS:
        missing = sorted(_RECEIPT_KEYS - actual)
        extra = sorted(actual - _RECEIPT_KEYS)
        raise ReuseReviewAuthorityError(
            f"reuse-review receipt fields mismatch: missing={missing!r} extra={extra!r}"
        )
    if type(receipt.get("schema")) is not int or receipt["schema"] != RECEIPT_SCHEMA:
        raise ReuseReviewAuthorityError("unsupported reuse-review receipt schema")
    if receipt.get("type") != RECEIPT_TYPE:
        raise ReuseReviewAuthorityError("unexpected reuse-review receipt type")

    expected_task = _text(task_id, "taskId")
    expected_repository = _repository(repository)
    expected_base = _base_sha(base_sha)
    expected_objective = _objective_sha256(objective)
    expected_paths = _paths(allowed_paths)
    expected_subsystem = _text(subsystem, "subsystem")
    expected_review = _review_digest(reuse_review, subsystem=expected_subsystem)

    receipt_task = _text(receipt["taskId"], "receipt.taskId")
    receipt_repository = _repository(receipt["repository"])
    receipt_base = _base_sha(receipt["baseSha"])
    receipt_objective = _text(
        receipt["objectiveSha256"], "receipt.objectiveSha256"
    ).lower()
    receipt_paths = _paths(receipt["allowedPaths"])
    receipt_subsystem = _text(receipt["subsystem"], "receipt.subsystem")
    receipt_review = _text(receipt["reviewSha256"], "receipt.reviewSha256").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_objective):
        raise ReuseReviewAuthorityError("receipt.objectiveSha256 must be 64 lowercase hex")
    if not re.fullmatch(r"[0-9a-f]{64}", receipt_review):
        raise ReuseReviewAuthorityError("receipt.reviewSha256 must be 64 lowercase hex")

    issued = _timestamp(receipt["issuedAt"], "issuedAt")
    expires = _timestamp(receipt["expiresAt"], "expiresAt")
    current = time.time() if now is None else _timestamp(now, "now")
    if expires <= issued or expires - issued > MAX_RECEIPT_TTL_SECONDS:
        raise ReuseReviewAuthorityError("reuse-review receipt TTL is invalid")
    if current < issued - 30:
        raise ReuseReviewAuthorityError("reuse-review receipt is not yet valid")
    if current >= expires:
        raise ReuseReviewAuthorityError("reuse-review receipt expired")

    signature = receipt["signature"]
    if not isinstance(signature, str) or not signature.startswith("hmac-sha256:"):
        raise ReuseReviewAuthorityError("reuse-review receipt signature is invalid")
    supplied = signature.split(":", 1)[1]
    if not re.fullmatch(r"[0-9a-f]{64}", supplied):
        raise ReuseReviewAuthorityError("reuse-review receipt signature is invalid")
    body = dict(receipt)
    body.pop("signature", None)
    wanted = hmac.new(secret_bytes, canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, wanted):
        raise ReuseReviewAuthorityError("reuse-review receipt signature mismatch")

    mismatches = []
    if receipt_task != expected_task:
        mismatches.append("taskId")
    if receipt_repository != expected_repository:
        mismatches.append("repository")
    if receipt_base != expected_base:
        mismatches.append("baseSha")
    if receipt_objective != expected_objective:
        mismatches.append("objective")
    if receipt_paths != expected_paths:
        mismatches.append("allowedPaths")
    if receipt_subsystem != expected_subsystem:
        mismatches.append("subsystem")
    if receipt_review != expected_review:
        mismatches.append("reuseReview")
    if mismatches:
        raise ReuseReviewAuthorityError(
            "reuse-review receipt binding mismatch: " + ",".join(mismatches)
        )

    return VerifiedReuseReviewReceipt(
        task_id=receipt_task,
        repository=receipt_repository,
        base_sha=receipt_base,
        objective_sha256=receipt_objective,
        allowed_paths=receipt_paths,
        subsystem=receipt_subsystem,
        review_sha256=receipt_review,
        issued_at=issued,
        expires_at=expires,
    )


def evaluate_authorized_reuse_readiness(
    *,
    task_id: str,
    repository: str,
    base_sha: str,
    objective: str,
    allowed_paths,
    secret: bytes,
    small_repair_exemption: object | None,
    subsystem: str,
    reuse_review: object | None,
    reuse_review_receipt: object | None,
    now: float | None = None,
) -> BuildReadiness:
    try:
        work_kind = classify_work_kind(
            task_id=task_id,
            repository=repository,
            base_sha=base_sha,
            objective=objective,
            allowed_paths=allowed_paths,
            secret=secret,
            exemption=small_repair_exemption,
            now=now,
        )
    except SmallRepairAuthorityError as ex:
        raise ReuseReviewAuthorityError(str(ex)) from ex

    if work_kind == "small-repair":
        return BuildReadiness(True, work_kind, None, None)

    if reuse_review is None:
        return BuildReadiness(
            False,
            work_kind,
            "UPSTREAM_REUSE_REVIEW_REQUIRED",
            None,
        )

    try:
        parsed = validate_reuse_review(
            reuse_review,
            expected_subsystem=_text(subsystem, "subsystem"),
        )
    except Exception as ex:
        return BuildReadiness(
            False,
            work_kind,
            f"UPSTREAM_REUSE_REVIEW_INVALID: {ex}",
            None,
        )

    if reuse_review_receipt is None:
        return BuildReadiness(
            False,
            work_kind,
            "UPSTREAM_REUSE_REVIEW_RECEIPT_REQUIRED",
            None,
        )

    verify_reuse_review_receipt(
        reuse_review_receipt,
        task_id=task_id,
        repository=repository,
        base_sha=base_sha,
        objective=objective,
        allowed_paths=allowed_paths,
        subsystem=subsystem,
        reuse_review=reuse_review,
        secret=secret,
        now=now,
    )
    return BuildReadiness(True, work_kind, None, parsed)
