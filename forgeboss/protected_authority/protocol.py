from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from typing import Any, Mapping

MAX_REQUEST_BYTES = 128 * 1024
MAX_TEXT = 64 * 1024
SCHEMA = 1
OPERATIONS = {
    "read_github_control",
    "publish_report_comment",
    "publish_reviewed_draft_pr",
    "verify_launch_authority",
}
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_PEER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_SECRET_KEY = re.compile(r"(?:token|secret|private[_-]?key|pem|jwt|credential|password)", re.I)


class AuthorityError(RuntimeError):
    def __init__(self, code: str, message: str = "protected authority request denied"):
        super().__init__(message)
        self.code = code


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AuthorityError("NONFINITE_JSON")
        return value
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuthorityError("JSON_KEY_INVALID")
            out[key] = _jsonable(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    raise AuthorityError("JSON_TYPE_INVALID")


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except AuthorityError:
        raise
    except Exception as exc:
        raise AuthorityError("JSON_INVALID") from exc


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def strict_loads(raw: str | bytes) -> Any:
    if isinstance(raw, bytes):
        data = raw
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuthorityError("JSON_INVALID") from exc
    elif isinstance(raw, str):
        text = raw
        data = raw.encode("utf-8")
    else:
        raise AuthorityError("JSON_INVALID")
    if not data or len(data) > MAX_REQUEST_BYTES:
        raise AuthorityError("REQUEST_SIZE_INVALID")

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise AuthorityError("DUPLICATE_JSON_KEY")
            out[key] = value
        return out

    def constant(_):
        raise AuthorityError("NONFINITE_JSON")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except AuthorityError:
        raise
    except Exception as exc:
        raise AuthorityError("JSON_INVALID") from exc


def _exact_object(value: Any, keys: tuple[str, ...], code: str) -> dict:
    if not isinstance(value, Mapping) or set(value) != set(keys):
        raise AuthorityError(code)
    return dict(value)


def _text(value: Any, code: str, *, max_len: int = MAX_TEXT, pattern: re.Pattern | None = None, lower: bool = False) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > max_len or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise AuthorityError(code)
    out = value.lower() if lower else value
    if pattern is not None and not pattern.fullmatch(out):
        raise AuthorityError(code)
    return out


def _positive_int(value: Any, code: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuthorityError(code)
    if value < (0 if allow_zero else 1) or value > 2**63 - 1:
        raise AuthorityError(code)
    return value


def _request_id(value: Any) -> str:
    text = _text(value, "REQUEST_ID_INVALID", max_len=36)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise AuthorityError("REQUEST_ID_INVALID") from exc
    if parsed.version != 4 or str(parsed) != text.lower():
        raise AuthorityError("REQUEST_ID_INVALID")
    return text.lower()


def _payload(operation: str, raw: Any) -> dict:
    if operation == "read_github_control":
        obj = _exact_object(raw, ("rootPr", "preferredRepairPr"), "PAYLOAD_INVALID")
        obj["rootPr"] = _positive_int(obj["rootPr"], "ROOT_PR_INVALID")
        obj["preferredRepairPr"] = _positive_int(obj["preferredRepairPr"], "REPAIR_PR_INVALID", allow_zero=True)
        return obj
    if operation == "publish_report_comment":
        obj = _exact_object(raw, ("issue", "body", "reportDigest"), "PAYLOAD_INVALID")
        obj["issue"] = _positive_int(obj["issue"], "ISSUE_INVALID")
        obj["body"] = _text(obj["body"], "COMMENT_BODY_INVALID")
        obj["reportDigest"] = _text(obj["reportDigest"], "REPORT_DIGEST_INVALID", max_len=64, pattern=_HEX64, lower=True)
        return obj
    if operation == "publish_reviewed_draft_pr":
        obj = _exact_object(raw, ("baseSha", "headSha", "title", "body", "reviewDigest"), "PAYLOAD_INVALID")
        obj["baseSha"] = _text(obj["baseSha"], "BASE_SHA_INVALID", max_len=64, pattern=_OID, lower=True)
        obj["headSha"] = _text(obj["headSha"], "HEAD_SHA_INVALID", max_len=64, pattern=_OID, lower=True)
        if len(obj["baseSha"]) != len(obj["headSha"]):
            raise AuthorityError("OBJECT_FORMAT_MISMATCH")
        if obj["baseSha"] == obj["headSha"]:
            raise AuthorityError("DRAFT_PR_EMPTY_DIFF")
        obj["title"] = _text(obj["title"], "PR_TITLE_INVALID", max_len=256)
        obj["body"] = _text(obj["body"], "PR_BODY_INVALID")
        obj["reviewDigest"] = _text(obj["reviewDigest"], "REVIEW_DIGEST_INVALID", max_len=64, pattern=_HEX64, lower=True)
        return obj
    if operation == "verify_launch_authority":
        obj = _exact_object(raw, ("envelope", "envelopeDigest"), "PAYLOAD_INVALID")
        if not isinstance(obj["envelope"], Mapping):
            raise AuthorityError("LAUNCH_ENVELOPE_INVALID")
        obj["envelope"] = _jsonable(obj["envelope"])
        obj["envelopeDigest"] = _text(obj["envelopeDigest"], "ENVELOPE_DIGEST_INVALID", max_len=64, pattern=_HEX64, lower=True)
        if canonical_digest(obj["envelope"]) != obj["envelopeDigest"]:
            raise AuthorityError("ENVELOPE_DIGEST_MISMATCH")
        return obj
    raise AuthorityError("OPERATION_DENIED")


def unsigned_request(raw: Any) -> dict:
    obj = _exact_object(raw, ("schema", "operation", "requestId", "peerId", "repository", "controlRevision", "requestDigest", "signature", "payload"), "REQUEST_FIELDS_INVALID")
    if obj["schema"] != SCHEMA:
        raise AuthorityError("SCHEMA_INVALID")
    operation = _text(obj["operation"], "OPERATION_INVALID", max_len=64)
    if operation not in OPERATIONS:
        raise AuthorityError("OPERATION_DENIED")
    repository = _text(obj["repository"], "REPOSITORY_INVALID", max_len=201, pattern=_REPO, lower=True)
    control_revision = _positive_int(obj["controlRevision"], "CONTROL_REVISION_INVALID")
    request_id = _request_id(obj["requestId"])
    peer_id = _text(obj["peerId"], "PEER_ID_INVALID", max_len=128, pattern=_PEER)
    payload = _payload(operation, obj["payload"])
    request_digest = _text(obj["requestDigest"], "REQUEST_DIGEST_INVALID", max_len=64, pattern=_HEX64, lower=True)
    signature = _text(obj["signature"], "SIGNATURE_INVALID", max_len=4096)
    unsigned = {
        "schema": SCHEMA,
        "operation": operation,
        "requestId": request_id,
        "peerId": peer_id,
        "repository": repository,
        "controlRevision": control_revision,
        "payload": payload,
    }
    if canonical_digest(unsigned) != request_digest:
        raise AuthorityError("REQUEST_DIGEST_MISMATCH")
    return {**unsigned, "requestDigest": request_digest, "signature": signature}


def build_request(*, operation: str, request_id: str, peer_id: str, repository: str, control_revision: int, payload: Mapping[str, Any], signature: str) -> dict:
    unsigned = {
        "schema": SCHEMA,
        "operation": operation,
        "requestId": request_id,
        "peerId": peer_id,
        "repository": repository,
        "controlRevision": control_revision,
        "payload": dict(payload),
    }
    digest = canonical_digest(unsigned)
    return unsigned_request({**unsigned, "requestDigest": digest, "signature": signature})


def assert_public_result(value: Any, private_values: tuple[str | bytes, ...] = ()) -> Any:
    clean = _jsonable(value)
    secret_texts = []
    for item in private_values:
        if isinstance(item, bytes):
            try:
                secret_texts.append(item.decode("utf-8"))
            except UnicodeDecodeError:
                continue
        elif isinstance(item, str):
            secret_texts.append(item)

    def walk(node: Any):
        if isinstance(node, Mapping):
            for key, item in node.items():
                if _SECRET_KEY.search(str(key)):
                    raise AuthorityError("SECRET_FIELD_DENIED")
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            for secret in secret_texts:
                if secret and secret in node:
                    raise AuthorityError("SECRET_VALUE_DENIED")

    walk(clean)
    return clean
