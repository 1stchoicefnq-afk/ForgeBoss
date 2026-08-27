from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

MAX_RESPONSE_BYTES = 256 * 1024


class ResponseFrameError(RuntimeError):
    code = "RESPONSE_FRAME_INVALID"


class ResponseCorrelationError(ResponseFrameError):
    code = "RESPONSE_ID_MISMATCH"


@dataclass(frozen=True)
class ValidatedResponse:
    request_id: str
    ok: bool
    payload: dict[str, Any] | None
    error: dict[str, str] | None


def _request_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ResponseFrameError(f"{name} must be a non-empty bounded string")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ResponseFrameError(f"{name} contains control characters")
    return value


def parse_response_frame(line: object, expected_request_id: object) -> ValidatedResponse:
    expected = _request_id(expected_request_id, "expected request id")
    if not isinstance(line, (bytes, bytearray)):
        raise ResponseFrameError("response frame must be bytes")
    raw = bytes(line)
    if not raw:
        raise ResponseFrameError("response frame is empty")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ResponseFrameError("response frame exceeds 256 KiB")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ResponseFrameError("response frame is not valid UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise ResponseFrameError("response frame must be object")
    if obj.get("type") != "res":
        raise ResponseFrameError("response type must be res")
    response_id = _request_id(obj.get("id"), "response id")
    if response_id != expected:
        raise ResponseCorrelationError(
            f"response id {response_id!r} does not match outstanding request"
        )
    if not isinstance(obj.get("ok"), bool):
        raise ResponseFrameError("response ok must be boolean")

    if obj["ok"]:
        if set(obj) - {"type", "id", "ok", "payload"}:
            raise ResponseFrameError("successful response contains unexpected keys")
        payload = obj.get("payload", {})
        if not isinstance(payload, dict):
            raise ResponseFrameError("successful response payload must be object")
        return ValidatedResponse(response_id, True, payload, None)

    if set(obj) - {"type", "id", "ok", "error"}:
        raise ResponseFrameError("error response contains unexpected keys")
    error = obj.get("error")
    if not isinstance(error, dict) or set(error) != {"code", "message"}:
        raise ResponseFrameError("error response must contain exact code/message object")
    code = error.get("code")
    message = error.get("message")
    if not isinstance(code, str) or not code or len(code) > 128:
        raise ResponseFrameError("error code must be non-empty bounded string")
    if not isinstance(message, str) or not message or len(message) > 4096:
        raise ResponseFrameError("error message must be non-empty bounded string")
    if any(ord(ch) < 32 and ch not in "\t" for ch in code + message):
        raise ResponseFrameError("error response contains control characters")
    return ValidatedResponse(response_id, False, None, {"code": code, "message": message})
