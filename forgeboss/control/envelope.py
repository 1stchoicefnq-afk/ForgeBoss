from __future__ import annotations
import hashlib
import hmac
import json
import math
import os
import secrets
import time
from pathlib import Path
from forgeboss.security.local_acl import harden_private_dir, harden_private_path


def canonical(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def secret_file(root: Path):
    """LEGACY launch-HMAC storage; Phase-A also uses it as connect-auth source for compatibility."""
    path = Path(root) / "state" / "forgebossd" / "daemon-secret.bin"
    harden_private_dir(path.parent)
    if not path.exists():
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, secrets.token_bytes(32))
                os.fsync(fd)
            finally:
                os.close(fd)
        except FileExistsError:
            pass
    harden_private_path(path)
    data = path.read_bytes()
    if len(data) < 32:
        raise RuntimeError("forgebossd secret is invalid")
    return path, data


def sign_envelope(payload, secret: bytes):
    """Explicit legacy migration API only; never a protected authority signature."""
    body = dict(payload)
    body.pop("signature", None)
    sig = hmac.new(secret, canonical(body), hashlib.sha256).hexdigest()
    body["signature"] = "hmac-sha256:" + sig
    return body


def verify_envelope(payload, secret: bytes, now=None):
    """Explicit legacy migration verifier. Protected mode must use ControllerAuthorityVerifier."""
    current = time.time() if now is None else float(now)
    if not math.isfinite(current):
        raise ValueError("verification time invalid")
    if not isinstance(payload, dict):
        raise ValueError("envelope must be object")
    allowed = {
        "envelopeVersion", "taskId", "repository", "baseSha", "branch", "worktreePath", "runId",
        "attempt", "ownerEpoch", "runtime", "allowedPaths", "deniedPaths", "allowedTools",
        "contextBundleHash", "transcript", "events", "budgetUsd", "expiresAt", "protocolVersion", "signature",
    }
    extra = set(payload) - allowed
    if extra:
        raise ValueError("unexpected envelope keys: " + ",".join(sorted(extra)))
    required = {
        "envelopeVersion", "taskId", "repository", "baseSha", "worktreePath", "runId", "ownerEpoch",
        "runtime", "allowedPaths", "allowedTools", "expiresAt", "protocolVersion", "signature",
    }
    missing = required - set(payload)
    if missing:
        raise ValueError("missing envelope keys: " + ",".join(sorted(missing)))
    if isinstance(payload["envelopeVersion"], bool) or payload["envelopeVersion"] != 1:
        raise ValueError("unsupported envelope version")
    if isinstance(payload["protocolVersion"], bool) or payload["protocolVersion"] != 1:
        raise ValueError("unsupported protocol version")
    expiry = payload["expiresAt"]
    if isinstance(expiry, bool) or not isinstance(expiry, (int, float)):
        raise ValueError("worker launch envelope expiry invalid")
    expiry = float(expiry)
    if not math.isfinite(expiry):
        raise ValueError("worker launch envelope expiry invalid")
    if expiry <= current:
        raise PermissionError("worker launch envelope expired")
    signature = payload["signature"]
    if not isinstance(signature, str) or not signature.startswith("hmac-sha256:"):
        raise PermissionError("unsupported legacy signature")
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    want = hmac.new(secret, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.split(":", 1)[1], want):
        raise PermissionError("worker launch envelope signature mismatch")
    return unsigned
