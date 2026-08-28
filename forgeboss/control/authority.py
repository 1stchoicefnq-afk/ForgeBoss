from __future__ import annotations
import base64
import copy
import math
import re
from dataclasses import dataclass
from .envelope import canonical

AUTHORITY_VERSION = 1
PROTOCOL_VERSION = 1
ALGORITHM = "ed25519"
PURPOSE = "worker-launch"

_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_GIT_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOS_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.I)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    Ed25519PublicKey = None


def _strict_str(value, name, *, max_len=1024, pattern=None):
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ValueError(f"{name} invalid")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{name} invalid")
    if pattern is not None and not pattern.fullmatch(value):
        raise ValueError(f"{name} invalid")
    return value


def _strict_int(value, name, *, minimum=1):
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{name} invalid")
    return value


def _finite(value, name, *, positive=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} invalid")
    number = float(value)
    if not math.isfinite(number) or (positive and number <= 0):
        raise ValueError(f"{name} invalid")
    return number


def _git_sha(value, name):
    return _strict_str(value, name, max_len=64, pattern=_GIT_OBJECT_ID)


def _sha256(value, name):
    return _strict_str(value, name, max_len=64, pattern=_SHA256)


def _branch(value):
    branch = _strict_str(value, "branch", max_len=255)
    bad_chars = set(" ~^:?*[\\")
    if (
        branch == "@"
        or any(ch in bad_chars for ch in branch)
        or branch.startswith(("/", "."))
        or branch.endswith(("/", ".", ".lock"))
        or ".." in branch
        or "//" in branch
        or "@{" in branch
    ):
        raise ValueError("branch invalid")
    return branch


def _worktree(value):
    path = _strict_str(value, "worktreePath", max_len=2048)
    normalized = path.replace("\\", "/")
    if not (normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized) or normalized.startswith("//")):
        raise ValueError("worktreePath must be absolute")
    if any(part in (".", "..") for part in normalized.split("/")):
        raise ValueError("worktreePath invalid")
    return path


def _canonical_path(value, name):
    path = _strict_str(value, name, max_len=1024).replace("\\", "/").strip()
    if not path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        raise ValueError(f"{name} invalid path")
    parts = []
    for raw in path.split("/"):
        if raw in ("", "."):
            continue
        if raw == ".." or raw != raw.rstrip(" ."):
            raise ValueError(f"{name} invalid path")
        if any(ch in raw for ch in ':*?<>|"') or _DOS_RESERVED.match(raw):
            raise ValueError(f"{name} invalid path")
        parts.append(raw)
    if not parts:
        raise ValueError(f"{name} invalid path")
    normalized = "/".join(parts)
    return normalized, normalized.casefold()


def _paths(value, name):
    if not isinstance(value, list):
        raise ValueError(f"{name} must be list")
    out = []
    seen = set()
    for item in value:
        normalized, key = _canonical_path(item, name)
        if key in seen:
            raise ValueError(f"{name} duplicate/colliding path")
        seen.add(key)
        out.append(normalized)
    return out, seen


def _contains(left, right):
    return left == right or right.startswith(left + "/")


def _tools(value):
    if not isinstance(value, list):
        raise ValueError("allowedTools must be list")
    seen = set()
    out = []
    for item in value:
        tool = _strict_str(item, "allowedTools item", max_len=128, pattern=_ID)
        key = tool.casefold()
        if key in seen:
            raise ValueError("allowedTools duplicate/colliding tool")
        seen.add(key)
        out.append(tool)
    return out


def _runtime(value):
    if not isinstance(value, dict) or set(value) != {"adapter", "provider", "model"}:
        raise ValueError("runtime invalid")
    return {
        "adapter": _strict_str(value["adapter"], "runtime.adapter", max_len=128, pattern=_ID),
        "provider": _strict_str(value["provider"], "runtime.provider", max_len=128, pattern=_ID),
        "model": _strict_str(value["model"], "runtime.model", max_len=256),
    }


def _known_good(value):
    if not isinstance(value, dict) or set(value) != {"revision", "manifestSha256", "identitySha256"}:
        raise ValueError("controllerKnownGood invalid")
    return {
        "revision": _strict_int(value["revision"], "controllerKnownGood.revision"),
        "manifestSha256": _sha256(value["manifestSha256"], "controllerKnownGood.manifestSha256"),
        "identitySha256": _sha256(value["identitySha256"], "controllerKnownGood.identitySha256"),
    }


def _review_policy(value):
    if not isinstance(value, dict) or set(value) != {"independentReviewRequired", "reviewerId"}:
        raise ValueError("reviewPolicy invalid")
    if value["independentReviewRequired"] is not True:
        raise ValueError("reviewPolicy.independentReviewRequired invalid")
    return {
        "independentReviewRequired": True,
        "reviewerId": _strict_str(value["reviewerId"], "reviewPolicy.reviewerId", max_len=128, pattern=_ID),
    }


@dataclass(frozen=True)
class AuthorityKey:
    key_id: str
    public_key_b64: str
    activation_at: float
    retirement_at: float | None = None
    cutoff_at: float | None = None

    def __post_init__(self):
        _strict_str(self.key_id, "keyId", max_len=128, pattern=_ID)
        _strict_str(self.public_key_b64, "public key", max_len=128)
        try:
            raw = base64.b64decode(self.public_key_b64, validate=True)
        except Exception as exc:
            raise ValueError("authority public key encoding invalid") from exc
        if len(raw) != 32:
            raise ValueError("authority public key length invalid")
        activation = _finite(self.activation_at, "activation_at")
        retirement = None if self.retirement_at is None else _finite(self.retirement_at, "retirement_at")
        cutoff = None if self.cutoff_at is None else _finite(self.cutoff_at, "cutoff_at")
        if retirement is not None and retirement < activation:
            raise ValueError("authority key retirement precedes activation")
        if cutoff is not None and cutoff < activation:
            raise ValueError("authority key cutoff precedes activation")
        if retirement is not None and cutoff is not None and cutoff < retirement:
            raise ValueError("authority key cutoff precedes retirement")


@dataclass(frozen=True)
class PinnedAuthorityTrust:
    generation: int
    keys: tuple[AuthorityKey, ...]
    minimum_generation: int = 1

    def __post_init__(self):
        generation = _strict_int(self.generation, "trust generation")
        minimum = _strict_int(self.minimum_generation, "minimum trust generation")
        if generation < minimum:
            raise PermissionError("stale authority trust generation")
        if not isinstance(self.keys, tuple) or not self.keys or any(not isinstance(key, AuthorityKey) for key in self.keys):
            raise ValueError("authority trust keys invalid")
        ids = [key.key_id for key in self.keys]
        if len({key.casefold() for key in ids}) != len(ids):
            raise ValueError("duplicate authority key id")

    def key_for(self, key_id: str, now: float):
        _strict_str(key_id, "keyId", max_len=128, pattern=_ID)
        current = _finite(now, "verification time")
        if self.generation < self.minimum_generation:
            raise PermissionError("stale authority trust generation")
        matches = [key for key in self.keys if key.key_id == key_id]
        if len(matches) != 1:
            raise PermissionError("unknown authority key id")
        key = matches[0]
        if current < float(key.activation_at):
            raise PermissionError("authority key not active")
        if key.cutoff_at is not None and current >= float(key.cutoff_at):
            raise PermissionError("authority key cutoff reached")
        return key


_REQUIRED = {
    "authorityVersion", "protocolVersion", "algorithm", "keyId", "purpose", "authorityId",
    "assignmentId", "taskId", "runId", "ownerEpoch", "attempt", "repository", "baseSha",
    "branch", "worktreePath", "runtime", "allowedPaths", "deniedPaths", "allowedTools",
    "contextBundleHash", "budgetUsd", "issuedAt", "expiresAt", "controllerKnownGood", "reviewPolicy",
}


def validate_authority(authority, now=None):
    if not isinstance(authority, dict):
        raise ValueError("authority must be object")
    if set(authority) != _REQUIRED:
        raise ValueError("authority schema mismatch")
    if authority["authorityVersion"] != AUTHORITY_VERSION:
        raise ValueError("unsupported authority version")
    if authority["protocolVersion"] != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if authority["algorithm"] != ALGORITHM or authority["purpose"] != PURPOSE:
        raise ValueError("unsupported authority domain")

    _strict_str(authority["keyId"], "keyId", max_len=128, pattern=_ID)
    _strict_str(authority["authorityId"], "authorityId", max_len=128, pattern=_ID)
    _strict_str(authority["assignmentId"], "assignmentId", max_len=128, pattern=_ID)
    _strict_str(authority["taskId"], "taskId", max_len=128, pattern=_ID)
    _strict_str(authority["runId"], "runId", max_len=128, pattern=_ID)
    _strict_int(authority["ownerEpoch"], "ownerEpoch")
    _strict_int(authority["attempt"], "attempt")
    repo = _strict_str(authority["repository"], "repository", max_len=201, pattern=_REPO)
    if any(part in (".", "..") for part in repo.split("/")):
        raise ValueError("repository invalid")
    _git_sha(authority["baseSha"], "baseSha")
    _branch(authority["branch"])
    _worktree(authority["worktreePath"])
    _runtime(authority["runtime"])

    _, allowed_keys = _paths(authority["allowedPaths"], "allowedPaths")
    _, denied_keys = _paths(authority["deniedPaths"], "deniedPaths")
    if any(_contains(a, d) or _contains(d, a) for a in allowed_keys for d in denied_keys):
        raise ValueError("allowedPaths and deniedPaths overlap")
    _tools(authority["allowedTools"])
    _sha256(authority["contextBundleHash"], "contextBundleHash")
    _known_good(authority["controllerKnownGood"])
    _review_policy(authority["reviewPolicy"])

    _finite(authority["budgetUsd"], "budgetUsd", positive=True)
    issued = _finite(authority["issuedAt"], "issuedAt")
    expires = _finite(authority["expiresAt"], "expiresAt")
    if expires <= issued:
        raise ValueError("authority time window invalid")
    if now is not None:
        current = _finite(now, "verification time")
        if current < issued:
            raise PermissionError("authority not yet valid")
        if current >= expires:
            raise PermissionError("authority expired")
    return authority


class ControllerAuthorityVerifier:
    def __init__(self, trust: PinnedAuthorityTrust):
        if not isinstance(trust, PinnedAuthorityTrust):
            raise TypeError("pinned authority trust required")
        self._trust = trust

    def verify(self, packet, now):
        if not isinstance(packet, dict) or set(packet) != {"authority", "signature"}:
            raise ValueError("signed authority schema mismatch")
        authority = copy.deepcopy(packet["authority"])
        validate_authority(authority, now)
        key = self._trust.key_for(authority["keyId"], now)
        signature = packet["signature"]
        if not isinstance(signature, str) or not signature.startswith("ed25519:"):
            raise PermissionError("protected authority requires ed25519")
        if Ed25519PublicKey is None:
            raise RuntimeError("cryptography Ed25519 support unavailable")
        try:
            public_bytes = base64.b64decode(key.public_key_b64, validate=True)
            signature_bytes = base64.b64decode(signature.split(":", 1)[1], validate=True)
            if len(signature_bytes) != 64:
                raise ValueError("invalid Ed25519 signature length")
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature_bytes, canonical(authority))
        except Exception as exc:
            raise PermissionError("authority signature mismatch") from exc
        return authority


class ControllerAuthoritySignerClient:
    def __init__(self, transport, controller_identity: str):
        if not callable(transport):
            raise TypeError("signer transport must be callable")
        self._transport = transport
        self._controller_identity = _strict_str(controller_identity, "controller identity", max_len=128, pattern=_ID)

    def sign_worker_launch(self, authority):
        if not isinstance(authority, dict):
            raise ValueError("authority must be object")
        checked = copy.deepcopy(authority)
        validate_authority(checked)
        expected = canonical(checked)
        request = {"type": "sign-worker-launch", "controllerIdentity": self._controller_identity, "authority": copy.deepcopy(checked)}
        response = self._transport(request)
        if not isinstance(response, dict) or set(response) != {"authority", "signature"} or not isinstance(response["authority"], dict):
            raise PermissionError("protected signer returned malformed authority")
        try:
            returned = copy.deepcopy(response["authority"])
            validate_authority(returned)
            if canonical(returned) != expected:
                raise PermissionError("protected signer returned mismatched authority")
        except PermissionError:
            raise
        except Exception as exc:
            raise PermissionError("protected signer returned invalid authority") from exc
        signature = response["signature"]
        if not isinstance(signature, str) or not signature.startswith("ed25519:"):
            raise PermissionError("protected signer returned unsupported signature")
        return {"authority": returned, "signature": signature}
