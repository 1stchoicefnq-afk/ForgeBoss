from __future__ import annotations
import base64
import copy
import json
import math
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
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


def _safe_component(component, name):
    if not component or component in (".", "..") or component != component.rstrip(" ."):
        raise ValueError(f"{name} invalid path")
    if any(ch in component for ch in ':*?<>|"') or _DOS_RESERVED.match(component):
        raise ValueError(f"{name} invalid path")


def _worktree(value):
    path = _strict_str(value, "worktreePath", max_len=2048)
    if path != path.strip() or "\\" in path:
        raise ValueError("worktreePath must be canonical slash form")
    is_drive = bool(re.match(r"^[A-Z]:/", path))
    is_unc = path.startswith("//")
    is_posix = path.startswith("/") and not is_unc
    if not (is_drive or is_unc or is_posix):
        raise ValueError("worktreePath must be absolute")
    if is_drive:
        tail = path[3:]
    elif is_unc:
        tail = path[2:]
    else:
        tail = path[1:]
    parts = tail.split("/") if tail else []
    if not parts or any(not part for part in parts):
        raise ValueError("worktreePath invalid")
    for part in parts:
        _safe_component(part, "worktreePath")
    if is_unc and len(parts) < 2:
        raise ValueError("worktreePath UNC share invalid")
    return path


def _canonical_path(value, name):
    path = _strict_str(value, name, max_len=1024)
    if path != path.strip() or "\\" in path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        raise ValueError(f"{name} invalid path")
    parts = path.split("/")
    if any(not part for part in parts):
        raise ValueError(f"{name} invalid path")
    for part in parts:
        _safe_component(part, name)
    return path, path.casefold()


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
    for item in value:
        tool = _strict_str(item, "allowedTools item", max_len=128, pattern=_ID)
        key = tool.casefold()
        if key in seen:
            raise ValueError("allowedTools duplicate/colliding tool")
        seen.add(key)
    return value


def _runtime(value):
    if not isinstance(value, dict) or set(value) != {"adapter", "provider", "model"}:
        raise ValueError("runtime invalid")
    _strict_str(value["adapter"], "runtime.adapter", max_len=128, pattern=_ID)
    _strict_str(value["provider"], "runtime.provider", max_len=128, pattern=_ID)
    _strict_str(value["model"], "runtime.model", max_len=256)
    return value


def _known_good(value):
    if not isinstance(value, dict) or set(value) != {"revision", "manifestSha256", "identitySha256"}:
        raise ValueError("controllerKnownGood invalid")
    _strict_int(value["revision"], "controllerKnownGood.revision")
    _sha256(value["manifestSha256"], "controllerKnownGood.manifestSha256")
    _sha256(value["identitySha256"], "controllerKnownGood.identitySha256")
    return value


def _review_policy(value):
    expected = {"independentReviewRequired", "authorMayReview", "reviewerId"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("reviewPolicy invalid")
    if value["independentReviewRequired"] is not True or value["authorMayReview"] is not False:
        raise ValueError("reviewPolicy invalid")
    _strict_str(value["reviewerId"], "reviewPolicy.reviewerId", max_len=128, pattern=_ID)
    return value


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
        activation = _finite(self.activation_at, "activationAt")
        retirement = None if self.retirement_at is None else _finite(self.retirement_at, "retirementAt")
        cutoff = None if self.cutoff_at is None else _finite(self.cutoff_at, "cutoffAt")
        if retirement is not None and retirement < activation:
            raise ValueError("authority key retirement precedes activation")
        if cutoff is not None and cutoff < activation:
            raise ValueError("authority key cutoff precedes activation")
        if retirement is not None and cutoff is not None and cutoff < retirement:
            raise ValueError("authority key cutoff precedes retirement")

    def to_record(self):
        return {
            "keyId": self.key_id,
            "publicKey": self.public_key_b64,
            "activationAt": self.activation_at,
            "retirementAt": self.retirement_at,
            "cutoffAt": self.cutoff_at,
        }

    @classmethod
    def from_record(cls, record):
        if not isinstance(record, dict) or set(record) != {"keyId", "publicKey", "activationAt", "retirementAt", "cutoffAt"}:
            raise ValueError("authority key record invalid")
        return cls(record["keyId"], record["publicKey"], record["activationAt"], record["retirementAt"], record["cutoffAt"])


@dataclass(frozen=True)
class PinnedAuthorityTrust:
    generation: int
    keys: tuple[AuthorityKey, ...]
    current_key_id: str
    next_key_id: str | None = None
    minimum_generation: int = 1
    authority_version: int = AUTHORITY_VERSION
    algorithm: str = ALGORITHM

    def __post_init__(self):
        _strict_int(self.authority_version, "trust authorityVersion")
        if self.authority_version != AUTHORITY_VERSION or self.algorithm != ALGORITHM:
            raise ValueError("unsupported authority trust domain")
        generation = _strict_int(self.generation, "trust generation")
        minimum = _strict_int(self.minimum_generation, "minimum trust generation")
        if generation < minimum:
            raise PermissionError("stale authority trust generation")
        if not isinstance(self.keys, tuple) or not self.keys or any(not isinstance(key, AuthorityKey) for key in self.keys):
            raise ValueError("authority trust keys invalid")
        ids = [key.key_id for key in self.keys]
        if len({key.casefold() for key in ids}) != len(ids):
            raise ValueError("duplicate authority key id")
        current_id = _strict_str(self.current_key_id, "currentKeyId", max_len=128, pattern=_ID)
        by_id = {key.key_id: key for key in self.keys}
        if current_id not in by_id:
            raise ValueError("current authority key missing")
        if self.next_key_id is not None:
            next_id = _strict_str(self.next_key_id, "nextKeyId", max_len=128, pattern=_ID)
            if next_id == current_id or next_id not in by_id:
                raise ValueError("next authority key invalid")
            current = by_id[current_id]
            nxt = by_id[next_id]
            if current.cutoff_at is None:
                raise ValueError("current authority key needs cutoff for rotation")
            overlap_end = float(current.cutoff_at)
            if nxt.cutoff_at is not None:
                overlap_end = min(overlap_end, float(nxt.cutoff_at))
            if max(float(current.activation_at), float(nxt.activation_at)) >= overlap_end:
                raise ValueError("current/next authority key windows do not overlap")
        active_ids = {current_id}
        if self.next_key_id is not None:
            active_ids.add(self.next_key_id)
        for key in self.keys:
            if key.key_id not in active_ids and key.cutoff_at is None:
                raise ValueError("retired authority key requires cutoff")

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

    def to_record(self):
        return {
            "authorityVersion": self.authority_version,
            "algorithm": self.algorithm,
            "generation": self.generation,
            "currentKeyId": self.current_key_id,
            "nextKeyId": self.next_key_id,
            "keys": [key.to_record() for key in self.keys],
        }

    @classmethod
    def from_record(cls, record, *, minimum_generation=1):
        expected = {"authorityVersion", "algorithm", "generation", "currentKeyId", "nextKeyId", "keys"}
        if not isinstance(record, dict) or set(record) != expected or not isinstance(record["keys"], list):
            raise ValueError("authority trust record invalid")
        return cls(
            generation=record["generation"],
            keys=tuple(AuthorityKey.from_record(item) for item in record["keys"]),
            current_key_id=record["currentKeyId"],
            next_key_id=record["nextKeyId"],
            minimum_generation=minimum_generation,
            authority_version=record["authorityVersion"],
            algorithm=record["algorithm"],
        )


def _reject_constant(value):
    raise ValueError(f"non-finite JSON constant rejected: {value}")


def _unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key rejected: {key}")
        out[key] = value
    return out


def load_pinned_trust(path, *, minimum_generation=1):
    text = Path(path).read_text(encoding="utf-8")
    record = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    return PinnedAuthorityTrust.from_record(record, minimum_generation=minimum_generation)


def write_pinned_trust(path, trust: PinnedAuthorityTrust):
    if not isinstance(trust, PinnedAuthorityTrust):
        raise TypeError("pinned authority trust required")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(trust.to_record(), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    temp = target.parent / f".{target.name}.tmp-{uuid.uuid4().hex}"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(temp), flags, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temp, target)
        try:
            directory_fd = os.open(str(target.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    except Exception:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise
    return target


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
    _strict_int(authority["authorityVersion"], "authorityVersion")
    _strict_int(authority["protocolVersion"], "protocolVersion")
    if authority["authorityVersion"] != AUTHORITY_VERSION or authority["protocolVersion"] != PROTOCOL_VERSION:
        raise ValueError("unsupported authority version")
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
