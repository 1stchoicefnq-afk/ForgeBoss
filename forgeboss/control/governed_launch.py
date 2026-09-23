from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import shutil
import sys
import time
from typing import Sequence

from forgeboss.control.envelope import canonical
from forgeboss.control.scheduler import _canonical_path as _scope_path
from forgeboss.control.store import _git_object_id, _repository_identity, canonical_worktree_path


class GovernedLaunchError(RuntimeError):
    """Raised when governed launch authority cannot be established safely."""


SCHEMA = 1
TYPE = "governed-launch-attestation"
MAX_TTL_SECONDS = 15 * 60
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ADAPTERS = frozenset({"mini-swe", "openhands"})
_SAFE_TOOLS = frozenset({"git", "node", "npm", "python", "pytest", "docker"})
_TOKEN_KEYS = frozenset({
    "schema",
    "type",
    "taskId",
    "repository",
    "baseSha",
    "runId",
    "adapter",
    "runnerPath",
    "runnerSha256",
    "interpreterPath",
    "interpreterSha256",
    "workspacePath",
    "allowedPaths",
    "allowedTools",
    "budgetUsd",
    "issuedAt",
    "expiresAt",
    "signature",
})


@dataclass(frozen=True)
class RunnerIdentity:
    adapter: str
    runner_path: str
    runner_sha256: str
    interpreter_path: str
    interpreter_sha256: str


@dataclass(frozen=True)
class VerifiedGovernedLaunch:
    task_id: str
    repository: str
    base_sha: str
    run_id: str
    identity: RunnerIdentity
    workspace_path: str
    allowed_paths: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    budget_usd: str
    issued_at: float
    expires_at: float


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise GovernedLaunchError(f"{label} must be a string")
    clean = value.strip()
    if not clean:
        raise GovernedLaunchError(f"{label} is required")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
        raise GovernedLaunchError(f"{label} contains control characters")
    return clean


def _secret(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise GovernedLaunchError("launch secret must be bytes")
    out = bytes(value)
    if len(out) < 32:
        raise GovernedLaunchError("launch secret must be at least 32 bytes")
    return out


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as ex:
        raise GovernedLaunchError(f"{label} is unavailable") from ex
    if not resolved.is_file():
        raise GovernedLaunchError(f"{label} must be a regular file")
    return resolved


def _regular_executable(path: Path, label: str) -> Path:
    resolved = _regular_file(path, label)
    if os.name != "nt" and not os.access(resolved, os.X_OK):
        raise GovernedLaunchError(f"{label} is not executable")
    return resolved


def resolve_runner_identity(adapter: object, *, repo_root: str | Path) -> RunnerIdentity:
    clean = _text(adapter, "adapter")
    if clean not in _SAFE_ADAPTERS:
        raise GovernedLaunchError(f"unsupported governed adapter: {clean}")

    root = Path(repo_root).resolve(strict=True)
    runners = {
        "mini-swe": root / "forgeboss" / "executors" / "mini_swe_runner.py",
        "openhands": root / "forgeboss" / "executors" / "openhands_runner.py",
    }
    runner = _regular_file(runners[clean], "runner")

    interpreter = _regular_executable(Path(sys.executable), "python interpreter")

    before_runner = _sha256_file(runner)
    before_interpreter = _sha256_file(interpreter)
    after_runner = _sha256_file(runner)
    after_interpreter = _sha256_file(interpreter)
    if before_runner != after_runner or before_interpreter != after_interpreter:
        raise GovernedLaunchError("runner/interpreter identity changed while hashing")

    return RunnerIdentity(
        adapter=clean,
        runner_path=str(runner),
        runner_sha256=before_runner,
        interpreter_path=str(interpreter),
        interpreter_sha256=before_interpreter,
    )


def _paths(values: object) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        raise GovernedLaunchError("allowedPaths must be an array")
    out = []
    seen = set()
    for raw in values:
        if not isinstance(raw, str) or not raw.strip():
            raise GovernedLaunchError("allowedPaths contains invalid path")
        if raw.startswith(("/", "\\\\")) or re.match(r"^[A-Za-z]:[\\/]", raw):
            raise GovernedLaunchError("allowedPaths must be repository-relative")
        if any(part == ".." for part in raw.replace("\\", "/").split("/")):
            raise GovernedLaunchError("allowedPaths must not contain parent traversal")
        value = _scope_path(raw)
        if not value:
            raise GovernedLaunchError("allowedPaths contains empty/root path")
        if value not in seen:
            seen.add(value)
            out.append(value)
    if not out:
        raise GovernedLaunchError("allowedPaths must not be empty")
    return tuple(sorted(out))


def _tools(values: object) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        raise GovernedLaunchError("allowedTools must be an array")
    out = []
    seen = set()
    for raw in values:
        tool = _text(raw, "allowedTools item")
        if tool not in _SAFE_TOOLS:
            raise GovernedLaunchError(f"unapproved tool id: {tool}")
        if tool not in seen:
            seen.add(tool)
            out.append(tool)
    return tuple(sorted(out))


def _budget(value: object) -> str:
    if isinstance(value, bool):
        raise GovernedLaunchError("budgetUsd must be finite and non-negative")
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as ex:
        raise GovernedLaunchError("budgetUsd must be finite and non-negative") from ex
    if not amount.is_finite() or amount <= 0:
        raise GovernedLaunchError("budgetUsd must be finite and positive")
    normalized = amount.normalize()
    text = format(normalized, "f")
    return "0" if Decimal(text) == 0 else text


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GovernedLaunchError(f"{label} must be numeric")
    out = float(value)
    if not math.isfinite(out):
        raise GovernedLaunchError(f"{label} must be finite")
    return out


def issue_governed_launch_attestation(
    *,
    task_id: str,
    repository: str,
    base_sha: str,
    run_id: str,
    adapter: str,
    repo_root: str | Path,
    workspace_path: str | Path,
    worktree_root: str | Path,
    allowed_paths,
    allowed_tools,
    budget_usd: object,
    secret: bytes,
    ttl_seconds: int = 300,
    now: float | None = None,
) -> dict[str, object]:
    launch_secret = _secret(secret)
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise GovernedLaunchError("ttl_seconds must be an integer")
    if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
        raise GovernedLaunchError(
            f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"
        )

    identity = resolve_runner_identity(adapter, repo_root=repo_root)
    workspace = canonical_worktree_path(workspace_path, worktree_root)
    issued = time.time() if now is None else _timestamp(now, "now")
    body: dict[str, object] = {
        "schema": SCHEMA,
        "type": TYPE,
        "taskId": _text(task_id, "taskId"),
        "repository": _repository_identity(repository),
        "baseSha": _git_object_id(base_sha),
        "runId": _text(run_id, "runId"),
        "adapter": identity.adapter,
        "runnerPath": identity.runner_path,
        "runnerSha256": identity.runner_sha256,
        "interpreterPath": identity.interpreter_path,
        "interpreterSha256": identity.interpreter_sha256,
        "workspacePath": workspace,
        "allowedPaths": list(_paths(allowed_paths)),
        "allowedTools": list(_tools(allowed_tools)),
        "budgetUsd": _budget(budget_usd),
        "issuedAt": issued,
        "expiresAt": issued + ttl_seconds,
    }
    sig = hmac.new(launch_secret, canonical(body), hashlib.sha256).hexdigest()
    body["signature"] = "hmac-sha256:" + sig
    return body


def verify_governed_launch_attestation(
    attestation: object,
    *,
    task_id: str,
    repository: str,
    base_sha: str,
    run_id: str,
    adapter: str,
    repo_root: str | Path,
    workspace_path: str | Path,
    worktree_root: str | Path,
    allowed_paths,
    allowed_tools,
    budget_usd: object,
    secret: bytes,
    now: float | None = None,
) -> VerifiedGovernedLaunch:
    launch_secret = _secret(secret)
    if not isinstance(attestation, dict):
        raise GovernedLaunchError("governed launch attestation must be an object")
    actual = frozenset(attestation)
    if actual != _TOKEN_KEYS:
        missing = sorted(_TOKEN_KEYS - actual)
        extra = sorted(actual - _TOKEN_KEYS)
        raise GovernedLaunchError(
            f"governed launch fields mismatch: missing={missing!r} extra={extra!r}"
        )
    if type(attestation.get("schema")) is not int or attestation["schema"] != SCHEMA:
        raise GovernedLaunchError("unsupported governed launch schema")
    if attestation.get("type") != TYPE:
        raise GovernedLaunchError("unexpected governed launch type")

    expected_identity = resolve_runner_identity(adapter, repo_root=repo_root)
    expected_workspace = canonical_worktree_path(workspace_path, worktree_root)
    expected = {
        "taskId": _text(task_id, "taskId"),
        "repository": _repository_identity(repository),
        "baseSha": _git_object_id(base_sha),
        "runId": _text(run_id, "runId"),
        "adapter": expected_identity.adapter,
        "runnerPath": expected_identity.runner_path,
        "runnerSha256": expected_identity.runner_sha256,
        "interpreterPath": expected_identity.interpreter_path,
        "interpreterSha256": expected_identity.interpreter_sha256,
        "workspacePath": expected_workspace,
        "allowedPaths": _paths(allowed_paths),
        "allowedTools": _tools(allowed_tools),
        "budgetUsd": _budget(budget_usd),
    }

    for field in ("runnerSha256", "interpreterSha256"):
        if not isinstance(attestation[field], str) or not _SHA256.fullmatch(attestation[field]):
            raise GovernedLaunchError(f"{field} must be lowercase SHA-256")

    issued = _timestamp(attestation["issuedAt"], "issuedAt")
    expires = _timestamp(attestation["expiresAt"], "expiresAt")
    current = time.time() if now is None else _timestamp(now, "now")
    if expires <= issued or expires - issued > MAX_TTL_SECONDS:
        raise GovernedLaunchError("governed launch TTL is invalid")
    if current < issued - 30:
        raise GovernedLaunchError("governed launch is not yet valid")
    if current >= expires:
        raise GovernedLaunchError("governed launch expired")

    signature = attestation["signature"]
    if not isinstance(signature, str) or not signature.startswith("hmac-sha256:"):
        raise GovernedLaunchError("governed launch signature is invalid")
    supplied = signature.split(":", 1)[1]
    if not _SHA256.fullmatch(supplied):
        raise GovernedLaunchError("governed launch signature is invalid")
    body = dict(attestation)
    body.pop("signature", None)
    wanted = hmac.new(launch_secret, canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, wanted):
        raise GovernedLaunchError("governed launch signature mismatch")

    mismatches = []
    for key, wanted_value in expected.items():
        got = attestation[key]
        if key in {"allowedPaths", "allowedTools"}:
            got = tuple(got) if isinstance(got, list) else got
        if got != wanted_value:
            mismatches.append(key)
    if mismatches:
        raise GovernedLaunchError(
            "governed launch binding mismatch: " + ",".join(mismatches)
        )

    identity = RunnerIdentity(
        adapter=expected_identity.adapter,
        runner_path=expected_identity.runner_path,
        runner_sha256=expected_identity.runner_sha256,
        interpreter_path=expected_identity.interpreter_path,
        interpreter_sha256=expected_identity.interpreter_sha256,
    )
    return VerifiedGovernedLaunch(
        task_id=expected["taskId"],
        repository=expected["repository"],
        base_sha=expected["baseSha"],
        run_id=expected["runId"],
        identity=identity,
        workspace_path=expected_workspace,
        allowed_paths=expected["allowedPaths"],
        allowed_tools=expected["allowedTools"],
        budget_usd=expected["budgetUsd"],
        issued_at=issued,
        expires_at=expires,
    )