from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
from pathlib import Path

from .envelope import canonical

SCHEMA = 1
KIND = "forgeboss-governed-launch"
MAX_TTL_SECONDS = 600
_RUNTIME_RUNNERS = {
    "mini-swe": {
        "path": "forgeboss/executors/mini_swe_runner.py",
        "sha256": "be7d59991ee55b5b999dc14ede809647f843a19d8506b11d8b15777fc24cd2bc",
    },
}
_REQUIRED = {
    "schema",
    "kind",
    "taskId",
    "repository",
    "baseSha",
    "runId",
    "worktreePath",
    "runtimeId",
    "runnerRelpath",
    "runnerSha256",
    "allowedPaths",
    "allowedTools",
    "provider",
    "model",
    "budgetUsd",
    "issuedAt",
    "expiresAt",
    "nonce",
    "signature",
}


class GovernedLaunchAttestationError(ValueError):
    pass


def _runner_path(root: Path, runtime_id: str) -> tuple[str, Path]:
    entry = _RUNTIME_RUNNERS.get(str(runtime_id or ""))
    if not entry:
        raise GovernedLaunchAttestationError("runtime is not approved for governed launch attestation")
    rel = entry["path"]
    root = Path(root).resolve()
    candidate = root / rel
    current = root
    for part in Path(rel).parts:
        current = current / part
        if current.is_symlink():
            raise GovernedLaunchAttestationError("governed runner path contains a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as ex:
        raise GovernedLaunchAttestationError("governed runner is missing") from ex
    expected = candidate.absolute()
    if resolved != expected:
        raise GovernedLaunchAttestationError("governed runner path resolved unexpectedly")
    if not resolved.is_file():
        raise GovernedLaunchAttestationError("governed runner is not a regular file")
    return rel, resolved


def runner_identity(root: Path, runtime_id: str) -> tuple[str, str]:
    rel, path = _runner_path(root, runtime_id)
    text = path.read_text(encoding="utf-8").replace("\r\n","\n").replace("\r","\n")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    expected = _RUNTIME_RUNNERS[str(runtime_id)]["sha256"]
    if not hmac.compare_digest(digest, expected):
        raise GovernedLaunchAttestationError("governed runner does not match reviewed SHA-256")
    return rel, digest


def _normalise_paths(values):
    if not isinstance(values, list) or not values:
        raise GovernedLaunchAttestationError("allowedPaths must be a non-empty array")
    out = []
    seen = set()
    for value in values:
        if not isinstance(value, str) or not value or value != value.strip():
            raise GovernedLaunchAttestationError("allowedPaths contains invalid value")
        key = value.replace("\\", "/").casefold()
        if key in seen:
            raise GovernedLaunchAttestationError("allowedPaths contains duplicate aliases")
        seen.add(key)
        out.append(value.replace("\\", "/"))
    return out


def _normalise_tools(values):
    if not isinstance(values, list):
        raise GovernedLaunchAttestationError("allowedTools must be an array")
    out = []
    seen = set()
    for value in values:
        if not isinstance(value, str) or not value or value != value.strip():
            raise GovernedLaunchAttestationError("allowedTools contains invalid value")
        if value in seen:
            raise GovernedLaunchAttestationError("allowedTools contains duplicates")
        seen.add(value)
        out.append(value)
    return out


def _finite_budget(value):
    try:
        budget = float(value)
    except Exception as ex:
        raise GovernedLaunchAttestationError("budgetUsd must be numeric") from ex
    if not math.isfinite(budget) or budget < 0:
        raise GovernedLaunchAttestationError("budgetUsd must be finite and non-negative")
    return budget


def issue_governed_launch_attestation(
    *,
    root: Path,
    secret: bytes,
    task_id: str,
    repository: str,
    base_sha: str,
    run_id: str,
    worktree_path: str,
    runtime_id: str,
    allowed_paths,
    allowed_tools,
    provider=None,
    model=None,
    budget_usd=0.0,
    ttl_seconds=120,
    now=None,
    nonce=None,
):
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
        raise GovernedLaunchAttestationError("launch attestation secret is invalid")
    now = time.time() if now is None else float(now)
    ttl = int(ttl_seconds)
    if ttl <= 0 or ttl > MAX_TTL_SECONDS:
        raise GovernedLaunchAttestationError("launch attestation ttl is out of range")
    rel, runner_sha = runner_identity(root, runtime_id)
    body = {
        "schema": SCHEMA,
        "kind": KIND,
        "taskId": str(task_id),
        "repository": str(repository),
        "baseSha": str(base_sha),
        "runId": str(run_id),
        "worktreePath": str(Path(worktree_path).resolve(strict=False)),
        "runtimeId": str(runtime_id),
        "runnerRelpath": rel,
        "runnerSha256": runner_sha,
        "allowedPaths": _normalise_paths(allowed_paths),
        "allowedTools": _normalise_tools(allowed_tools),
        "provider": None if provider is None else str(provider),
        "model": None if model is None else str(model),
        "budgetUsd": _finite_budget(budget_usd),
        "issuedAt": now,
        "expiresAt": now + ttl,
        "nonce": str(nonce or hashlib.sha256(f"{task_id}:{run_id}:{now}".encode("utf-8")).hexdigest()[:32]),
    }
    sig = hmac.new(bytes(secret), canonical(body), hashlib.sha256).hexdigest()
    body["signature"] = "hmac-sha256:" + sig
    return body


def verify_governed_launch_attestation(
    attestation,
    *,
    root: Path,
    secret: bytes,
    task_id: str,
    repository: str,
    base_sha: str,
    run_id: str,
    worktree_path: str,
    runtime_id: str,
    allowed_paths,
    allowed_tools,
    provider=None,
    model=None,
    budget_usd=0.0,
    now=None,
):
    if not isinstance(attestation, dict):
        raise GovernedLaunchAttestationError("launch attestation must be an object")
    if set(attestation) != _REQUIRED:
        raise GovernedLaunchAttestationError("launch attestation fields are not canonical")
    if attestation.get("schema") != SCHEMA or attestation.get("kind") != KIND:
        raise GovernedLaunchAttestationError("unsupported launch attestation")
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
        raise GovernedLaunchAttestationError("launch attestation secret is invalid")

    sig = attestation.get("signature")
    if not isinstance(sig, str) or not sig.startswith("hmac-sha256:"):
        raise GovernedLaunchAttestationError("launch attestation signature is invalid")
    unsigned = dict(attestation)
    unsigned.pop("signature")
    want = hmac.new(bytes(secret), canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig.split(":", 1)[1], want):
        raise GovernedLaunchAttestationError("launch attestation signature mismatch")

    now = time.time() if now is None else float(now)
    try:
        issued = float(attestation["issuedAt"])
        expires = float(attestation["expiresAt"])
    except Exception as ex:
        raise GovernedLaunchAttestationError("launch attestation time fields are invalid") from ex
    if not math.isfinite(issued) or not math.isfinite(expires):
        raise GovernedLaunchAttestationError("launch attestation time fields are invalid")
    if issued > now + 5:
        raise GovernedLaunchAttestationError("launch attestation issued in the future")
    if expires <= now:
        raise GovernedLaunchAttestationError("launch attestation expired")
    if expires <= issued or expires - issued > MAX_TTL_SECONDS:
        raise GovernedLaunchAttestationError("launch attestation ttl is invalid")

    rel, runner_sha = runner_identity(root, runtime_id)
    expected = {
        "taskId": str(task_id),
        "repository": str(repository),
        "baseSha": str(base_sha),
        "runId": str(run_id),
        "worktreePath": str(Path(worktree_path).resolve(strict=False)),
        "runtimeId": str(runtime_id),
        "runnerRelpath": rel,
        "runnerSha256": runner_sha,
        "allowedPaths": _normalise_paths(allowed_paths),
        "allowedTools": _normalise_tools(allowed_tools),
        "provider": None if provider is None else str(provider),
        "model": None if model is None else str(model),
        "budgetUsd": _finite_budget(budget_usd),
    }
    for key, value in expected.items():
        if attestation.get(key) != value:
            raise GovernedLaunchAttestationError(f"launch attestation binding mismatch: {key}")
    if not isinstance(attestation.get("nonce"), str) or len(attestation["nonce"]) < 16:
        raise GovernedLaunchAttestationError("launch attestation nonce is invalid")
    return unsigned
