from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from types import MappingProxyType
import uuid

from forgeboss.control.envelope import canonical
from forgeboss.control.governed_launch import (
    GovernedLaunchError,
    issue_governed_launch_attestation,
    resolve_runner_identity,
)
from forgeboss.control.store import _scope_authorities
from forgeboss.security.executor_guard import SecurityError, issue_lease, validate_packet


class GovernedLauncherError(RuntimeError):
    """Raised when a governed task cannot be prepared for trusted execution."""


@dataclass(frozen=True)
class PreparedGovernedLaunch:
    task_id: str
    run_id: str
    adapter: str
    authoritative_head: str
    argv: tuple[str, ...]
    env: MappingProxyType
    launch_envelope: MappingProxyType
    executor_lease_path: str
    executor_lease_token: str


def _packet(path: str | Path) -> tuple[Path, dict]:
    p = Path(path)
    try:
        resolved = p.resolve(strict=True)
    except OSError as ex:
        raise GovernedLauncherError(f"packet is unavailable: {p}") from ex
    if not resolved.is_file():
        raise GovernedLauncherError("packet must be a regular file")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as ex:
        raise GovernedLauncherError("packet must be valid UTF-8 JSON") from ex
    if not isinstance(value, dict):
        raise GovernedLauncherError("packet root must be an object")
    return resolved, value


def _authoritative_head(task: dict) -> str:
    value = str(task.get("result_head") or task.get("base_sha") or "").strip()
    if not value:
        raise GovernedLauncherError("task has no authoritative head")
    return value


def _packet_head(packet: dict) -> str:
    exact = packet.get("expected_head_revision")
    alternate = packet.get("exact_head")
    if exact and alternate and str(exact) != str(alternate):
        raise GovernedLauncherError("packet contains conflicting exact-head fields")
    value = exact or alternate
    if not isinstance(value, str) or not value.strip():
        raise GovernedLauncherError("governed packet requires exact_head/expected_head_revision")
    return value.strip()


def _same_scope_subset(packet_paths, task_paths) -> bool:
    packet = set(_scope_authorities(list(packet_paths)))
    task = set(_scope_authorities(list(task_paths)))
    return bool(packet) and packet.issubset(task)


def prepare_governed_launch(
    daemon,
    *,
    task_id: str,
    packet_path: str | Path,
    workspace_path: str | Path,
    adapter: str,
    allowed_tools,
    budget_usd: object,
    ttl_seconds: int = 300,
) -> PreparedGovernedLaunch:
    task = daemon.store.get_task(task_id)
    if not task:
        raise GovernedLauncherError("task not found")
    if task.get("governance_mode") != "reuse-v1":
        raise GovernedLauncherError("task is not governed by reuse-v1")

    packet_file, packet = _packet(packet_path)
    objective = packet.get("objective")
    if not isinstance(objective, str) or objective != task.get("purpose"):
        raise GovernedLauncherError("packet objective differs from canonical task purpose")

    try:
        allowed, _ = validate_packet(packet)
    except SecurityError as ex:
        raise GovernedLauncherError(f"packet scope is invalid: {ex}") from ex

    try:
        task_paths = json.loads(task.get("allowed_paths_json") or "[]")
    except json.JSONDecodeError as ex:
        raise GovernedLauncherError("task allowed-path state is invalid") from ex
    if not _same_scope_subset(allowed, task_paths):
        raise GovernedLauncherError("packet writable scope exceeds canonical task scope")

    authoritative_head = _authoritative_head(task)
    if _packet_head(packet) != authoritative_head:
        raise GovernedLauncherError("packet exact head differs from canonical task head")

    run_id = uuid.uuid4().hex
    try:
        identity = resolve_runner_identity(adapter, repo_root=daemon.ROOT if hasattr(daemon, "ROOT") else Path(__file__).resolve().parents[2])
    except GovernedLaunchError:
        # ForgeBossDaemon exposes ROOT at module level rather than instance state.
        from forgeboss.control import daemon as daemon_module
        try:
            identity = resolve_runner_identity(adapter, repo_root=daemon_module.ROOT)
        except GovernedLaunchError as ex:
            raise GovernedLauncherError(str(ex)) from ex

    from forgeboss.control import daemon as daemon_module
    worktree_root = daemon_module.WORKTREE_ROOT
    repo_root = daemon_module.ROOT

    try:
        launch_attestation = issue_governed_launch_attestation(
            task_id=task["task_id"],
            repository=task["repository"],
            base_sha=task["base_sha"],
            run_id=run_id,
            adapter=adapter,
            repo_root=repo_root,
            workspace_path=workspace_path,
            worktree_root=worktree_root,
            allowed_paths=allowed,
            allowed_tools=allowed_tools,
            budget_usd=budget_usd,
            secret=daemon.launch_secret,
            ttl_seconds=ttl_seconds,
        )
    except Exception as ex:
        if isinstance(ex, GovernedLauncherError):
            raise
        raise GovernedLauncherError(f"cannot mint governed launch attestation: {ex}") from ex

    # Executor-security preflight happens before budget/workspace mutation.
    try:
        executor_lease = issue_lease(
            packet_file,
            workspace_path,
            adapter,
            ttl=ttl_seconds,
        )
    except SecurityError as ex:
        raise GovernedLauncherError(f"executor-security preflight denied launch: {ex}") from ex

    request = {
        "method": "workspace.claim",
        "idempotencyKey": uuid.uuid4().hex,
        "params": {
            "taskId": task["task_id"],
            "repository": task["repository"],
            "baseSha": task["base_sha"],
            "allowedPaths": list(allowed),
            "allowedTools": list(allowed_tools),
            "worktreePath": str(Path(workspace_path).resolve()),
            "runId": run_id,
            "currentHead": authoritative_head,
            "ttlSeconds": ttl_seconds,
            "runtimeId": adapter,
            "budgetUsd": budget_usd,
            "governedLaunchAttestation": launch_attestation,
        },
    }
    try:
        claimed = daemon.dispatch(request, True)
    except Exception as ex:
        raise GovernedLauncherError(f"governed workspace claim failed: {ex}") from ex

    envelope = claimed.get("launchEnvelope")
    if not isinstance(envelope, dict):
        raise GovernedLauncherError("daemon did not return a signed launch envelope")

    runtime = envelope.get("runtime")
    if not isinstance(runtime, dict):
        raise GovernedLauncherError("launch envelope runtime identity is missing")
    for field, expected in (
        ("adapter", identity.adapter),
        ("runnerPath", identity.runner_path),
        ("runnerSha256", identity.runner_sha256),
        ("interpreterPath", identity.interpreter_path),
        ("interpreterSha256", identity.interpreter_sha256),
    ):
        if runtime.get(field) != expected:
            raise GovernedLauncherError(f"launch envelope runtime identity mismatch: {field}")

    envelope_text = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    env = MappingProxyType({
        "FORGEBOSS_ALLOW_PAID_EXECUTOR": "YES",
        "FORGEBOSS_GOVERNED_LAUNCH": "YES",
        "FORGEBOSS_EXECUTOR_LEASE": str(executor_lease["lease"]),
        "FORGEBOSS_EXECUTOR_LEASE_TOKEN": str(executor_lease["token"]),
        "FORGEBOSS_CONTROL_ENVELOPE": envelope_text,
        "FORGEBOSS_PYTHON": identity.interpreter_path,
    })
    argv = (
        identity.interpreter_path,
        identity.runner_path,
        str(packet_file),
        str(Path(workspace_path).resolve()),
        str(budget_usd),
    )
    return PreparedGovernedLaunch(
        task_id=task["task_id"],
        run_id=run_id,
        adapter=identity.adapter,
        authoritative_head=authoritative_head,
        argv=argv,
        env=env,
        launch_envelope=MappingProxyType(dict(envelope)),
        executor_lease_path=str(executor_lease["lease"]),
        executor_lease_token=str(executor_lease["token"]),
    )
