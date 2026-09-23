from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
from types import MappingProxyType
from typing import Mapping
import uuid

from forgeboss.control.client import Client
from forgeboss.control.envelope import (
    launch_secret_file,
    secret_file,
    verify_envelope,
)
from forgeboss.control.governed_launch import (
    GovernedLaunchError,
    issue_governed_launch_attestation,
    resolve_runner_identity,
)
from forgeboss.control.store import (
    _git_object_id,
    _repository_identity,
    _scope_authorities,
    canonical_worktree_path,
)
from forgeboss.security.executor_guard import (
    SecurityError,
    issue_lease,
    validate_packet,
)


class GovernedLauncherError(RuntimeError):
    """Raised when trusted governed launch preparation cannot fail safely."""


def _reject_duplicate_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise GovernedLauncherError(f"duplicate JSON object key: {key!r}")
        out[key] = value
    return out


def _reject_json_constant(value: str):
    raise GovernedLauncherError(f"non-standard JSON constant is forbidden: {value}")


def _freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({str(k): _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


R0_ADAPTER = "mini-swe"
R0_ALLOWED_TOOLS = ("docker",)
_PROVIDER_KEYS = MappingProxyType({
    "openai": frozenset({"OPENAI_API_KEY", "LLM_API_KEY"}),
    "anthropic": frozenset({"ANTHROPIC_API_KEY"}),
    "google": frozenset({"GEMINI_API_KEY", "GOOGLE_API_KEY"}),
    "openrouter": frozenset({"OPENROUTER_API_KEY"}),
})


@dataclass(frozen=True)
class PreparedGovernedLaunch:
    task_id: str
    run_id: str
    adapter: str
    provider: str
    model: str
    packet_sha256: str
    workspace_path: str
    current_head: str
    budget_usd: str
    owner_epoch: int
    argv: tuple[str, ...]
    authority_env: Mapping[str, str] = field(repr=False)
    executor_lease_path: str = field(repr=False)
    launch_envelope: Mapping[str, object] = field(repr=False)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise GovernedLauncherError(f"{label} must be a string")
    clean = value.strip()
    if not clean:
        raise GovernedLauncherError(f"{label} is required")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
        raise GovernedLauncherError(f"{label} contains control characters")
    return clean


def _budget(value: object) -> tuple[Decimal, str]:
    if isinstance(value, bool):
        raise GovernedLauncherError("budget_usd must be finite and positive")
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as ex:
        raise GovernedLauncherError("budget_usd must be finite and positive") from ex
    if not amount.is_finite() or amount <= 0:
        raise GovernedLauncherError("budget_usd must be finite and positive")
    normalized = amount.normalize()
    text = format(normalized, "f")
    return amount, text


def _task_budget_remaining(task: Mapping[str, object]) -> Decimal:
    try:
        allocated = Decimal(str(task["budget_allocated"]))
        spent = Decimal(str(task["budget_spent"]))
    except (KeyError, InvalidOperation, TypeError, ValueError) as ex:
        raise GovernedLauncherError("canonical task budget state is invalid") from ex
    if not allocated.is_finite() or not spent.is_finite() or allocated < 0 or spent < 0 or spent > allocated:
        raise GovernedLauncherError("canonical task budget state is invalid")
    return allocated - spent


def _packet(path: str | Path, task: Mapping[str, object]) -> tuple[Path, dict[str, object], str, tuple[str, ...]]:
    p = Path(path)
    try:
        resolved = p.resolve(strict=True)
    except OSError as ex:
        raise GovernedLauncherError("packet file is unavailable") from ex
    if not resolved.is_file() or p.is_symlink():
        raise GovernedLauncherError("packet must be a non-symlink regular file")
    try:
        raw = resolved.read_bytes()
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as ex:
        raise GovernedLauncherError("packet must be valid UTF-8 JSON") from ex
    if not isinstance(document, dict):
        raise GovernedLauncherError("packet root must be an object")

    objective = document.get("objective")
    if objective != task.get("purpose"):
        raise GovernedLauncherError("packet objective differs from canonical task purpose")

    heads = [
        document.get("expected_head_revision"),
        document.get("exact_head"),
    ]
    present = [str(x) for x in heads if x is not None and str(x)]
    if not present:
        raise GovernedLauncherError("packet must bind expected_head_revision or exact_head")
    if len(set(present)) != 1:
        raise GovernedLauncherError("packet contains conflicting head identities")
    try:
        packet_head = _git_object_id(present[0])
        current_head = _git_object_id(task.get("result_head") or task.get("base_sha"))
    except Exception as ex:
        raise GovernedLauncherError("packet/task head identity is invalid") from ex
    if packet_head != current_head:
        raise GovernedLauncherError("packet head differs from canonical task head")

    try:
        allowed, _ = validate_packet(document)
    except SecurityError as ex:
        raise GovernedLauncherError(f"packet scope is invalid: {ex}") from ex
    task_scope = tuple(sorted(_scope_authorities(task.get("allowed_paths_json"))))
    packet_scope = tuple(sorted(_scope_authorities(list(allowed))))
    if packet_scope != task_scope:
        raise GovernedLauncherError("packet writable scope differs from canonical task scope")
    try:
        raw_task_scope = task.get("allowed_paths_json")
        if isinstance(raw_task_scope, str):
            raw_task_scope = json.loads(raw_task_scope)
        task_allowed, _ = validate_packet({"allowed_files": raw_task_scope or [], "context_files": []})
    except Exception as ex:
        raise GovernedLauncherError("canonical task writable scope cannot be normalized safely") from ex
    task_spelling = tuple(sorted(x.casefold() for x in task_allowed))
    packet_spelling = tuple(sorted(x.casefold() for x in allowed))
    if packet_spelling != task_spelling:
        raise GovernedLauncherError(
            "packet/task writable scope uses ambiguous alias spelling; normalize task scope before launch"
        )

    return resolved, document, hashlib.sha256(raw).hexdigest(), tuple(allowed)


def _provider_env(provider: str, values: Mapping[str, object]) -> Mapping[str, str]:
    clean_provider = _text(provider, "provider").casefold()
    allowed = _PROVIDER_KEYS.get(clean_provider)
    if allowed is None:
        raise GovernedLauncherError(f"provider is not enabled in trusted launcher R0: {clean_provider}")
    if not isinstance(values, Mapping):
        raise GovernedLauncherError("provider_env must be a mapping")
    unknown = sorted(set(values) - set(allowed))
    if unknown:
        raise GovernedLauncherError(
            "provider_env contains non-allowlisted keys: " + ",".join(unknown)
        )
    out: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(value, str) or not value:
            raise GovernedLauncherError(f"{key} must be a non-empty string")
        if value != value.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise GovernedLauncherError(f"{key} contains invalid whitespace/control characters")
        out[str(key)] = value
    if not out:
        raise GovernedLauncherError("provider_env must contain an approved provider credential")
    return MappingProxyType(out)


def _verify_executor_lease_artifact(
    lease_obj: Mapping[str, object],
    *,
    repo_root: str | Path,
    packet_sha256: str,
    workspace: Path,
    adapter: str,
    allowed_paths: tuple[str, ...],
) -> tuple[str, str]:
    if lease_obj.get("ok") is not True:
        raise GovernedLauncherError("executor lease issuer did not return ok=true")
    lease_raw = _text(lease_obj.get("lease"), "executor lease path")
    token = _text(lease_obj.get("token"), "executor lease token")
    if len(token) < 32:
        raise GovernedLauncherError("executor lease token is too short")
    raw_path = Path(lease_raw)
    try:
        state = (Path(repo_root).resolve(strict=True) / "state" / "executor-security").resolve(strict=False)
        if raw_path.is_symlink():
            raise GovernedLauncherError("executor lease file must not be a symlink")
        lease_path = raw_path.resolve(strict=True)
    except GovernedLauncherError:
        raise
    except Exception as ex:
        raise GovernedLauncherError("executor lease file is unavailable") from ex
    try:
        if os.path.commonpath((str(state), str(lease_path))) != str(state):
            raise GovernedLauncherError("executor lease escaped ForgeBoss executor-security state")
    except ValueError as ex:
        raise GovernedLauncherError("executor lease path identity is invalid") from ex
    if not lease_path.is_file():
        raise GovernedLauncherError("executor lease must be a regular file")
    try:
        lease = json.loads(
            lease_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except GovernedLauncherError:
        raise
    except Exception as ex:
        raise GovernedLauncherError("executor lease file is invalid JSON") from ex
    if not isinstance(lease, dict):
        raise GovernedLauncherError("executor lease root must be an object")
    if lease.get("schema") != 3:
        raise GovernedLauncherError("executor lease schema is unsupported")
    if lease.get("executor") != adapter:
        raise GovernedLauncherError("executor lease adapter mismatch")
    try:
        if Path(str(lease.get("workspace"))).resolve() != workspace:
            raise GovernedLauncherError("executor lease workspace mismatch")
    except GovernedLauncherError:
        raise
    except Exception as ex:
        raise GovernedLauncherError("executor lease workspace is invalid") from ex
    if str(lease.get("packet_sha256") or "").lower() != packet_sha256:
        raise GovernedLauncherError("executor lease packet hash mismatch")
    lease_scope = tuple(sorted(_scope_authorities(lease.get("allowed_files"))))
    expected_scope = tuple(sorted(_scope_authorities(list(allowed_paths))))
    if lease_scope != expected_scope:
        raise GovernedLauncherError("executor lease writable scope mismatch")
    supplied_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(str(lease.get("token_sha256") or ""), supplied_token_hash):
        raise GovernedLauncherError("executor lease token identity mismatch")
    try:
        expires_at = float(lease.get("expires_at"))
    except Exception as ex:
        raise GovernedLauncherError("executor lease expiry is invalid") from ex
    if expires_at <= time.time():
        raise GovernedLauncherError("executor lease is already expired")
    if lease.get("isolation_verified") is not True:
        raise GovernedLauncherError("executor lease isolation proof is missing")
    if lease.get("paid_consumed") is True:
        raise GovernedLauncherError("executor lease paid authority is already consumed")
    return str(lease_path), token


def _cleanup_executor_lease(lease_obj: Mapping[str, object] | None, repo_root: str | Path) -> None:
    if not lease_obj:
        return
    raw = lease_obj.get("lease")
    if not isinstance(raw, str) or not raw:
        return
    try:
        p = Path(raw).resolve(strict=False)
        state = (Path(repo_root).resolve(strict=False) / "state" / "executor-security").resolve(strict=False)
        if os.path.commonpath((str(state), str(p))) == str(state) and p.is_file():
            p.unlink()
    except Exception:
        pass


def _release_claim(client, task_id: str, run_id: str, owner_epoch: int, current_head: str) -> None:
    try:
        client.call(
            "workspace.release",
            {
                "taskId": task_id,
                "runId": run_id,
                "ownerEpoch": owner_epoch,
                "resultHead": current_head,
                "outcome": "queued",
                "expectedHead": current_head,
            },
        )
    except Exception:
        pass


def prepare_governed_launch(
    *,
    client,
    repo_root: str | Path,
    worktree_root: str | Path,
    task_id: str,
    packet_path: str | Path,
    workspace_path: str | Path,
    budget_usd: object,
    provider: str,
    model: str,
    provider_env: Mapping[str, object],
    daemon_secret: bytes,
    launch_secret: bytes,
    lease_issuer=issue_lease,
) -> PreparedGovernedLaunch:
    if not hasattr(client, "call"):
        raise GovernedLauncherError("client must provide call()")
    if not isinstance(daemon_secret, (bytes, bytearray)) or len(daemon_secret) < 32:
        raise GovernedLauncherError("daemon_secret must be at least 32 bytes")
    if not isinstance(launch_secret, (bytes, bytearray)) or len(launch_secret) < 32:
        raise GovernedLauncherError("launch_secret must be at least 32 bytes")
    if hmac.compare_digest(bytes(daemon_secret), bytes(launch_secret)):
        raise GovernedLauncherError("daemon and governed-launch key material must differ")

    clean_task_id = _text(task_id, "task_id")
    clean_provider = _text(provider, "provider").casefold()
    clean_model = _text(model, "model")
    if not clean_model.casefold().startswith(clean_provider + "/"):
        raise GovernedLauncherError("model identifier must be explicitly namespaced by provider")
    credentials = _provider_env(clean_provider, provider_env)

    try:
        task = client.call("task.get", {"taskId": clean_task_id}, mutation=False)
    except Exception as ex:
        raise GovernedLauncherError(f"unable to read canonical task: {ex}") from ex
    if not isinstance(task, Mapping):
        raise GovernedLauncherError("canonical task response is invalid")
    if task.get("task_id") != clean_task_id:
        raise GovernedLauncherError("canonical task identity mismatch")
    if task.get("governance_mode") != "reuse-v1":
        raise GovernedLauncherError("task is not governed by reuse-v1")
    if task.get("status") != "queued":
        raise GovernedLauncherError("trusted launcher R0 requires a queued task")
    if task.get("cancel_requested_at") is not None:
        raise GovernedLauncherError("task cancellation has been requested")

    repository_raw = _text(task.get("repository"), "canonical task repository")
    try:
        _repository_identity(repository_raw)
        base_sha = _git_object_id(task.get("base_sha"))
        current_head = _git_object_id(task.get("result_head") or base_sha)
        task_scope = tuple(sorted(_scope_authorities(task.get("allowed_paths_json"))))
    except Exception as ex:
        raise GovernedLauncherError("canonical task authority state is invalid") from ex
    if not task_scope:
        raise GovernedLauncherError("canonical task has empty writable scope")

    requested_budget, budget_text = _budget(budget_usd)
    if requested_budget > _task_budget_remaining(task):
        raise GovernedLauncherError("requested launch budget exceeds canonical task remaining budget")

    packet, packet_document, packet_sha256, packet_allowed = _packet(packet_path, task)
    try:
        workspace = Path(canonical_worktree_path(workspace_path, worktree_root))
    except Exception as ex:
        raise GovernedLauncherError("workspace path is outside the trusted worktree root") from ex
    try:
        workspace = workspace.resolve(strict=True)
    except OSError as ex:
        raise GovernedLauncherError("workspace is unavailable") from ex
    if not workspace.is_dir():
        raise GovernedLauncherError("workspace must be a directory")
    try:
        if os.path.commonpath((str(workspace), str(packet))) == str(workspace):
            raise GovernedLauncherError("authority packet must live outside the writable workspace")
    except ValueError as ex:
        raise GovernedLauncherError("packet/workspace path identity is invalid") from ex

    identity = resolve_runner_identity(R0_ADAPTER, repo_root=repo_root)
    run_id = uuid.uuid4().hex

    lease_obj = None
    claim = None
    try:
        try:
            lease_obj = lease_issuer(packet, workspace, R0_ADAPTER, 1200)
        except Exception as ex:
            raise GovernedLauncherError(f"executor lease preparation failed: {ex}") from ex
        if not isinstance(lease_obj, Mapping):
            raise GovernedLauncherError("executor lease issuer returned invalid result")
        lease_path, lease_token = _verify_executor_lease_artifact(
            lease_obj,
            repo_root=repo_root,
            packet_sha256=packet_sha256,
            workspace=workspace,
            adapter=R0_ADAPTER,
            allowed_paths=packet_allowed,
        )

        attestation = issue_governed_launch_attestation(
            task_id=clean_task_id,
            repository=repository_raw,
            base_sha=base_sha,
            run_id=run_id,
            adapter=R0_ADAPTER,
            provider=clean_provider,
            model=clean_model,
            packet_sha256=packet_sha256,
            repo_root=repo_root,
            workspace_path=workspace,
            worktree_root=worktree_root,
            allowed_paths=packet_allowed,
            allowed_tools=R0_ALLOWED_TOOLS,
            budget_usd=budget_text,
            secret=bytes(launch_secret),
            ttl_seconds=300,
        )

        claim_params = {
            "taskId": clean_task_id,
            "repository": repository_raw,
            "baseSha": base_sha,
            "branch": task.get("branch"),
            "allowedPaths": list(packet_allowed),
            "allowedTools": list(R0_ALLOWED_TOOLS),
            "worktreePath": str(workspace),
            "runId": run_id,
            "currentHead": current_head,
            "ttlSeconds": 1200,
            "runtimeId": R0_ADAPTER,
            "provider": clean_provider,
            "model": clean_model,
            "packetSha256": packet_sha256,
            "budgetUsd": float(requested_budget),
            "governedLaunchAttestation": attestation,
        }
        try:
            claim = client.call("workspace.claim", claim_params)
        except Exception as ex:
            raise GovernedLauncherError(f"governed workspace claim failed: {ex}") from ex
        if not isinstance(claim, Mapping):
            raise GovernedLauncherError("workspace claim response is invalid")
        lease = claim.get("lease")
        envelope = claim.get("launchEnvelope")
        if not isinstance(lease, Mapping) or not isinstance(envelope, dict):
            raise GovernedLauncherError("workspace claim response is incomplete")

        if str(lease.get("task_id")) != clean_task_id:
            raise GovernedLauncherError("workspace claim returned wrong task identity")
        if str(lease.get("owner_run_id")) != run_id:
            raise GovernedLauncherError("workspace claim returned wrong run identity")
        owner_epoch = int(lease.get("owner_epoch"))
        if owner_epoch <= 0:
            raise GovernedLauncherError("workspace claim returned invalid owner epoch")
        if Path(str(lease.get("worktree_path"))).resolve() != workspace:
            raise GovernedLauncherError("workspace claim returned different workspace")
        if Decimal(str(lease.get("budget_reserved"))) != requested_budget:
            raise GovernedLauncherError("workspace claim returned different budget reservation")
        if str(lease.get("current_head")) != current_head:
            raise GovernedLauncherError("workspace claim returned different head")
        if lease.get("released_at") is not None:
            raise GovernedLauncherError("workspace claim returned an already released lease")
        try:
            if float(lease.get("expires_at")) <= time.time():
                raise GovernedLauncherError("workspace claim returned an expired lease")
        except GovernedLauncherError:
            raise
        except Exception as ex:
            raise GovernedLauncherError("workspace claim returned invalid expiry") from ex

        try:
            verified = verify_envelope(envelope, bytes(daemon_secret))
        except Exception as ex:
            raise GovernedLauncherError("daemon-signed launch envelope verification failed") from ex
        expected_runtime = {
            "adapter": R0_ADAPTER,
            "provider": clean_provider,
            "model": clean_model,
            "runnerPath": identity.runner_path,
            "runnerSha256": identity.runner_sha256,
            "interpreterPath": identity.interpreter_path,
            "interpreterSha256": identity.interpreter_sha256,
        }
        checks = {
            "taskId": clean_task_id,
            "repository": repository_raw,
            "baseSha": base_sha,
            "worktreePath": str(workspace),
            "runId": run_id,
            "packetSha256": packet_sha256,
        }
        for key, value in checks.items():
            if verified.get(key) != value:
                raise GovernedLauncherError(f"signed launch envelope mismatch: {key}")
        if verified.get("runtime") != expected_runtime:
            raise GovernedLauncherError("signed launch envelope runtime identity mismatch")
        if tuple(sorted(_scope_authorities(verified.get("allowedPaths")))) != task_scope:
            raise GovernedLauncherError("signed launch envelope writable scope mismatch")
        if tuple(sorted(str(x) for x in verified.get("allowedTools", []))) != tuple(sorted(R0_ALLOWED_TOOLS)):
            raise GovernedLauncherError("signed launch envelope tool metadata mismatch")
        if Decimal(str(verified.get("budgetUsd"))) != requested_budget:
            raise GovernedLauncherError("signed launch envelope budget mismatch")
        if int(verified.get("ownerEpoch")) != owner_epoch:
            raise GovernedLauncherError("signed launch envelope owner epoch mismatch")

        try:
            admitted = client.call(
                "worker.admit",
                {"envelope": envelope, "expectedHead": current_head},
            )
        except Exception as ex:
            raise GovernedLauncherError(f"worker admission failed: {ex}") from ex
        if not isinstance(admitted, Mapping) or admitted.get("admitted") is not True:
            raise GovernedLauncherError("worker admission was not confirmed")
        if admitted.get("taskId") != clean_task_id or admitted.get("runId") != run_id:
            raise GovernedLauncherError("worker admission identity mismatch")
        if int(admitted.get("ownerEpoch")) != owner_epoch:
            raise GovernedLauncherError("worker admission owner epoch mismatch")

        authority_env = dict(credentials)
        authority_env.update({
            "FORGEBOSS_ALLOW_PAID_EXECUTOR": "YES",
            "FORGEBOSS_GOVERNED_LAUNCH": "YES",
            "FORGEBOSS_CONTROL_ENVELOPE": json.dumps(
                envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ),
            "FORGEBOSS_EXECUTOR_LEASE": lease_path,
            "FORGEBOSS_EXECUTOR_LEASE_TOKEN": lease_token,
            "FORGEBOSS_PYTHON": identity.interpreter_path,
            "FORGEBOSS_MINISWE_MODEL": clean_model,
        })
        forbidden = {
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GITHUB_PAT",
            "FORGEBOSS_DAEMON_SECRET",
            "FORGEBOSS_POLICY_SECRET",
            "FORGEBOSS_LAUNCH_SECRET",
        }
        if forbidden.intersection(authority_env):
            raise GovernedLauncherError("forbidden secret key reached child environment")

        argv = (
            identity.interpreter_path,
            identity.runner_path,
            str(packet),
            str(workspace),
            budget_text,
        )
        return PreparedGovernedLaunch(
            task_id=clean_task_id,
            run_id=run_id,
            adapter=R0_ADAPTER,
            provider=clean_provider,
            model=clean_model,
            packet_sha256=packet_sha256,
            workspace_path=str(workspace),
            current_head=current_head,
            budget_usd=budget_text,
            owner_epoch=owner_epoch,
            argv=argv,
            authority_env=MappingProxyType(authority_env),
            executor_lease_path=lease_path,
            launch_envelope=_freeze(envelope),
        )
    except Exception as ex:
        if claim and isinstance(claim, Mapping) and isinstance(claim.get("lease"), Mapping):
            try:
                epoch = int(claim["lease"].get("owner_epoch"))
                _release_claim(client, clean_task_id, run_id, epoch, current_head)
            except Exception:
                pass
        _cleanup_executor_lease(lease_obj, repo_root)
        if isinstance(ex, GovernedLauncherError):
            raise
        raise GovernedLauncherError(
            f"trusted launch preparation failed: {type(ex).__name__}: {ex}"
        ) from ex


def prepare_local_governed_launch(
    *,
    task_id: str,
    packet_path: str | Path,
    workspace_path: str | Path,
    budget_usd: object,
    provider: str,
    model: str,
    provider_env: Mapping[str, object],
    repo_root: str | Path | None = None,
    worktree_root: str | Path | None = None,
) -> PreparedGovernedLaunch:
    root = Path(repo_root or Path(__file__).resolve().parents[2]).resolve(strict=True)
    worktrees = Path(
        worktree_root
        or os.environ.get("FORGEBOSS_WORKTREE_ROOT")
        or root / "state" / "forgebossd" / "worktrees"
    ).resolve(strict=False)
    daemon_path, daemon_secret = secret_file(root)
    launch_path, launch_secret = launch_secret_file(root)
    if daemon_path.resolve() == launch_path.resolve() or hmac.compare_digest(daemon_secret, launch_secret):
        raise GovernedLauncherError("daemon and governed-launch key separation failed")
    client = Client()
    try:
        return prepare_governed_launch(
            client=client,
            repo_root=root,
            worktree_root=worktrees,
            task_id=task_id,
            packet_path=packet_path,
            workspace_path=workspace_path,
            budget_usd=budget_usd,
            provider=provider,
            model=model,
            provider_env=provider_env,
            daemon_secret=daemon_secret,
            launch_secret=launch_secret,
        )
    finally:
        client.close()