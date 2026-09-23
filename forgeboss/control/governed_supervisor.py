from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import uuid

from forgeboss.control.envelope import verify_envelope
from forgeboss.control.governed_launch import issue_governed_launch_attestation, resolve_runner_identity
from forgeboss.security.executor_guard import SecurityError, _assert_live_control_lease, issue_lease, revoke_lease


class GovernedSupervisorError(RuntimeError):
    pass


@dataclass(frozen=True)
class GovernedRunResult:
    task_id: str
    run_id: str
    exit_code: int | None
    revoked: bool
    revoke_reason: str | None
    stdout_tail: str
    stderr_tail: str
    duration_seconds: float
    finalization_error: str | None


class _BoundedText:
    def __init__(self, limit: int = 32768):
        self.limit = limit
        self.parts = deque()
        self.size = 0
        self.lock = threading.Lock()

    def append(self, text: str) -> None:
        with self.lock:
            self.parts.append(text)
            self.size += len(text)
            while self.size > self.limit and self.parts:
                first = self.parts.popleft()
                self.size -= len(first)

    def value(self) -> str:
        with self.lock:
            return "".join(self.parts)[-self.limit:]


def _reader(stream, sink: _BoundedText):
    try:
        for chunk in iter(lambda: stream.read(4096), ""):
            if not chunk:
                break
            sink.append(chunk)
    finally:
        try: stream.close()
        except Exception: pass


def _posix_group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _tree_alive(proc: subprocess.Popen) -> bool:
    if os.name == "nt":
        # Portable Python cannot prove descendant liveness after the direct parent exits.
        # Native Windows job-object acceptance remains a separate gate.
        return proc.poll() is None
    return _posix_group_alive(proc.pid)


def _kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        if not proc.pid:
            return
        result = subprocess.run(
            ["taskkill.exe", "/pid", str(proc.pid), "/t", "/f"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.poll() is None and result.returncode != 0:
            try:
                proc.kill()
            except Exception:
                pass
        return

    if not proc.pid:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.time() + 1.5
    while _posix_group_alive(proc.pid) and time.time() < deadline:
        time.sleep(0.05)
    if _posix_group_alive(proc.pid):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        deadline = time.time() + 1.5
        while _posix_group_alive(proc.pid) and time.time() < deadline:
            time.sleep(0.05)


def _validated_openai_credentials(
    provider: str,
    model: str,
    credential_env: dict[str, str] | None,
) -> dict[str, str]:
    if provider != "openai":
        raise GovernedSupervisorError("R0 supervisor supports provider=openai only")
    if not isinstance(model, str) or not model.startswith("openai/"):
        raise GovernedSupervisorError("R0 mini-swe model must use the openai/ provider prefix")
    supplied = dict(credential_env or {})
    if set(supplied) != {"OPENAI_API_KEY"}:
        raise GovernedSupervisorError(
            "R0 governed launch requires exactly OPENAI_API_KEY and no other provider credentials"
        )
    value = supplied["OPENAI_API_KEY"]
    if not isinstance(value, str) or not value.strip() or any(ch in value for ch in "\r\n\x00"):
        raise GovernedSupervisorError("OPENAI_API_KEY is invalid")
    return {"OPENAI_API_KEY": value}


def supervise_governed_run(
    daemon,
    *,
    task_id: str,
    packet_path: str | Path,
    workspace_path: str | Path,
    allowed_tools: list[str],
    adapter: str,
    provider: str,
    model: str,
    budget_usd: float,
    credential_env: dict[str, str] | None = None,
    poll_seconds: float = 0.25,
) -> GovernedRunResult:
    if adapter != "mini-swe":
        raise GovernedSupervisorError("R0 supervisor supports mini-swe only")
    if poll_seconds <= 0 or poll_seconds > 5:
        raise GovernedSupervisorError("poll_seconds must be between 0 and 5 seconds")
    provider_credentials = _validated_openai_credentials(provider, model, credential_env)

    task = daemon.store.get_task(task_id)
    if not task:
        raise GovernedSupervisorError("task not found")
    if task.get("governance_mode") != "reuse-v1":
        raise GovernedSupervisorError("task is not governed")
    if task.get("cancel_requested_at") is not None:
        raise GovernedSupervisorError("task cancellation already requested")

    packet_path = Path(packet_path).resolve(strict=True)
    workspace = Path(workspace_path).resolve(strict=True)
    packet_sha = hashlib.sha256(packet_path.read_bytes()).hexdigest()
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    allowed_paths = packet.get("allowed_files") or []
    if not allowed_paths:
        raise GovernedSupervisorError("packet has no allowed_files")
    expected = packet.get("expected_head_revision") or packet.get("exact_head") or task["base_sha"]
    if str(expected) != str(task["base_sha"]):
        raise GovernedSupervisorError("packet/base task identity mismatch")

    run_id = uuid.uuid4().hex
    identity = resolve_runner_identity(adapter, repo_root=daemon.ROOT if hasattr(daemon, "ROOT") else Path(__file__).resolve().parents[2])

    attestation = issue_governed_launch_attestation(
        task_id=task_id,
        repository=task["repository"],
        base_sha=task["base_sha"],
        run_id=run_id,
        adapter=adapter,
        provider=provider,
        model=model,
        packet_sha256=packet_sha,
        repo_root=Path(__file__).resolve().parents[2],
        workspace_path=workspace,
        worktree_root=Path(os.environ.get("FORGEBOSS_WORKTREE_ROOT") or (Path(__file__).resolve().parents[2]/"state"/"forgebossd"/"worktrees")).resolve(),
        allowed_paths=allowed_paths,
        allowed_tools=allowed_tools,
        budget_usd=budget_usd,
        secret=daemon.launch_secret,
        ttl_seconds=300,
    )

    claim = daemon.dispatch({
        "method":"workspace.claim",
        "idempotencyKey":uuid.uuid4().hex,
        "params":{
            "taskId":task_id,
            "repository":task["repository"],
            "baseSha":task["base_sha"],
            "allowedPaths":allowed_paths,
            "allowedTools":allowed_tools,
            "worktreePath":str(workspace),
            "runId":run_id,
            "currentHead":task.get("result_head") or task["base_sha"],
            "ttlSeconds":900,
            "runtimeId":adapter,
            "provider":provider,
            "model":model,
            "packetSha256":packet_sha,
            "budgetUsd":budget_usd,
            "governedLaunchAttestation":attestation,
        }
    }, True)
    lease = claim["lease"]
    control_envelope = claim["launchEnvelope"]

    executor_lease = None
    proc = None
    try:
        executor_lease = issue_lease(packet_path, workspace, adapter, ttl=900)
    except Exception as ex:
        try:
            daemon.store.release(
                task_id,run_id,int(lease["owner_epoch"]),
                result_head=lease["current_head"],outcome="failed",respect_cancel=True
            )
        except Exception as release_ex:
            raise GovernedSupervisorError(
                f"executor lease creation failed ({ex}); workspace release also failed ({release_ex})"
            ) from ex
        raise GovernedSupervisorError(f"executor lease creation failed: {ex}") from ex

    env = {
        "PATH": os.environ.get("PATH",""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT",""),
        "WINDIR": os.environ.get("WINDIR",""),
        "TEMP": os.environ.get("TEMP",""),
        "TMP": os.environ.get("TMP",""),
        "FORGEBOSS_ALLOW_PAID_EXECUTOR":"YES",
        "FORGEBOSS_GOVERNED_LAUNCH":"YES",
        "FORGEBOSS_CONTROL_ENVELOPE":json.dumps(control_envelope,separators=(",",":")),
        "FORGEBOSS_EXECUTOR_LEASE":executor_lease["lease"],
        "FORGEBOSS_EXECUTOR_LEASE_TOKEN":executor_lease["token"],
        "FORGEBOSS_MINISWE_MODEL":model,
    }
    env.update(provider_credentials)

    argv=[identity.interpreter_path, identity.runner_path, str(packet_path), str(workspace), str(budget_usd)]
    flags=getattr(subprocess,"CREATE_NEW_PROCESS_GROUP",0)|getattr(subprocess,"CREATE_NO_WINDOW",0) if os.name=="nt" else 0
    try:
        proc=subprocess.Popen(
            argv,
            cwd=str(Path(__file__).resolve().parents[2]),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            creationflags=flags,
            start_new_session=(os.name!="nt"),
        )
    except Exception as ex:
        cleanup_errors=[]
        try:
            revoked_lease=revoke_lease(
                executor_lease["lease"],executor_lease["token"],workspace,adapter
            )
            if not revoked_lease.get("removed",False):
                cleanup_errors.append("executor lease removal failed: "+str(revoked_lease.get("error")))
        except Exception as lease_ex:
            cleanup_errors.append("executor lease revoke failed: "+str(lease_ex))
        try:
            daemon.store.release(
                task_id,run_id,int(lease["owner_epoch"]),
                result_head=lease["current_head"],outcome="failed",respect_cancel=True
            )
        except Exception as release_ex:
            cleanup_errors.append("workspace release failed: "+str(release_ex))
        if cleanup_errors:
            raise GovernedSupervisorError(
                f"runner start failed ({ex}); cleanup errors: {'; '.join(cleanup_errors)}"
            ) from ex
        raise GovernedSupervisorError(f"runner start failed: {ex}") from ex
    out=_BoundedText(); err=_BoundedText()
    t1=threading.Thread(target=_reader,args=(proc.stdout,out),daemon=True)
    t2=threading.Thread(target=_reader,args=(proc.stderr,err),daemon=True)
    t1.start(); t2.start()

    authority=verify_envelope(control_envelope,daemon.secret)
    started=time.time()
    revoked=False
    reason=None
    monitor_error=None
    try:
        while proc.poll() is None:
            try:
                _assert_live_control_lease(authority,adapter)
            except SecurityError as ex:
                revoked=True; reason=str(ex); _kill_tree(proc); break
            time.sleep(poll_seconds)

        if os.name!="nt" and _tree_alive(proc):
            revoked=True
            reason=reason or "runner exited while descendant process group remained alive"
            _kill_tree(proc)

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            revoked=True
            reason=reason or "runner did not terminate"
            _kill_tree(proc)
            proc.wait(timeout=10)
    except BaseException as ex:
        monitor_error=ex
        revoked=True
        reason=reason or f"supervisor interrupted: {type(ex).__name__}"
        try:
            _kill_tree(proc)
        except Exception:
            pass
    finally:
        t1.join(timeout=2); t2.join(timeout=2)

    finalization_errors=[]
    try:
        revoked_lease=revoke_lease(
            executor_lease["lease"],executor_lease["token"],workspace,adapter
        )
        if not revoked_lease.get("removed",False):
            finalization_errors.append(
                "executor lease removal failed: "+str(revoked_lease.get("error"))
            )
    except Exception as ex:
        finalization_errors.append(f"executor lease revoke failed: {type(ex).__name__}: {ex}")

    try:
        release_result=daemon.store.release(
            task_id,run_id,int(lease["owner_epoch"]),
            result_head=lease["current_head"],
            outcome="cancelled" if revoked else ("completed" if proc.returncode==0 else "failed"),
            respect_cancel=True,
        )
        if release_result and release_result.get("outcome")=="cancelled" and not revoked:
            revoked=True
            reason=reason or "task cancellation requested before finalization"
    except Exception as ex:
        finalization_errors.append(f"workspace release failed: {type(ex).__name__}: {ex}")

    finalization_error="; ".join(finalization_errors) if finalization_errors else None
    if monitor_error is not None:
        if finalization_error and hasattr(monitor_error,"add_note"):
            monitor_error.add_note(finalization_error)
        raise monitor_error

    return GovernedRunResult(
        task_id=task_id,
        run_id=run_id,
        exit_code=proc.returncode,
        revoked=revoked,
        revoke_reason=reason,
        stdout_tail=out.value(),
        stderr_tail=err.value(),
        duration_seconds=round(time.time()-started,3),
        finalization_error=finalization_error,
    )