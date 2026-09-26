from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from .governed_launch import runner_identity
from forgeboss.security.executor_guard import SecurityError, git as guarded_git, git_metadata_snapshot, no_remotes
from forgeboss.security.local_acl import harden_private_dir, harden_private_path


class GovernedHostLaunchError(RuntimeError):
    def __init__(self, message: str, *, release_safe: bool = True, quarantine: bool = False):
        super().__init__(message)
        self.release_safe = bool(release_safe)
        self.quarantine = bool(quarantine)


SENSITIVE_CHILD_ENV = {
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITHUB_PAT",
    "FORGEBOSS_DAEMON_SECRET",
    "FORGEBOSS_POLICY_APPROVAL_SECRET",
    "FORGEBOSS_GOVERNED_LAUNCH_SECRET",
}


def build_executor_packet(task: dict, current_head: str) -> dict:
    try:
        allowed = json.loads(task.get("allowed_paths_json") or "[]")
        required_tests = json.loads(task.get("required_tests_json") or "[]")
    except Exception as ex:
        raise GovernedHostLaunchError("task scope/test state is invalid JSON") from ex
    if not isinstance(allowed, list) or not allowed:
        raise GovernedHostLaunchError("governed task has no writable scope")
    if not isinstance(required_tests, list):
        raise GovernedHostLaunchError("governed task required tests are invalid")
    return {
        "schema": 1,
        "objective": str(task.get("purpose") or ""),
        "allowed_files": allowed,
        "context_files": [],
        "acceptance_criteria": required_tests,
        "expected_head_revision": str(current_head),
        "task_id": str(task.get("task_id") or ""),
        "governance_mode": str(task.get("governance_mode") or ""),
        "work_kind": str(task.get("work_kind") or ""),
        "subsystem": str(task.get("subsystem") or ""),
    }


def _write_private_packet(state_dir: Path, packet: dict) -> Path:
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    harden_private_dir(state_dir)
    fd, raw = tempfile.mkstemp(prefix="governed-packet-", suffix=".json", dir=str(state_dir))
    path = Path(raw)
    try:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(packet, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        harden_private_path(path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise
    return path


def _workspace_identity(workspace: Path) -> str:
    resolved = Path(workspace).resolve(strict=False)
    return os.path.normcase(os.path.normpath(str(resolved)))


def _quarantine_marker(state_dir: Path, workspace: Path) -> Path:
    root = Path(state_dir).parent / "workspace-quarantine"
    identity = _workspace_identity(workspace)
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return root / f"{digest}.json"


def quarantine_workspace(state_dir: Path, workspace: Path, reason: str) -> Path:
    marker = _quarantine_marker(state_dir, workspace)
    marker.parent.mkdir(parents=True, exist_ok=True)
    harden_private_dir(marker.parent)
    payload = {
        "schema": 1,
        "workspace": _workspace_identity(workspace),
        "reason": str(reason)[:2000],
        "quarantinedAt": time.time(),
    }
    fd, raw = tempfile.mkstemp(prefix=marker.name + ".tmp-", dir=str(marker.parent))
    temp = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        harden_private_path(temp)
        os.replace(temp, marker)
        harden_private_path(marker)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        temp.unlink(missing_ok=True)
        raise
    return marker


def _quarantine_or_fail_closed(state_dir: Path, workspace: Path, reason: str) -> Path:
    try:
        return quarantine_workspace(state_dir, workspace, reason)
    except Exception as ex:
        raise GovernedHostLaunchError(
            "workspace quarantine could not be persisted",
            release_safe=False,
            quarantine=True,
        ) from ex


def assert_governed_workspace_ready(state_dir: Path, workspace: Path) -> Path:
    try:
        work = Path(workspace).resolve(strict=True)
    except Exception as ex:
        raise GovernedHostLaunchError("governed workspace is missing or unresolved") from ex
    if not work.is_dir():
        raise GovernedHostLaunchError("governed workspace is not a directory")
    marker = _quarantine_marker(state_dir, work)
    if marker.exists():
        raise GovernedHostLaunchError(
            "governed workspace is quarantined after an earlier failed/uncertain run"
        )
    try:
        # Validate execution-capable Git metadata/config before invoking status.
        # This prevents the pristine probe itself from becoming a hook/fsmonitor
        # execution path.
        git_metadata_snapshot(work)
        no_remotes(work)
        dirty = guarded_git(
            work,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        )
    except SecurityError as ex:
        raise GovernedHostLaunchError(
            "unable to prove governed workspace is pristine: " + str(ex)
        ) from ex
    if dirty:
        raise GovernedHostLaunchError(
            "governed workspace must be pristine before paid launch"
        )
    return work


def _issue_executor_guard_lease(
    *,
    root: Path,
    packet_path: Path,
    workspace: Path,
    runtime_id: str,
    env: dict,
    timeout_seconds: int = 60,
) -> dict:
    guard = Path(root) / "forgeboss" / "security" / "executor_guard.py"
    try:
        guard = guard.resolve(strict=True)
    except FileNotFoundError as ex:
        raise GovernedHostLaunchError("executor guard is missing") from ex
    proc = subprocess.run(
        [
            sys.executable,
            str(guard),
            "issue",
            "--packet",
            str(packet_path),
            "--workspace",
            str(workspace),
            "--executor",
            runtime_id,
            "--ttl",
            "1800",
        ],
        cwd=str(Path(root).resolve()),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    if proc.returncode:
        raise GovernedHostLaunchError(
            "executor guard refused governed launch: "
            + ((proc.stdout or proc.stderr) or "")[-2000:]
        )
    try:
        line = [x for x in proc.stdout.splitlines() if x.strip()][-1]
        issued = json.loads(line)
    except Exception as ex:
        raise GovernedHostLaunchError("executor guard returned invalid lease output") from ex
    if issued.get("ok") is not True or not issued.get("lease") or not issued.get("token"):
        raise GovernedHostLaunchError("executor guard did not issue a usable lease")
    return issued


def resolve_workspace_head(workspace: Path) -> str:
    try:
        value = guarded_git(Path(workspace), "rev-parse", "HEAD")
    except SecurityError as ex:
        raise GovernedHostLaunchError("unable to resolve governed result HEAD") from ex
    if not value:
        raise GovernedHostLaunchError("governed result HEAD is empty")
    return value


DOCKER_ENV_KEYS = {
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
    "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    "DOCKER_HOST", "DOCKER_CONTEXT",
}


def _docker_env(env: dict) -> dict:
    return {key: value for key, value in env.items() if key in DOCKER_ENV_KEYS}


def _docker_workspace_containers(workspace: Path, env: dict) -> list[str]:
    safe_env = _docker_env(env)
    try:
        listed = subprocess.run(
            ["docker", "ps", "-aq"],
            env=safe_env,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except Exception as ex:
        raise GovernedHostLaunchError(
            "cannot prove Docker workspace isolation: docker inventory unavailable",
            release_safe=False,
            quarantine=True,
        ) from ex
    if listed.returncode:
        raise GovernedHostLaunchError(
            "cannot prove Docker workspace isolation: "
            + ((listed.stderr or listed.stdout) or "")[-1200:],
            release_safe=False,
            quarantine=True,
        )
    ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    if not ids:
        return []
    try:
        inspected = subprocess.run(
            ["docker", "inspect", *ids],
            env=safe_env,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as ex:
        raise GovernedHostLaunchError(
            "cannot inspect Docker containers for governed workspace",
            release_safe=False,
            quarantine=True,
        ) from ex
    if inspected.returncode:
        raise GovernedHostLaunchError(
            "cannot inspect Docker containers for governed workspace: "
            + ((inspected.stderr or inspected.stdout) or "")[-1200:],
            release_safe=False,
            quarantine=True,
        )
    try:
        rows = json.loads(inspected.stdout or "[]")
    except Exception as ex:
        raise GovernedHostLaunchError(
            "Docker inspection returned invalid JSON",
            release_safe=False,
            quarantine=True,
        ) from ex
    target = _workspace_identity(workspace)
    hits: list[str] = []
    for row in rows if isinstance(rows, list) else []:
        mounts = row.get("Mounts") if isinstance(row, dict) else None
        if not isinstance(mounts, list):
            continue
        for mount in mounts:
            source = mount.get("Source") if isinstance(mount, dict) else None
            if not isinstance(source, str) or not source:
                continue
            if os.path.normcase(os.path.normpath(source)) == target:
                ident = str(row.get("Id") or row.get("Name") or "").strip()
                if ident:
                    hits.append(ident)
                break
    return hits


def _ensure_workspace_containers_absent(workspace: Path, env: dict, *, force: bool) -> None:
    hits = _docker_workspace_containers(workspace, env)
    if hits and force:
        try:
            removed = subprocess.run(
                ["docker", "rm", "-f", *hits],
                env=_docker_env(env),
                capture_output=True,
                text=True,
                timeout=60,
            )
        except Exception as ex:
            raise GovernedHostLaunchError(
                "failed to stop governed Docker descendants",
                release_safe=False,
                quarantine=True,
            ) from ex
        if removed.returncode:
            raise GovernedHostLaunchError(
                "failed to stop governed Docker descendants: "
                + ((removed.stderr or removed.stdout) or "")[-1200:],
                release_safe=False,
                quarantine=True,
            )
        hits = _docker_workspace_containers(workspace, env)
    if hits:
        raise GovernedHostLaunchError(
            "governed Docker descendants still hold the workspace",
            release_safe=False,
            quarantine=True,
        )


def run_governed_worker(
    *,
    root: Path,
    state_dir: Path,
    task: dict,
    workspace: str,
    current_head: str,
    runtime_id: str,
    launch_envelope: dict,
    expected_runner_sha256: str,
    budget_usd: float,
    model: str | None,
    timeout_seconds: int = 1200,
) -> dict:
    if runtime_id != "mini-swe":
        raise GovernedHostLaunchError("only mini-swe is approved for governed host launch r0")
    root = Path(root).resolve()
    workspace_path = assert_governed_workspace_ready(Path(state_dir), Path(workspace))

    rel, actual_runner_sha = runner_identity(root, runtime_id)
    if actual_runner_sha != expected_runner_sha256:
        raise GovernedHostLaunchError("approved runner identity changed before host launch")
    runner = (root / rel).resolve(strict=True)

    packet = build_executor_packet(task, current_head)
    packet_path = _write_private_packet(Path(state_dir), packet)
    try:
        allowed_host_env = {
            "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
            "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
            "DOCKER_HOST", "DOCKER_CONTEXT", "OPENAI_API_KEY", "LLM_API_KEY",
        }
        child_env = {k: v for k, v in os.environ.items() if k in allowed_host_env}
        for key in SENSITIVE_CHILD_ENV:
            child_env.pop(key, None)
        child_env["FORGEBOSS_ALLOW_PAID_EXECUTOR"] = "YES"
        child_env["FORGEBOSS_GOVERNED_RUN"] = "YES"
        child_env["FORGEBOSS_EXPECTED_RUNNER_SHA256"] = expected_runner_sha256
        child_env["FORGEBOSS_CONTROL_ENVELOPE"] = json.dumps(
            launch_envelope, sort_keys=True, separators=(",", ":")
        )
        if model:
            child_env["FORGEBOSS_MINISWE_MODEL"] = str(model)
        for key in ("GH_TOKEN", "GITHUB_TOKEN", "GITHUB_PAT"):
            child_env.pop(key, None)

        # A governed workspace must not already be held by any Docker container.
        _ensure_workspace_containers_absent(workspace_path, child_env, force=False)

        issued = _issue_executor_guard_lease(
            root=root,
            packet_path=packet_path,
            workspace=workspace_path,
            runtime_id=runtime_id,
            env=child_env,
        )
        child_env["FORGEBOSS_EXECUTOR_LEASE"] = str(issued["lease"])
        child_env["FORGEBOSS_EXECUTOR_LEASE_TOKEN"] = str(issued["token"])
        child_env["FORGEBOSS_PYTHON"] = sys.executable

        # Re-check the exact runner immediately before spawning it.
        _, final_runner_sha = runner_identity(root, runtime_id)
        if final_runner_sha != expected_runner_sha256:
            raise GovernedHostLaunchError("approved runner identity changed at spawn boundary")

        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(runner),
                    str(packet_path),
                    str(workspace_path),
                    str(float(budget_usd)),
                ],
                cwd=str(root),
                env=child_env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as ex:
            cleanup_error = None
            try:
                _ensure_workspace_containers_absent(workspace_path, child_env, force=True)
            except GovernedHostLaunchError as cleanup:
                cleanup_error = cleanup
            _quarantine_or_fail_closed(
                Path(state_dir),
                workspace_path,
                "governed worker timeout; workspace requires owner reconciliation",
            )
            if cleanup_error is not None:
                raise GovernedHostLaunchError(
                    "governed worker timed out and Docker descendant cleanup could not be proven",
                    release_safe=False,
                    quarantine=True,
                ) from cleanup_error
            raise GovernedHostLaunchError(
                "governed worker exceeded host launch timeout",
                release_safe=False,
                quarantine=True,
            ) from ex
        except Exception as ex:
            cleanup_error = None
            try:
                _ensure_workspace_containers_absent(workspace_path, child_env, force=True)
            except GovernedHostLaunchError as cleanup:
                cleanup_error = cleanup
            if cleanup_error is not None:
                _quarantine_or_fail_closed(
                    Path(state_dir),
                    workspace_path,
                    "worker spawn failed and Docker cleanup could not be proven",
                )
                raise GovernedHostLaunchError(
                    "governed worker spawn failed and Docker descendant cleanup could not be proven",
                    release_safe=False,
                    quarantine=True,
                ) from cleanup_error
            raise GovernedHostLaunchError("governed worker spawn failed: " + str(ex)) from ex

        try:
            _ensure_workspace_containers_absent(workspace_path, child_env, force=True)
        except GovernedHostLaunchError as ex:
            _quarantine_or_fail_closed(
                Path(state_dir),
                workspace_path,
                "worker exited but Docker descendant cleanup could not be proven",
            )
            raise GovernedHostLaunchError(
                str(ex),
                release_safe=False,
                quarantine=True,
            ) from ex

        if int(proc.returncode) != 0:
            _quarantine_or_fail_closed(
                Path(state_dir),
                workspace_path,
                f"governed worker failed with return code {int(proc.returncode)}",
            )

        return {
            "returncode": int(proc.returncode),
            "stdout_tail": (proc.stdout or "")[-4000:],
            "stderr_tail": (proc.stderr or "")[-4000:],
            "result_head": resolve_workspace_head(workspace_path),
            "runner_relpath": rel,
            "runner_sha256": final_runner_sha,
        }
    finally:
        try:
            packet_path.unlink(missing_ok=True)
        except OSError:
            # The packet is private and contains no provider secret. Do not let
            # cleanup failure mask a stronger worker/quarantine safety result.
            pass
