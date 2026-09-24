from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from .governed_launch import runner_identity
from forgeboss.security.local_acl import harden_private_dir,harden_private_path


class GovernedHostLaunchError(RuntimeError):
    pass


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
        harden_private_path(path)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(packet, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise
    return path


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
    p = subprocess.run(
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
        ],
        cwd=str(Path(root).resolve()),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    if p.returncode:
        raise GovernedHostLaunchError(
            "executor guard refused governed launch: " + ((p.stdout or p.stderr) or "")[-2000:]
        )
    try:
        line = [x for x in p.stdout.splitlines() if x.strip()][-1]
        issued = json.loads(line)
    except Exception as ex:
        raise GovernedHostLaunchError("executor guard returned invalid lease output") from ex
    if issued.get("ok") is not True or not issued.get("lease") or not issued.get("token"):
        raise GovernedHostLaunchError("executor guard did not issue a usable lease")
    return issued


def resolve_workspace_head(workspace: Path) -> str:
    p = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(workspace),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if p.returncode:
        raise GovernedHostLaunchError("unable to resolve governed result HEAD")
    value = p.stdout.strip()
    if not value:
        raise GovernedHostLaunchError("governed result HEAD is empty")
    return value


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
    workspace_path = Path(workspace).resolve(strict=True)
    if not workspace_path.is_dir():
        raise GovernedHostLaunchError("governed workspace is not a directory")

    rel, actual_runner_sha = runner_identity(root, runtime_id)
    if actual_runner_sha != expected_runner_sha256:
        raise GovernedHostLaunchError("approved runner identity changed before host launch")
    runner = (root / rel).resolve(strict=True)

    packet = build_executor_packet(task, current_head)
    packet_path = _write_private_packet(Path(state_dir), packet)
    try:
        allowed_host_env = {
            "PATH","PATHEXT","SYSTEMROOT","WINDIR","COMSPEC","TEMP","TMP",
            "USERPROFILE","HOME","APPDATA","LOCALAPPDATA","PROGRAMDATA",
            "DOCKER_HOST","DOCKER_CONTEXT","OPENAI_API_KEY","LLM_API_KEY",
            "FORGEBOSS_MINISWE_IMAGE",
        }
        child_env = {k:v for k,v in os.environ.items() if k in allowed_host_env}
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
        return {
            "returncode": int(proc.returncode),
            "stdout_tail": (proc.stdout or "")[-4000:],
            "stderr_tail": (proc.stderr or "")[-4000:],
            "result_head": resolve_workspace_head(workspace_path),
            "runner_relpath": rel,
            "runner_sha256": final_runner_sha,
        }
    except subprocess.TimeoutExpired as ex:
        raise GovernedHostLaunchError("governed worker exceeded host launch timeout") from ex
    finally:
        packet_path.unlink(missing_ok=True)
