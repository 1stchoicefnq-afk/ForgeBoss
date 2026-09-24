from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

from .governed_launch import runner_identity
from forgeboss.security.local_acl import harden_private_dir,harden_private_path


class GovernedHostLaunchError(RuntimeError):
    pass

class GovernedHostLaunchCancelled(GovernedHostLaunchError):
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
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(packet, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        harden_private_path(path)
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


def _signal_cancel(path: Path) -> None:
    path=Path(path)
    try:
        fd=os.open(str(path),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:
            os.write(fd,b"cancel\n");os.fsync(fd)
        finally:
            os.close(fd)
        harden_private_path(path)
    except FileExistsError:
        return


def _finish_process(proc,grace_seconds=8):
    try:
        return proc.communicate(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:proc.terminate()
        except Exception:pass
        try:return proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:proc.kill()
            except Exception:pass
            return proc.communicate()


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
    cancel_event=None,
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
    state_dir=Path(state_dir)
    packet_path = _write_private_packet(state_dir, packet)
    cancel_path=state_dir/("cancel-"+secrets.token_hex(16)+".signal")
    try:
        allowed_host_env = {
            "PATH","PATHEXT","SYSTEMROOT","WINDIR","COMSPEC","TEMP","TMP",
            "USERPROFILE","HOME","APPDATA","LOCALAPPDATA","PROGRAMDATA",
            "DOCKER_HOST","DOCKER_CONTEXT","OPENAI_API_KEY","LLM_API_KEY",
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
        child_env["FORGEBOSS_CANCEL_FILE"] = str(cancel_path)
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

        if cancel_event is not None and cancel_event.is_set():
            _signal_cancel(cancel_path)
            raise GovernedHostLaunchCancelled("governed run cancelled before worker spawn")

        proc = subprocess.Popen(
            [
                sys.executable,
                str(runner),
                str(packet_path),
                str(workspace_path),
                str(float(budget_usd)),
            ],
            cwd=str(root),
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        started=time.monotonic();cancelled=False;timed_out=False
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled=True;_signal_cancel(cancel_path);break
            if time.monotonic()-started>=timeout_seconds:
                timed_out=True;_signal_cancel(cancel_path);break
            time.sleep(.1)
        stdout,stderr=_finish_process(proc) if proc.poll() is None else proc.communicate()
        if cancelled:
            raise GovernedHostLaunchCancelled("governed run cancelled")
        if timed_out:
            raise GovernedHostLaunchError("governed worker exceeded host launch timeout")
        return {
            "returncode": int(proc.returncode),
            "stdout_tail": (stdout or "")[-4000:],
            "stderr_tail": (stderr or "")[-4000:],
            "result_head": resolve_workspace_head(workspace_path),
            "runner_relpath": rel,
            "runner_sha256": final_runner_sha,
        }
    finally:
        cancel_path.unlink(missing_ok=True)
        packet_path.unlink(missing_ok=True)
