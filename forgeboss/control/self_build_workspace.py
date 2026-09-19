from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from forgeboss.control.project_runtime import ProjectRuntimeError, assert_write_not_live_root

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
DEFAULT_WORKTREE_ROOT = Path.home() / ".forgeboss" / "worktrees" / "self-build"
DEFAULT_STATE_ROOT = Path.home() / ".forgeboss" / "self-build" / "workspaces"


class SelfBuildWorkspaceError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git(cwd: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    git = shutil.which("git")
    if not git:
        raise SelfBuildWorkspaceError("git is unavailable")
    try:
        return subprocess.run(
            [git, "-C", str(cwd), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SelfBuildWorkspaceError(f"git command failed to start: {' '.join(args)}") from exc


def _git_ok(cwd: Path, *args: str, timeout: int = 60) -> str:
    p = _git(cwd, *args, timeout=timeout)
    if p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip()
        raise SelfBuildWorkspaceError(
            f"git {' '.join(args)} failed with exit {p.returncode}: {detail[:1200]}"
        )
    return (p.stdout or "").strip()


def _atomic_write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _validate_base_sha(live_root: Path, base_sha: str) -> str:
    sha = str(base_sha or "").strip().lower()
    if not SHA_RE.fullmatch(sha):
        raise SelfBuildWorkspaceError("base_sha must be an exact 40-hex commit SHA")
    resolved = _git_ok(live_root, "rev-parse", "--verify", f"{sha}^{{commit}}").lower()
    if resolved != sha:
        raise SelfBuildWorkspaceError(
            f"requested base SHA resolved to different commit: requested={sha} resolved={resolved}"
        )
    return sha


def _safe_external_path(path: Path, live_root: Path) -> Path:
    try:
        return assert_write_not_live_root(path, live_root=live_root)
    except ProjectRuntimeError as exc:
        raise SelfBuildWorkspaceError(str(exc)) from exc


def create_successor_workspace(
    live_root: str | os.PathLike[str],
    base_sha: str,
    *,
    worktree_root: Path | None = None,
    state_root: Path | None = None,
    workspace_id: str | None = None,
) -> dict:
    live = Path(live_root).expanduser().resolve(strict=True)
    if not live.is_dir():
        raise SelfBuildWorkspaceError(f"live root is not a directory: {live}")

    top = Path(_git_ok(live, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if os.path.normcase(str(top)) != os.path.normcase(str(live)):
        raise SelfBuildWorkspaceError(
            f"live root must be the effective Git worktree root: live={live} git={top}"
        )

    sha = _validate_base_sha(live, base_sha)

    wid = workspace_id or uuid.uuid4().hex
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,80}", wid):
        raise SelfBuildWorkspaceError("workspace_id contains unsafe characters or length")

    wt_root = Path(worktree_root or DEFAULT_WORKTREE_ROOT).expanduser()
    st_root = Path(state_root or DEFAULT_STATE_ROOT).expanduser()
    workspace = wt_root / wid
    receipt_path = st_root / f"{wid}.json"
    branch = f"forgeboss/selfbuild/{wid}"

    _safe_external_path(wt_root, live)
    _safe_external_path(st_root, live)
    _safe_external_path(workspace, live)
    _safe_external_path(receipt_path, live)

    if workspace.exists():
        raise SelfBuildWorkspaceError(f"successor workspace already exists: {workspace}")

    branch_check = _git(live, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}")
    if branch_check.returncode == 0:
        raise SelfBuildWorkspaceError(f"successor branch already exists: {branch}")

    wt_root.mkdir(parents=True, exist_ok=True)
    st_root.mkdir(parents=True, exist_ok=True)

    worktree_created = False
    branch_created = False
    try:
        _git_ok(live, "worktree", "add", "-b", branch, str(workspace), sha, timeout=120)
        worktree_created = True
        branch_created = True

        effective = Path(_git_ok(workspace, "rev-parse", "--show-toplevel")).resolve(strict=True)
        expected = workspace.resolve(strict=True)
        if os.path.normcase(str(effective)) != os.path.normcase(str(expected)):
            raise SelfBuildWorkspaceError(
                f"successor worktree identity mismatch: expected={expected} effective={effective}"
            )

        head = _git_ok(workspace, "rev-parse", "HEAD").lower()
        if head != sha:
            raise SelfBuildWorkspaceError(
                f"successor HEAD mismatch: expected={sha} actual={head}"
            )

        status = _git_ok(workspace, "status", "--porcelain=v1", "--untracked-files=all")
        if status:
            raise SelfBuildWorkspaceError(
                f"successor workspace is not pristine immediately after creation: {status[:800]}"
            )

        receipt = {
            "schema": 1,
            "workspace_id": wid,
            "live_root": str(live),
            "worktree_root": str(expected),
            "branch": branch,
            "base_sha": sha,
            "head_sha": head,
            "created_at": _now(),
            "network_used": False,
            "status": "READY",
        }
        _atomic_write_json(receipt_path, receipt)
        receipt["receipt_path"] = str(receipt_path.resolve())
        return receipt
    except Exception:
        if worktree_created:
            _git(live, "worktree", "remove", "--force", str(workspace), timeout=120)
        if branch_created:
            _git(live, "branch", "-D", branch, timeout=60)
        if workspace.exists():
            _safe_external_path(workspace, live)
            shutil.rmtree(workspace, ignore_errors=True)
        raise
