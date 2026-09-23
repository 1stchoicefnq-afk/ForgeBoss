from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from forgeboss.control.project_runtime import ProjectRuntimeError, assert_write_not_live_root
from forgeboss.security.executor_guard import (
    SecurityError,
    _git_executable_identity,
    _resolve_git_executable,
    git_metadata_snapshot,
)
from forgeboss.security.local_acl import LocalAclError, harden_private_dir

SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
DEFAULT_WORKTREE_ROOT = Path.home() / ".forgeboss" / "worktrees" / "self-build"
DEFAULT_STATE_ROOT = Path.home() / ".forgeboss" / "self-build" / "workspaces"


class SelfBuildWorkspaceError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _trusted_git_identity() -> dict:
    try:
        return _git_executable_identity()
    except SecurityError as exc:
        raise SelfBuildWorkspaceError(f"trusted Git executable unavailable: {exc}") from exc


def _git_environment() -> dict[str, str]:
    env = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def _git(
    cwd: Path,
    *args: str,
    timeout: int = 60,
    hooks_dir: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        git = _resolve_git_executable()
    except SecurityError as exc:
        raise SelfBuildWorkspaceError(f"trusted Git executable unavailable: {exc}") from exc
    command = [str(git), "-C", str(cwd)]
    if hooks_dir is not None:
        command.extend(["-c", f"core.hooksPath={hooks_dir}"])
    command.extend(args)
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=_git_environment(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SelfBuildWorkspaceError(f"git command failed to start: {' '.join(args)}") from exc


def _git_ok(
    cwd: Path,
    *args: str,
    timeout: int = 60,
    hooks_dir: Path | None = None,
) -> str:
    p = _git(cwd, *args, timeout=timeout, hooks_dir=hooks_dir)
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


def _same_or_descendant(path: Path, root: Path) -> bool:
    a = os.path.normcase(os.path.normpath(str(path)))
    b = os.path.normcase(os.path.normpath(str(root)))
    try:
        return os.path.commonpath([a, b]) == b
    except ValueError:
        return False


def _metadata_digest(metadata: dict) -> str:
    encoded = json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validated_git_metadata(root: Path) -> dict:
    try:
        return git_metadata_snapshot(root)
    except SecurityError as exc:
        raise SelfBuildWorkspaceError(
            f"unsafe Git execution/config state: {exc}"
        ) from exc


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

    git_identity_before = _trusted_git_identity()
    source_git_metadata = _validated_git_metadata(live)
    sha = _validate_base_sha(live, base_sha)

    wid = workspace_id or uuid.uuid4().hex
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,80}", wid):
        raise SelfBuildWorkspaceError("workspace_id contains unsafe characters or length")

    wt_root = _safe_external_path(Path(worktree_root or DEFAULT_WORKTREE_ROOT).expanduser(), live)
    st_root = _safe_external_path(Path(state_root or DEFAULT_STATE_ROOT).expanduser(), live)
    workspace = _safe_external_path(wt_root / wid, live)
    receipt_path = _safe_external_path(st_root / f"{wid}.json", live)
    branch = f"forgeboss/selfbuild/{wid}"

    if _same_or_descendant(receipt_path, workspace):
        raise SelfBuildWorkspaceError(
            "self-build state/receipt path must not be inside successor workspace"
        )

    if workspace.exists():
        raise SelfBuildWorkspaceError(f"successor workspace already exists: {workspace}")

    branch_check = _git(live, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}")
    if branch_check.returncode == 0:
        raise SelfBuildWorkspaceError(f"successor branch already exists: {branch}")

    try:
        harden_private_dir(wt_root)
        harden_private_dir(st_root)
    except LocalAclError as exc:
        raise SelfBuildWorkspaceError(
            f"cannot harden self-build state/worktree roots: {exc}"
        ) from exc

    worktree_created = False
    branch_created = False
    hooks_parent = st_root / "hooks"
    try:
        harden_private_dir(hooks_parent)
    except LocalAclError as exc:
        raise SelfBuildWorkspaceError(f"cannot harden hooks state: {exc}") from exc

    try:
        with tempfile.TemporaryDirectory(prefix=f"{wid}-", dir=str(hooks_parent)) as hooks_temp:
            hooks_dir = Path(hooks_temp)
            if any(hooks_dir.iterdir()):
                raise SelfBuildWorkspaceError("private hooks directory is not empty")

            _git_ok(
                live,
                "worktree",
                "add",
                "-b",
                branch,
                str(workspace),
                sha,
                timeout=120,
                hooks_dir=hooks_dir,
            )
            worktree_created = True
            branch_created = True

            effective = Path(
                _git_ok(
                    workspace,
                    "rev-parse",
                    "--show-toplevel",
                    hooks_dir=hooks_dir,
                )
            ).resolve(strict=True)
            expected = workspace.resolve(strict=True)
            if os.path.normcase(str(effective)) != os.path.normcase(str(expected)):
                raise SelfBuildWorkspaceError(
                    f"successor worktree identity mismatch: expected={expected} effective={effective}"
                )

            head = _git_ok(
                workspace,
                "rev-parse",
                "HEAD",
                hooks_dir=hooks_dir,
            ).lower()
            if head != sha:
                raise SelfBuildWorkspaceError(
                    f"successor HEAD mismatch: expected={sha} actual={head}"
                )

            status = _git_ok(
                workspace,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                hooks_dir=hooks_dir,
            )
            if status:
                raise SelfBuildWorkspaceError(
                    f"successor workspace is not pristine immediately after creation: {status[:800]}"
                )

            successor_git_metadata = _validated_git_metadata(workspace)
            git_identity_after = _trusted_git_identity()
            if git_identity_after != git_identity_before:
                raise SelfBuildWorkspaceError(
                    "trusted Git executable identity changed during successor creation"
                )

            receipt = {
                "schema": 2,
                "workspace_id": wid,
                "live_root": str(live),
                "worktree_root": str(expected),
                "branch": branch,
                "base_sha": sha,
                "head_sha": head,
                "created_at": _now(),
                "network_policy": "LOCAL_ONLY",
                "network_used": False,
                "git_executable_sha256": git_identity_after["sha256"],
                "source_git_metadata_sha256": _metadata_digest(source_git_metadata),
                "successor_git_metadata_sha256": _metadata_digest(successor_git_metadata),
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