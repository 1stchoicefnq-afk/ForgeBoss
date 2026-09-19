from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

FORGEBOSS_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STATE_ROOT = Path.home() / ".forgeboss" / "projects"


class ProjectRuntimeError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(path: str | os.PathLike[str], *, must_exist: bool = True) -> Path:
    p = Path(path).expanduser()
    try:
        return p.resolve(strict=must_exist)
    except (FileNotFoundError, OSError) as exc:
        raise ProjectRuntimeError(f"project path is unavailable: {p}") from exc


def _norm(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _same_path(a: Path, b: Path) -> bool:
    return _norm(a) == _norm(b)


def _same_or_descendant(path: Path, root: Path) -> bool:
    a, b = _norm(path), _norm(root)
    try:
        return os.path.commonpath([a, b]) == b
    except ValueError:
        return False


def _git_head(root: Path) -> str | None:
    git = shutil.which("git")
    if not git:
        return None
    try:
        p = subprocess.run(
            [git, "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    head = (p.stdout or "").strip()
    return head if p.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40}", head) else None


def inspect_project(path: str | os.PathLike[str], *, live_root: Path | None = None) -> dict:
    root = _canonical(path)
    if not root.is_dir():
        raise ProjectRuntimeError(f"project path is not a directory: {root}")
    live = _canonical(live_root or FORGEBOSS_ROOT)
    return {
        "schema": 1,
        "name": root.name or "project",
        "root": str(root),
        "git_head": _git_head(root),
        "is_self_build": _same_path(root, live),
        "registered_at": _now(),
    }


def _atomic_write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def register_project(
    path: str | os.PathLike[str],
    *,
    state_root: Path | None = None,
    live_root: Path | None = None,
) -> dict:
    project = inspect_project(path, live_root=live_root)
    root = state_root or DEFAULT_STATE_ROOT
    _atomic_write_json(root / "active.json", project)
    return project


def load_active_project(*, state_root: Path | None = None) -> dict | None:
    path = (state_root or DEFAULT_STATE_ROOT) / "active.json"
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProjectRuntimeError(f"active project state is invalid: {path}") from exc
    if not isinstance(value, dict) or value.get("schema") != 1 or not value.get("root"):
        raise ProjectRuntimeError(f"active project state has invalid schema: {path}")
    return value


def assert_write_not_live_root(
    target: str | os.PathLike[str],
    *,
    live_root: Path | None = None,
) -> Path:
    """Return canonical target when it is outside the live ForgeBoss tree.

    This is a reusable safety primitive. Builders must call it before any path
    becomes write-authorized during self-build.
    """
    live = _canonical(live_root or FORGEBOSS_ROOT)
    candidate = _canonical(target, must_exist=False)
    if _same_or_descendant(candidate, live):
        raise ProjectRuntimeError(
            f"SELF_BUILD_LIVE_ROOT_WRITE_DENIED: {candidate} is inside running ForgeBoss root {live}"
        )
    return candidate
