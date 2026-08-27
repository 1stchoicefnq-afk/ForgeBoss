from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


class WorkspaceProvisionError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class WorkspaceIdentity:
    source_root: str
    source_git_dir: str
    source_common_dir: str
    source_head: str
    source_identity: str
    workspace_root: str
    git_dir: str
    common_dir: str
    git_identity: str
    object_format: str
    base_sha: str
    head_sha: str
    branch: str
    remotes: tuple[str, ...]

    def as_dict(self) -> dict:
        value = asdict(self)
        value["remotes"] = list(self.remotes)
        return value


def _is_reparse(path: Path) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attrs & flag)


def _assert_plain_existing_path(path: Path, code: str) -> Path:
    try:
        st = path.lstat()
    except OSError as ex:
        raise WorkspaceProvisionError(code, f"path does not exist: {path}") from ex
    if stat.S_ISLNK(st.st_mode) or _is_reparse(path):
        raise WorkspaceProvisionError(code, f"link/reparse path denied: {path}")
    return path


def _assert_no_link_components(path: Path, code: str) -> None:
    current = Path(path.anchor) if path.anchor else Path()
    parts = path.parts[1:] if path.anchor else path.parts
    for part in parts:
        current = current / part
        if not current.exists():
            continue
        try:
            st = current.lstat()
        except OSError as ex:
            raise WorkspaceProvisionError(code, f"cannot inspect path component: {current}") from ex
        if stat.S_ISLNK(st.st_mode) or _is_reparse(current):
            raise WorkspaceProvisionError(code, f"link/reparse component denied: {current}")


def _canonical_existing_dir(path: str | os.PathLike[str], code: str) -> Path:
    raw = Path(path)
    if not raw.is_absolute():
        raise WorkspaceProvisionError(code, f"absolute path required: {raw}")
    _assert_no_link_components(raw, code)
    _assert_plain_existing_path(raw, code)
    if not raw.is_dir():
        raise WorkspaceProvisionError(code, f"directory required: {raw}")
    try:
        return raw.resolve(strict=True)
    except OSError as ex:
        raise WorkspaceProvisionError(code, f"cannot resolve directory: {raw}") from ex


def _workspace_target(
    workspace: str | os.PathLike[str],
    workspace_root: str | os.PathLike[str],
) -> tuple[Path, Path]:
    root = _canonical_existing_dir(workspace_root, "WORKSPACE_ROOT_INVALID")
    target = Path(workspace)
    if not target.is_absolute():
        raise WorkspaceProvisionError("WORKSPACE_PATH_INVALID", "workspace path must be absolute")
    _assert_no_link_components(target.parent, "WORKSPACE_PATH_INVALID")
    try:
        parent = target.parent.resolve(strict=True)
    except OSError as ex:
        raise WorkspaceProvisionError("WORKSPACE_PATH_INVALID", "workspace parent does not exist") from ex
    candidate = parent / target.name
    try:
        common = Path(os.path.commonpath([str(root), str(candidate)]))
    except ValueError as ex:
        raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes provision root") from ex
    if common != root:
        raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes provision root")
    if candidate.exists() or candidate.is_symlink() or _is_reparse(candidate):
        raise WorkspaceProvisionError("WORKSPACE_EXISTS", "workspace target must not already exist")
    return root, candidate


def _git_executable(path: str | os.PathLike[str]) -> Path:
    git = Path(path)
    if not git.is_absolute():
        raise WorkspaceProvisionError("GIT_EXECUTABLE_INVALID", "git executable must be an explicit absolute path")
    _assert_no_link_components(git, "GIT_EXECUTABLE_INVALID")
    _assert_plain_existing_path(git, "GIT_EXECUTABLE_INVALID")
    try:
        st = git.stat()
    except OSError as ex:
        raise WorkspaceProvisionError("GIT_EXECUTABLE_INVALID", "cannot stat git executable") from ex
    if not stat.S_ISREG(st.st_mode):
        raise WorkspaceProvisionError("GIT_EXECUTABLE_INVALID", "git executable must be a regular file")
    return git.resolve(strict=True)


def _clean_git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_PROTOCOL_FROM_USER": "0",
        }
    )
    return env


def _run_git(
    git: Path,
    args: Iterable[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [str(git), *[str(x) for x in args]],
            cwd=str(cwd) if cwd is not None else None,
            env=_clean_git_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise WorkspaceProvisionError("GIT_EXECUTION_FAILED", f"git execution failed: {ex}") from ex
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise WorkspaceProvisionError("GIT_COMMAND_FAILED", detail or f"git exited {result.returncode}")
    return result


def _git_text(git: Path, args: Iterable[str], *, cwd: Path | None = None) -> str:
    return _run_git(git, args, cwd=cwd).stdout.strip()


def _object_format(git: Path, repo: Path) -> tuple[str, int]:
    fmt = _git_text(git, ["rev-parse", "--show-object-format"], cwd=repo).strip().lower()
    if fmt == "sha1":
        return fmt, 40
    if fmt == "sha256":
        return fmt, 64
    raise WorkspaceProvisionError("OBJECT_FORMAT_UNSUPPORTED", f"unsupported Git object format: {fmt}")


def _canonical_oid(value: str, length: int, code: str = "BASE_SHA_INVALID") -> str:
    raw = str(value or "")
    if len(raw) != length or any(ch not in "0123456789abcdefABCDEF" for ch in raw):
        raise WorkspaceProvisionError(code, f"exact {length}-hex Git object id required")
    return raw.lower()


def _validate_branch(git: Path, branch: str) -> str:
    raw = str(branch or "")
    if not raw or raw != raw.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise WorkspaceProvisionError("BRANCH_INVALID", "task branch is malformed")
    result = _run_git(git, ["check-ref-format", "--branch", raw], check=False)
    if result.returncode != 0:
        raise WorkspaceProvisionError("BRANCH_INVALID", "task branch is malformed")
    return raw


def _repo_dirs(git: Path, repo: Path) -> tuple[Path, Path, Path]:
    top = Path(_git_text(git, ["rev-parse", "--show-toplevel"], cwd=repo))
    git_dir = Path(_git_text(git, ["rev-parse", "--absolute-git-dir"], cwd=repo))
    common_raw = _git_text(git, ["rev-parse", "--git-common-dir"], cwd=repo)
    common = Path(common_raw)
    if not common.is_absolute():
        common = (repo / common).resolve(strict=True)
    for path, code in (
        (top, "GIT_ROOT_INVALID"),
        (git_dir, "GIT_DIR_INVALID"),
        (common, "GIT_COMMON_DIR_INVALID"),
    ):
        _assert_no_link_components(path, code)
        _assert_plain_existing_path(path, code)
    try:
        return top.resolve(strict=True), git_dir.resolve(strict=True), common.resolve(strict=True)
    except OSError as ex:
        raise WorkspaceProvisionError("GIT_IDENTITY_INVALID", "cannot resolve Git repository identity") from ex


def _digest_identity(*parts: str) -> str:
    payload = json.dumps(parts, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _no_alternates(git_dir: Path, common_dir: Path) -> None:
    for root in {git_dir, common_dir}:
        for name in ("alternates", "http-alternates"):
            path = root / "objects" / "info" / name
            if path.exists() or path.is_symlink() or _is_reparse(path):
                raise WorkspaceProvisionError("SHARED_OBJECT_AUTHORITY", f"Git alternates denied: {path}")


def inspect_source(
    source_repo: str | os.PathLike[str],
    base_sha: str,
    git_executable: str | os.PathLike[str],
) -> dict:
    git = _git_executable(git_executable)
    source = _canonical_existing_dir(source_repo, "SOURCE_INVALID")
    top, git_dir, common_dir = _repo_dirs(git, source)
    if top != source:
        raise WorkspaceProvisionError("SOURCE_ROOT_MISMATCH", "source must be the exact Git worktree root")
    fmt, oid_len = _object_format(git, source)
    requested = _canonical_oid(base_sha, oid_len)
    observed = _canonical_oid(
        _git_text(git, ["rev-parse", "--verify", f"{requested}^{{commit}}"], cwd=source),
        oid_len,
    )
    if observed != requested:
        raise WorkspaceProvisionError("BASE_SHA_MISMATCH", "requested base does not resolve to the exact commit")
    head = _canonical_oid(_git_text(git, ["rev-parse", "HEAD"], cwd=source), oid_len, "SOURCE_HEAD_INVALID")
    identity = _digest_identity(str(top), str(git_dir), str(common_dir), fmt, head)
    return {
        "source_root": str(top),
        "source_git_dir": str(git_dir),
        "source_common_dir": str(common_dir),
        "source_head": head,
        "source_identity": identity,
        "object_format": fmt,
        "base_sha": requested,
    }


def verify_workspace(
    workspace: str | os.PathLike[str],
    workspace_root: str | os.PathLike[str],
    expected_base_sha: str,
    expected_branch: str,
    git_executable: str | os.PathLike[str],
    *,
    source_identity: dict | None = None,
) -> WorkspaceIdentity:
    git = _git_executable(git_executable)
    root = _canonical_existing_dir(workspace_root, "WORKSPACE_ROOT_INVALID")
    work = _canonical_existing_dir(workspace, "WORKSPACE_INVALID")
    try:
        common_path = Path(os.path.commonpath([str(root), str(work)]))
    except ValueError as ex:
        raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes provision root") from ex
    if common_path != root or work == root:
        raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes provision root")

    top, git_dir, common_dir = _repo_dirs(git, work)
    if top != work:
        raise WorkspaceProvisionError("WORKSPACE_ROOT_MISMATCH", "observed Git root does not equal exact workspace")
    for value in (git_dir, common_dir):
        try:
            inside = Path(os.path.commonpath([str(work), str(value)])) == work
        except ValueError:
            inside = False
        if not inside:
            raise WorkspaceProvisionError("SHARED_GIT_AUTHORITY", "Git metadata/common refs escape disposable workspace")
    _no_alternates(git_dir, common_dir)

    fmt, oid_len = _object_format(git, work)
    expected = _canonical_oid(expected_base_sha, oid_len)
    head = _canonical_oid(_git_text(git, ["rev-parse", "HEAD"], cwd=work), oid_len, "WORKSPACE_HEAD_INVALID")
    if head != expected:
        raise WorkspaceProvisionError("WORKSPACE_HEAD_MISMATCH", "observed HEAD does not equal exact base")

    branch = _validate_branch(git, expected_branch)
    branch_result = _run_git(git, ["symbolic-ref", "--quiet", "--short", "HEAD"], cwd=work, check=False)
    if branch_result.returncode != 0:
        raise WorkspaceProvisionError("WORKSPACE_BRANCH_MISMATCH", "workspace is detached or branch cannot be observed")
    observed_branch = branch_result.stdout.strip()
    if observed_branch != branch:
        raise WorkspaceProvisionError("WORKSPACE_BRANCH_MISMATCH", "observed branch does not match task branch")

    remotes = tuple(x for x in _git_text(git, ["remote"], cwd=work).splitlines() if x.strip())
    if remotes:
        raise WorkspaceProvisionError("WORKSPACE_REMOTE_PRESENT", "disposable workspace must not retain remotes")

    if source_identity is None:
        source_identity = {}
    source_root = str(source_identity.get("source_root") or "")
    source_git_dir = str(source_identity.get("source_git_dir") or "")
    source_common_dir = str(source_identity.get("source_common_dir") or "")
    source_head = str(source_identity.get("source_head") or "")
    source_digest = str(source_identity.get("source_identity") or "")
    if source_git_dir and Path(source_git_dir) == git_dir:
        raise WorkspaceProvisionError("SHARED_GIT_AUTHORITY", "workspace reuses supervisor Git directory")
    if source_common_dir and Path(source_common_dir) == common_dir:
        raise WorkspaceProvisionError("SHARED_GIT_AUTHORITY", "workspace reuses supervisor common refs")

    git_identity = _digest_identity(str(top), str(git_dir), str(common_dir), fmt, head, observed_branch)
    return WorkspaceIdentity(
        source_root=source_root,
        source_git_dir=source_git_dir,
        source_common_dir=source_common_dir,
        source_head=source_head,
        source_identity=source_digest,
        workspace_root=str(work),
        git_dir=str(git_dir),
        common_dir=str(common_dir),
        git_identity=git_identity,
        object_format=fmt,
        base_sha=expected,
        head_sha=head,
        branch=observed_branch,
        remotes=remotes,
    )


def cleanup_workspace(
    workspace: str | os.PathLike[str],
    workspace_root: str | os.PathLike[str],
) -> bool:
    root = _canonical_existing_dir(workspace_root, "WORKSPACE_ROOT_INVALID")
    target = Path(workspace)
    if not target.is_absolute():
        raise WorkspaceProvisionError("WORKSPACE_PATH_INVALID", "workspace path must be absolute")
    _assert_no_link_components(target.parent, "WORKSPACE_PATH_INVALID")
    try:
        parent = target.parent.resolve(strict=True)
    except OSError as ex:
        raise WorkspaceProvisionError("WORKSPACE_PATH_INVALID", "workspace parent does not exist") from ex
    candidate = parent / target.name
    try:
        common = Path(os.path.commonpath([str(root), str(candidate)]))
    except ValueError as ex:
        raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes provision root") from ex
    if common != root or candidate == root:
        raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes provision root")
    if not candidate.exists() and not candidate.is_symlink():
        return False
    _assert_plain_existing_path(candidate, "WORKSPACE_CLEANUP_DENIED")
    shutil.rmtree(candidate)
    return True


def provision_workspace(
    source_repo: str | os.PathLike[str],
    workspace: str | os.PathLike[str],
    workspace_root: str | os.PathLike[str],
    base_sha: str,
    task_branch: str,
    git_executable: str | os.PathLike[str],
) -> WorkspaceIdentity:
    git = _git_executable(git_executable)
    root, target = _workspace_target(workspace, workspace_root)
    source = inspect_source(source_repo, base_sha, git)
    branch = _validate_branch(git, task_branch)
    requested = source["base_sha"]

    try:
        with tempfile.TemporaryDirectory(prefix="forgeboss-git-template-", dir=str(root)) as template_dir:
            template = Path(template_dir)
            _run_git(
                git,
                [
                    "-c",
                    "protocol.file.allow=always",
                    "clone",
                    "--no-local",
                    "--no-hardlinks",
                    "--no-checkout",
                    "--no-tags",
                    f"--template={template}",
                    source["source_root"],
                    str(target),
                ],
                cwd=root,
            )
        # The clone transport is local file-only and all remote authority is removed
        # before any worker-visible success object is produced.
        for remote in [x for x in _git_text(git, ["remote"], cwd=target).splitlines() if x.strip()]:
            _run_git(git, ["remote", "remove", remote], cwd=target)

        _run_git(git, ["checkout", "--detach", requested], cwd=target)
        _run_git(git, ["branch", "-f", branch, requested], cwd=target)
        _run_git(git, ["checkout", branch], cwd=target)

        return verify_workspace(
            target,
            root,
            requested,
            branch,
            git,
            source_identity=source,
        )
    except Exception:
        try:
            if target.exists() and not target.is_symlink() and not _is_reparse(target):
                shutil.rmtree(target)
        except Exception:
            pass
        raise
