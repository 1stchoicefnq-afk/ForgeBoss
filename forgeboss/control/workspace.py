from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

QUARANTINE_DIRNAME = ".forgeboss-quarantine"
STAGE_PREFIX = ".forgeboss-stage-"
QUARANTINE_VERSION = 3


class WorkspaceProvisionError(RuntimeError):
    def __init__(self, code: str, message: str, *, provision_code: str | None = None,
                 cleanup_code: str | None = None, generation_id: str | None = None):
        super().__init__(message)
        self.code = code
        self.provision_code = provision_code
        self.cleanup_code = cleanup_code
        self.generation_id = generation_id


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
    return bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


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


def _candidate_under_root(workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str]) -> tuple[Path, Path]:
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
    return root, candidate


def _quarantine_dir(root: Path) -> Path:
    qdir = root / QUARANTINE_DIRNAME
    if qdir.exists():
        _assert_no_link_components(qdir, "WORKSPACE_QUARANTINE_INVALID")
        _assert_plain_existing_path(qdir, "WORKSPACE_QUARANTINE_INVALID")
        if not qdir.is_dir():
            raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "quarantine state path is not a directory")
    else:
        qdir.mkdir(mode=0o700)
    return qdir


def _record_path(root: Path, target: Path) -> Path:
    key = hashlib.sha256(str(target).encode("utf-8")).hexdigest()
    return _quarantine_dir(root) / f"{key}.json"


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_json_write(path: Path, value: dict) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    temp = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(temp), flags, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temp, path)
        _fsync_dir(path.parent)
    except Exception:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise


def _read_record(path: Path) -> dict:
    _assert_no_link_components(path.parent, "WORKSPACE_QUARANTINE_INVALID")
    _assert_plain_existing_path(path, "WORKSPACE_QUARANTINE_INVALID")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as ex:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", f"cannot read quarantine record: {path}") from ex
    required = {"version", "generation", "target", "stage", "identity", "state", "updatedAt"}
    if not isinstance(value, dict) or not required.issubset(value) or value["version"] != QUARANTINE_VERSION:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "quarantine record schema invalid")
    if not isinstance(value["generation"], str) or len(value["generation"]) < 16:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "quarantine generation invalid")
    if value["state"] not in {"preparing", "provisioning", "finalizing", "quarantined"}:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "quarantine state invalid")
    return value


def _write_record(path: Path, record: dict) -> None:
    out = dict(record)
    out["version"] = QUARANTINE_VERSION
    out["updatedAt"] = time.time()
    _atomic_json_write(path, out)


def _path_identity(path: Path, code: str = "WORKSPACE_IDENTITY_INVALID") -> dict:
    _assert_no_link_components(path, code)
    _assert_plain_existing_path(path, code)
    try:
        st = path.stat()
        resolved = path.resolve(strict=True)
    except OSError as ex:
        raise WorkspaceProvisionError(code, f"cannot inspect workspace identity: {path}") from ex
    if not stat.S_ISDIR(st.st_mode):
        raise WorkspaceProvisionError(code, "workspace generation must be a directory")
    ino = int(getattr(st, "st_ino", 0))
    ctime_ns = int(getattr(st, "st_ctime_ns", int(st.st_ctime * 1_000_000_000)))
    dev = int(getattr(st, "st_dev", -1))
    if ino <= 0 or ctime_ns <= 0 or dev < 0:
        raise WorkspaceProvisionError(code, "stable workspace file identity unavailable")
    return {
        "resolved": str(resolved),
        "dev": dev,
        "ino": ino,
        "ctimeNs": ctime_ns,
        "mode": int(st.st_mode),
    }


def _identity_shape_valid(identity: dict | None) -> bool:
    if not isinstance(identity, dict):
        return False
    required = {"resolved", "dev", "ino", "ctimeNs", "mode"}
    if set(identity) != required:
        return False
    if not isinstance(identity["resolved"], str) or not identity["resolved"]:
        return False
    try:
        return int(identity["dev"]) >= 0 and int(identity["ino"]) > 0 and int(identity["ctimeNs"]) > 0 and int(identity["mode"]) > 0
    except (TypeError, ValueError):
        return False


def _same_live_object(before: dict, after: dict) -> bool:
    """Continuity check during a live rename; ctime/resolved may legitimately change."""
    if not (_identity_shape_valid(before) and _identity_shape_valid(after)):
        return False
    return all(int(before[k]) == int(after[k]) for k in ("dev", "ino", "mode"))


def _identity_matches(path: Path, expected: dict | None) -> bool:
    """Full persisted generation check; every stabilized discriminator must match."""
    if not _identity_shape_valid(expected):
        return False
    try:
        observed = _path_identity(path)
    except WorkspaceProvisionError:
        return False
    if observed["resolved"] != expected["resolved"]:
        return False
    return all(int(observed[k]) == int(expected[k]) for k in ("dev", "ino", "ctimeNs", "mode"))


def _record_for_target(root: Path, target: Path) -> tuple[Path, dict] | None:
    path = _record_path(root, target)
    if not path.exists():
        return None
    record = _read_record(path)
    if record.get("target") != str(target):
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "quarantine target identity mismatch")
    return path, record


def quarantine_status(workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str]) -> dict | None:
    root, target = _candidate_under_root(workspace, workspace_root)
    found = _record_for_target(root, target)
    return None if found is None else dict(found[1])


def _assert_not_quarantined(root: Path, target: Path, allow_generation: str | None = None) -> None:
    found = _record_for_target(root, target)
    if found is None:
        return
    record = found[1]
    if allow_generation is not None and record["generation"] == allow_generation and record["state"] == "finalizing":
        return
    raise WorkspaceProvisionError("WORKSPACE_QUARANTINED",
                                  f"workspace target is quarantined/in-flight generation {record['generation']}",
                                  generation_id=record["generation"])


def discover_quarantined_workspaces(workspace_root: str | os.PathLike[str]) -> list[dict]:
    root = _canonical_existing_dir(workspace_root, "WORKSPACE_ROOT_INVALID")
    qdir = _quarantine_dir(root)
    records: list[dict] = []
    referenced_stages: set[str] = set()
    for path in sorted(qdir.glob("*.json")):
        record = _read_record(path)
        target = Path(record["target"])
        stage = Path(record["stage"])
        try:
            common = Path(os.path.commonpath([str(root), str(target)]))
            stage_common = Path(os.path.commonpath([str(root), str(stage)]))
        except ValueError as ex:
            raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "recorded path escapes workspace root") from ex
        if common != root or stage_common != root:
            raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "recorded path escapes workspace root")
        referenced_stages.add(str(stage))
        if record["state"] != "quarantined":
            record["state"] = "quarantined"
            record["recoveredAfterRestart"] = True
            _write_record(path, record)
        records.append(dict(record))
    for stage in sorted(root.glob(f"{STAGE_PREFIX}*")):
        if str(stage) in referenced_stages:
            continue
        state = "orphan-untrusted" if stage.is_symlink() or _is_reparse(stage) else "orphan-untracked"
        records.append({"version": QUARANTINE_VERSION, "state": state, "stage": str(stage), "target": None})
    return records


def _remove_record_after_absence(path: Path, target: Path, stage: Path) -> None:
    if target.exists() or target.is_symlink() or _is_reparse(target):
        raise WorkspaceProvisionError("WORKSPACE_CLEANUP_INCOMPLETE", "workspace target still exists after cleanup")
    if stage.exists() or stage.is_symlink() or _is_reparse(stage):
        raise WorkspaceProvisionError("WORKSPACE_CLEANUP_INCOMPLETE", "workspace staging generation still exists after cleanup")
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    _fsync_dir(path.parent)


def reconcile_quarantined_workspace(workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str], generation_id: str) -> dict:
    root, target = _candidate_under_root(workspace, workspace_root)
    found = _record_for_target(root, target)
    if found is None:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_NOT_FOUND", "no quarantine record exists")
    record_path, record = found
    if record["generation"] != generation_id:
        raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH", "quarantine generation does not match requested cleanup generation",
                                      generation_id=record["generation"])
    stage = Path(record["stage"])
    existing = target if (target.exists() or target.is_symlink() or _is_reparse(target)) else stage
    if existing.exists() or existing.is_symlink() or _is_reparse(existing):
        _assert_no_link_components(existing, "WORKSPACE_CLEANUP_DENIED")
        _assert_plain_existing_path(existing, "WORKSPACE_CLEANUP_DENIED")
        if not _identity_matches(existing, record.get("identity")):
            raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH",
                                          "surviving workspace no longer matches quarantined generation identity",
                                          generation_id=generation_id)
        try:
            shutil.rmtree(existing)
        except Exception as ex:
            raise WorkspaceProvisionError("WORKSPACE_CLEANUP_FAILED", f"quarantined workspace cleanup failed: {ex}",
                                          cleanup_code=type(ex).__name__.upper(), generation_id=generation_id) from ex
    _remove_record_after_absence(record_path, target, stage)
    return {"reconciled": True, "generation": generation_id, "target": str(target)}


def _workspace_target(workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str]) -> tuple[Path, Path]:
    root, candidate = _candidate_under_root(workspace, workspace_root)
    _assert_not_quarantined(root, candidate)
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
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "", "GIT_ALLOW_PROTOCOL": "file", "GIT_PROTOCOL_FROM_USER": "0"})
    return env


def _run_git(git: Path, args: Iterable[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run([str(git), *[str(x) for x in args]], cwd=str(cwd) if cwd is not None else None,
                                env=_clean_git_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=120, check=False)
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
    if fmt == "sha1": return fmt, 40
    if fmt == "sha256": return fmt, 64
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
    if _run_git(git, ["check-ref-format", "--branch", raw], check=False).returncode != 0:
        raise WorkspaceProvisionError("BRANCH_INVALID", "task branch is malformed")
    return raw


def _repo_dirs(git: Path, repo: Path) -> tuple[Path, Path, Path]:
    top = Path(_git_text(git, ["rev-parse", "--show-toplevel"], cwd=repo))
    git_dir = Path(_git_text(git, ["rev-parse", "--absolute-git-dir"], cwd=repo))
    common_raw = _git_text(git, ["rev-parse", "--git-common-dir"], cwd=repo)
    common = Path(common_raw)
    if not common.is_absolute(): common = (repo / common).resolve(strict=True)
    for path, code in ((top, "GIT_ROOT_INVALID"), (git_dir, "GIT_DIR_INVALID"), (common, "GIT_COMMON_DIR_INVALID")):
        _assert_no_link_components(path, code); _assert_plain_existing_path(path, code)
    try:
        return top.resolve(strict=True), git_dir.resolve(strict=True), common.resolve(strict=True)
    except OSError as ex:
        raise WorkspaceProvisionError("GIT_IDENTITY_INVALID", "cannot resolve Git repository identity") from ex


def _digest_identity(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts, ensure_ascii=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _no_alternates(git_dir: Path, common_dir: Path) -> None:
    for root in {git_dir, common_dir}:
        for name in ("alternates", "http-alternates"):
            path = root / "objects" / "info" / name
            if path.exists() or path.is_symlink() or _is_reparse(path):
                raise WorkspaceProvisionError("SHARED_OBJECT_AUTHORITY", f"Git alternates denied: {path}")


def inspect_source(source_repo: str | os.PathLike[str], base_sha: str, git_executable: str | os.PathLike[str]) -> dict:
    git = _git_executable(git_executable)
    source = _canonical_existing_dir(source_repo, "SOURCE_INVALID")
    top, git_dir, common_dir = _repo_dirs(git, source)
    if top != source: raise WorkspaceProvisionError("SOURCE_ROOT_MISMATCH", "source must be the exact Git worktree root")
    fmt, oid_len = _object_format(git, source)
    requested = _canonical_oid(base_sha, oid_len)
    observed = _canonical_oid(_git_text(git, ["rev-parse", "--verify", f"{requested}^{{commit}}"], cwd=source), oid_len)
    if observed != requested: raise WorkspaceProvisionError("BASE_SHA_MISMATCH", "requested base does not resolve to the exact commit")
    head = _canonical_oid(_git_text(git, ["rev-parse", "HEAD"], cwd=source), oid_len, "SOURCE_HEAD_INVALID")
    return {"source_root": str(top), "source_git_dir": str(git_dir), "source_common_dir": str(common_dir),
            "source_head": head, "source_identity": _digest_identity(str(top), str(git_dir), str(common_dir), fmt, head),
            "object_format": fmt, "base_sha": requested}


def verify_workspace(workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str], expected_base_sha: str,
                     expected_branch: str, git_executable: str | os.PathLike[str], *, source_identity: dict | None = None,
                     _allow_generation: str | None = None) -> WorkspaceIdentity:
    git = _git_executable(git_executable)
    root = _canonical_existing_dir(workspace_root, "WORKSPACE_ROOT_INVALID")
    work = _canonical_existing_dir(workspace, "WORKSPACE_INVALID")
    _assert_not_quarantined(root, work, _allow_generation)
    try: common_path = Path(os.path.commonpath([str(root), str(work)]))
    except ValueError as ex: raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes provision root") from ex
    if common_path != root or work == root: raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes provision root")
    top, git_dir, common_dir = _repo_dirs(git, work)
    if top != work: raise WorkspaceProvisionError("WORKSPACE_ROOT_MISMATCH", "observed Git root does not equal exact workspace")
    for value in (git_dir, common_dir):
        try: inside = Path(os.path.commonpath([str(work), str(value)])) == work
        except ValueError: inside = False
        if not inside: raise WorkspaceProvisionError("SHARED_GIT_AUTHORITY", "Git metadata/common refs escape disposable workspace")
    _no_alternates(git_dir, common_dir)
    fmt, oid_len = _object_format(git, work)
    expected = _canonical_oid(expected_base_sha, oid_len)
    head = _canonical_oid(_git_text(git, ["rev-parse", "HEAD"], cwd=work), oid_len, "WORKSPACE_HEAD_INVALID")
    if head != expected: raise WorkspaceProvisionError("WORKSPACE_HEAD_MISMATCH", "observed HEAD does not equal exact base")
    branch = _validate_branch(git, expected_branch)
    br = _run_git(git, ["symbolic-ref", "--quiet", "--short", "HEAD"], cwd=work, check=False)
    if br.returncode != 0 or br.stdout.strip() != branch:
        raise WorkspaceProvisionError("WORKSPACE_BRANCH_MISMATCH", "observed branch does not match task branch")
    observed_branch = br.stdout.strip()
    remotes = tuple(x for x in _git_text(git, ["remote"], cwd=work).splitlines() if x.strip())
    if remotes: raise WorkspaceProvisionError("WORKSPACE_REMOTE_PRESENT", "disposable workspace must not retain remotes")
    source_identity = source_identity or {}
    source_root = str(source_identity.get("source_root") or ""); source_git_dir = str(source_identity.get("source_git_dir") or "")
    source_common_dir = str(source_identity.get("source_common_dir") or ""); source_head = str(source_identity.get("source_head") or "")
    source_digest = str(source_identity.get("source_identity") or "")
    if source_git_dir and Path(source_git_dir) == git_dir: raise WorkspaceProvisionError("SHARED_GIT_AUTHORITY", "workspace reuses supervisor Git directory")
    if source_common_dir and Path(source_common_dir) == common_dir: raise WorkspaceProvisionError("SHARED_GIT_AUTHORITY", "workspace reuses supervisor common refs")
    return WorkspaceIdentity(source_root, source_git_dir, source_common_dir, source_head, source_digest, str(work), str(git_dir),
                             str(common_dir), _digest_identity(str(top), str(git_dir), str(common_dir), fmt, head, observed_branch),
                             fmt, expected, head, observed_branch, remotes)


def cleanup_workspace(workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str]) -> bool:
    root, candidate = _candidate_under_root(workspace, workspace_root)
    found = _record_for_target(root, candidate)
    if found is not None:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINED", "quarantined workspaces require generation-bound reconciliation",
                                      generation_id=found[1]["generation"])
    if not candidate.exists() and not candidate.is_symlink() and not _is_reparse(candidate): return False
    _assert_no_link_components(candidate, "WORKSPACE_CLEANUP_DENIED"); _assert_plain_existing_path(candidate, "WORKSPACE_CLEANUP_DENIED")
    shutil.rmtree(candidate)
    if candidate.exists() or candidate.is_symlink() or _is_reparse(candidate):
        raise WorkspaceProvisionError("WORKSPACE_CLEANUP_INCOMPLETE", "workspace still exists after cleanup")
    return True


def _exception_code(ex: BaseException) -> str:
    return ex.code if isinstance(ex, WorkspaceProvisionError) else type(ex).__name__.upper()


def _provision_failure_cleanup(root: Path, target: Path, stage: Path, record_path: Path, record: dict,
                               provision_error: BaseException) -> None:
    candidate = target if (target.exists() or target.is_symlink() or _is_reparse(target)) else stage
    cleanup_error: BaseException | None = None
    try:
        if candidate.exists() or candidate.is_symlink() or _is_reparse(candidate):
            _assert_no_link_components(candidate, "WORKSPACE_CLEANUP_DENIED"); _assert_plain_existing_path(candidate, "WORKSPACE_CLEANUP_DENIED")
            if record.get("state") == "provisioning":
                record["identity"] = _path_identity(candidate)
                _write_record(record_path, record)
            elif not _identity_matches(candidate, record.get("identity")):
                raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH", "failed generation identity changed before cleanup")
            shutil.rmtree(candidate)
        _remove_record_after_absence(record_path, target, stage)
    except BaseException as ex:
        cleanup_error = ex
    if cleanup_error is None: return
    quarantined = dict(record); quarantined["state"] = "quarantined"
    survivor = target if (target.exists() or target.is_symlink() or _is_reparse(target)) else stage
    try:
        if survivor.exists() or survivor.is_symlink() or _is_reparse(survivor):
            quarantined["identity"] = _path_identity(survivor)
    except BaseException as identity_error:
        quarantined["identity"] = None
        cleanup_error = WorkspaceProvisionError("WORKSPACE_IDENTITY_INVALID", f"cleanup failed and stable survivor identity unavailable: {identity_error}")
    quarantined["provisionError"] = {"code": _exception_code(provision_error), "message": str(provision_error)}
    quarantined["cleanupError"] = {"code": _exception_code(cleanup_error), "message": str(cleanup_error)}
    try: _write_record(record_path, quarantined)
    except Exception as record_error:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_WRITE_FAILED",
                                      f"provisioning failed ({_exception_code(provision_error)}); cleanup failed ({_exception_code(cleanup_error)}); quarantine persistence failed ({type(record_error).__name__})",
                                      provision_code=_exception_code(provision_error), cleanup_code=_exception_code(cleanup_error),
                                      generation_id=record["generation"]) from record_error
    raise WorkspaceProvisionError("WORKSPACE_PROVISION_CLEANUP_FAILED",
                                  f"provisioning failed ({_exception_code(provision_error)}); cleanup/quarantine failed ({_exception_code(cleanup_error)})",
                                  provision_code=_exception_code(provision_error), cleanup_code=_exception_code(cleanup_error),
                                  generation_id=record["generation"]) from cleanup_error


def provision_workspace(source_repo: str | os.PathLike[str], workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str],
                        base_sha: str, task_branch: str, git_executable: str | os.PathLike[str]) -> WorkspaceIdentity:
    git = _git_executable(git_executable); root, target = _workspace_target(workspace, workspace_root)
    source = inspect_source(source_repo, base_sha, git); branch = _validate_branch(git, task_branch); requested = source["base_sha"]
    generation = uuid.uuid4().hex; target_hash = hashlib.sha256(str(target).encode("utf-8")).hexdigest()[:16]
    stage = root / f"{STAGE_PREFIX}{target_hash}-{generation}"; record_path = _record_path(root, target)
    record = {"version": QUARANTINE_VERSION, "generation": generation, "target": str(target), "stage": str(stage),
              "identity": None, "state": "preparing", "updatedAt": time.time()}
    _write_record(record_path, record)
    try:
        stage.mkdir(mode=0o700); _fsync_dir(root)
        record["state"] = "provisioning"; _write_record(record_path, record)
        with tempfile.TemporaryDirectory(prefix="forgeboss-git-template-", dir=str(root)) as template_dir:
            _run_git(git, ["-c", "protocol.file.allow=always", "clone", "--no-local", "--no-hardlinks", "--no-checkout", "--no-tags",
                           f"--template={Path(template_dir)}", source["source_root"], str(stage)], cwd=root)
        for remote in [x for x in _git_text(git, ["remote"], cwd=stage).splitlines() if x.strip()]:
            _run_git(git, ["remote", "remove", remote], cwd=stage)
        _run_git(git, ["checkout", "--detach", requested], cwd=stage)
        _run_git(git, ["branch", "-f", branch, requested], cwd=stage)
        _run_git(git, ["checkout", branch], cwd=stage)
        stable_stage_identity = _path_identity(stage)
        if target.exists() or target.is_symlink() or _is_reparse(target):
            raise WorkspaceProvisionError("WORKSPACE_EXISTS", "workspace target appeared during provisioning")
        stage.rename(target); _fsync_dir(root)
        renamed_identity = _path_identity(target)
        if not _same_live_object(stable_stage_identity, renamed_identity):
            raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH", "workspace object changed across final rename")
        record["identity"] = renamed_identity; record["state"] = "finalizing"; _write_record(record_path, record)
        identity = verify_workspace(target, root, requested, branch, git, source_identity=source, _allow_generation=generation)
        _remove_record_after_absence_for_success(record_path, stage)
        return identity
    except BaseException as ex:
        _provision_failure_cleanup(root, target, stage, record_path, record, ex)
        raise


def _remove_record_after_absence_for_success(record_path: Path, stage: Path) -> None:
    if stage.exists() or stage.is_symlink() or _is_reparse(stage):
        raise WorkspaceProvisionError("WORKSPACE_STAGE_REMAINS", "staging path still exists after final rename")
    try: record_path.unlink()
    except FileNotFoundError:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "provision record disappeared before success commit")
    _fsync_dir(record_path.parent)
