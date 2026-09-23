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
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .workspace_state import ProtectedWorkspaceState, ProtectedWorkspaceStateError

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
STAGE_PREFIX = ".forgeboss-stage-"
QUARANTINE_VERSION = 7


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


def _require_state(value: ProtectedWorkspaceState | None) -> ProtectedWorkspaceState:
    if not isinstance(value, ProtectedWorkspaceState):
        raise WorkspaceProvisionError("WORKSPACE_PROTECTED_STATE_REQUIRED", "protected workspace state authority is required")
    return value


def _state_error(ex: ProtectedWorkspaceStateError) -> WorkspaceProvisionError:
    return WorkspaceProvisionError("WORKSPACE_PROTECTED_STATE_DENIED", str(ex))


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
        raise WorkspaceProvisionError(code, "absolute directory required")
    _assert_no_link_components(raw, code)
    _assert_plain_existing_path(raw, code)
    if not raw.is_dir():
        raise WorkspaceProvisionError(code, "directory required")
    try:
        return raw.resolve(strict=True)
    except OSError as ex:
        raise WorkspaceProvisionError(code, "cannot resolve directory") from ex


def _candidate_under_root(workspace: str | os.PathLike[str], workspace_root: str | os.PathLike[str]) -> tuple[Path, Path]:
    root = _canonical_existing_dir(workspace_root, "WORKSPACE_ROOT_INVALID")
    target = Path(workspace)
    if not target.is_absolute():
        raise WorkspaceProvisionError("WORKSPACE_PATH_INVALID", "workspace path must be absolute")
    _assert_no_link_components(target.parent, "WORKSPACE_PATH_INVALID")
    try:
        candidate = target.parent.resolve(strict=True) / target.name
        common = Path(os.path.commonpath([str(root), str(candidate)]))
    except (OSError, ValueError) as ex:
        raise WorkspaceProvisionError("WORKSPACE_PATH_INVALID", "workspace path cannot be resolved") from ex
    if common != root or candidate == root:
        raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes provision root")
    return root, candidate


def _create_stage_dir(path: Path) -> None:
    """Create a protected staging directory without Windows 0o700 ACL synthesis."""
    if os.name == "nt":
        path.mkdir()
    else:
        path.mkdir(mode=0o700)


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


def _linux_native_identity(path: Path) -> dict:
    if not sys.platform.startswith("linux"):
        raise WorkspaceProvisionError("WORKSPACE_IDENTITY_INVALID", "Linux native identity unavailable")
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        class FH(ctypes.Structure):
            _fields_ = [("handle_bytes", ctypes.c_uint), ("handle_type", ctypes.c_int), ("f_handle", ctypes.c_ubyte * 128)]
        fn = libc.name_to_handle_at
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(FH), ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        fn.restype = ctypes.c_int
        h = FH(); h.handle_bytes = 128; mount_id = ctypes.c_int()
        if fn(-100, os.fsencode(path), ctypes.byref(h), ctypes.byref(mount_id), 0) != 0:
            err = ctypes.get_errno(); raise OSError(err, os.strerror(err))
        raw = bytes(h.f_handle[:h.handle_bytes]).hex()
        if not raw:
            raise OSError("empty Linux file handle")
        return {"mountId": int(mount_id.value), "handleType": int(h.handle_type), "handleHex": raw}
    except Exception as ex:
        raise WorkspaceProvisionError("WORKSPACE_IDENTITY_INVALID", f"stable Linux workspace identity unavailable: {ex}") from ex


def _path_identity(path: Path, code: str = "WORKSPACE_IDENTITY_INVALID") -> dict:
    _assert_no_link_components(path, code); _assert_plain_existing_path(path, code)
    try:
        st = path.stat(); resolved = path.resolve(strict=True)
    except OSError as ex:
        raise WorkspaceProvisionError(code, "cannot inspect workspace identity") from ex
    if not stat.S_ISDIR(st.st_mode):
        raise WorkspaceProvisionError(code, "workspace generation must be a directory")
    dev = int(getattr(st, "st_dev", -1)); ino = int(getattr(st, "st_ino", 0)); ctime_ns = int(getattr(st, "st_ctime_ns", 0))
    if dev < 0 or ino <= 0 or ctime_ns <= 0:
        raise WorkspaceProvisionError(code, "stable file identity unavailable")
    out = {"resolved": str(resolved), "dev": dev, "ino": ino, "ctimeNs": ctime_ns, "mode": int(st.st_mode)}
    if os.name == "nt":
        from .windows_cleanup import native_identity
        out["native"] = native_identity(path)
    elif sys.platform.startswith("linux"):
        out["linuxHandle"] = _linux_native_identity(path)
    else:
        raise WorkspaceProvisionError(code, "native workspace identity unavailable")
    return out


def _identity_shape_valid(identity: dict | None) -> bool:
    if not isinstance(identity, dict): return False
    base = {"resolved", "dev", "ino", "ctimeNs", "mode"}
    if set(identity) not in (base | {"native"}, base | {"linuxHandle"}): return False
    try:
        if int(identity["dev"]) < 0 or int(identity["ino"]) <= 0 or int(identity["ctimeNs"]) <= 0 or int(identity["mode"]) <= 0: return False
    except Exception: return False
    return isinstance(identity.get("resolved"), str) and bool(identity["resolved"])


def _stable_generation_equal(before: dict, after: dict) -> bool:
    if not (_identity_shape_valid(before) and _identity_shape_valid(after)): return False
    if not all(int(before[k]) == int(after[k]) for k in ("dev", "ino", "mode")): return False
    return before.get("native") == after.get("native") and before.get("linuxHandle") == after.get("linuxHandle")


def _identity_matches(path: Path, expected: dict | None, *, continuity: bool = False) -> bool:
    if not _identity_shape_valid(expected): return False
    try:
        observed = _path_identity(path)
    except WorkspaceProvisionError:
        return False
    if not _stable_generation_equal(expected, observed): return False
    if continuity: return True
    return observed["resolved"] == expected["resolved"] and int(observed["ctimeNs"]) == int(expected["ctimeNs"])


def _validate_record(record: dict, root: Path, target: Path) -> dict:
    required = {"version", "generation", "target", "stage", "identity", "contentOid", "state", "updatedAt"}
    if not isinstance(record, dict) or not required.issubset(record) or record["version"] != QUARANTINE_VERSION:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "protected state schema invalid")
    if record["target"] != str(target):
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "protected target identity mismatch")
    if not isinstance(record["generation"], str) or len(record["generation"]) < 16:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "generation invalid")
    if record["state"] not in {"preparing", "provisioning", "renaming", "finalizing", "quarantined"}:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "state invalid")
    stage = Path(record["stage"])
    try:
        if Path(os.path.commonpath([str(root), str(stage)])) != root:
            raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "stage escapes workspace root")
    except ValueError as ex:
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "stage escapes workspace root") from ex
    oid = record["contentOid"]
    if not isinstance(oid, str) or len(oid) not in (40, 64) or any(c not in "0123456789abcdef" for c in oid):
        raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_INVALID", "content OID invalid")
    return dict(record)


def _read_record(state: ProtectedWorkspaceState, root: Path, target: Path) -> dict | None:
    try:
        raw = state.read(root, target)
    except ProtectedWorkspaceStateError as ex:
        raise _state_error(ex) from ex
    return None if raw is None else _validate_record(raw, root, target)


def _write_record(state: ProtectedWorkspaceState, root: Path, target: Path, record: dict) -> None:
    out = dict(record); out["version"] = QUARANTINE_VERSION; out["updatedAt"] = time.time()
    _validate_record(out, root, target)
    try:
        state.write(root, target, out)
    except ProtectedWorkspaceStateError as ex:
        raise _state_error(ex) from ex


def _delete_record(state: ProtectedWorkspaceState, root: Path, target: Path) -> None:
    try:
        state.delete(root, target)
    except ProtectedWorkspaceStateError as ex:
        raise _state_error(ex) from ex


def quarantine_status(workspace, workspace_root, *, protected_state: ProtectedWorkspaceState | None = None) -> dict | None:
    state = _require_state(protected_state); root, target = _candidate_under_root(workspace, workspace_root)
    record = _read_record(state, root, target)
    return None if record is None else dict(record)


def _assert_not_quarantined(state: ProtectedWorkspaceState, root: Path, target: Path, allow_generation: str | None = None) -> None:
    record = _read_record(state, root, target)
    if record is None: return
    if allow_generation is not None and record["generation"] == allow_generation and record["state"] == "finalizing": return
    raise WorkspaceProvisionError("WORKSPACE_QUARANTINED", "workspace is quarantined", generation_id=record["generation"])


def discover_quarantined_workspaces(workspace_root, *, protected_state: ProtectedWorkspaceState | None = None) -> list[dict]:
    state = _require_state(protected_state); root = _canonical_existing_dir(workspace_root, "WORKSPACE_ROOT_INVALID"); records = []
    try:
        source = list(state.records())
    except ProtectedWorkspaceStateError as ex:
        raise _state_error(ex) from ex
    for raw in source:
        if raw.get("target") is None: continue
        target = Path(str(raw["target"]))
        try:
            if Path(os.path.commonpath([str(root), str(target)])) != root: continue
        except ValueError:
            continue
        record = _validate_record(raw, root, target)
        if record["state"] != "quarantined":
            record["recoveredFromState"] = record["state"]; record["recoveredAfterRestart"] = True; record["state"] = "quarantined"
            _write_record(state, root, target, record)
        records.append(dict(record))
    return records


def _rmtree_windows_safe(path: Path, expected_identity: dict | None = None) -> None:
    if os.name != "nt":
        shutil.rmtree(path); return
    if not _identity_shape_valid(expected_identity) or "native" not in expected_identity:
        raise WorkspaceProvisionError("WORKSPACE_CLEANUP_DENIED", "native Windows identity required")
    from .windows_cleanup import delete_tree_exact
    delete_tree_exact(path, expected_identity["native"])


def _git_executable(path) -> Path:
    git = Path(path)
    if not git.is_absolute(): raise WorkspaceProvisionError("GIT_EXECUTABLE_INVALID", "absolute git path required")
    _assert_no_link_components(git, "GIT_EXECUTABLE_INVALID"); _assert_plain_existing_path(git, "GIT_EXECUTABLE_INVALID")
    if not stat.S_ISREG(git.stat().st_mode): raise WorkspaceProvisionError("GIT_EXECUTABLE_INVALID", "git must be regular file")
    return git.resolve(strict=True)


def _clean_git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "GIT_ALLOW_PROTOCOL": "file", "GIT_PROTOCOL_FROM_USER": "0"})
    return env


def _run_git(git: Path, args: Iterable[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run([str(git), *map(str, args)], cwd=str(cwd) if cwd else None, env=_clean_git_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120, check=False, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise WorkspaceProvisionError("GIT_EXECUTION_FAILED", str(ex)) from ex
    if check and result.returncode:
        raise WorkspaceProvisionError("GIT_COMMAND_FAILED", (result.stderr or result.stdout or "git failed").strip())
    return result


def _git_text(git: Path, args: Iterable[str], *, cwd: Path | None = None) -> str:
    return _run_git(git, args, cwd=cwd).stdout.strip()


def _object_format(git: Path, repo: Path) -> tuple[str, int]:
    fmt = _git_text(git, ["rev-parse", "--show-object-format"], cwd=repo).lower()
    if fmt == "sha1": return fmt, 40
    if fmt == "sha256": return fmt, 64
    raise WorkspaceProvisionError("OBJECT_FORMAT_UNSUPPORTED", fmt)


def _canonical_oid(value: str, length: int, code: str = "BASE_SHA_INVALID") -> str:
    raw = str(value or "")
    if len(raw) != length or any(c not in "0123456789abcdefABCDEF" for c in raw): raise WorkspaceProvisionError(code, "exact Git OID required")
    return raw.lower()


def _validate_branch(git: Path, branch: str) -> str:
    raw = str(branch or "")
    if not raw or raw != raw.strip() or _run_git(git, ["check-ref-format", "--branch", raw], check=False).returncode:
        raise WorkspaceProvisionError("BRANCH_INVALID", "task branch invalid")
    return raw


def _repo_dirs(git: Path, repo: Path) -> tuple[Path, Path, Path]:
    top = Path(_git_text(git, ["rev-parse", "--show-toplevel"], cwd=repo)).resolve(strict=True)
    gd = Path(_git_text(git, ["rev-parse", "--absolute-git-dir"], cwd=repo)).resolve(strict=True)
    common = Path(_git_text(git, ["rev-parse", "--git-common-dir"], cwd=repo))
    if not common.is_absolute(): common = (repo / common).resolve(strict=True)
    else: common = common.resolve(strict=True)
    for p in (top, gd, common): _assert_no_link_components(p, "GIT_IDENTITY_INVALID"); _assert_plain_existing_path(p, "GIT_IDENTITY_INVALID")
    return top, gd, common


def _digest_identity(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


def inspect_source(source_repo, base_sha, git_executable) -> dict:
    git = _git_executable(git_executable); source = _canonical_existing_dir(source_repo, "SOURCE_INVALID"); top, gd, common = _repo_dirs(git, source)
    if top != source: raise WorkspaceProvisionError("SOURCE_ROOT_MISMATCH", "source must be exact root")
    fmt, n = _object_format(git, source); requested = _canonical_oid(base_sha, n); observed = _canonical_oid(_git_text(git, ["rev-parse", "--verify", f"{requested}^{{commit}}"], cwd=source), n)
    if requested != observed: raise WorkspaceProvisionError("BASE_SHA_MISMATCH", "base mismatch")
    head = _canonical_oid(_git_text(git, ["rev-parse", "HEAD"], cwd=source), n, "SOURCE_HEAD_INVALID")
    return {"source_root": str(top), "source_git_dir": str(gd), "source_common_dir": str(common), "source_head": head, "source_identity": _digest_identity(str(top), str(gd), str(common), fmt, head), "object_format": fmt, "base_sha": requested}


def verify_workspace(workspace, workspace_root, expected_base_sha, expected_branch, git_executable, *, source_identity: dict | None = None, protected_state: ProtectedWorkspaceState | None = None, _allow_generation: str | None = None) -> WorkspaceIdentity:
    state = _require_state(protected_state); git = _git_executable(git_executable); root = _canonical_existing_dir(workspace_root, "WORKSPACE_ROOT_INVALID"); work = _canonical_existing_dir(workspace, "WORKSPACE_INVALID")
    _assert_not_quarantined(state, root, work, _allow_generation)
    if Path(os.path.commonpath([str(root), str(work)])) != root or work == root: raise WorkspaceProvisionError("WORKSPACE_ESCAPE", "workspace escapes root")
    top, gd, common = _repo_dirs(git, work)
    if top != work: raise WorkspaceProvisionError("WORKSPACE_ROOT_MISMATCH", "Git root mismatch")
    for p in (gd, common):
        if Path(os.path.commonpath([str(work), str(p)])) != work: raise WorkspaceProvisionError("SHARED_GIT_AUTHORITY", "Git authority escapes workspace")
    for r in {gd, common}:
        for name in ("alternates", "http-alternates"):
            p = r / "objects" / "info" / name
            if p.exists() or p.is_symlink() or _is_reparse(p): raise WorkspaceProvisionError("SHARED_OBJECT_AUTHORITY", "alternates denied")
    fmt, n = _object_format(git, work); expected = _canonical_oid(expected_base_sha, n); head = _canonical_oid(_git_text(git, ["rev-parse", "HEAD"], cwd=work), n, "WORKSPACE_HEAD_INVALID")
    if head != expected: raise WorkspaceProvisionError("WORKSPACE_HEAD_MISMATCH", "HEAD mismatch")
    branch = _validate_branch(git, expected_branch); br = _run_git(git, ["symbolic-ref", "--quiet", "--short", "HEAD"], cwd=work, check=False)
    if br.returncode or br.stdout.strip() != branch: raise WorkspaceProvisionError("WORKSPACE_BRANCH_MISMATCH", "branch mismatch")
    remotes = tuple(x for x in _git_text(git, ["remote"], cwd=work).splitlines() if x.strip())
    if remotes: raise WorkspaceProvisionError("WORKSPACE_REMOTE_PRESENT", "remotes denied")
    src = source_identity or {}; sgd = str(src.get("source_git_dir") or ""); scd = str(src.get("source_common_dir") or "")
    if sgd and Path(sgd) == gd or scd and Path(scd) == common: raise WorkspaceProvisionError("SHARED_GIT_AUTHORITY", "shared Git metadata")
    return WorkspaceIdentity(str(src.get("source_root") or ""), sgd, scd, str(src.get("source_head") or ""), str(src.get("source_identity") or ""), str(work), str(gd), str(common), _digest_identity(str(top), str(gd), str(common), fmt, head, branch), fmt, expected, head, branch, remotes)


def _current_content_oid(path: Path, git: Path, expected_len: int) -> str:
    return _canonical_oid(_git_text(git, ["rev-parse", "HEAD"], cwd=path), expected_len, "WORKSPACE_CONTENT_OID_INVALID")


def reconcile_quarantined_workspace(workspace, workspace_root, generation_id, git_executable, *, protected_state: ProtectedWorkspaceState | None = None) -> dict:
    state = _require_state(protected_state); root, target = _candidate_under_root(workspace, workspace_root); record = _read_record(state, root, target)
    if record is None: raise WorkspaceProvisionError("WORKSPACE_QUARANTINE_NOT_FOUND", "no protected record")
    if record["generation"] != generation_id: raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH", "generation mismatch", generation_id=record["generation"])
    git = _git_executable(git_executable)
    stage = Path(record["stage"]); existing = target if (target.exists() or target.is_symlink() or _is_reparse(target)) else stage
    if existing.exists() or existing.is_symlink() or _is_reparse(existing):
        _assert_no_link_components(existing, "WORKSPACE_CLEANUP_DENIED"); _assert_plain_existing_path(existing, "WORKSPACE_CLEANUP_DENIED")
        continuity = record.get("recoveredFromState") in {"provisioning", "renaming"}
        if not _identity_matches(existing, record.get("identity"), continuity=continuity): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH", "generation identity mismatch")
        expected_oid = str(record["contentOid"]); observed_oid = _current_content_oid(existing, git, len(expected_oid))
        if observed_oid != expected_oid: raise WorkspaceProvisionError("WORKSPACE_CONTENT_OID_MISMATCH", "protected content identity mismatch")
        identity = _path_identity(existing)
        if not _stable_generation_equal(record["identity"], identity): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH", "identity changed before mutation")
        _rmtree_windows_safe(existing, identity)
    if target.exists() or stage.exists() or target.is_symlink() or stage.is_symlink() or _is_reparse(target) or _is_reparse(stage): raise WorkspaceProvisionError("WORKSPACE_CLEANUP_INCOMPLETE", "workspace remains")
    _delete_record(state, root, target)
    return {"reconciled": True, "generation": generation_id, "target": str(target), "contentOid": record["contentOid"]}


def cleanup_workspace(workspace, workspace_root, *, protected_state: ProtectedWorkspaceState | None = None) -> bool:
    state = _require_state(protected_state); root, target = _candidate_under_root(workspace, workspace_root)
    record = _read_record(state, root, target)
    if record is not None: raise WorkspaceProvisionError("WORKSPACE_QUARANTINED", "generation-bound reconciliation required", generation_id=record["generation"])
    if not target.exists() and not target.is_symlink() and not _is_reparse(target): return False
    identity = _path_identity(target, "WORKSPACE_CLEANUP_DENIED"); _rmtree_windows_safe(target, identity)
    if target.exists() or target.is_symlink() or _is_reparse(target): raise WorkspaceProvisionError("WORKSPACE_CLEANUP_INCOMPLETE", "workspace remains")
    return True


def _exception_code(ex: BaseException) -> str:
    return ex.code if isinstance(ex, WorkspaceProvisionError) else type(ex).__name__.upper()


def provision_workspace(source_repo, workspace, workspace_root, base_sha, task_branch, git_executable, *, protected_state: ProtectedWorkspaceState | None = None) -> WorkspaceIdentity:
    state = _require_state(protected_state); git = _git_executable(git_executable); root, target = _candidate_under_root(workspace, workspace_root)
    _assert_not_quarantined(state, root, target)
    if target.exists() or target.is_symlink() or _is_reparse(target): raise WorkspaceProvisionError("WORKSPACE_EXISTS", "workspace exists")
    source = inspect_source(source_repo, base_sha, git); branch = _validate_branch(git, task_branch); requested = source["base_sha"]
    generation = uuid.uuid4().hex; stage = root / f"{STAGE_PREFIX}{hashlib.sha256(str(target).encode()).hexdigest()[:16]}-{generation}"
    record = {"version": QUARANTINE_VERSION, "generation": generation, "target": str(target), "stage": str(stage), "identity": None, "contentOid": requested, "state": "preparing", "updatedAt": time.time()}
    try:
        # Windows must inherit the already-hardened protected parent ACL. CPython
        # 3.13 mkdir(mode=0o700) can synthesize an OWNER RIGHTS ACL that Docker
        # Desktop's Linux backend cannot traverse for bind mounts.
        _create_stage_dir(stage)
        _fsync_dir(root); record["identity"] = _path_identity(stage); record["state"] = "provisioning"; _write_record(state, root, target, record)
        with tempfile.TemporaryDirectory(prefix="forgeboss-git-template-", dir=str(root)) as template:
            _run_git(git, ["-c", "protocol.file.allow=always", "clone", "--no-local", "--no-hardlinks", "--no-checkout", "--no-tags", f"--template={Path(template)}", source["source_root"], str(stage)], cwd=root)
        for remote in [x for x in _git_text(git, ["remote"], cwd=stage).splitlines() if x.strip()]: _run_git(git, ["remote", "remove", remote], cwd=stage)
        _run_git(git, ["checkout", "--detach", requested], cwd=stage); _run_git(git, ["branch", "-f", branch, requested], cwd=stage); _run_git(git, ["checkout", branch], cwd=stage)
        if _current_content_oid(stage, git, len(requested)) != requested: raise WorkspaceProvisionError("WORKSPACE_CONTENT_OID_MISMATCH", "stage content mismatch")
        if not _identity_matches(stage, record["identity"], continuity=True): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH", "stage generation changed")
        stable = _path_identity(stage); record["identity"] = stable; record["state"] = "renaming"; _write_record(state, root, target, record)
        if target.exists() or target.is_symlink() or _is_reparse(target): raise WorkspaceProvisionError("WORKSPACE_EXISTS", "target appeared")
        stage.rename(target); _fsync_dir(root); renamed = _path_identity(target)
        if not _stable_generation_equal(stable, renamed): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH", "object changed across rename")
        record["identity"] = renamed; record["state"] = "finalizing"; _write_record(state, root, target, record)
        identity = verify_workspace(target, root, requested, branch, git, source_identity=source, protected_state=state, _allow_generation=generation)
        if stage.exists() or stage.is_symlink() or _is_reparse(stage): raise WorkspaceProvisionError("WORKSPACE_STAGE_REMAINS", "staging path remains")
        _delete_record(state, root, target)
        return identity
    except BaseException as ex:
        candidate = target if (target.exists() or target.is_symlink() or _is_reparse(target)) else stage
        cleanup_error = None
        try:
            if candidate.exists() or candidate.is_symlink() or _is_reparse(candidate):
                if not _identity_matches(candidate, record.get("identity"), continuity=record.get("state") in {"provisioning", "renaming"}): raise WorkspaceProvisionError("WORKSPACE_GENERATION_MISMATCH", "failed generation changed")
                _rmtree_windows_safe(candidate, _path_identity(candidate))
            if not target.exists() and not stage.exists(): _delete_record(state, root, target)
        except BaseException as ce:
            cleanup_error = ce
        if cleanup_error is None: raise
        record["state"] = "quarantined"; record["provisionError"] = {"code": _exception_code(ex), "message": str(ex)}; record["cleanupError"] = {"code": _exception_code(cleanup_error), "message": str(cleanup_error)}
        survivor = target if target.exists() else stage
        if survivor.exists(): record["identity"] = _path_identity(survivor)
        _write_record(state, root, target, record)
        raise WorkspaceProvisionError("WORKSPACE_PROVISION_CLEANUP_FAILED", "provisioning failed and generation quarantined", provision_code=_exception_code(ex), cleanup_code=_exception_code(cleanup_error), generation_id=generation) from cleanup_error