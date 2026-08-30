from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Iterable

from forgeboss.protected_authority.boundary import PlatformMachineBoundary

STATE_DIRNAME = "workspace-state-v7"
MAX_RECORD_BYTES = 128 * 1024


class ProtectedWorkspaceStateError(RuntimeError):
    def __init__(self, code: str, message: str = "protected workspace state denied"):
        super().__init__(message)
        self.code = code


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _identity_text(path: Path) -> str:
    value = str(path)
    return os.path.normcase(value) if os.name == "nt" else value


def _fd_identity(st) -> tuple[int, int, int, int, int]:
    return (int(st.st_dev), int(st.st_ino), int(st.st_mode), int(getattr(st, "st_uid", -1)), int(getattr(st, "st_gid", -1)))


class ProtectedWorkspaceState:
    """Workspace state anchored to the accepted service-owned protected root.

    On POSIX, pathname checks are used only while acquiring the protected root
    and state-directory file descriptors. All later record I/O is relative to
    the held state-directory fd, so replacing the pathname cannot redirect
    authoritative state operations.
    """

    def __init__(self, *, protected_root: str | os.PathLike[str], boundary: PlatformMachineBoundary):
        self.boundary = boundary
        self._root_fd: int | None = None
        self._state_fd: int | None = None
        self._root_identity: tuple[int, int, int, int, int] | None = None
        self._state_identity: tuple[int, int, int, int, int] | None = None
        try:
            self.root = Path(protected_root).resolve(strict=True)
            self.boundary.assert_service_principal(self.root)
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID") from ex
        self.state_dir = self.root / STATE_DIRNAME
        if os.name == "nt":
            try:
                if not self.state_dir.exists():
                    self.state_dir.mkdir(mode=0o700)
                    _fsync_dir(self.root)
                self._assert_windows_state_dir()
            except ProtectedWorkspaceStateError:
                raise
            except Exception as ex:
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID") from ex
        else:
            self._open_posix_anchor()

    def close(self) -> None:
        for name in ("_state_fd", "_root_fd"):
            fd = getattr(self, name, None)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, None)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _assert_service(self) -> None:
        try:
            self.boundary.assert_service_principal(self.root)
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_PRINCIPAL_DENIED") from ex

    def _assert_windows_state_dir(self) -> None:
        self._assert_service()
        try:
            if self.state_dir.is_symlink() or not self.state_dir.is_dir():
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID")
            self.boundary.assert_protected_path(self.state_dir, protected_root=self.root)
        except ProtectedWorkspaceStateError:
            raise
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID") from ex

    def _open_posix_anchor(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            root_fd = os.open(str(self.root), flags)
            root_st = os.fstat(root_fd)
            if not stat.S_ISDIR(root_st.st_mode):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID")
            try:
                state_fd = os.open(STATE_DIRNAME, flags, dir_fd=root_fd)
            except FileNotFoundError:
                os.mkdir(STATE_DIRNAME, 0o700, dir_fd=root_fd)
                os.fsync(root_fd)
                state_fd = os.open(STATE_DIRNAME, flags, dir_fd=root_fd)
            state_st = os.fstat(state_fd)
            if not stat.S_ISDIR(state_st.st_mode):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID")

            # Re-run the accepted protected-boundary checks after acquiring the
            # handles, then prove those checked pathnames still name the held
            # objects. A swap before this point fails; a swap after this point
            # cannot redirect fd-relative I/O.
            self.boundary.assert_service_principal(self.root)
            self.boundary.assert_protected_path(self.state_dir, protected_root=self.root)
            root_path_st = os.stat(self.root, follow_symlinks=False)
            state_path_st = os.stat(self.state_dir, follow_symlinks=False)
            if _fd_identity(root_st) != _fd_identity(root_path_st):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_CHANGED")
            if _fd_identity(state_st) != _fd_identity(state_path_st):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_CHANGED")

            self._root_fd = root_fd
            self._state_fd = state_fd
            self._root_identity = _fd_identity(root_st)
            self._state_identity = _fd_identity(state_st)
        except ProtectedWorkspaceStateError:
            for fd in (locals().get("state_fd"), locals().get("root_fd")):
                if isinstance(fd, int):
                    try: os.close(fd)
                    except OSError: pass
            raise
        except Exception as ex:
            for fd in (locals().get("state_fd"), locals().get("root_fd")):
                if isinstance(fd, int):
                    try: os.close(fd)
                    except OSError: pass
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID") from ex

    def _assert_posix_anchor(self) -> int:
        if self._root_fd is None or self._state_fd is None or self._root_identity is None or self._state_identity is None:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ANCHOR_CLOSED")
        try:
            root_st = os.fstat(self._root_fd)
            state_st = os.fstat(self._state_fd)
        except OSError as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ANCHOR_INVALID") from ex
        if not stat.S_ISDIR(root_st.st_mode) or not stat.S_ISDIR(state_st.st_mode):
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ANCHOR_INVALID")
        if _fd_identity(root_st) != self._root_identity or _fd_identity(state_st) != self._state_identity:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ANCHOR_CHANGED")
        return self._state_fd

    def key_for(self, workspace_root: Path, target: Path) -> str:
        root = Path(workspace_root).resolve(strict=True)
        parent = Path(target).parent.resolve(strict=True)
        canonical_target = parent / Path(target).name
        payload = json.dumps(
            {"workspaceRoot": _identity_text(root), "target": _identity_text(canonical_target)},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _name_for(self, workspace_root: Path, target: Path) -> str:
        return f"{self.key_for(workspace_root, target)}.json"

    def path_for(self, workspace_root: Path, target: Path) -> Path:
        # Display/diagnostic path only. POSIX authority never opens this path.
        return self.state_dir / self._name_for(workspace_root, target)

    @staticmethod
    def _payload(value: dict) -> bytes:
        try:
            payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID") from ex
        if not payload or len(payload) > MAX_RECORD_BYTES:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
        return payload

    def write(self, workspace_root: Path, target: Path, value: dict) -> None:
        payload = self._payload(value)
        if os.name == "nt":
            self._write_windows(workspace_root, target, payload)
            return
        state_fd = self._assert_posix_anchor()
        name = self._name_for(workspace_root, target)
        temp_name = f".{name}.tmp-{uuid.uuid4().hex}"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = None
        try:
            fd = os.open(temp_name, flags, 0o600, dir_fd=state_fd)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_WRITE_FAILED")
            os.write(fd, payload)
            os.fsync(fd)
            os.close(fd); fd = None
            self._assert_posix_anchor()
            os.replace(temp_name, name, src_dir_fd=state_fd, dst_dir_fd=state_fd)
            os.fsync(state_fd)
            self._assert_posix_anchor()
        except ProtectedWorkspaceStateError:
            try: os.unlink(temp_name, dir_fd=state_fd)
            except OSError: pass
            raise
        except Exception as ex:
            try: os.unlink(temp_name, dir_fd=state_fd)
            except OSError: pass
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_WRITE_FAILED") from ex
        finally:
            if fd is not None:
                try: os.close(fd)
                except OSError: pass

    def _write_windows(self, workspace_root: Path, target: Path, payload: bytes) -> None:
        self._assert_windows_state_dir()
        path = self.path_for(workspace_root, target)
        temp = self.state_dir / f".{path.name}.tmp-{uuid.uuid4().hex}"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = None
        try:
            fd = os.open(str(temp), flags, 0o600)
            os.write(fd, payload); os.fsync(fd); os.close(fd); fd = None
            self.boundary.assert_protected_path(temp, protected_root=self.root, secret=True)
            os.replace(temp, path); _fsync_dir(self.state_dir)
            self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
        except Exception as ex:
            try: temp.unlink()
            except OSError: pass
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_WRITE_FAILED") from ex
        finally:
            if fd is not None:
                try: os.close(fd)
                except OSError: pass

    def read(self, workspace_root: Path, target: Path) -> dict | None:
        if os.name == "nt":
            return self._read_windows(workspace_root, target)
        state_fd = self._assert_posix_anchor()
        return self._read_posix_name(self._name_for(workspace_root, target), state_fd, missing_ok=True)

    def _read_posix_name(self, name: str, state_fd: int, *, missing_ok: bool) -> dict | None:
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=state_fd)
        except FileNotFoundError:
            if missing_ok: return None
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
        except OSError as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID") from ex
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
            chunks: list[bytes] = []; total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk: break
                total += len(chunk)
                if total > MAX_RECORD_BYTES:
                    raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
                chunks.append(chunk)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_CHANGED")
            self._assert_posix_anchor()
            value = json.loads(b"".join(chunks).decode("utf-8"))
        except ProtectedWorkspaceStateError:
            raise
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID") from ex
        finally:
            os.close(fd)
        if not isinstance(value, dict):
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
        return value

    def _read_windows(self, workspace_root: Path, target: Path) -> dict | None:
        self._assert_windows_state_dir()
        path = self.path_for(workspace_root, target)
        if not path.exists(): return None
        if path.is_symlink(): raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
        fd = None
        try:
            self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode): raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
            chunks: list[bytes] = []; total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk: break
                total += len(chunk)
                if total > MAX_RECORD_BYTES: raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
                chunks.append(chunk)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino): raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_CHANGED")
            self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
            value = json.loads(b"".join(chunks).decode("utf-8"))
        except ProtectedWorkspaceStateError:
            raise
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID") from ex
        finally:
            if fd is not None: os.close(fd)
        if not isinstance(value, dict): raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
        return value

    def delete(self, workspace_root: Path, target: Path) -> None:
        if os.name == "nt":
            self._delete_windows(workspace_root, target)
            return
        state_fd = self._assert_posix_anchor()
        name = self._name_for(workspace_root, target)
        try:
            row = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_DELETE_FAILED") from ex
        if not stat.S_ISREG(row.st_mode):
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
        try:
            self._assert_posix_anchor()
            os.unlink(name, dir_fd=state_fd)
            os.fsync(state_fd)
            self._assert_posix_anchor()
        except ProtectedWorkspaceStateError:
            raise
        except OSError as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_DELETE_FAILED") from ex

    def _delete_windows(self, workspace_root: Path, target: Path) -> None:
        self._assert_windows_state_dir()
        path = self.path_for(workspace_root, target)
        if not path.exists(): return
        try:
            self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
            path.unlink(); _fsync_dir(self.state_dir)
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_DELETE_FAILED") from ex

    def records(self) -> Iterable[dict]:
        if os.name == "nt":
            yield from self._records_windows(); return
        state_fd = self._assert_posix_anchor()
        try:
            names = sorted(os.listdir(state_fd))
        except OSError as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID") from ex
        for name in names:
            if not name.endswith(".json") or name.startswith("."):
                continue
            value = self._read_posix_name(name, state_fd, missing_ok=False)
            assert value is not None
            yield value

    def _records_windows(self) -> Iterable[dict]:
        self._assert_windows_state_dir()
        for path in sorted(self.state_dir.glob("*.json")):
            if path.is_symlink(): raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
            try:
                self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
                raw = path.read_bytes()
                if not raw or len(raw) > MAX_RECORD_BYTES: raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
                value = json.loads(raw.decode("utf-8"))
            except ProtectedWorkspaceStateError:
                raise
            except Exception as ex:
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID") from ex
            if not isinstance(value, dict): raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
            yield value
