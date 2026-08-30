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


class ProtectedWorkspaceState:
    """Workspace quarantine/generation state anchored under the accepted service-owned root."""

    def __init__(self, *, protected_root: str | os.PathLike[str], boundary: PlatformMachineBoundary):
        self.boundary = boundary
        try:
            self.root = Path(protected_root).resolve(strict=True)
            self.boundary.assert_service_principal(self.root)
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID") from ex
        self.state_dir = self.root / STATE_DIRNAME
        try:
            if not self.state_dir.exists():
                self.state_dir.mkdir(mode=0o700)
                _fsync_dir(self.root)
            self._assert_state_dir()
        except ProtectedWorkspaceStateError:
            raise
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID") from ex

    def _assert_service(self) -> None:
        try:
            self.boundary.assert_service_principal(self.root)
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_PRINCIPAL_DENIED") from ex

    def _assert_state_dir(self) -> None:
        self._assert_service()
        try:
            if self.state_dir.is_symlink() or not self.state_dir.is_dir():
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID")
            self.boundary.assert_protected_path(self.state_dir, protected_root=self.root)
        except ProtectedWorkspaceStateError:
            raise
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_ROOT_INVALID") from ex

    def key_for(self, workspace_root: Path, target: Path) -> str:
        root = Path(workspace_root).resolve(strict=True)
        parent = Path(target).parent.resolve(strict=True)
        canonical_target = parent / Path(target).name
        payload = json.dumps(
            {"workspaceRoot": _identity_text(root), "target": _identity_text(canonical_target)},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def path_for(self, workspace_root: Path, target: Path) -> Path:
        return self.state_dir / f"{self.key_for(workspace_root, target)}.json"

    def write(self, workspace_root: Path, target: Path, value: dict) -> None:
        self._assert_state_dir()
        path = self.path_for(workspace_root, target)
        try:
            payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID") from ex
        if not payload or len(payload) > MAX_RECORD_BYTES:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
        temp = self.state_dir / f".{path.name}.tmp-{uuid.uuid4().hex}"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = None
        try:
            fd = os.open(str(temp), flags, 0o600)
            os.write(fd, payload)
            os.fsync(fd)
        except OSError as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_WRITE_FAILED") from ex
        finally:
            if fd is not None:
                os.close(fd)
        try:
            self.boundary.assert_protected_path(temp, protected_root=self.root, secret=True)
            os.replace(temp, path)
            _fsync_dir(self.state_dir)
            self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
        except Exception as ex:
            try:
                temp.unlink()
            except OSError:
                pass
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_WRITE_FAILED") from ex

    def read(self, workspace_root: Path, target: Path) -> dict | None:
        self._assert_state_dir()
        path = self.path_for(workspace_root, target)
        if not path.exists():
            return None
        if path.is_symlink():
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
        fd = None
        try:
            self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_RECORD_BYTES:
                    raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
                chunks.append(chunk)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_CHANGED")
            self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
            value = json.loads(b"".join(chunks).decode("utf-8"))
        except ProtectedWorkspaceStateError:
            raise
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID") from ex
        finally:
            if fd is not None:
                os.close(fd)
        if not isinstance(value, dict):
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
        return value

    def delete(self, workspace_root: Path, target: Path) -> None:
        self._assert_state_dir()
        path = self.path_for(workspace_root, target)
        if not path.exists():
            return
        try:
            self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
            path.unlink()
            _fsync_dir(self.state_dir)
        except Exception as ex:
            raise ProtectedWorkspaceStateError("PROTECTED_STATE_DELETE_FAILED") from ex

    def records(self) -> Iterable[dict]:
        self._assert_state_dir()
        for path in sorted(self.state_dir.glob("*.json")):
            if path.is_symlink():
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
            try:
                self.boundary.assert_protected_path(path, protected_root=self.root, secret=True)
                raw = path.read_bytes()
                if not raw or len(raw) > MAX_RECORD_BYTES:
                    raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
                value = json.loads(raw.decode("utf-8"))
            except ProtectedWorkspaceStateError:
                raise
            except Exception as ex:
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID") from ex
            if not isinstance(value, dict):
                raise ProtectedWorkspaceStateError("PROTECTED_STATE_RECORD_INVALID")
            yield value
