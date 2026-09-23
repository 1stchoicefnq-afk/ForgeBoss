from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
from types import MappingProxyType
from typing import Mapping

from forgeboss.security.local_acl import LocalAclError, harden_private_dir


class CodeIntelligenceError(RuntimeError):
    """Raised when the optional code-intelligence adapter cannot fail safely."""


ALLOWED_TOOLS = frozenset({
    "index_repository",
    "list_projects",
    "search_graph",
    "trace_call_path",
    "get_architecture",
    "search_code",
    "get_code_snippet",
})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_STDERR = 16_000
_MAX_STDOUT = 2_000_000
_MAX_STDERR_CAPTURE = 1_000_000
_MAX_ARGUMENT_BYTES = 24_000
_POLL_SECONDS = 0.05


@dataclass(frozen=True)
class CodeIntelligenceResult:
    tool: str
    binary_sha256: str
    workspace: str
    payload: object
    stderr: str
    advisory: bool = True
    freshness_proven: bool = False


def _clean_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise CodeIntelligenceError(f"{label} must be a string")
    clean = value.strip()
    if not clean:
        raise CodeIntelligenceError(f"{label} is required")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
        raise CodeIntelligenceError(f"{label} contains control characters")
    return clean


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        return os.path.commonpath((str(root), str(candidate))) == str(root)
    except ValueError:
        return False


def _outside_workspace(workspace: Path, candidate: Path, label: str) -> Path:
    resolved = candidate.resolve(strict=False)
    if _is_within(workspace, resolved) or _is_within(resolved, workspace):
        raise CodeIntelligenceError(
            f"{label} must be disjoint from the project workspace, not inside it or an ancestor"
        )
    return resolved


def _read_tail(path: Path, limit: int) -> str:
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > limit:
            handle.seek(size - limit)
        data = handle.read(limit)
    return data.decode("utf-8", errors="replace")


def _terminate_process_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            subprocess.run(
                ["taskkill.exe", "/pid", str(process.pid), "/t", "/f"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                shell=False,
                creationflags=flags,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            try:
                process.kill()
            except OSError:
                pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _wait_bounded(
    process: subprocess.Popen,
    *,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while True:
        returncode = process.poll()
        if returncode is not None:
            return returncode
        try:
            stdout_size = stdout_path.stat().st_size
            stderr_size = stderr_path.stat().st_size
        except OSError as ex:
            _terminate_process_tree(process)
            raise CodeIntelligenceError(
                f"cannot inspect code-intelligence output files: {ex}"
            ) from ex
        if stdout_size > _MAX_STDOUT:
            _terminate_process_tree(process)
            raise CodeIntelligenceError(
                f"code-intelligence stdout exceeded {_MAX_STDOUT} bytes"
            )
        if stderr_size > _MAX_STDERR_CAPTURE:
            _terminate_process_tree(process)
            raise CodeIntelligenceError(
                f"code-intelligence stderr exceeded {_MAX_STDERR_CAPTURE} bytes"
            )
        if time.monotonic() >= deadline:
            _terminate_process_tree(process)
            raise CodeIntelligenceError(
                f"code-intelligence tool timed out after {timeout_seconds}s"
            )
        time.sleep(_POLL_SECONDS)


def _freeze_json(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({str(k): _freeze_json(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


class CodebaseMemoryAdapter:
    """Pinned, local-only adapter for codebase-memory-mcp direct CLI tools.

    This adapter does not install, download, auto-configure or grant authority to
    codebase-memory-mcp. Its output is advisory and explicitly not release proof.
    """

    def __init__(
        self,
        *,
        binary_path: str | Path,
        expected_sha256: str,
        workspace: str | Path,
        cache_dir: str | Path,
        runtime_dir: str | Path,
        timeout_seconds: int = 120,
    ) -> None:
        self.binary = Path(binary_path).resolve(strict=True)
        if not self.binary.is_file():
            raise CodeIntelligenceError("binary_path must be a file")

        expected = _clean_text(expected_sha256, "expected_sha256").lower()
        if not _SHA256.fullmatch(expected):
            raise CodeIntelligenceError("expected_sha256 must be 64 hexadecimal characters")
        actual = _sha256_file(self.binary)
        if actual != expected:
            raise CodeIntelligenceError(
                f"codebase-memory-mcp SHA-256 mismatch: expected {expected}, got {actual}"
            )

        self.workspace = Path(workspace).resolve(strict=True)
        if not self.workspace.is_dir():
            raise CodeIntelligenceError("workspace must be a directory")

        self.cache_dir = _outside_workspace(
            self.workspace, Path(cache_dir), "cache_dir"
        )
        self.runtime_dir = _outside_workspace(
            self.workspace, Path(runtime_dir), "runtime_dir"
        )
        if _is_within(self.cache_dir, self.runtime_dir) or _is_within(
            self.runtime_dir, self.cache_dir
        ):
            raise CodeIntelligenceError("cache_dir and runtime_dir must be separate")

        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise CodeIntelligenceError("timeout_seconds must be an integer")
        if timeout_seconds <= 0 or timeout_seconds > 900:
            raise CodeIntelligenceError("timeout_seconds must be between 1 and 900")

        self.timeout_seconds = timeout_seconds
        self.binary_sha256 = actual

        try:
            harden_private_dir(self.cache_dir)
            harden_private_dir(self.runtime_dir)
            self.home_dir = self.runtime_dir / "home"
            harden_private_dir(self.home_dir)
            staged_dir = self.runtime_dir / "verified-bin"
            harden_private_dir(staged_dir)
        except LocalAclError as ex:
            raise CodeIntelligenceError(
                f"cannot harden code-intelligence state directories: {ex}"
            ) from ex
        suffix = self.binary.suffix if self.binary.suffix else ""
        self.staged_binary = staged_dir / f"codebase-memory-mcp-{actual}{suffix}"
        if self.staged_binary.exists():
            if not self.staged_binary.is_file() or _sha256_file(self.staged_binary) != actual:
                raise CodeIntelligenceError("existing staged code-intelligence binary has wrong identity")
        else:
            temp = staged_dir / f".{self.staged_binary.name}.tmp"
            try:
                shutil.copyfile(self.binary, temp)
                shutil.copymode(self.binary, temp)
                if os.name != "nt":
                    os.chmod(temp, 0o700)
                if _sha256_file(temp) != actual:
                    raise CodeIntelligenceError("staged code-intelligence binary failed SHA-256 verification")
                os.replace(temp, self.staged_binary)
            finally:
                try:
                    if temp.exists():
                        temp.unlink()
                except OSError:
                    pass
        if _sha256_file(self.staged_binary) != actual:
            raise CodeIntelligenceError("staged code-intelligence binary identity mismatch")

    def _verify_binary(self) -> None:
        source_actual = _sha256_file(self.binary)
        if source_actual != self.binary_sha256:
            raise CodeIntelligenceError(
                "codebase-memory-mcp source binary changed after adapter initialization"
            )
        staged_actual = _sha256_file(self.staged_binary)
        if staged_actual != self.binary_sha256:
            raise CodeIntelligenceError(
                "staged codebase-memory-mcp binary changed after verification"
            )

    def _environment(self) -> dict[str, str]:
        env = {
            "CBM_ALLOWED_ROOT": str(self.workspace),
            "CBM_CACHE_DIR": str(self.cache_dir),
            "CBM_RUNTIME_DIR": str(self.runtime_dir),
            "CBM_LOG_LEVEL": "error",
            "HOME": str(self.home_dir),
            "USERPROFILE": str(self.home_dir),
        }
        for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
            value = os.environ.get(key)
            if value:
                env[key] = value
        return env

    def call(self, tool: str, arguments: Mapping[str, object] | None = None) -> CodeIntelligenceResult:
        clean_tool = _clean_text(tool, "tool")
        if clean_tool not in ALLOWED_TOOLS:
            raise CodeIntelligenceError(f"code-intelligence tool is not allowlisted: {clean_tool}")

        if arguments is None:
            args_obj: dict[str, object] = {}
        elif isinstance(arguments, Mapping):
            args_obj = dict(arguments)
        else:
            raise CodeIntelligenceError("arguments must be a mapping")

        if clean_tool == "index_repository":
            supplied = args_obj.get("repo_path")
            if supplied is not None:
                supplied_path = Path(_clean_text(supplied, "repo_path")).resolve(strict=False)
                if supplied_path != self.workspace:
                    raise CodeIntelligenceError(
                        "index_repository repo_path must equal the bound workspace"
                    )
            args_obj["repo_path"] = str(self.workspace)

        self._verify_binary()

        try:
            encoded = json.dumps(
                args_obj,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as ex:
            raise CodeIntelligenceError(
                f"code-intelligence arguments are not valid JSON data: {ex}"
            ) from ex
        if len(encoded.encode("utf-8")) > _MAX_ARGUMENT_BYTES:
            raise CodeIntelligenceError(
                f"code-intelligence arguments exceed {_MAX_ARGUMENT_BYTES} UTF-8 bytes"
            )
        argv = [str(self.staged_binary), "cli", clean_tool, encoded]

        flags = 0
        if os.name == "nt":
            flags = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )

        with tempfile.TemporaryDirectory(
            prefix="cbm-call-",
            dir=str(self.runtime_dir),
        ) as temp_dir:
            out_path = Path(temp_dir) / "stdout.bin"
            err_path = Path(temp_dir) / "stderr.bin"
            try:
                with out_path.open("wb") as out_handle, err_path.open("wb") as err_handle:
                    process = subprocess.Popen(
                        argv,
                        cwd=str(self.workspace),
                        env=self._environment(),
                        shell=False,
                        stdin=subprocess.DEVNULL,
                        stdout=out_handle,
                        stderr=err_handle,
                        start_new_session=(os.name != "nt"),
                        creationflags=flags,
                    )
                    returncode = _wait_bounded(
                        process,
                        stdout_path=out_path,
                        stderr_path=err_path,
                        timeout_seconds=self.timeout_seconds,
                    )
            except CodeIntelligenceError:
                raise
            except OSError as ex:
                raise CodeIntelligenceError(
                    f"code-intelligence process could not start: {type(ex).__name__}: {ex}"
                ) from ex

            stderr_size = err_path.stat().st_size
            if stderr_size > _MAX_STDERR_CAPTURE:
                raise CodeIntelligenceError(
                    f"code-intelligence stderr exceeded {_MAX_STDERR_CAPTURE} bytes"
                )
            stderr = _read_tail(err_path, _MAX_STDERR)
            stdout_size = out_path.stat().st_size
            if stdout_size > _MAX_STDOUT:
                raise CodeIntelligenceError(
                    f"code-intelligence stdout exceeded {_MAX_STDOUT} bytes"
                )
            if returncode != 0:
                raise CodeIntelligenceError(
                    f"code-intelligence tool failed with exit {returncode}: {stderr}"
                )

            try:
                stdout_text = out_path.read_text(encoding="utf-8")
            except UnicodeDecodeError as ex:
                raise CodeIntelligenceError(
                    "code-intelligence tool returned non-UTF-8 stdout"
                ) from ex
            try:
                payload = json.loads(stdout_text)
            except json.JSONDecodeError as ex:
                raise CodeIntelligenceError(
                    "code-intelligence tool returned non-JSON stdout"
                ) from ex

        self._verify_binary()

        return CodeIntelligenceResult(
            tool=clean_tool,
            binary_sha256=self.binary_sha256,
            workspace=str(self.workspace),
            payload=_freeze_json(payload),
            stderr=stderr,
            advisory=True,
            freshness_proven=False,
        )