from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from types import MappingProxyType
from typing import Mapping


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
    if _is_within(workspace, resolved):
        raise CodeIntelligenceError(f"{label} must live outside the project workspace")
    return resolved


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

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.home_dir = self.runtime_dir / "home"
        self.home_dir.mkdir(parents=True, exist_ok=True)

        staged_dir = self.runtime_dir / "verified-bin"
        staged_dir.mkdir(parents=True, exist_ok=True)
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

        encoded = json.dumps(
            args_obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        argv = [str(self.staged_binary), "cli", clean_tool, encoded]

        try:
            completed = subprocess.run(
                argv,
                cwd=str(self.workspace),
                env=self._environment(),
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as ex:
            raise CodeIntelligenceError(
                f"code-intelligence tool timed out after {self.timeout_seconds}s"
            ) from ex
        except OSError as ex:
            raise CodeIntelligenceError(
                f"code-intelligence process could not start: {type(ex).__name__}: {ex}"
            ) from ex

        stderr = completed.stderr[-_MAX_STDERR:]
        if completed.returncode != 0:
            raise CodeIntelligenceError(
                f"code-intelligence tool failed with exit {completed.returncode}: {stderr}"
            )

        try:
            payload = json.loads(completed.stdout)
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