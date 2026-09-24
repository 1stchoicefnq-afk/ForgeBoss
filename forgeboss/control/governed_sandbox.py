from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Callable, Sequence

from forgeboss.security.executor_guard import (
    SecurityError,
    _assert_live_control_lease,
    paid_start_authority,
)


class GovernedSandboxError(RuntimeError):
    """Raised when the host-side governed sandbox cannot fail safely."""


_IMAGE_DIGEST = re.compile(r"^[A-Za-z0-9._/:@+-]+@sha256:[0-9a-f]{64}$")
_VOLUME_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_DEFAULT_MAX_OUTPUT = 64 * 1024
_DEFAULT_MAX_SOURCE_BYTES = 512 * 1024 * 1024
_DEFAULT_MAX_SOURCE_FILES = 100_000
_DEFAULT_WORKSPACE_TMPFS = "768m"
_TRUNCATION = "\n[...TRUNCATED...]\n"
_READ_DENY_PREFIXES = (
    ".git/",
    "secrets/",
    "appdata/",
    ".openhands/",
    "ci/credentials/",
    "build/credentials/",
    "state/forgebossd/",
    "state/learning/",
    ".aws/",
    ".ssh/",
    ".gnupg/",
)
_READ_DENY_EXACT = {
    ".git",
    ".npmrc",
    ".pypirc",
}


@dataclass(frozen=True)
class DockerIdentity:
    path: str
    sha256: str


@dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


@dataclass(frozen=True)
class SandboxResult:
    docker: DockerIdentity
    image: str
    volume: str
    worker: ProcessResult
    result_dir: str
    network_mode: str = "none"
    authority_consumed: bool = True


class _BoundedText:
    def __init__(self, limit: int):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < len(_TRUNCATION) + 32:
            raise GovernedSandboxError("output limit is invalid")
        self.limit = limit
        kept = limit - len(_TRUNCATION)
        self.head_limit = (kept + 1) // 2
        self.tail_limit = kept // 2
        self.head = ""
        self.tail = ""
        self.truncated = False
        self.lock = threading.Lock()

    def append(self, text: str) -> None:
        if not text:
            return
        with self.lock:
            if not self.truncated:
                combined = self.head + text
                if len(combined) <= self.limit:
                    self.head = combined
                    return
                self.truncated = True
                self.head = combined[: self.head_limit]
                self.tail = combined[-self.tail_limit :] if self.tail_limit else ""
                return
            if self.tail_limit:
                self.tail = (self.tail + text)[-self.tail_limit :]

    def value(self) -> str:
        with self.lock:
            if self.truncated:
                return self.head + _TRUNCATION + self.tail
            return self.head


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_docker_identity(explicit_path: str | Path | None = None) -> DockerIdentity:
    raw = str(explicit_path) if explicit_path is not None else shutil.which(
        "docker.exe" if os.name == "nt" else "docker"
    )
    if not raw:
        raise GovernedSandboxError("Docker CLI is unavailable")
    original = Path(raw)
    try:
        if original.is_symlink():
            raise GovernedSandboxError("Docker CLI must not be a symlink")
        if hasattr(original, "is_junction") and original.is_junction():
            raise GovernedSandboxError("Docker CLI must not be a junction")
        resolved = original.resolve(strict=True)
    except GovernedSandboxError:
        raise
    except OSError as ex:
        raise GovernedSandboxError("Docker CLI identity cannot be resolved") from ex
    if not resolved.is_file():
        raise GovernedSandboxError("Docker CLI must be a regular file")
    if os.name != "nt" and not os.access(resolved, os.X_OK):
        raise GovernedSandboxError("Docker CLI is not executable")
    before = _sha256_file(resolved)
    after = _sha256_file(resolved)
    if before != after:
        raise GovernedSandboxError("Docker CLI changed while hashing")
    return DockerIdentity(str(resolved), before)


def _validate_image(image: object) -> str:
    if not isinstance(image, str):
        raise GovernedSandboxError("image must be a digest-pinned string")
    clean = image.strip()
    if clean != image or not _IMAGE_DIGEST.fullmatch(clean):
        raise GovernedSandboxError("image must be pinned as name@sha256:<64 lowercase hex>")
    return clean


def _absolute_dir(path: str | Path, label: str, *, must_exist: bool = True) -> Path:
    p = Path(path)
    if not p.is_absolute():
        raise GovernedSandboxError(f"{label} must be absolute")
    try:
        resolved = p.resolve(strict=must_exist)
    except OSError as ex:
        raise GovernedSandboxError(f"{label} cannot be resolved") from ex
    if must_exist and not resolved.is_dir():
        raise GovernedSandboxError(f"{label} must be a directory")
    return resolved


def _read_denied(relative: str) -> bool:
    key = relative.replace("\\", "/").casefold().strip("/")
    if not key:
        return False
    name = key.rsplit("/", 1)[-1]
    if name == ".env" or name.startswith(".env."):
        return True
    if key in _READ_DENY_EXACT:
        return True
    return any(key.startswith(prefix) for prefix in _READ_DENY_PREFIXES)


def create_sanitized_source(
    source: Path,
    destination: Path,
    *,
    max_bytes: int = _DEFAULT_MAX_SOURCE_BYTES,
    max_files: int = _DEFAULT_MAX_SOURCE_FILES,
) -> tuple[int, int]:
    if max_bytes <= 0 or max_files <= 0:
        raise GovernedSandboxError("sandbox source limits must be positive")
    source = source.resolve(strict=True)
    destination = destination.resolve(strict=True)
    total_bytes = 0
    total_files = 0

    for root, dirnames, filenames in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        rel_root = root_path.relative_to(source)

        kept_dirs = []
        for name in dirnames:
            src = root_path / name
            rel = (rel_root / name).as_posix()
            try:
                if src.is_symlink() or (hasattr(src, "is_junction") and src.is_junction()):
                    raise GovernedSandboxError(f"source contains linklike directory: {rel}")
            except OSError as ex:
                raise GovernedSandboxError(f"source directory identity unreadable: {rel}") from ex
            if _read_denied(rel):
                continue
            kept_dirs.append(name)
            (destination / rel).mkdir(parents=True, exist_ok=True)
        dirnames[:] = kept_dirs

        for name in filenames:
            src = root_path / name
            rel = (rel_root / name).as_posix()
            if _read_denied(rel):
                continue
            try:
                if src.is_symlink() or (hasattr(src, "is_junction") and src.is_junction()):
                    raise GovernedSandboxError(f"source contains linklike file: {rel}")
                stat = src.stat()
            except OSError as ex:
                raise GovernedSandboxError(f"source file identity unreadable: {rel}") from ex
            if not src.is_file():
                raise GovernedSandboxError(f"source contains non-regular file: {rel}")
            total_files += 1
            total_bytes += int(stat.st_size)
            if total_files > max_files:
                raise GovernedSandboxError("sandbox source file-count limit exceeded")
            if total_bytes > max_bytes:
                raise GovernedSandboxError("sandbox source byte limit exceeded")
            dst = destination / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    return total_files, total_bytes


def _mount_value(path: Path) -> str:
    value = str(path)
    if "," in value or "\x00" in value or "\r" in value or "\n" in value:
        raise GovernedSandboxError("Docker mount path contains unsupported characters")
    return value


def _worker_command(values: object) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        raise GovernedSandboxError("worker command must be an argv array")
    out = []
    for value in values:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise GovernedSandboxError("worker command contains invalid argv")
        out.append(value)
    if not out:
        raise GovernedSandboxError("worker command must not be empty")
    return tuple(out)


def assert_docker_identity(identity: DockerIdentity) -> None:
    path = Path(identity.path)
    try:
        if path.is_symlink():
            raise GovernedSandboxError("Docker CLI became a symlink")
        if hasattr(path, "is_junction") and path.is_junction():
            raise GovernedSandboxError("Docker CLI became a junction")
        resolved = path.resolve(strict=True)
    except GovernedSandboxError:
        raise
    except OSError as ex:
        raise GovernedSandboxError("Docker CLI identity cannot be revalidated") from ex
    if str(resolved) != identity.path:
        raise GovernedSandboxError("Docker CLI path identity changed")
    if _sha256_file(resolved) != identity.sha256:
        raise GovernedSandboxError("Docker CLI bytes changed after verification")


def _docker_base(container_name: str) -> list[str]:
    if not _VOLUME_NAME.fullmatch(container_name):
        raise GovernedSandboxError("invalid Docker container name")
    return [
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "1g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
    ]


def build_stage_argv(
    docker: DockerIdentity,
    image: str,
    volume: str,
    source: Path,
    container_name: str | None = None,
) -> tuple[str, ...]:
    if not _VOLUME_NAME.fullmatch(volume):
        raise GovernedSandboxError("invalid Docker volume name")
    return tuple(
        [docker.path]
        + _docker_base(container_name or (volume + "_stage"))
        + [
            "--entrypoint",
            "/bin/cp",
            "--mount",
            f"type=bind,src={_mount_value(source)},dst=/source,readonly",
            "--mount",
            f"type=volume,src={volume},dst=/workspace",
            "-w",
            "/workspace",
            image,
            "-a",
            "/source/.",
            "/workspace/",
        ]
    )


def build_worker_argv(
    docker: DockerIdentity,
    image: str,
    volume: str,
    command: Sequence[str],
    container_name: str | None = None,
) -> tuple[str, ...]:
    if not _VOLUME_NAME.fullmatch(volume):
        raise GovernedSandboxError("invalid Docker volume name")
    cmd = _worker_command(command)
    return tuple(
        [docker.path]
        + _docker_base(container_name or (volume + "_worker"))
        + [
            "--mount",
            f"type=volume,src={volume},dst=/workspace",
            "-w",
            "/workspace",
            image,
        ]
        + list(cmd)
    )


def build_extract_argv(
    docker: DockerIdentity,
    image: str,
    volume: str,
    result_dir: Path,
    container_name: str | None = None,
) -> tuple[str, ...]:
    if not _VOLUME_NAME.fullmatch(volume):
        raise GovernedSandboxError("invalid Docker volume name")
    return tuple(
        [docker.path]
        + _docker_base(container_name or (volume + "_extract"))
        + [
            "--entrypoint",
            "/bin/cp",
            "--mount",
            f"type=volume,src={volume},dst=/workspace,readonly",
            "--mount",
            f"type=bind,src={_mount_value(result_dir)},dst=/result",
            "-w",
            "/workspace",
            image,
            "-a",
            "/workspace/.",
            "/result/",
        ]
    )


def _docker_cli_env() -> dict[str, str]:
    allowed = (
        "SYSTEMROOT",
        "WINDIR",
        "HOME",
        "USERPROFILE",
        "TEMP",
        "TMP",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    )
    return {key: os.environ[key] for key in allowed if os.environ.get(key)}


def run_process_bounded(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    max_output: int = _DEFAULT_MAX_OUTPUT,
    watchdog: Callable[[], None] | None = None,
) -> ProcessResult:
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool):
        raise GovernedSandboxError("timeout_seconds must be an integer")
    if timeout_seconds <= 0 or timeout_seconds > 3600:
        raise GovernedSandboxError("timeout_seconds must be between 1 and 3600")
    if not argv:
        raise GovernedSandboxError("argv must not be empty")
    out = _BoundedText(max_output)
    err = _BoundedText(max_output)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            env=_docker_cli_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as ex:
        raise GovernedSandboxError(
            f"Docker process could not start: {type(ex).__name__}: {ex}"
        ) from ex

    def pump(stream, sink: _BoundedText):
        try:
            for chunk in iter(lambda: stream.read(4096), ""):
                if not chunk:
                    break
                sink.append(chunk)
        finally:
            try:
                stream.close()
            except Exception:
                pass

    threads = [
        threading.Thread(target=pump, args=(proc.stdout, out), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, err), daemon=True),
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            if watchdog is not None:
                try:
                    watchdog()
                except Exception as ex:
                    try:
                        proc.kill()
                    finally:
                        proc.wait(timeout=10)
                    raise GovernedSandboxError(
                        f"live authority revoked during Docker execution: {ex}"
                    ) from ex
            if time.monotonic() >= deadline:
                try:
                    proc.kill()
                finally:
                    proc.wait(timeout=10)
                raise GovernedSandboxError(
                    f"Docker process timed out after {timeout_seconds}s"
                )
            time.sleep(0.25)
    finally:
        for thread in threads:
            thread.join(timeout=5)

    return ProcessResult(
        argv=tuple(str(x) for x in argv),
        returncode=int(rc),
        stdout=out.value(),
        stderr=err.value(),
        duration_seconds=max(0.0, time.monotonic() - started),
    )


def _require_ok(result: ProcessResult, label: str) -> ProcessResult:
    if result.returncode != 0:
        raise GovernedSandboxError(
            f"{label} failed with exit {result.returncode}: {result.stderr[-4000:]}"
        )
    return result


def _assert_result_tree_safe(root: Path) -> None:
    root = root.resolve(strict=True)
    for path in root.rglob("*"):
        try:
            if path.is_symlink():
                raise GovernedSandboxError(
                    f"sandbox result contains symlink: {path.relative_to(root)}"
                )
            if hasattr(path, "is_junction") and path.is_junction():
                raise GovernedSandboxError(
                    f"sandbox result contains junction: {path.relative_to(root)}"
                )
        except OSError as ex:
            raise GovernedSandboxError("sandbox result identity cannot be inspected") from ex


def run_governed_sandbox(
    *,
    source_workspace: str | Path,
    result_dir: str | Path,
    image: str,
    worker_command: Sequence[str],
    lease_path: str | Path,
    lease_token: str,
    packet_path: str | Path,
    executor: str,
    control_envelope: object,
    cli_budget: object,
    docker_path: str | Path | None = None,
    timeout_seconds: int = 900,
    process_runner: Callable[..., ProcessResult] = run_process_bounded,
) -> SandboxResult:
    """Run an already-authorized worker command inside a no-network Docker sandbox.

    Authority is consumed on the trusted host. ForgeBoss source/control state is
    never mounted into the worker container by this primitive.
    """
    source = _absolute_dir(source_workspace, "source_workspace")
    result = _absolute_dir(result_dir, "result_dir")
    if any(result.iterdir()):
        raise GovernedSandboxError("result_dir must be empty")
    if os.path.commonpath((str(source), str(result))) in (str(source), str(result)):
        raise GovernedSandboxError("result_dir and source_workspace must be disjoint")

    pinned_image = _validate_image(image)
    docker = resolve_docker_identity(docker_path)
    command = _worker_command(worker_command)
    volume = "forgeboss_gov_" + secrets.token_hex(12)
    names = {
        "stage": volume + "_stage",
        "worker": volume + "_worker",
        "extract": volume + "_extract",
    }

    create = (
        docker.path,
        "volume",
        "create",
        "--driver",
        "local",
        "--opt",
        "type=tmpfs",
        "--opt",
        "device=tmpfs",
        "--opt",
        f"o=size={_DEFAULT_WORKSPACE_TMPFS}",
        volume,
    )
    remove_volume = (docker.path, "volume", "rm", "-f", volume)
    volume_attempted = False
    created = False
    worker_result: ProcessResult | None = None
    primary_error: BaseException | None = None
    cleanup_errors: list[str] = []

    def run_docker(
        argv: Sequence[str],
        *,
        timeout_seconds: int,
        watchdog: Callable[[], None] | None = None,
    ) -> ProcessResult:
        assert_docker_identity(docker)
        return process_runner(
            argv,
            timeout_seconds=timeout_seconds,
            watchdog=watchdog,
        )

    try:
        with paid_start_authority(
            lease_path,
            lease_token,
            packet_path,
            source,
            executor,
            control_envelope,
            cli_budget=cli_budget,
        ) as authority:
            volume_attempted = True
            created_result = _require_ok(
                run_docker(create, timeout_seconds=60),
                "Docker volume create",
            )
            if created_result.stdout.strip() != volume:
                raise GovernedSandboxError(
                    "Docker volume create returned unexpected identity"
                )
            created = True

            _require_ok(
                run_docker(
                    build_stage_argv(
                        docker,
                        pinned_image,
                        volume,
                        source,
                        names["stage"],
                    ),
                    timeout_seconds=min(timeout_seconds, 300),
                ),
                "Docker workspace stage",
            )

            worker_result = run_docker(
                build_worker_argv(
                    docker,
                    pinned_image,
                    volume,
                    command,
                    names["worker"],
                ),
                timeout_seconds=timeout_seconds,
                watchdog=lambda: _assert_live_control_lease(authority, executor),
            )
            _require_ok(worker_result, "sandbox worker")

            _require_ok(
                run_docker(
                    build_extract_argv(
                        docker,
                        pinned_image,
                        volume,
                        result,
                        names["extract"],
                    ),
                    timeout_seconds=min(timeout_seconds, 300),
                ),
                "Docker result extraction",
            )
            _assert_result_tree_safe(result)

        return SandboxResult(
            docker=docker,
            image=pinned_image,
            volume=volume,
            worker=worker_result,
            result_dir=str(result),
        )
    except SecurityError as ex:
        primary_error = GovernedSandboxError(
            f"host authority denied sandbox launch: {ex}"
        )
        raise primary_error from ex
    except BaseException as ex:
        primary_error = ex
        raise
    finally:
        if created:
            for name in names.values():
                try:
                    assert_docker_identity(docker)
                    result_cleanup = process_runner(
                        (docker.path, "container", "rm", "-f", name),
                        timeout_seconds=60,
                        watchdog=None,
                    )
                    # Missing --rm containers are expected after successful runs.
                    # Any other text is retained as cleanup evidence, not silently lost.
                    if result_cleanup.returncode not in (0, 1):
                        cleanup_errors.append(
                            f"container cleanup {name} exit {result_cleanup.returncode}"
                        )
                except Exception as ex:
                    cleanup_errors.append(f"container cleanup {name}: {ex}")
        if volume_attempted:
            try:
                assert_docker_identity(docker)
                volume_cleanup = process_runner(
                    remove_volume,
                    timeout_seconds=60,
                    watchdog=None,
                )
                if volume_cleanup.returncode != 0:
                    cleanup_errors.append(
                        f"volume cleanup exit {volume_cleanup.returncode}: "
                        f"{volume_cleanup.stderr[-1000:]}"
                    )
            except Exception as ex:
                cleanup_errors.append(f"volume cleanup: {ex}")
        if cleanup_errors:
            detail = "sandbox cleanup failed: " + "; ".join(cleanup_errors)
            if primary_error is None:
                raise GovernedSandboxError(detail)
            if hasattr(primary_error, "add_note"):
                primary_error.add_note(detail)