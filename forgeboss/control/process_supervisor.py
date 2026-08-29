"""Generation-bound process supervision for ForgeBoss worker slots.

Authority model
---------------
The supervisor owns a set of named *slots*. A slot holds at most one
assignment, and every assignment is bound to a **process identity that the
supervisor observed itself**. Callers hand over a PID and nothing else that is
trusted: any identity a caller supplies is treated as a claim that must match
what the supervisor probes, never as a source of truth.

Every mutation (`register`, `reassign`, `stop`) is a compare-and-set against
the slot's monotonic `generation` and carries an explicit operation id. A stop
is bound to the generation it was issued against, so a slow stop whose
completion lands after the slot has already moved on is discarded instead of
overwriting newer state.

Fail-closed rules
-----------------
* Identity or topology probe failure never degrades into a blind kill.
* PID reuse (same PID, different start time / image) refuses to signal.
* Tooling is resolved from trusted OS directories only, never from ``PATH``.
* Every timeout is validated finite, positive and bounded before it is used.
"""
from __future__ import annotations

import copy
import hashlib
import os
import re
import signal as _signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence, Tuple

__all__ = [
    "SupervisorError", "ProcessIdentityError", "TopologyError", "GenerationConflict",
    "ToolResolutionError", "TimeoutValidationError", "UnknownAssignment",
    "ProcessIdentity", "AssignmentView", "Evidence",
    "NativeToolResolver", "ProcProbe", "WindowsProbe", "default_probe",
    "PosixProcessControl", "WindowsProcessControl", "default_process_control",
    "ProcessSupervisor", "validated_timeout",
]

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SupervisorError(RuntimeError):
    """Base class carrying a stable machine-readable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ProcessIdentityError(SupervisorError):
    """The supervisor could not prove which process it is looking at."""


class TopologyError(SupervisorError):
    """The supervisor could not prove the shape of a process tree."""


class GenerationConflict(SupervisorError):
    """A compare-and-set against the slot generation lost."""


class ToolResolutionError(SupervisorError):
    """A required OS tool could not be resolved from a trusted location."""


class TimeoutValidationError(SupervisorError):
    """A caller-supplied timeout was not finite, positive and bounded."""


class UnknownAssignment(SupervisorError):
    """The named slot holds no assignment."""


# ---------------------------------------------------------------------------
# Bounded, finite timeout validation
# ---------------------------------------------------------------------------

MIN_TIMEOUT = 0.001
MAX_TIMEOUT = 3600.0
DEFAULT_GRACE_TIMEOUT = 10.0
DEFAULT_ESCALATION_TIMEOUT = 5.0
DEFAULT_POLL_INTERVAL = 0.02
DEFAULT_PROBE_TIMEOUT = 15.0
MAX_PID = 2 ** 31 - 1


def validated_timeout(value: Any, name: str = "timeout", maximum: float = MAX_TIMEOUT,
                      minimum: float = MIN_TIMEOUT) -> float:
    """Return ``value`` as a float proven finite, positive and bounded.

    ``bool`` is rejected outright: ``True`` is a typo for a timeout, not a
    one-second budget. NaN and both infinities are rejected, as are values
    outside ``[minimum, maximum]``.
    """
    if isinstance(value, bool):
        raise TimeoutValidationError("TIMEOUT_INVALID", f"{name} must be a number, not a bool")
    if isinstance(value, str) or value is None:
        raise TimeoutValidationError("TIMEOUT_INVALID", f"{name} must be a number")
    try:
        seconds = float(value)
    except (TypeError, ValueError) as ex:
        raise TimeoutValidationError("TIMEOUT_INVALID", f"{name} must be a number") from ex
    # float('nan') != float('nan') and the infinities compare out of range.
    if seconds != seconds:
        raise TimeoutValidationError("TIMEOUT_INVALID", f"{name} must be a finite number")
    if seconds in (float("inf"), float("-inf")):
        raise TimeoutValidationError("TIMEOUT_INVALID", f"{name} must be a finite number")
    if seconds < minimum:
        raise TimeoutValidationError("TIMEOUT_INVALID", f"{name} must be >= {minimum} seconds")
    if seconds > maximum:
        raise TimeoutValidationError("TIMEOUT_INVALID", f"{name} must be <= {maximum} seconds")
    return seconds


def _validated_pid(value: Any) -> int:
    if isinstance(value, bool):
        raise SupervisorError("PID_INVALID", "pid must be an integer, not a bool")
    try:
        pid = int(value)
    except (TypeError, ValueError) as ex:
        raise SupervisorError("PID_INVALID", "pid must be an integer") from ex
    if isinstance(value, float) and pid != value:
        raise SupervisorError("PID_INVALID", "pid must be a whole number")
    if pid <= 0 or pid > MAX_PID:
        raise SupervisorError("PID_INVALID", f"pid out of range: {pid}")
    return pid


_SLOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _validated_slot(value: Any) -> str:
    slot = str(value or "")
    if not _SLOT_RE.match(slot):
        raise SupervisorError("SLOT_INVALID", f"slot name is not acceptable: {value!r}")
    return slot


# ---------------------------------------------------------------------------
# Immutable value objects handed back to callers
# ---------------------------------------------------------------------------


def _freeze(value: Any) -> Any:
    """Copy and deep-freeze a value.

    This both detaches the result from supervisor-internal containers and makes
    it unwritable, so a caller cannot reach back into authority state through a
    returned assignment or evidence object. Note that ``copy.deepcopy`` cannot
    be used first: it refuses to copy a ``mappingproxy``, and nested values may
    already be frozen from an earlier pass.
    """
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(v) for v in value)
    if isinstance(value, (str, bytes, int, float, bool, type(None), ProcessIdentity, Evidence)):
        return value
    return copy.deepcopy(value)


def _frozen_detail(detail: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
    return _freeze(dict(detail or {}))


@dataclass(frozen=True)
class ProcessIdentity:
    """A process identity the supervisor observed for itself.

    ``token`` binds the PID to the boot the observation was made on, to the
    process start time and to the image path. Two observations with the same
    token are the same process; a PID that has been recycled produces a
    different token.
    """

    pid: int
    ppid: int
    boot_id: str
    start_ticks: int
    image: str
    observed_at: float = 0.0

    @property
    def token(self) -> str:
        material = "\x1f".join([
            str(self.pid), str(self.ppid), self.boot_id,
            str(self.start_ticks), self.image,
        ])
        return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()

    def same_process(self, other: Optional["ProcessIdentity"]) -> bool:
        """Identity excluding ``ppid``: a live process may be re-parented."""
        if other is None:
            return False
        return (self.pid == other.pid and self.boot_id == other.boot_id
                and self.start_ticks == other.start_ticks and self.image == other.image)

    def as_dict(self) -> Mapping[str, Any]:
        return _freeze({
            "pid": self.pid, "ppid": self.ppid, "bootId": self.boot_id,
            "startTicks": self.start_ticks, "image": self.image,
            "observedAt": self.observed_at, "token": self.token,
        })


@dataclass(frozen=True)
class AssignmentView:
    """Read-only snapshot of a slot. Frozen, with frozen nested data."""

    slot: str
    task_id: Optional[str]
    generation: int
    state: str
    identity: Optional[ProcessIdentity]
    operation_id: Optional[str]
    pending_stop: Optional[Mapping[str, Any]]
    updated_at: float


@dataclass(frozen=True)
class Evidence:
    """Explicit, immutable record of one supervisor operation."""

    operation_id: str
    slot: str
    generation: int
    kind: str
    outcome: str
    detail: Mapping[str, Any]
    at: float


STATE_RUNNING = "running"
STATE_STOPPING = "stopping"
STATE_STOPPED = "stopped"
STATE_STOP_FAILED = "stop-failed"
STATE_IDENTITY_LOST = "identity-lost"
TERMINAL_STATES = (STATE_STOPPED, STATE_STOP_FAILED, STATE_IDENTITY_LOST)


# ---------------------------------------------------------------------------
# Trusted tool resolution -- never PATH
# ---------------------------------------------------------------------------

_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_POSIX_TRUSTED_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")


def _windows_trusted_dirs() -> Tuple[str, ...]:
    candidates = []
    for env_name in ("SystemRoot", "windir"):
        raw = os.environ.get(env_name)
        # An attacker-influenced SystemRoot must not redirect us elsewhere.
        if raw and re.match(r"^[A-Za-z]:[\\/][^\\/]", raw) and Path(raw).is_dir():
            candidates.append(raw)
    candidates.append(r"C:\Windows")
    dirs = []
    for root in candidates:
        system32 = Path(root) / "System32"
        if system32.is_dir():
            for sub in (system32, system32 / "wbem", system32 / "WindowsPowerShell" / "v1.0"):
                text = str(sub)
                if sub.is_dir() and text not in dirs:
                    dirs.append(text)
    if not dirs:
        raise ToolResolutionError("TOOL_ROOT_UNTRUSTED", "no trusted Windows system directory found")
    return tuple(dirs)


class NativeToolResolver:
    """Resolve OS tools from a fixed allowlist of trusted system directories.

    ``PATH`` is deliberately never consulted: a worker (or anything else able
    to influence the environment) must not be able to decide which binary the
    supervisor executes. On POSIX the binary must additionally be root-owned,
    not group/world writable, and not itself a symlink.
    """

    def __init__(self, trusted_dirs: Optional[Sequence[str]] = None,
                 windows: Optional[bool] = None, require_root_owned: Optional[bool] = None):
        self._windows = os.name == "nt" if windows is None else bool(windows)
        if trusted_dirs is None:
            trusted_dirs = _windows_trusted_dirs() if self._windows else _POSIX_TRUSTED_DIRS
        self._trusted = tuple(str(d) for d in trusted_dirs)
        self._require_root_owned = (not self._windows) if require_root_owned is None else bool(require_root_owned)
        self._cache: dict = {}
        self._lock = threading.Lock()

    @property
    def trusted_dirs(self) -> Tuple[str, ...]:
        return self._trusted

    def resolve(self, name: str) -> str:
        # Validate before the cache so an unhashable or hostile name cannot
        # even become a cache key.
        if not isinstance(name, str) or not _TOOL_NAME_RE.match(name):
            raise ToolResolutionError("TOOL_NAME_INVALID", f"tool name is not acceptable: {name!r}")
        with self._lock:
            if name in self._cache:
                cached = self._cache[name]
                if isinstance(cached, tuple):
                    # A negative result is cached as (code, message) and re-raised
                    # freshly, so one shared exception object cannot accumulate
                    # tracebacks across callers.
                    raise ToolResolutionError(*cached)
                return cached
            try:
                resolved = self._resolve_uncached(name)
            except ToolResolutionError as ex:
                self._cache[name] = (ex.code, str(ex))
                raise
            self._cache[name] = resolved
            return resolved

    def _resolve_uncached(self, name: str) -> str:
        if not _TOOL_NAME_RE.match(str(name or "")):
            raise ToolResolutionError("TOOL_NAME_INVALID", f"tool name is not acceptable: {name!r}")
        names = [name]
        if self._windows and not name.lower().endswith(".exe"):
            names.append(name + ".exe")
        for directory in self._trusted:
            base = Path(directory)
            try:
                real_base = base.resolve(strict=True)
            except OSError:
                continue
            for candidate_name in names:
                candidate = base / candidate_name
                if self._acceptable(candidate, real_base):
                    return str(candidate)
        raise ToolResolutionError(
            "TOOL_NOT_TRUSTED",
            f"{name!r} was not found in a trusted system directory: {','.join(self._trusted)}")

    def _acceptable(self, candidate: Path, real_base: Path) -> bool:
        try:
            info = candidate.lstat()
        except OSError:
            return False
        # A symlinked tool is a hijack surface even inside a trusted directory.
        if not os.path.isfile(str(candidate)) or os.path.islink(str(candidate)):
            return False
        try:
            if candidate.resolve(strict=True).parent != real_base:
                return False
        except OSError:
            return False
        if self._windows:
            return True
        if info.st_mode & 0o022:
            return False
        if self._require_root_owned and info.st_uid != 0:
            return False
        return bool(info.st_mode & 0o111)


# ---------------------------------------------------------------------------
# Identity / topology probes -- fail closed
# ---------------------------------------------------------------------------


class ProcProbe:
    """Identity and topology from ``/proc``. Any unexpected error fails closed."""

    def __init__(self, proc_root: str = "/proc", clock=time.time):
        self._root = Path(proc_root)
        self._clock = clock

    @property
    def supported(self) -> bool:
        return self._root.is_dir()

    def boot_id(self) -> str:
        try:
            return (self._root / "sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        except OSError as ex:
            raise ProcessIdentityError("BOOT_ID_UNAVAILABLE", f"cannot read boot id: {ex}") from ex

    def identity(self, pid: int) -> ProcessIdentity:
        pid = _validated_pid(pid)
        ppid, start_ticks = self._stat(pid)
        return ProcessIdentity(pid=pid, ppid=ppid, boot_id=self.boot_id(),
                               start_ticks=start_ticks, image=self._image(pid),
                               observed_at=self._clock())

    def _stat(self, pid: int) -> Tuple[int, int]:
        try:
            raw = (self._root / str(pid) / "stat").read_text(encoding="utf-8", errors="surrogateescape")
        except FileNotFoundError as ex:
            raise ProcessIdentityError("PROCESS_GONE", f"pid {pid} does not exist") from ex
        except OSError as ex:
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"cannot stat pid {pid}: {ex}") from ex
        # comm is parenthesised and may itself contain spaces and ')'.
        close = raw.rfind(")")
        if close < 0:
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"malformed stat for pid {pid}")
        rest = raw[close + 1:].split()
        # rest[0] is state; ppid is field 4 and starttime is field 22 (1-based).
        if len(rest) < 20:
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"truncated stat for pid {pid}")
        try:
            return int(rest[1]), int(rest[19])
        except ValueError as ex:
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"unparsable stat for pid {pid}") from ex

    def _image(self, pid: int) -> str:
        exe = self._root / str(pid) / "exe"
        try:
            return os.readlink(str(exe))
        except FileNotFoundError as ex:
            raise ProcessIdentityError("PROCESS_GONE", f"pid {pid} does not exist") from ex
        except OSError as ex:
            # EPERM/ESRCH here means we cannot prove the image: refuse to guess.
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"cannot read image of pid {pid}: {ex}") from ex

    def children(self, pid: int) -> Tuple[int, ...]:
        pid = _validated_pid(pid)
        found = []
        try:
            entries = list(self._root.iterdir())
        except OSError as ex:
            raise TopologyError("TOPOLOGY_PROBE_FAILED", f"cannot enumerate processes: {ex}") from ex
        for entry in entries:
            name = entry.name
            if not name.isdigit():
                continue
            candidate = int(name)
            try:
                parent, _ = self._stat(candidate)
            except ProcessIdentityError as ex:
                if ex.code == "PROCESS_GONE":
                    continue  # the process exited mid-scan; not a topology failure
                raise TopologyError("TOPOLOGY_PROBE_FAILED", str(ex)) from ex
            if parent == pid:
                found.append(candidate)
        return tuple(sorted(found))


class WindowsProbe:
    """Identity and topology via PowerShell resolved from ``System32``."""

    _QUERY = (
        "$ErrorActionPreference='Stop';"
        "$p=Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\";"
        "if(-not $p){{exit 3}};"
        "$b=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks;"
        "Write-Output ($p.ParentProcessId.ToString()+'|'+"
        "$p.CreationDate.ToUniversalTime().Ticks.ToString()+'|'+$b.ToString()+'|'+"
        "[string]$p.ExecutablePath)"
    )

    def __init__(self, resolver: Optional[NativeToolResolver] = None,
                 runner=None, clock=time.time, timeout: float = DEFAULT_PROBE_TIMEOUT):
        self._resolver = resolver or NativeToolResolver()
        self._runner = runner or self._run
        self._clock = clock
        self._timeout = validated_timeout(timeout, "probe timeout")

    @property
    def supported(self) -> bool:
        return os.name == "nt"

    def _run(self, argv, timeout):
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def _powershell(self, script: str) -> str:
        tool = self._resolver.resolve("powershell.exe")
        argv = [tool, "-NoProfile", "-NonInteractive", "-Command", script]
        try:
            done = self._runner(argv, self._timeout)
        except (OSError, subprocess.SubprocessError) as ex:
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"process query failed: {ex}") from ex
        if done.returncode == 3:
            raise ProcessIdentityError("PROCESS_GONE", "process does not exist")
        if done.returncode != 0:
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED",
                                       (done.stderr or done.stdout or "process query failed").strip())
        return (done.stdout or "").strip()

    def boot_id(self) -> str:
        return self._powershell(
            "$ErrorActionPreference='Stop';"
            "Write-Output (Get-CimInstance Win32_OperatingSystem)."
            "LastBootUpTime.ToUniversalTime().Ticks.ToString()")

    def identity(self, pid: int) -> ProcessIdentity:
        pid = _validated_pid(pid)
        fields = self._powershell(self._QUERY.format(pid=pid)).split("|", 3)
        if len(fields) != 4:
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"unparsable process record for pid {pid}")
        try:
            ppid, start_ticks = int(fields[0]), int(fields[1])
        except ValueError as ex:
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"unparsable process record for pid {pid}") from ex
        image = fields[3].strip()
        if not image:
            # Without an image path we cannot distinguish a recycled PID.
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"cannot read image of pid {pid}")
        return ProcessIdentity(pid=pid, ppid=ppid, boot_id=fields[2].strip(),
                               start_ticks=start_ticks, image=image, observed_at=self._clock())

    def children(self, pid: int) -> Tuple[int, ...]:
        pid = _validated_pid(pid)
        script = ("$ErrorActionPreference='Stop';"
                  "Get-CimInstance Win32_Process -Filter \"ParentProcessId=" + str(pid) + "\" |"
                  " ForEach-Object { Write-Output $_.ProcessId }")
        try:
            out = self._powershell(script)
        except ProcessIdentityError as ex:
            if ex.code == "PROCESS_GONE":
                return ()
            raise TopologyError("TOPOLOGY_PROBE_FAILED", str(ex)) from ex
        kids = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                kids.append(int(line))
            except ValueError as ex:
                raise TopologyError("TOPOLOGY_PROBE_FAILED", f"unparsable child pid {line!r}") from ex
        return tuple(sorted(kids))


def default_probe():
    """Return the probe for this platform, or fail closed if there is none."""
    if os.name == "nt":
        return WindowsProbe()
    proc = ProcProbe()
    if proc.supported:
        return proc
    raise ProcessIdentityError("PROBE_UNAVAILABLE",
                               f"no trusted process identity probe for platform {sys.platform!r}")


# ---------------------------------------------------------------------------
# Signalling -- native syscalls first, trusted tooling second
# ---------------------------------------------------------------------------


class PosixProcessControl:
    """Signal by syscall. Uses ``pidfd`` where available to defeat PID reuse."""

    def __init__(self, use_pidfd: Optional[bool] = None):
        available = hasattr(os, "pidfd_open") and hasattr(_signal, "pidfd_send_signal")
        self._use_pidfd = available if use_pidfd is None else (bool(use_pidfd) and available)

    def signal(self, identity: ProcessIdentity, probe, escalate: bool = False) -> str:
        sig = _signal.SIGKILL if escalate else _signal.SIGTERM
        if self._use_pidfd:
            try:
                fd = os.pidfd_open(identity.pid)
            except ProcessLookupError:
                return "already-exited"
            except OSError:
                fd = None
            if fd is not None:
                try:
                    # The pidfd pins the PID, so this re-check cannot be raced.
                    observed = probe.identity(identity.pid)
                    if not identity.same_process(observed):
                        raise ProcessIdentityError("PID_REUSED",
                                                   f"pid {identity.pid} no longer identifies the target process")
                    _signal.pidfd_send_signal(fd, sig)
                except ProcessLookupError:
                    return "already-exited"
                finally:
                    os.close(fd)
                return "escalated" if escalate else "signalled"
        try:
            observed = probe.identity(identity.pid)
        except ProcessIdentityError as ex:
            if ex.code == "PROCESS_GONE":
                return "already-exited"
            raise
        if not identity.same_process(observed):
            raise ProcessIdentityError("PID_REUSED", f"pid {identity.pid} no longer identifies the target process")
        try:
            os.kill(identity.pid, sig)
        except ProcessLookupError:
            return "already-exited"
        except OSError as ex:
            raise SupervisorError("SIGNAL_FAILED", f"cannot signal pid {identity.pid}: {ex}") from ex
        return "escalated" if escalate else "signalled"


class WindowsProcessControl:
    """Signal via ``taskkill.exe`` resolved from ``System32``, never from PATH."""

    def __init__(self, resolver: Optional[NativeToolResolver] = None, runner=None,
                 timeout: float = DEFAULT_PROBE_TIMEOUT):
        self._resolver = resolver or NativeToolResolver()
        self._runner = runner or self._run
        self._timeout = validated_timeout(timeout, "signal timeout")

    def _run(self, argv, timeout):
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def signal(self, identity: ProcessIdentity, probe, escalate: bool = False) -> str:
        try:
            observed = probe.identity(identity.pid)
        except ProcessIdentityError as ex:
            if ex.code == "PROCESS_GONE":
                return "already-exited"
            raise
        if not identity.same_process(observed):
            raise ProcessIdentityError("PID_REUSED", f"pid {identity.pid} no longer identifies the target process")
        tool = self._resolver.resolve("taskkill.exe")
        argv = [tool, "/PID", str(identity.pid)] + (["/F"] if escalate else [])
        try:
            done = self._runner(argv, self._timeout)
        except (OSError, subprocess.SubprocessError) as ex:
            raise SupervisorError("SIGNAL_FAILED", f"cannot signal pid {identity.pid}: {ex}") from ex
        # 128 == process not found, which is the outcome we wanted anyway.
        if done.returncode not in (0, 128):
            message = (done.stderr or done.stdout or f"taskkill exit {done.returncode}").strip()

            if not escalate and "only be terminated forcefully" in message.lower():
                return "signalled"

            raise SupervisorError("SIGNAL_FAILED", message)


def default_process_control():
    return WindowsProcessControl() if os.name == "nt" else PosixProcessControl()


# ---------------------------------------------------------------------------
# Internal mutable state
# ---------------------------------------------------------------------------


@dataclass
class _Assignment:
    slot: str
    task_id: Optional[str]
    generation: int
    state: str
    identity: Optional[ProcessIdentity]
    operation_id: Optional[str]
    updated_at: float
    stop_operation_id: Optional[str] = None
    stop_generation: Optional[int] = None
    stop_started_at: Optional[float] = None


@dataclass
class _StopOp:
    operation_id: str
    slot: str
    generation: int
    done: threading.Event = field(default_factory=threading.Event)
    evidence: Optional[Evidence] = None
    error: Optional[BaseException] = None
    preempted: bool = False
    signals: int = 0


def _new_operation_id(prefix: str) -> str:
    return f"{prefix}-{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{os.urandom(8).hex()}"


# ---------------------------------------------------------------------------
# Supervisor
# ---------------------------------------------------------------------------


class ProcessSupervisor:
    """Generation-bound supervisor over named process slots."""

    def __init__(self, probe=None, control=None, resolver: Optional[NativeToolResolver] = None,
                 clock=time.monotonic, wall_clock=time.time, sleep=time.sleep,
                 evidence_limit: int = 2048):
        self._resolver = resolver
        self._probe = probe if probe is not None else default_probe()
        self._control = control if control is not None else default_process_control()
        self._clock = clock
        self._wall_clock = wall_clock
        self._sleep = sleep
        self._lock = threading.RLock()
        self._assignments: dict = {}
        self._inflight: dict = {}
        self._evidence = deque(maxlen=max(1, int(evidence_limit)))
        self._self_pid = os.getpid()

    # -- read side ---------------------------------------------------------

    def _view(self, a: _Assignment) -> AssignmentView:
        pending = None
        if a.stop_operation_id is not None:
            pending = _frozen_detail({
                "operationId": a.stop_operation_id,
                "generation": a.stop_generation,
                "startedAt": a.stop_started_at,
            })
        return AssignmentView(slot=a.slot, task_id=a.task_id, generation=a.generation,
                              state=a.state, identity=a.identity, operation_id=a.operation_id,
                              pending_stop=pending, updated_at=a.updated_at)

    def get(self, slot: str) -> AssignmentView:
        slot = _validated_slot(slot)
        with self._lock:
            a = self._assignments.get(slot)
            if a is None:
                raise UnknownAssignment("SLOT_UNKNOWN", f"no assignment for slot {slot!r}")
            return self._view(a)

    def snapshot(self) -> Tuple[AssignmentView, ...]:
        with self._lock:
            return tuple(self._view(a) for a in sorted(self._assignments.values(), key=lambda x: x.slot))

    def evidence(self, slot: Optional[str] = None) -> Tuple[Evidence, ...]:
        with self._lock:
            items = tuple(self._evidence)
        if slot is None:
            return items
        slot = _validated_slot(slot)
        return tuple(e for e in items if e.slot == slot)

    def _record(self, operation_id: str, slot: str, generation: int, kind: str,
                outcome: str, detail: Optional[Mapping[str, Any]] = None) -> Evidence:
        ev = Evidence(operation_id=operation_id, slot=slot, generation=generation, kind=kind,
                      outcome=outcome, detail=_frozen_detail(detail), at=self._wall_clock())
        with self._lock:
            self._evidence.append(ev)
        return ev

    # -- binding (register / reassign) -------------------------------------

    def register(self, slot: str, pid: Any, *, task_id: Optional[str] = None,
                 expected_generation: Optional[int] = None, claimed_identity: Any = None,
                 operation_id: Optional[str] = None, force: bool = False) -> AssignmentView:
        """Bind a fresh (or terminal) slot to a process the supervisor observes."""
        return self._bind(slot, pid, kind="register", task_id=task_id,
                          expected_generation=expected_generation, claimed_identity=claimed_identity,
                          operation_id=operation_id, force=force, require_existing=False)

    def reassign(self, slot: str, pid: Any, *, expected_generation: int,
                 task_id: Optional[str] = None, claimed_identity: Any = None,
                 operation_id: Optional[str] = None, force: bool = False) -> AssignmentView:
        """Replace the process bound to an existing slot, bumping its generation."""
        return self._bind(slot, pid, kind="reassign", task_id=task_id,
                          expected_generation=expected_generation, claimed_identity=claimed_identity,
                          operation_id=operation_id, force=force, require_existing=True)

    def _bind(self, slot, pid, *, kind, task_id, expected_generation, claimed_identity,
              operation_id, force, require_existing) -> AssignmentView:
        slot = _validated_slot(slot)
        pid = _validated_pid(pid)
        op = str(operation_id or _new_operation_id(kind.upper()))
        if expected_generation is not None:
            if isinstance(expected_generation, bool) or not isinstance(expected_generation, int):
                raise GenerationConflict("GENERATION_INVALID", "expected_generation must be an int or None")

        # Phase 1: check the CAS precondition before touching the OS at all.
        with self._lock:
            current = self._assignments.get(slot)
            self._assert_bindable(slot, current, kind=kind, expected_generation=expected_generation,
                                  force=force, require_existing=require_existing)
            base_generation = current.generation if current else 0

        # Phase 2: observe identity ourselves. A probe failure fails closed and
        # leaves the slot exactly as it was.
        try:
            observed = self._observe(pid)
        except (ProcessIdentityError, TopologyError) as ex:
            self._record(op, slot, base_generation, kind, "identity-probe-failed",
                         {"pid": pid, "code": ex.code, "error": str(ex)})
            raise
        if claimed_identity is not None:
            self._verify_claim(op, slot, base_generation, kind, observed, claimed_identity)

        # Phase 3: re-check the CAS, then commit. The generation may have moved
        # while we were probing, in which case this binding is stale.
        with self._lock:
            current = self._assignments.get(slot)
            self._assert_bindable(slot, current, kind=kind, expected_generation=expected_generation,
                                  force=force, require_existing=require_existing)
            if (current.generation if current else 0) != base_generation:
                raise GenerationConflict(
                    "GENERATION_STALE",
                    f"slot {slot!r} changed generation during identity probe")
            preempted = None
            inflight = self._inflight.get(slot)
            if inflight is not None:
                # A stop is in flight. We are allowed to move on (force), and the
                # stop's completion will be discarded by the generation CAS.
                inflight.preempted = True
                self._inflight.pop(slot, None)
                preempted = inflight.operation_id
            generation = base_generation + 1
            self._assignments[slot] = _Assignment(
                slot=slot, task_id=task_id if task_id is not None else (current.task_id if current else None),
                generation=generation, state=STATE_RUNNING, identity=observed,
                operation_id=op, updated_at=self._wall_clock())
            view = self._view(self._assignments[slot])
        self._record(op, slot, generation, kind, "bound", {
            "pid": pid, "taskId": view.task_id, "identity": observed.as_dict(),
            "preemptedStopOperationId": preempted, "forced": bool(force),
        })
        return view

    def _assert_bindable(self, slot, current, *, kind, expected_generation, force, require_existing):
        if current is None:
            if require_existing:
                raise UnknownAssignment("SLOT_UNKNOWN", f"no assignment for slot {slot!r}")
            if expected_generation not in (None, 0):
                raise GenerationConflict("GENERATION_MISMATCH",
                                         f"slot {slot!r} is empty but generation {expected_generation} was expected")
            return
        if expected_generation is None:
            raise GenerationConflict("GENERATION_REQUIRED",
                                     f"slot {slot!r} is occupied; expected_generation is required")
        if expected_generation != current.generation:
            raise GenerationConflict(
                "GENERATION_MISMATCH",
                f"slot {slot!r} is at generation {current.generation}, not {expected_generation}")
        if current.state == STATE_STOPPING and not force:
            raise GenerationConflict("SLOT_STOPPING",
                                     f"slot {slot!r} has a stop in flight; pass force=True to preempt it")
        if kind == "register" and current.state not in TERMINAL_STATES and not force:
            raise GenerationConflict("SLOT_OCCUPIED",
                                     f"slot {slot!r} is {current.state}; use reassign() to replace it")

    def _observe(self, pid: int) -> ProcessIdentity:
        if pid == self._self_pid:
            raise SupervisorError("PID_FORBIDDEN", "refusing to supervise the supervisor's own process")
        if pid == 1:
            raise SupervisorError("PID_FORBIDDEN", "refusing to supervise pid 1")
        observed = self._probe.identity(pid)
        if not isinstance(observed, ProcessIdentity):
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", "probe did not return a ProcessIdentity")
        if observed.pid != pid or not observed.boot_id or not observed.image:
            raise ProcessIdentityError("IDENTITY_PROBE_FAILED", f"incomplete identity for pid {pid}")
        return observed

    def _verify_claim(self, op, slot, generation, kind, observed: ProcessIdentity, claimed: Any):
        """A caller's identity claim is only ever a check, never a source."""
        if isinstance(claimed, ProcessIdentity):
            claim = dict(claimed.as_dict())
        elif isinstance(claimed, Mapping):
            claim = dict(claimed)
        else:
            raise ProcessIdentityError("IDENTITY_CLAIM_INVALID", "claimed_identity must be a mapping or ProcessIdentity")
        truth = dict(observed.as_dict())
        mismatched = sorted(k for k, v in claim.items()
                            if k in truth and k != "observedAt" and truth[k] != v)
        unknown = sorted(k for k in claim if k not in truth)
        if mismatched or unknown:
            self._record(op, slot, generation, kind, "identity-claim-rejected",
                         {"mismatchedFields": mismatched, "unknownFields": unknown,
                          "observed": observed.as_dict()})
            raise ProcessIdentityError(
                "IDENTITY_CLAIM_MISMATCH",
                "caller identity claim does not match observed process: " + ",".join(mismatched + unknown))

    # -- stop --------------------------------------------------------------

    def stop(self, slot: str, *, expected_generation: int, timeout: Any = DEFAULT_GRACE_TIMEOUT,
             escalation_timeout: Any = DEFAULT_ESCALATION_TIMEOUT,
             poll_interval: Any = DEFAULT_POLL_INTERVAL, operation_id: Optional[str] = None,
             join_timeout: Any = None, include_tree: bool = True) -> Evidence:
        """Stop the process bound to ``slot`` at ``expected_generation``.

        Concurrent stops of the same generation are serialised: the first
        caller performs the stop and the others join it and receive the same
        evidence, so a slot is never signalled twice for one generation. A stop
        whose completion arrives after the slot has moved on is discarded.
        """
        slot = _validated_slot(slot)
        grace = validated_timeout(timeout, "timeout")
        escalation = validated_timeout(escalation_timeout, "escalation_timeout")
        poll = validated_timeout(poll_interval, "poll_interval", maximum=max(MIN_TIMEOUT, grace))
        if join_timeout is None:
            join_timeout = min(MAX_TIMEOUT, grace + escalation + 30.0)
        join = validated_timeout(join_timeout, "join_timeout")
        if isinstance(expected_generation, bool) or not isinstance(expected_generation, int):
            raise GenerationConflict("GENERATION_INVALID", "expected_generation must be an int")

        with self._lock:
            a = self._assignments.get(slot)
            if a is None:
                raise UnknownAssignment("SLOT_UNKNOWN", f"no assignment for slot {slot!r}")
            inflight = self._inflight.get(slot)
            if inflight is not None:
                if inflight.generation != expected_generation:
                    raise GenerationConflict(
                        "GENERATION_MISMATCH",
                        f"slot {slot!r} has a stop in flight for generation {inflight.generation}")
                joined = inflight  # duplicate stop: join, do not signal again
            else:
                if a.generation != expected_generation:
                    raise GenerationConflict(
                        "GENERATION_MISMATCH",
                        f"slot {slot!r} is at generation {a.generation}, not {expected_generation}")
                if a.state == STATE_STOPPED:
                    return self._record(str(operation_id or _new_operation_id("STOP")), slot, a.generation,
                                        "stop", "already-stopped", {"state": a.state})
                if a.state == STATE_IDENTITY_LOST:
                    raise ProcessIdentityError(
                        "IDENTITY_LOST",
                        f"slot {slot!r} lost process identity; reconcile before stopping again")
                joined = None
                op = _StopOp(operation_id=str(operation_id or _new_operation_id("STOP")),
                             slot=slot, generation=a.generation)
                self._inflight[slot] = op
                a.state = STATE_STOPPING
                a.stop_operation_id = op.operation_id
                a.stop_generation = op.generation
                a.stop_started_at = self._wall_clock()
                a.updated_at = a.stop_started_at
                identity = a.identity

        if joined is not None:
            if not joined.done.wait(join):
                raise SupervisorError("STOP_JOIN_TIMEOUT",
                                      f"in-flight stop for slot {slot!r} did not complete within {join}s")
            if joined.error is not None:
                raise joined.error
            return joined.evidence

        try:
            outcome, detail = self._execute_stop(op, identity, grace, escalation, poll, include_tree)
        except BaseException as ex:  # noqa: BLE001 - completion must always run
            evidence = self._complete_stop(op, "stop-failed",
                                           {"error": str(ex), "code": getattr(ex, "code", type(ex).__name__)})
            op.error = ex
            op.evidence = evidence
            op.done.set()
            raise
        evidence = self._complete_stop(op, outcome, detail)
        op.evidence = evidence
        op.done.set()
        return evidence

    def _execute_stop(self, op: _StopOp, identity: Optional[ProcessIdentity],
                      grace: float, escalation: float, poll: float, include_tree: bool):
        if identity is None:
            return "identity-lost", {"reason": "no identity recorded for slot"}

        # Re-observe the target. A probe failure here fails closed: we would
        # rather leave a process running than signal one we cannot identify.
        try:
            observed = self._probe.identity(identity.pid)
        except ProcessIdentityError as ex:
            if ex.code == "PROCESS_GONE":
                return "stopped", {"reason": "process already exited", "signalled": False,
                                   "escalated": False, "children": ()}
            return "stop-failed", {"reason": "identity probe failed", "code": ex.code, "error": str(ex),
                                   "signalled": False, "escalated": False}
        if not identity.same_process(observed):
            return "identity-lost", {"reason": "pid no longer identifies the supervised process",
                                     "recorded": identity.as_dict(), "observed": observed.as_dict(),
                                     "signalled": False, "escalated": False}

        targets = [identity]
        skipped = []
        if include_tree:
            try:
                children = self._verified_descendants(identity)
            except TopologyError as ex:
                # Topology is unproven, so tree scope is unproven: fail closed.
                return "stop-failed", {"reason": "topology probe failed", "code": ex.code,
                                       "error": str(ex), "signalled": False, "escalated": False}
            targets = list(children["verified"]) + [identity]
            skipped = list(children["skipped"])

        signalled = self._signal_all(targets, escalate=False, op=op)
        if self._await_gone(targets, grace, poll):
            return "stopped", {"signalled": signalled, "escalated": False, "reason": "graceful",
                               "children": tuple(t.pid for t in targets if t.pid != identity.pid),
                               "skippedChildren": tuple(skipped), "signalCount": op.signals}
        escalated = self._signal_all(targets, escalate=True, op=op)
        if self._await_gone(targets, escalation, poll):
            return "stopped", {"signalled": signalled, "escalated": escalated, "reason": "escalated",
                               "children": tuple(t.pid for t in targets if t.pid != identity.pid),
                               "skippedChildren": tuple(skipped), "signalCount": op.signals}
        return "stop-failed", {"reason": "process survived escalation", "signalled": signalled,
                               "escalated": escalated,
                               "children": tuple(t.pid for t in targets if t.pid != identity.pid),
                               "skippedChildren": tuple(skipped), "signalCount": op.signals}

    def _verified_descendants(self, root: ProcessIdentity):
        """Descendants proven to belong to ``root``'s tree, breadth-first.

        A candidate is only accepted when it is on the same boot, still claims
        ``root`` (or an already-verified descendant) as its parent, and started
        no earlier than its parent. That last check is what stops a recycled
        PID from dragging an unrelated process into the kill set.
        """
        verified, skipped, seen = [], [], {root.pid}
        frontier = [root]
        while frontier:
            parent = frontier.pop(0)
            for pid in self._probe.children(parent.pid):
                if pid in seen or pid in (0, 1, self._self_pid):
                    continue
                seen.add(pid)
                try:
                    child = self._probe.identity(pid)
                except ProcessIdentityError as ex:
                    if ex.code == "PROCESS_GONE":
                        continue  # exited mid-walk
                    raise TopologyError("TOPOLOGY_PROBE_FAILED",
                                        f"cannot identify child {pid}: {ex}") from ex
                if (child.ppid != parent.pid or child.boot_id != parent.boot_id
                        or child.start_ticks < parent.start_ticks):
                    skipped.append(pid)
                    continue
                verified.append(child)
                frontier.append(child)
        # Deepest first so parents cannot re-parent survivors mid-stop.
        verified.reverse()
        return {"verified": tuple(verified), "skipped": tuple(sorted(skipped))}

    def _signal_all(self, targets, *, escalate: bool, op: _StopOp):
        results = []
        for target in targets:
            outcome = self._control.signal(target, self._probe, escalate)
            if outcome in ("signalled", "escalated"):
                op.signals += 1
            results.append({"pid": target.pid, "outcome": outcome})
        return tuple(results)

    def _await_gone(self, targets, budget: float, poll: float) -> bool:
        deadline = self._clock() + budget
        while True:
            if all(self._gone(t) for t in targets):
                return True
            if self._clock() >= deadline:
                return False
            self._sleep(min(poll, max(MIN_TIMEOUT, deadline - self._clock())))

    def _gone(self, target: ProcessIdentity) -> bool:
        try:
            observed = self._probe.identity(target.pid)
        except ProcessIdentityError as ex:
            if ex.code == "PROCESS_GONE":
                return True
            # An unreadable process is not a dead process.
            return False
        return not target.same_process(observed)

    def _complete_stop(self, op: _StopOp, outcome: str, detail: Mapping[str, Any]) -> Evidence:
        """Apply a stop result under a generation CAS, or discard it as stale."""
        detail = dict(detail or {})
        with self._lock:
            current = self._inflight.get(op.slot)
            if current is op:
                self._inflight.pop(op.slot, None)
            a = self._assignments.get(op.slot)
            stale_reason = None
            if a is None:
                stale_reason = "slot no longer exists"
            elif a.generation != op.generation:
                stale_reason = f"slot advanced to generation {a.generation}"
            elif a.stop_operation_id != op.operation_id:
                stale_reason = f"slot is now owned by stop {a.stop_operation_id}"
            elif op.preempted:
                stale_reason = "stop was preempted"
            if stale_reason is not None:
                detail.update({"stale": True, "staleReason": stale_reason, "attemptedOutcome": outcome})
                return self._record(op.operation_id, op.slot, op.generation, "stop",
                                    "stale-discarded", detail)
            a.stop_operation_id = None
            a.stop_generation = None
            a.stop_started_at = None
            a.updated_at = self._wall_clock()
            if outcome == "stopped":
                a.state = STATE_STOPPED
            elif outcome == "identity-lost":
                a.state = STATE_IDENTITY_LOST
            else:
                # Generation is deliberately unchanged so the caller can retry
                # the same stop with the same expected_generation.
                a.state = STATE_STOP_FAILED
            a.operation_id = op.operation_id
            detail["stale"] = False
            detail["state"] = a.state
        return self._record(op.operation_id, op.slot, op.generation, "stop", outcome, detail)
