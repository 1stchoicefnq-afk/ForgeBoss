"""Owned-containment process supervision for ForgeBoss Finish Line 1.

The supervisor never treats a caller supplied PID snapshot as kill authority.
Production workers are launched by the supervisor into an owned containment
before their executable is allowed to run:
- Linux: a dedicated session/process group plus inherited seccomp filter that
  denies setsid(2)/setpgid(2), preventing descendants from escaping the group.
- Windows: CREATE_SUSPENDED + Job Object assignment with KILL_ON_JOB_CLOSE and
  no breakaway permission before ResumeThread.

All stop/reassign decisions are generation-bound and fail closed.
"""
from __future__ import annotations

import copy
import errno
import hashlib
import math
import os
import select
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence

MIN_TIMEOUT = 0.001
MAX_TIMEOUT = 3600.0
DEFAULT_GRACE_TIMEOUT = 2.0
DEFAULT_ESCALATION_TIMEOUT = 2.0
DEFAULT_POLL_INTERVAL = 0.02
DEFAULT_QUERY_TIMEOUT = 5.0
DEFAULT_LAUNCH_TIMEOUT = 10.0

STATE_RUNNING = "running"
STATE_STOPPING = "stopping"
STATE_STOPPED = "stopped"
STATE_STOP_FAILED = "stop-failed"
STATE_IDENTITY_LOST = "identity-lost"
STATE_ORPHANED = "orphaned-descendants"
STATE_COMPLETED = "completed"
STATE_FAILED = "failed"

REASSIGNABLE_STATES = frozenset({STATE_STOPPED, STATE_COMPLETED, STATE_FAILED})


class SupervisorError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class GenerationConflict(SupervisorError):
    pass


class TimeoutValidationError(SupervisorError):
    pass


class ContainmentError(SupervisorError):
    pass


class UnknownAssignment(SupervisorError):
    pass


def validated_timeout(value: Any, name: str = "timeout", *,
                      maximum: float = MAX_TIMEOUT,
                      minimum: float = MIN_TIMEOUT) -> float:
    if isinstance(value, bool) or isinstance(value, str) or value is None:
        raise TimeoutValidationError("TIMEOUT_INVALID", f"{name} must be a finite number")
    try:
        out = float(value)
    except (TypeError, ValueError, OverflowError) as ex:
        raise TimeoutValidationError("TIMEOUT_INVALID", f"{name} must be a finite number") from ex
    if not math.isfinite(out) or out < minimum or out > maximum:
        raise TimeoutValidationError(
            "TIMEOUT_INVALID", f"{name} must be finite and within [{minimum}, {maximum}]")
    return out


def _validate_generation(value: Any, *, optional: bool = False) -> Optional[int]:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GenerationConflict("GENERATION_INVALID", "generation must be a non-negative int")
    return value


def _validate_slot(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise SupervisorError("SLOT_INVALID", "slot must be a non-empty string <= 128 chars")
    if any(not (ch.isalnum() or ch in "._:-") for ch in value):
        raise SupervisorError("SLOT_INVALID", "slot contains an invalid character")
    return value


def _validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)) or argv is None:
        raise SupervisorError("ARGV_INVALID", "argv must be a non-empty sequence")
    try:
        items = list(argv)
    except TypeError as ex:
        raise SupervisorError("ARGV_INVALID", "argv must be a non-empty sequence") from ex
    if not items:
        raise SupervisorError("ARGV_INVALID", "argv must be a non-empty sequence")
    out = []
    for item in items:
        if not isinstance(item, str) or "\x00" in item:
            raise SupervisorError("ARGV_INVALID", "argv entries must be NUL-free strings")
        out.append(item)
    exe = Path(out[0])
    if not exe.is_absolute():
        raise SupervisorError("EXECUTABLE_INVALID", "argv[0] must be an absolute executable path")
    try:
        resolved = exe.resolve(strict=True)
    except OSError as ex:
        raise SupervisorError("EXECUTABLE_INVALID", f"cannot resolve executable: {exe}") from ex
    if not resolved.is_file():
        raise SupervisorError("EXECUTABLE_INVALID", "argv[0] must be a regular file")
    out[0] = str(resolved)
    return tuple(out)


def _validate_cwd(cwd: str | os.PathLike[str] | None) -> str | None:
    if cwd is None:
        return None
    raw = os.fspath(cwd)
    if not isinstance(raw, str) or not raw or "\x00" in raw or not os.path.isabs(raw):
        raise SupervisorError("CWD_INVALID", "cwd must be an absolute NUL-free path")
    p = Path(raw)
    try:
        p = p.resolve(strict=True)
    except OSError as ex:
        raise SupervisorError("CWD_INVALID", "cwd does not exist") from ex
    if not p.is_dir():
        raise SupervisorError("CWD_INVALID", "cwd must be a directory")
    return str(p)


def _validate_env(env: Mapping[str, str] | None) -> dict[str, str]:
    source = dict(os.environ) if env is None else dict(env)
    out: dict[str, str] = {}
    seen: set[str] = set()
    for key, value in source.items():
        if (not isinstance(key, str) or not key or "=" in key or "\x00" in key
                or not isinstance(value, str) or "\x00" in value):
            raise SupervisorError("ENV_INVALID", "environment contains invalid key/value")
        folded = key.casefold()
        if os.name == "nt" and folded in seen:
            raise SupervisorError("ENV_INVALID", "case-colliding Windows environment keys")
        seen.add(folded)
        out[key] = value
    return out


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(v) for v in value)
    if isinstance(value, (str, bytes, int, float, bool, type(None))):
        return value
    return copy.deepcopy(value)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_token: str
    image: str

    @property
    def token(self) -> str:
        return hashlib.sha256(
            f"{self.pid}\x1f{self.start_token}\x1f{self.image}".encode("utf-8", "surrogatepass")
        ).hexdigest()


@dataclass(frozen=True)
class AssignmentView:
    slot: str
    task_id: str | None
    generation: int
    state: str
    identity: ProcessIdentity
    operation_id: str
    exit_code: int | None
    pending_stop: Mapping[str, Any] | None
    updated_at: float


@dataclass(frozen=True)
class Evidence:
    operation_id: str
    slot: str
    generation: int
    kind: str
    outcome: str
    detail: Mapping[str, Any]
    at: float


def _opid(prefix: str) -> str:
    return f"{prefix}-{time.time_ns():x}-{os.urandom(8).hex()}"


# ---------------------------------------------------------------------------
# Linux owned process group: launch trampoline + inherited anti-escape seccomp
# ---------------------------------------------------------------------------

_TRAMPOLINE = r"""
import ctypes, errno, os, platform, sys
fd=int(sys.argv[1]); target=sys.argv[2]; args=sys.argv[2:]
try:
    os.setsid()
    machine=platform.machine().lower()
    if machine in ("x86_64","amd64"): denied=(109,112)
    elif machine in ("aarch64","arm64"): denied=(154,157)
    else: raise RuntimeError("unsupported Linux seccomp architecture: "+machine)
    libc=ctypes.CDLL(None,use_errno=True)
    PR_SET_NO_NEW_PRIVS=38; PR_SET_SECCOMP=22; SECCOMP_MODE_FILTER=2
    BPF_LD_W_ABS=0x20; BPF_JMP_JEQ_K=0x15; BPF_RET_K=0x06
    RET_ALLOW=0x7fff0000; RET_ERRNO=0x00050000
    class F(ctypes.Structure):
        _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
    class P(ctypes.Structure):
        _fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(F))]
    arr=(F*6)(
        F(BPF_LD_W_ABS,0,0,0),
        F(BPF_JMP_JEQ_K,0,1,denied[0]),
        F(BPF_RET_K,0,0,RET_ERRNO|errno.EPERM),
        F(BPF_JMP_JEQ_K,0,1,denied[1]),
        F(BPF_RET_K,0,0,RET_ERRNO|errno.EPERM),
        F(BPF_RET_K,0,0,RET_ALLOW),
    )
    prog=P(len(arr),arr)
    if libc.prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0:
        raise OSError(ctypes.get_errno(),"PR_SET_NO_NEW_PRIVS")
    if libc.prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,ctypes.byref(prog),0,0)!=0:
        raise OSError(ctypes.get_errno(),"PR_SET_SECCOMP")
    os.write(fd,b"READY\n"); os.close(fd)
    os.execve(target,args,os.environ)
except BaseException as e:
    try: os.write(fd,("ERROR:"+repr(e)+"\n").encode("utf-8","replace"))
    except BaseException: pass
    try: os.close(fd)
    except BaseException: pass
    os._exit(126)
"""


def _linux_proc_identity(pid: int) -> ProcessIdentity:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="surrogateescape")
        close = raw.rfind(")")
        if close < 0:
            raise ValueError("malformed stat")
        rest = raw[close + 1:].split()
        start_ticks = int(rest[19])
        image = os.readlink(f"/proc/{pid}/exe")
    except FileNotFoundError as ex:
        raise ContainmentError("PROCESS_GONE", f"pid {pid} is gone") from ex
    except (OSError, ValueError, IndexError) as ex:
        raise ContainmentError("IDENTITY_QUERY_FAILED", f"cannot identify pid {pid}: {ex}") from ex
    return ProcessIdentity(pid=pid, start_token=str(start_ticks), image=image)


def _linux_group_non_zombie_members(pgid: int, query_timeout: float) -> tuple[int, ...]:
    deadline = time.monotonic() + query_timeout
    found: list[int] = []
    try:
        names = os.listdir("/proc")
    except OSError as ex:
        raise ContainmentError("CONTAINMENT_QUERY_FAILED", f"cannot enumerate /proc: {ex}") from ex
    for index, name in enumerate(names):
        if index % 64 == 0 and time.monotonic() >= deadline:
            raise ContainmentError("CONTAINMENT_QUERY_TIMEOUT", "process-group query exceeded its bound")
        if not name.isdigit():
            continue
        try:
            raw = Path("/proc", name, "stat").read_text(encoding="utf-8", errors="surrogateescape")
            close = raw.rfind(")")
            rest = raw[close + 1:].split()
            state = rest[0]
            group = int(rest[2])
        except (OSError, ValueError, IndexError):
            continue
        if group == pgid and state != "Z":
            found.append(int(name))
    if time.monotonic() >= deadline:
        raise ContainmentError("CONTAINMENT_QUERY_TIMEOUT", "process-group query exceeded its bound")
    return tuple(sorted(found))


class PosixOwnedProcess:
    """Linux-only non-escapable process-group containment."""

    def __init__(self, proc: subprocess.Popen, pgid: int, identity: ProcessIdentity):
        self._proc = proc
        self.pid = int(proc.pid)
        self.pgid = int(pgid)
        self.identity = identity
        self._closed = False

    @classmethod
    def launch(cls, argv: tuple[str, ...], cwd: str | None, env: dict[str, str],
               launch_timeout: float) -> "PosixOwnedProcess":
        if not sys.platform.startswith("linux"):
            raise ContainmentError("CONTAINMENT_UNAVAILABLE", "secure POSIX containment currently requires Linux")
        read_fd, write_fd = os.pipe()
        try:
            proc = subprocess.Popen(
                [sys.executable, "-c", _TRAMPOLINE, str(write_fd), *argv],
                cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=(write_fd,), close_fds=True,
            )
        except BaseException:
            os.close(read_fd); os.close(write_fd)
            raise
        os.close(write_fd)
        try:
            ready, _, _ = select.select([read_fd], [], [], launch_timeout)
            if not ready:
                proc.kill()
                raise ContainmentError("LAUNCH_TIMEOUT", "containment trampoline did not become ready")
            payload = os.read(read_fd, 4096)
            if not payload.startswith(b"READY\n"):
                proc.kill()
                raise ContainmentError("CONTAINMENT_SETUP_FAILED", payload.decode("utf-8", "replace").strip())
        finally:
            os.close(read_fd)
        deadline = time.monotonic() + launch_timeout
        expected_image = str(Path(argv[0]).resolve())
        identity = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise ContainmentError("LAUNCH_FAILED", f"worker exited before executable identity bound: {proc.returncode}")
            try:
                candidate = _linux_proc_identity(proc.pid)
            except ContainmentError:
                time.sleep(0.005)
                continue
            try:
                image = str(Path(candidate.image).resolve())
            except OSError:
                image = candidate.image
            if image == expected_image:
                identity = ProcessIdentity(candidate.pid, candidate.start_token, image)
                break
            time.sleep(0.005)
        if identity is None:
            proc.kill()
            raise ContainmentError("LAUNCH_TIMEOUT", "worker executable identity did not stabilize")
        try:
            pgid = os.getpgid(proc.pid)
        except OSError as ex:
            proc.kill()
            raise ContainmentError("CONTAINMENT_QUERY_FAILED", "cannot read owned process group") from ex
        if pgid != proc.pid:
            proc.kill()
            raise ContainmentError("CONTAINMENT_SETUP_FAILED", "worker did not become process-group leader")
        return cls(proc, pgid, identity)

    def root_exit_code(self) -> int | None:
        return self._proc.poll()

    def identity_valid(self) -> bool:
        if self._proc.poll() is not None:
            return True
        try:
            current = _linux_proc_identity(self.pid)
        except ContainmentError:
            return False
        return (current.pid == self.identity.pid
                and current.start_token == self.identity.start_token
                and str(Path(current.image).resolve()) == self.identity.image)

    def members(self, query_timeout: float) -> tuple[int, ...]:
        return _linux_group_non_zombie_members(self.pgid, query_timeout)

    def empty(self, query_timeout: float) -> bool:
        return not self.members(query_timeout)

    def terminate(self, grace: float, escalation: float, poll: float,
                  query_timeout: float) -> Mapping[str, Any]:
        def alive() -> tuple[int, ...]:
            return self.members(query_timeout)
        before = alive()
        if not before:
            return {"reason": "already-empty", "escalated": False, "membersBefore": before}
        try:
            os.killpg(self.pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            members = alive()
            if not members:
                self._reap_root()
                return {"reason": "graceful", "escalated": False,
                        "membersBefore": before, "membersAfter": members}
            time.sleep(min(poll, max(MIN_TIMEOUT, deadline - time.monotonic())))
        try:
            os.killpg(self.pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + escalation
        while time.monotonic() < deadline:
            members = alive()
            if not members:
                self._reap_root()
                return {"reason": "escalated", "escalated": True,
                        "membersBefore": before, "membersAfter": members}
            time.sleep(min(poll, max(MIN_TIMEOUT, deadline - time.monotonic())))
        members = alive()
        raise ContainmentError(
            "STOP_FAILED", f"owned process group still has members after escalation: {members}")

    def _reap_root(self) -> None:
        try:
            self._proc.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass

    def close(self) -> None:
        self._closed = True


class DefaultLauncher:
    def launch(self, argv: tuple[str, ...], cwd: str | None, env: dict[str, str],
               launch_timeout: float):
        if os.name == "nt":
            from .process_supervisor_windows import WindowsOwnedProcess
            return WindowsOwnedProcess.launch(argv, cwd, env, launch_timeout)
        return PosixOwnedProcess.launch(argv, cwd, env, launch_timeout)


@dataclass
class _Assignment:
    slot: str
    task_id: str | None
    generation: int
    state: str
    owned: Any
    identity: ProcessIdentity
    operation_id: str
    updated_at: float
    exit_code: int | None = None
    stop_operation_id: str | None = None
    stop_started_at: float | None = None
    exit_recorded: bool = False


@dataclass
class _StopOp:
    operation_id: str
    slot: str
    generation: int
    done: threading.Event = field(default_factory=threading.Event)
    evidence: Evidence | None = None
    error: BaseException | None = None


class ProcessSupervisor:
    """Generation-bound supervisor whose destructive authority is containment."""

    def __init__(self, launcher=None, *, wall_clock=time.time, clock=time.monotonic,
                 sleep=time.sleep, evidence_limit: int = 2048):
        self._launcher = launcher or DefaultLauncher()
        self._wall_clock = wall_clock
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.RLock()
        self._assignments: dict[str, _Assignment] = {}
        self._inflight: dict[str, _StopOp] = {}
        self._evidence = deque(maxlen=max(1, int(evidence_limit)))

    def _record(self, operation_id: str, slot: str, generation: int,
                kind: str, outcome: str, detail: Mapping[str, Any] | None = None) -> Evidence:
        ev = Evidence(operation_id, slot, generation, kind, outcome,
                      _freeze(dict(detail or {})), self._wall_clock())
        self._evidence.append(ev)
        return ev

    def evidence(self, slot: str | None = None) -> tuple[Evidence, ...]:
        with self._lock:
            items = tuple(self._evidence)
        if slot is None:
            return items
        slot = _validate_slot(slot)
        return tuple(x for x in items if x.slot == slot)

    def _view(self, a: _Assignment) -> AssignmentView:
        pending = None
        if a.stop_operation_id:
            pending = _freeze({"operationId": a.stop_operation_id, "startedAt": a.stop_started_at})
        return AssignmentView(a.slot, a.task_id, a.generation, a.state, a.identity,
                              a.operation_id, a.exit_code, pending, a.updated_at)

    def _refresh_locked(self, a: _Assignment, query_timeout: float) -> None:
        if a.state not in (STATE_RUNNING, STATE_ORPHANED):
            return
        code = a.owned.root_exit_code()
        if code is None:
            try:
                valid = a.owned.identity_valid()
            except BaseException as ex:
                raise ContainmentError(
                    "IDENTITY_QUERY_FAILED", f"owned identity query failed: {ex}") from ex
            if valid:
                return
            # The root can exit (or briefly be between executable-image states)
            # between the first stable-handle poll and identity observation.
            # Resolve that ambiguity for at most the caller's already-validated
            # query budget before classifying identity loss. Never turn one
            # transient read into authority for a new generation.
            deadline = self._clock() + min(query_timeout, 0.10)
            while code is None and self._clock() < deadline:
                self._sleep(min(0.005, max(MIN_TIMEOUT, deadline - self._clock())))
                code = a.owned.root_exit_code()
                if code is not None:
                    break
                try:
                    if a.owned.identity_valid():
                        return
                except BaseException as ex:
                    raise ContainmentError(
                        "IDENTITY_QUERY_FAILED", f"owned identity query failed: {ex}") from ex
            if code is None:
                a.state = STATE_IDENTITY_LOST
                a.updated_at = self._wall_clock()
                return
        a.exit_code = int(code)
        empty = a.owned.empty(query_timeout)
        if empty:
            a.state = STATE_COMPLETED if code == 0 else STATE_FAILED
            if not a.exit_recorded:
                outcome = "completed" if code == 0 else "failed"
                self._record(_opid("EXIT"), a.slot, a.generation, "exit", outcome,
                             {"exitCode": code, "treeEmpty": True})
                a.exit_recorded = True
        else:
            a.state = STATE_ORPHANED
        a.updated_at = self._wall_clock()

    def get(self, slot: str, *, query_timeout: Any = DEFAULT_QUERY_TIMEOUT) -> AssignmentView:
        slot = _validate_slot(slot)
        query = validated_timeout(query_timeout, "query_timeout")
        with self._lock:
            a = self._assignments.get(slot)
            if a is None:
                raise UnknownAssignment("SLOT_UNKNOWN", f"no assignment for slot {slot!r}")
            self._refresh_locked(a, query)
            return self._view(a)

    def snapshot(self, *, query_timeout: Any = DEFAULT_QUERY_TIMEOUT) -> tuple[AssignmentView, ...]:
        query = validated_timeout(query_timeout, "query_timeout")
        with self._lock:
            for a in self._assignments.values():
                self._refresh_locked(a, query)
            return tuple(self._view(a) for a in sorted(self._assignments.values(), key=lambda x: x.slot))

    def launch(self, slot: str, argv: Sequence[str], *, task_id: str | None = None,
               expected_generation: int | None = None, operation_id: str | None = None,
               cwd: str | os.PathLike[str] | None = None, env: Mapping[str, str] | None = None,
               launch_timeout: Any = DEFAULT_LAUNCH_TIMEOUT,
               query_timeout: Any = DEFAULT_QUERY_TIMEOUT,
               require_existing: bool = False) -> AssignmentView:
        # Every caller-controlled value is validated before any process mutation.
        slot = _validate_slot(slot)
        args = _validate_argv(argv)
        workdir = _validate_cwd(cwd)
        environ = _validate_env(env)
        launch_bound = validated_timeout(launch_timeout, "launch_timeout")
        query = validated_timeout(query_timeout, "query_timeout")
        expected = _validate_generation(expected_generation, optional=True)
        op = str(operation_id or _opid("LAUNCH"))
        with self._lock:
            current = self._assignments.get(slot)
            base_generation = self._assert_rebindable_locked(
                slot, current, expected, require_existing, query)
            # Launch while holding the authority lock. It is bounded and prevents
            # another register/reassign/stop from slipping between empty-proof
            # and the new generation commit.
            owned = None
            try:
                owned = self._launcher.launch(args, workdir, environ, launch_bound)
                identity = owned.identity
                if not isinstance(identity, ProcessIdentity) or identity.pid <= 1:
                    raise ContainmentError("IDENTITY_INVALID", "launcher returned invalid process identity")
                if owned.empty(query):
                    code = owned.root_exit_code()
                    raise ContainmentError("LAUNCH_FAILED", f"worker exited during launch with code {code}")
                generation = base_generation + 1
                a = _Assignment(slot, task_id, generation, STATE_RUNNING, owned,
                                identity, op, self._wall_clock())
                self._assignments[slot] = a
                self._record(op, slot, generation, "launch", "bound",
                             {"pid": identity.pid, "identityToken": identity.token,
                              "taskId": task_id, "ownedContainment": True})
                return self._view(a)
            except BaseException:
                if owned is not None:
                    try:
                        if not owned.empty(query):
                            owned.terminate(min(1.0, launch_bound), min(1.0, launch_bound),
                                            min(0.02, launch_bound), query)
                    except BaseException:
                        pass
                    try:
                        owned.close()
                    except BaseException:
                        pass
                raise

    # `register` remains the controller-facing name but now launches, never adopts
    # an arbitrary caller PID.
    def register(self, slot: str, argv: Sequence[str], **kwargs) -> AssignmentView:
        return self.launch(slot, argv, require_existing=False, **kwargs)

    def reassign(self, slot: str, argv: Sequence[str], *, expected_generation: int, **kwargs) -> AssignmentView:
        return self.launch(slot, argv, expected_generation=expected_generation,
                           require_existing=True, **kwargs)

    def _assert_rebindable_locked(self, slot: str, current: _Assignment | None,
                                  expected: int | None, require_existing: bool,
                                  query_timeout: float) -> int:
        if current is None:
            if require_existing:
                raise UnknownAssignment("SLOT_UNKNOWN", f"no assignment for slot {slot!r}")
            if expected not in (None, 0):
                raise GenerationConflict("GENERATION_MISMATCH", "empty slot has generation 0")
            return 0
        if expected is None:
            raise GenerationConflict("GENERATION_REQUIRED", "expected_generation is required")
        if expected != current.generation:
            raise GenerationConflict(
                "GENERATION_MISMATCH",
                f"slot {slot!r} is generation {current.generation}, not {expected}")
        if slot in self._inflight or current.state == STATE_STOPPING:
            raise GenerationConflict("SLOT_STOPPING", "stop is still in flight")
        self._refresh_locked(current, query_timeout)
        if current.state in (STATE_RUNNING, STATE_ORPHANED):
            raise GenerationConflict("SLOT_RUNNING", "old owned containment is still live")
        if current.state == STATE_STOP_FAILED:
            raise GenerationConflict("STOP_FAILED_UNRESOLVED", "failed stop must be retried successfully")
        if current.state == STATE_IDENTITY_LOST:
            raise GenerationConflict("IDENTITY_LOST_UNRESOLVED", "identity-lost generation must be stopped/reconciled")
        if current.state not in REASSIGNABLE_STATES:
            raise GenerationConflict("SLOT_NOT_REASSIGNABLE", f"state {current.state!r} is not reassignable")
        if not current.owned.empty(query_timeout):
            raise GenerationConflict("CONTAINMENT_NOT_EMPTY", "old owned containment is not empty")
        return current.generation

    def stop(self, slot: str, *, expected_generation: int,
             timeout: Any = DEFAULT_GRACE_TIMEOUT,
             escalation_timeout: Any = DEFAULT_ESCALATION_TIMEOUT,
             poll_interval: Any = DEFAULT_POLL_INTERVAL,
             query_timeout: Any = DEFAULT_QUERY_TIMEOUT,
             join_timeout: Any | None = None,
             include_tree: bool = True,
             operation_id: str | None = None) -> Evidence:
        # Validate all timing/downgrade inputs before state mutation.
        slot = _validate_slot(slot)
        generation = _validate_generation(expected_generation)
        grace = validated_timeout(timeout, "timeout")
        escalation = validated_timeout(escalation_timeout, "escalation_timeout")
        poll = validated_timeout(poll_interval, "poll_interval",
                                 maximum=max(MIN_TIMEOUT, min(grace, escalation)))
        query = validated_timeout(query_timeout, "query_timeout")
        if join_timeout is None:
            join_timeout = min(MAX_TIMEOUT, grace + escalation + query + 5.0)
        join = validated_timeout(join_timeout, "join_timeout")
        if include_tree is not True:
            raise SupervisorError("OWNED_TREE_REQUIRED", "root-only stop is forbidden for FL1")
        opid = str(operation_id or _opid("STOP"))
        with self._lock:
            a = self._assignments.get(slot)
            if a is None:
                raise UnknownAssignment("SLOT_UNKNOWN", f"no assignment for slot {slot!r}")
            if a.generation != generation:
                raise GenerationConflict("GENERATION_MISMATCH", "generation mismatch")
            existing = self._inflight.get(slot)
            if existing is not None:
                if existing.generation != generation:
                    raise GenerationConflict("GENERATION_MISMATCH", "different-generation stop is in flight")
                joined = existing
            else:
                self._refresh_locked(a, query)
                if a.state in (STATE_COMPLETED, STATE_FAILED) and a.owned.empty(query):
                    return self._record(opid, slot, generation, "stop", "already-empty",
                                        {"state": a.state, "exitCode": a.exit_code,
                                         "workerOutcome": "completed" if a.state == STATE_COMPLETED else "failed"})
                if a.state == STATE_STOPPED:
                    return self._record(opid, slot, generation, "stop", "already-stopped",
                                        {"state": a.state, "exitCode": a.exit_code})
                joined = None
                stopop = _StopOp(opid, slot, generation)
                self._inflight[slot] = stopop
                a.state = STATE_STOPPING
                a.stop_operation_id = opid
                a.stop_started_at = self._wall_clock()
                a.updated_at = a.stop_started_at
                owned = a.owned
        if joined is not None:
            if not joined.done.wait(join):
                raise SupervisorError("STOP_JOIN_TIMEOUT", "joined stop did not finish within bound")
            if joined.error is not None:
                raise joined.error
            assert joined.evidence is not None
            return joined.evidence
        try:
            detail = dict(owned.terminate(grace, escalation, poll, query))
            if not owned.empty(query):
                raise ContainmentError("STOP_FAILED", "owned containment not empty after termination")
            detail["exitCode"] = owned.root_exit_code()
            ev = self._complete_stop(stopop, "stopped", detail)
            stopop.evidence = ev
            return ev
        except BaseException as ex:
            ev = self._complete_stop(
                stopop, "stop-failed",
                {"code": getattr(ex, "code", type(ex).__name__), "error": str(ex)})
            stopop.evidence = ev
            stopop.error = ex
            raise
        finally:
            stopop.done.set()

    def _complete_stop(self, op: _StopOp, outcome: str,
                       detail: Mapping[str, Any]) -> Evidence:
        with self._lock:
            if self._inflight.get(op.slot) is op:
                self._inflight.pop(op.slot, None)
            a = self._assignments.get(op.slot)
            if a is None or a.generation != op.generation or a.stop_operation_id != op.operation_id:
                return self._record(op.operation_id, op.slot, op.generation, "stop",
                                    "stale-discarded",
                                    {**dict(detail), "attemptedOutcome": outcome, "stale": True})
            a.stop_operation_id = None
            a.stop_started_at = None
            a.operation_id = op.operation_id
            a.updated_at = self._wall_clock()
            if outcome == "stopped":
                a.state = STATE_STOPPED
                a.exit_code = a.owned.root_exit_code()
            else:
                a.state = STATE_STOP_FAILED
            return self._record(op.operation_id, op.slot, op.generation, "stop",
                                outcome, {**dict(detail), "state": a.state, "stale": False})

    def close(self, *, timeout: Any = 2.0) -> None:
        bound = validated_timeout(timeout, "close_timeout")
        with self._lock:
            assignments = list(self._assignments.values())
        for a in assignments:
            try:
                if not a.owned.empty(min(DEFAULT_QUERY_TIMEOUT, bound)):
                    a.owned.terminate(min(bound, 1.0), min(bound, 1.0), 0.02,
                                      min(DEFAULT_QUERY_TIMEOUT, bound))
            except BaseException:
                pass
            try:
                a.owned.close()
            except BaseException:
                pass
