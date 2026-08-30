from __future__ import annotations

import ctypes
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence

MAX_TIMEOUT_SECONDS = 3600.0
DEFAULT_POLL_SECONDS = 0.05
LINUX_QUERY_TIMEOUT_SECONDS = 0.25
LINUX_MAX_DESCENDANTS = 4096
LINUX_PROC_RECORD_MAX_BYTES = 64 * 1024
LINUX_STOP_ESCALATION_SECONDS = 1.0

STATE_RUNNING = "RUNNING"
STATE_STOPPING = "STOPPING"
STATE_STOPPED = "STOPPED"
STATE_FAILED = "FAILED"
STATE_STOP_FAILED = "STOP_FAILED"
STATE_IDENTITY_LOST = "IDENTITY_LOST"
STATE_QUARANTINED = "QUARANTINED"

_ADVANCEABLE = frozenset({STATE_STOPPED})
_BLOCKED = frozenset({STATE_RUNNING, STATE_STOPPING, STATE_FAILED, STATE_STOP_FAILED, STATE_IDENTITY_LOST, STATE_QUARANTINED})


class SupervisorError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _timeout(value, field: str, *, allow_zero: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SupervisorError("TIMING_INVALID", f"{field} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise SupervisorError("TIMING_INVALID", f"{field} must be finite")
    if number < 0 or (not allow_zero and number <= 0) or number > MAX_TIMEOUT_SECONDS:
        raise SupervisorError("TIMING_INVALID", f"{field} is outside the allowed range")
    return number


def _argv(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        raise SupervisorError("ARGV_INVALID", "argv must be a non-empty sequence")
    out = []
    for part in value:
        if not isinstance(part, str) or not part or "\x00" in part:
            raise SupervisorError("ARGV_INVALID", "argv entries must be non-empty NUL-free strings")
        out.append(part)
    executable = Path(out[0])
    if not executable.is_absolute():
        raise SupervisorError("ARGV_INVALID", "argv[0] must be an absolute executable path")
    return tuple(out)


def _cwd(value) -> str | None:
    if value is None:
        return None
    path = os.fspath(value)
    if not isinstance(path, str) or not path or "\x00" in path or not os.path.isabs(path):
        raise SupervisorError("CWD_INVALID", "cwd must be an absolute NUL-free path")
    return path


def _env(value: Mapping[str, str] | None) -> dict[str, str]:
    source = os.environ if value is None else value
    if not isinstance(source, Mapping):
        raise SupervisorError("ENV_INVALID", "env must be a mapping")
    out: dict[str, str] = {}
    seen: set[str] = set()
    for key, item in source.items():
        if not isinstance(key, str) or not isinstance(item, str) or not key or "=" in key or "\x00" in key or "\x00" in item:
            raise SupervisorError("ENV_INVALID", "environment contains an invalid entry")
        folded = key.casefold()
        if os.name == "nt" and folded in seen:
            raise SupervisorError("ENV_INVALID", "Windows environment contains case-colliding keys")
        seen.add(folded)
        out[key] = item
    return out


@dataclass(frozen=True)
class Evidence:
    operation_id: str
    worker_id: str
    generation: int
    state: str
    reason: str
    exit_code: int | None
    containment_empty: bool
    started_at: float
    finished_at: float

    def as_dict(self) -> dict:
        return {
            "operationId": self.operation_id,
            "workerId": self.worker_id,
            "generation": self.generation,
            "state": self.state,
            "reason": self.reason,
            "exitCode": self.exit_code,
            "containmentEmpty": self.containment_empty,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
        }


@dataclass(frozen=True)
class Assignment:
    worker_id: str
    generation: int
    state: str
    argv: tuple[str, ...]
    pid: int
    containment_id: str
    started_at: float
    exit_code: int | None = None
    last_evidence: Evidence | None = None

    def as_dict(self) -> dict:
        return MappingProxyType({
            "workerId": self.worker_id,
            "generation": self.generation,
            "state": self.state,
            "argv": self.argv,
            "pid": self.pid,
            "containmentId": self.containment_id,
            "startedAt": self.started_at,
            "exitCode": self.exit_code,
            "lastEvidence": None if self.last_evidence is None else self.last_evidence.as_dict(),
        })


class _Containment:
    pid: int
    containment_id: str

    def poll(self) -> int | None:
        raise NotImplementedError

    def empty(self, timeout: float) -> bool:
        raise NotImplementedError

    def terminate(self, timeout: float) -> bool:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


def _linux_subreaper_available() -> bool:
    return sys.platform.startswith("linux") and Path("/proc/self").exists()


class _PosixKeeperContainment(_Containment):
    """Worker tree owned by a dedicated Linux child-subreaper keeper.

    The keeper is the nearest subreaper for the worker. If the leader exits or
    descendants daemonize into a new session/process group, orphaned descendants
    are reparented to the keeper. The supervisor treats the containment as empty
    only when the keeper has positively observed that no worker descendants
    remain.
    """

    def __init__(self, argv: tuple[str, ...], cwd: str | None, env: dict[str, str]):
        if not _linux_subreaper_available():
            raise SupervisorError("CONTAINMENT_UNAVAILABLE", "Linux subreaper containment is unavailable")
        self._stop_requested = False
        spec = json.dumps({"argv": list(argv), "cwd": cwd, "env": env}, separators=(",", ":"))
        keeper_env = {"PYTHONIOENCODING": "utf-8"}
        self._proc = subprocess.Popen(
            [sys.executable, "-S", str(Path(__file__).resolve()), "--keeper"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=keeper_env,
            start_new_session=True,
            close_fds=True,
        )
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(spec + "\n")
            self._proc.stdin.flush()
            self._proc.stdin.close()
        except Exception as ex:
            self._kill_keeper()
            raise SupervisorError("CONTAINMENT_START_FAILED", "cannot transfer private keeper launch spec") from ex
        line = self._readline_bounded(5.0)
        try:
            hello = json.loads(line)
        except Exception as ex:
            self._kill_keeper()
            raise SupervisorError("CONTAINMENT_START_FAILED", "keeper did not provide valid launch identity") from ex
        if hello.get("ok") is not True or not isinstance(hello.get("pid"), int) or hello["pid"] <= 1:
            detail = str(hello.get("error") or "keeper launch failed")
            self._kill_keeper()
            raise SupervisorError("CONTAINMENT_START_FAILED", detail)
        self.pid = int(hello["pid"])
        self.containment_id = f"linux-subreaper:{self._proc.pid}:{self.pid}"

    def _readline_bounded(self, timeout: float) -> str:
        result: list[str] = []
        error: list[BaseException] = []
        def reader():
            try:
                result.append(self._proc.stdout.readline() if self._proc.stdout else "")
            except BaseException as ex:
                error.append(ex)
        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            self._kill_keeper()
            raise SupervisorError("CONTAINMENT_QUERY_TIMEOUT", "keeper identity query timed out")
        if error or not result or not result[0]:
            raise SupervisorError("CONTAINMENT_START_FAILED", "keeper exited before launch identity")
        return result[0]

    def poll(self) -> int | None:
        rc = self._proc.poll()
        if rc is None:
            return None
        return int(rc)

    def empty(self, timeout: float) -> bool:
        timeout = _timeout(timeout, "containment query timeout")
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        rc = int(self._proc.returncode)
        if self._stop_requested:
            return rc == 75
        return True

    def terminate(self, timeout: float) -> bool:
        timeout = _timeout(timeout, "termination timeout")
        self._stop_requested = True
        rc = self._proc.poll()
        if rc is not None:
            return int(rc) == 75
        try:
            os.kill(self._proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            rc = self._proc.poll()
            return rc is not None and int(rc) == 75
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        return int(self._proc.returncode) == 75

    def _kill_keeper(self):
        try:
            self._proc.kill()
        except Exception:
            pass
        try:
            self._proc.wait(timeout=2.0)
        except Exception:
            pass

    def close(self) -> None:
        if self._proc.poll() is None:
            self.terminate(2.0)
        for stream in (self._proc.stdout, self._proc.stderr):
            try:
                if stream:
                    stream.close()
            except Exception:
                pass


if os.name == "nt":
    from ctypes import wintypes

    CREATE_SUSPENDED = 0x00000004
    CREATE_UNICODE_ENVIRONMENT = 0x00000400
    CREATE_NO_WINDOW = 0x08000000
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JobObjectExtendedLimitInformation = 9
    JobObjectBasicAccountingInformation = 1

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_int64),
            ("TotalKernelTime", ctypes.c_int64),
            ("ThisPeriodTotalUserTime", ctypes.c_int64),
            ("ThisPeriodTotalKernelTime", ctypes.c_int64),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    class _STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
            ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
        ]


class _WindowsJobContainment(_Containment):
    def __init__(self, argv: tuple[str, ...], cwd: str | None, env: dict[str, str]):
        if os.name != "nt":
            raise SupervisorError("CONTAINMENT_UNAVAILABLE", "Windows Job containment is unavailable")
        from ctypes import wintypes
        self._k = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure()
        self._job = self._k.CreateJobObjectW(None, None)
        if not self._job:
            raise SupervisorError("CONTAINMENT_START_FAILED", "CreateJobObjectW failed")
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self._k.SetInformationJobObject(self._job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
            self._k.CloseHandle(self._job)
            raise SupervisorError("CONTAINMENT_START_FAILED", "SetInformationJobObject failed")
        cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        block = "\0".join(f"{k}={v}" for k, v in sorted(env.items(), key=lambda kv: kv[0].casefold())) + "\0\0"
        envbuf = ctypes.create_unicode_buffer(block)
        si = _STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        pi = _PROCESS_INFORMATION()
        flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
        if not self._k.CreateProcessW(argv[0], cmd, None, None, False, flags, ctypes.cast(envbuf, wintypes.LPVOID), cwd, ctypes.byref(si), ctypes.byref(pi)):
            self._k.CloseHandle(self._job)
            raise SupervisorError("CONTAINMENT_START_FAILED", "CreateProcessW failed")
        self._process, self._thread = pi.hProcess, pi.hThread
        self.pid = int(pi.dwProcessId)
        try:
            if not self._k.AssignProcessToJobObject(self._job, self._process):
                raise SupervisorError("CONTAINMENT_START_FAILED", "AssignProcessToJobObject failed")
            if self._k.ResumeThread(self._thread) == 0xFFFFFFFF:
                raise SupervisorError("CONTAINMENT_START_FAILED", "ResumeThread failed")
        except Exception:
            self._k.TerminateProcess(self._process, 70)
            self.close()
            raise
        self.containment_id = f"windows-job:{int(getattr(self._job, 'value', self._job) or 0)}:{self.pid}"

    def _configure(self):
        from ctypes import wintypes
        H, D, V = wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID
        specs = {
            "CreateJobObjectW": ([V, wintypes.LPCWSTR], H),
            "SetInformationJobObject": ([H, ctypes.c_int, V, D], wintypes.BOOL),
            "AssignProcessToJobObject": ([H, H], wintypes.BOOL),
            "TerminateJobObject": ([H, wintypes.UINT], wintypes.BOOL),
            "QueryInformationJobObject": ([H, ctypes.c_int, V, D, ctypes.POINTER(D)], wintypes.BOOL),
            "CreateProcessW": ([wintypes.LPCWSTR, wintypes.LPWSTR, V, V, wintypes.BOOL, D, V, wintypes.LPCWSTR, V, V], wintypes.BOOL),
            "ResumeThread": ([H], D),
            "GetExitCodeProcess": ([H, ctypes.POINTER(D)], wintypes.BOOL),
            "WaitForSingleObject": ([H, D], D),
            "TerminateProcess": ([H, wintypes.UINT], wintypes.BOOL),
            "CloseHandle": ([H], wintypes.BOOL),
        }
        for name, (args, result) in specs.items():
            fn = getattr(self._k, name)
            fn.argtypes = args
            fn.restype = result

    def poll(self) -> int | None:
        from ctypes import wintypes
        code = wintypes.DWORD()
        if not self._k.GetExitCodeProcess(self._process, ctypes.byref(code)):
            raise SupervisorError("IDENTITY_LOST", "cannot query stable worker process handle")
        return None if code.value == 259 else int(code.value)

    def empty(self, timeout: float) -> bool:
        timeout = _timeout(timeout, "containment query timeout")
        deadline = time.monotonic() + timeout
        info = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        while time.monotonic() < deadline:
            if not self._k.QueryInformationJobObject(self._job, JobObjectBasicAccountingInformation, ctypes.byref(info), ctypes.sizeof(info), None):
                raise SupervisorError("CONTAINMENT_QUERY_FAILED", "QueryInformationJobObject failed")
            if int(info.ActiveProcesses) == 0:
                return True
            time.sleep(min(DEFAULT_POLL_SECONDS, max(0.001, deadline - time.monotonic())))
        return False

    def terminate(self, timeout: float) -> bool:
        timeout = _timeout(timeout, "termination timeout")
        if not self._k.TerminateJobObject(self._job, 75):
            raise SupervisorError("STOP_FAILED", "TerminateJobObject failed")
        return self.empty(timeout)

    def close(self) -> None:
        for handle in (getattr(self, "_thread", None), getattr(self, "_process", None), getattr(self, "_job", None)):
            if handle:
                try:
                    self._k.CloseHandle(handle)
                except Exception:
                    pass


def _launch_containment(argv: tuple[str, ...], cwd: str | None, env: dict[str, str]) -> _Containment:
    if os.name == "nt":
        return _WindowsJobContainment(argv, cwd, env)
    if sys.platform.startswith("linux"):
        return _PosixKeeperContainment(argv, cwd, env)
    raise SupervisorError("CONTAINMENT_UNAVAILABLE", "no non-escapable containment backend for this platform")


class ProcessSupervisor:
    def __init__(self):
        self._lock = threading.RLock()
        self._slots: dict[str, Assignment] = {}
        self._containments: dict[str, _Containment] = {}
        self._stop_ops: dict[tuple[str, int], tuple[str, threading.Event]] = {}

    def launch(self, worker_id: str, argv: Sequence[str], *, cwd=None, env=None) -> Assignment:
        return self._bind(worker_id, argv, cwd=cwd, env=env, expected_generation=None)

    def reassign(self, worker_id: str, expected_generation: int, argv: Sequence[str], *, cwd=None, env=None) -> Assignment:
        return self._bind(worker_id, argv, cwd=cwd, env=env, expected_generation=expected_generation)

    def _bind(self, worker_id, argv, *, cwd, env, expected_generation):
        if not isinstance(worker_id, str) or not worker_id or worker_id.strip() != worker_id:
            raise SupervisorError("WORKER_ID_INVALID", "worker_id must be a non-empty canonical string")
        args = _argv(argv)
        workdir = _cwd(cwd)
        environment = _env(env)
        with self._lock:
            current = self._slots.get(worker_id)
            if current is not None:
                if expected_generation is None:
                    raise SupervisorError("GENERATION_OCCUPIED", "worker already has a generation")
                if not isinstance(expected_generation, int) or isinstance(expected_generation, bool) or expected_generation != current.generation:
                    raise SupervisorError("GENERATION_STALE", "expected generation does not match")
                if current.state not in _ADVANCEABLE:
                    raise SupervisorError("GENERATION_NOT_STOPPED", f"cannot advance from {current.state}")
                containment = self._containments.get(worker_id)
                if containment is None:
                    raise SupervisorError("IDENTITY_LOST", "prior containment identity is missing")
                if not containment.empty(1.0):
                    raise SupervisorError("GENERATION_NOT_STOPPED", "prior containment is not empty")
                generation = current.generation + 1
            else:
                if expected_generation is not None:
                    raise SupervisorError("GENERATION_UNKNOWN", "worker has no prior generation")
                generation = 1
        containment = _launch_containment(args, workdir, environment)
        started = time.time()
        assignment = Assignment(worker_id, generation, STATE_RUNNING, args, containment.pid, containment.containment_id, started)
        with self._lock:
            latest = self._slots.get(worker_id)
            if current is None:
                if latest is not None:
                    containment.terminate(2.0); containment.close()
                    raise SupervisorError("GENERATION_RACE", "worker generation changed during launch")
            else:
                if latest != current:
                    containment.terminate(2.0); containment.close()
                    raise SupervisorError("GENERATION_RACE", "worker generation changed during launch")
                old = self._containments.get(worker_id)
                if old is not None:
                    old.close()
            self._slots[worker_id] = assignment
            self._containments[worker_id] = containment
            return assignment

    def refresh(self, worker_id: str) -> Assignment:
        with self._lock:
            current = self._require(worker_id)
            containment = self._containments.get(worker_id)
        if containment is None:
            updated = replace(current, state=STATE_IDENTITY_LOST)
        else:
            try:
                rc = containment.poll()
            except Exception:
                updated = replace(current, state=STATE_IDENTITY_LOST)
            else:
                if rc is None:
                    return current
                empty = containment.empty(1.0)
                if not empty:
                    updated = replace(current, state=STATE_QUARANTINED, exit_code=rc)
                elif rc == 0:
                    updated = replace(current, state=STATE_QUARANTINED, exit_code=0)
                else:
                    updated = replace(current, state=STATE_FAILED, exit_code=rc)
        with self._lock:
            if self._slots.get(worker_id) == current:
                self._slots[worker_id] = updated
            return self._slots[worker_id]

    def stop(self, worker_id: str, expected_generation: int, *, timeout: float = 10.0) -> Evidence:
        timeout = _timeout(timeout, "stop timeout")
        if not isinstance(expected_generation, int) or isinstance(expected_generation, bool) or expected_generation <= 0:
            raise SupervisorError("GENERATION_INVALID", "expected_generation must be a positive integer")
        key = (worker_id, expected_generation)
        leader = False
        with self._lock:
            current = self._require(worker_id)
            if current.generation != expected_generation:
                raise SupervisorError("GENERATION_STALE", "stop targets a stale generation")
            existing = self._stop_ops.get(key)
            if existing is None:
                operation_id = uuid.uuid4().hex
                event = threading.Event()
                self._stop_ops[key] = (operation_id, event)
                self._slots[worker_id] = replace(current, state=STATE_STOPPING)
                leader = True
            else:
                operation_id, event = existing
        if not leader:
            if not event.wait(timeout):
                raise SupervisorError("STOP_JOIN_TIMEOUT", "duplicate stop did not finish within timeout")
            with self._lock:
                done = self._require(worker_id)
                if done.generation != expected_generation or done.last_evidence is None or done.last_evidence.operation_id != operation_id:
                    raise SupervisorError("STOP_EVIDENCE_LOST", "stop completion evidence is unavailable")
                return done.last_evidence

        started = time.time()
        state = STATE_STOP_FAILED
        reason = "stop-failed"
        exit_code = None
        empty = False
        containment = None
        try:
            with self._lock:
                containment = self._containments.get(worker_id)
            if containment is None:
                state, reason = STATE_IDENTITY_LOST, "containment-identity-lost"
            else:
                try:
                    if not containment.terminate(timeout):
                        state, reason = STATE_STOP_FAILED, "containment-survived-stop"
                    else:
                        empty = containment.empty(min(timeout, 5.0))
                        if not empty:
                            state, reason = STATE_STOP_FAILED, "containment-not-empty"
                        else:
                            exit_code = containment.poll()
                            state, reason = STATE_STOPPED, "verified-stopped"
                except SupervisorError as ex:
                    state, reason = STATE_STOP_FAILED, ex.code.lower()
                except Exception:
                    state, reason = STATE_STOP_FAILED, "containment-query-failed"
        finally:
            evidence = Evidence(operation_id, worker_id, expected_generation, state, reason, exit_code, empty, started, time.time())
            with self._lock:
                latest = self._slots.get(worker_id)
                if latest is not None and latest.generation == expected_generation and latest.state == STATE_STOPPING:
                    self._slots[worker_id] = replace(latest, state=state, exit_code=exit_code, last_evidence=evidence)
                op = self._stop_ops.pop(key, None)
                if op:
                    op[1].set()
            return evidence

    def get(self, worker_id: str, *, refresh: bool = False) -> Assignment:
        return self.refresh(worker_id) if refresh else self._require_public(worker_id)

    def _require(self, worker_id: str) -> Assignment:
        value = self._slots.get(worker_id)
        if value is None:
            raise SupervisorError("WORKER_UNKNOWN", "worker is unknown")
        return value

    def _require_public(self, worker_id: str) -> Assignment:
        with self._lock:
            return self._require(worker_id)

    def close(self):
        with self._lock:
            items = list(self._containments.items())
        for worker_id, containment in items:
            try:
                current = self.get(worker_id)
                if current.state != STATE_STOPPED:
                    self.stop(worker_id, current.generation, timeout=2.0)
            except Exception:
                pass
            try:
                containment.close()
            except Exception:
                pass


class _ProcQueryError(RuntimeError):
    """The keeper could not positively prove its owned Linux process set."""


def _proc_query_check(deadline: float, clock) -> None:
    if clock() > deadline:
        raise _ProcQueryError("owned process query deadline exceeded")


def _proc_pid_exists_linux(pid: int, proc_root: Path) -> bool:
    try:
        os.stat(proc_root / str(pid))
        return True
    except FileNotFoundError:
        return False
    except OSError as ex:
        raise _ProcQueryError(f"cannot establish /proc existence for pid {pid}") from ex


def _read_proc_record_linux(pid: int, relative: str, *, proc_root: Path, deadline: float, clock) -> str | None:
    _proc_query_check(deadline, clock)
    path = proc_root / str(pid) / relative
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            raw = handle.read(LINUX_PROC_RECORD_MAX_BYTES + 1)
    except FileNotFoundError:
        if not _proc_pid_exists_linux(pid, proc_root):
            return None
        raise _ProcQueryError(f"owned pid {pid} exists but {relative} is unavailable")
    except (OSError, UnicodeError) as ex:
        if not _proc_pid_exists_linux(pid, proc_root):
            return None
        raise _ProcQueryError(f"owned pid {pid} has unreadable {relative}") from ex
    if len(raw.encode("utf-8", "strict")) > LINUX_PROC_RECORD_MAX_BYTES:
        raise _ProcQueryError(f"owned pid {pid} {relative} exceeds record ceiling")
    _proc_query_check(deadline, clock)
    return raw


def _read_linux_identity(pid: int, *, proc_root: Path, deadline: float, clock) -> tuple[int, int] | None:
    raw = _read_proc_record_linux(pid, "stat", proc_root=proc_root, deadline=deadline, clock=clock)
    if raw is None:
        return None
    close = raw.rfind(")")
    if close < 0:
        raise _ProcQueryError(f"owned pid {pid} has malformed stat record")
    tail = raw[close + 1:].split()
    if len(tail) < 20:
        raise _ProcQueryError(f"owned pid {pid} has truncated stat record")
    try:
        ppid = int(tail[1])
        starttime = int(tail[19])
    except ValueError as ex:
        raise _ProcQueryError(f"owned pid {pid} has malformed process identity") from ex
    if ppid < 0 or starttime <= 0:
        raise _ProcQueryError(f"owned pid {pid} has invalid process identity")
    return ppid, starttime


def _read_linux_ppid(pid: int, *, proc_root: Path, deadline: float, clock) -> int | None:
    identity = _read_linux_identity(pid, proc_root=proc_root, deadline=deadline, clock=clock)
    return None if identity is None else identity[0]


def _read_linux_children(pid: int, *, proc_root: Path, deadline: float, clock) -> tuple[int, ...] | None:
    raw = _read_proc_record_linux(pid, f"task/{pid}/children", proc_root=proc_root, deadline=deadline, clock=clock)
    if raw is None:
        return None
    if not raw.strip():
        return ()
    out: list[int] = []
    seen: set[int] = set()
    for token in raw.split():
        if not token.isdigit():
            raise _ProcQueryError(f"owned pid {pid} has malformed children record")
        child = int(token)
        if child <= 1 or child > 2 ** 31 - 1 or child in seen:
            raise _ProcQueryError(f"owned pid {pid} has invalid children record")
        seen.add(child)
        out.append(child)
    return tuple(out)


def _owned_descendants_linux(keeper_pid: int, root_pid: int, *, proc_root: Path = Path("/proc"),
                             timeout: float = LINUX_QUERY_TIMEOUT_SECONDS,
                             max_records: int = LINUX_MAX_DESCENDANTS,
                             root_known_exited: bool = False, clock=time.monotonic) -> set[int]:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(float(timeout)) or float(timeout) <= 0:
        raise _ProcQueryError("owned process query timeout is invalid")
    if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records <= 0:
        raise _ProcQueryError("owned process record ceiling is invalid")
    proc_root = Path(proc_root)
    deadline = clock() + float(timeout)
    keeper_pid = int(keeper_pid)
    root_pid = int(root_pid)
    owned: set[int] = set()
    frontier: list[int] = [keeper_pid]
    scanned: set[int] = set()
    records = 0
    while frontier:
        _proc_query_check(deadline, clock)
        parent = frontier.pop(0)
        if parent in scanned:
            continue
        scanned.add(parent)
        children = _read_linux_children(parent, proc_root=proc_root, deadline=deadline, clock=clock)
        if children is None:
            if parent == keeper_pid:
                raise _ProcQueryError("keeper proc identity disappeared during query")
            continue
        for child in children:
            _proc_query_check(deadline, clock)
            if child == keeper_pid:
                raise _ProcQueryError("keeper appears in its own child set")
            if child in owned:
                continue
            records += 1
            if records > max_records:
                raise _ProcQueryError("owned process record ceiling exceeded")
            ppid = _read_linux_ppid(child, proc_root=proc_root, deadline=deadline, clock=clock)
            if ppid is None:
                continue
            if ppid not in ({keeper_pid, parent} | owned):
                raise _ProcQueryError(f"owned pid {child} changed to unowned parent {ppid}")
            owned.add(child)
            frontier.append(child)
    if not root_known_exited and root_pid not in owned and _proc_pid_exists_linux(root_pid, proc_root):
        raise _ProcQueryError("worker root exists but is absent from keeper-owned child authority")
    _proc_query_check(deadline, clock)
    return owned


def _reap_linux_children(root_pid: int, root_rc: int | None) -> tuple[int | None, bool]:
    no_children = False
    while True:
        try:
            waited, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            no_children = True
            break
        if waited == 0:
            break
        if waited == root_pid and root_rc is None:
            root_rc = os.waitstatus_to_exitcode(status)
    return root_rc, no_children


def _pidfd_signal_linux(pid: int, expected_starttime: int, sig: int, *, proc_root: Path = Path("/proc"), clock=time.monotonic) -> bool:
    opener = getattr(os, "pidfd_open", None)
    sender = getattr(signal, "pidfd_send_signal", None)
    if not callable(opener) or not callable(sender):
        raise _ProcQueryError("pidfd signaling is unavailable")
    try:
        pidfd = opener(int(pid), 0)
    except ProcessLookupError:
        return False
    except OSError as ex:
        raise _ProcQueryError(f"cannot establish stable pidfd for owned pid {pid}") from ex
    try:
        identity = _read_linux_identity(
            int(pid), proc_root=Path(proc_root),
            deadline=clock() + LINUX_QUERY_TIMEOUT_SECONDS, clock=clock,
        )
        if identity is None:
            return False
        if identity[1] != int(expected_starttime):
            raise _ProcQueryError(f"owned pid {pid} identity changed before pidfd signal")
        try:
            sender(pidfd, sig, None, 0)
        except ProcessLookupError:
            return False
        except OSError as ex:
            raise _ProcQueryError(f"pidfd signal failed for owned pid {pid}") from ex
        return True
    finally:
        try:
            os.close(pidfd)
        except OSError:
            pass


def _keeper_main() -> int:
    if not _linux_subreaper_available():
        print(json.dumps({"ok": False, "error": "subreaper unavailable"}), flush=True)
        return 125
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_CHILD_SUBREAPER = 36
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        print(json.dumps({"ok": False, "error": "prctl subreaper failed"}), flush=True)
        return 125
    try:
        line = sys.stdin.readline()
        if not line:
            raise ValueError("missing keeper launch spec")
        spec = json.loads(line)
        proc = subprocess.Popen(
            spec["argv"], cwd=spec.get("cwd"), env=spec.get("env"),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
        )
    except Exception as ex:
        print(json.dumps({"ok": False, "error": str(ex)}), flush=True)
        return 125
    print(json.dumps({"ok": True, "pid": proc.pid}), flush=True)
    stopping = False

    def request_stop(_sig, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    root_rc: int | None = None
    stop_started: float | None = None
    keeper_pid = os.getpid()
    term_sent: dict[int, int] = {}
    while True:
        if root_rc is None:
            root_rc = proc.poll()
        try:
            owned = _owned_descendants_linux(keeper_pid, proc.pid, root_known_exited=(root_rc is not None))
        except _ProcQueryError:
            time.sleep(0.02)
            continue
        if stopping:
            if stop_started is None:
                stop_started = time.monotonic()
            sig = signal.SIGKILL if time.monotonic() - stop_started >= LINUX_STOP_ESCALATION_SECONDS else signal.SIGTERM
            signal_ambiguous = False
            for pid in sorted(owned, reverse=True):
                try:
                    ident = _read_linux_identity(pid, proc_root=Path("/proc"), deadline=time.monotonic() + LINUX_QUERY_TIMEOUT_SECONDS, clock=time.monotonic)
                except _ProcQueryError:
                    signal_ambiguous = True
                    break
                if ident is None:
                    continue
                starttime = ident[1]
                if sig == signal.SIGTERM and term_sent.get(pid) == starttime:
                    continue
                if sig == signal.SIGTERM and pid not in term_sent and len(term_sent) >= LINUX_MAX_DESCENDANTS:
                    signal_ambiguous = True
                    break
                try:
                    delivered = _pidfd_signal_linux(pid, starttime, sig)
                except _ProcQueryError:
                    signal_ambiguous = True
                    break
                if not delivered:
                    continue
                if sig == signal.SIGTERM:
                    term_sent[pid] = starttime
            if signal_ambiguous:
                time.sleep(0.02)
                continue
        root_rc, no_children = _reap_linux_children(proc.pid, root_rc)
        if root_rc is None:
            root_rc = proc.poll()
        try:
            _owned_descendants_linux(keeper_pid, proc.pid, root_known_exited=(root_rc is not None))
        except _ProcQueryError:
            time.sleep(0.02)
            continue
        if root_rc is not None and no_children:
            if stopping:
                return 75
            if root_rc < 0:
                return min(255, 128 + abs(root_rc))
            return min(125, int(root_rc))
        time.sleep(0.02)


if __name__ == "__main__" and len(sys.argv) == 2 and sys.argv[1] == "--keeper":
    raise SystemExit(_keeper_main())
