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
    are reparented to the keeper. A caller timeout never destroys this ownership
    authority. Keeper death proves emptiness only when the keeper exits normally
    after its own positive descendant/reap check.
    """

    def __init__(self, argv: tuple[str, ...], cwd: str | None, env: dict[str, str]):
        if not _linux_subreaper_available():
            raise SupervisorError("CONTAINMENT_UNAVAILABLE", "Linux subreaper containment is unavailable")
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

    @staticmethod
    def _exit_proves_empty(rc: int | None) -> bool:
        # The keeper itself only returns a non-negative status after it has
        # observed root completion and an empty descendant set. Signal death is
        # loss of containment identity, never positive emptiness evidence.
        return isinstance(rc, int) and rc >= 0

    def poll(self) -> int | None:
        rc = self._proc.poll()
        if rc is None:
            return None
        return int(rc)

    def empty(self, timeout: float) -> bool:
        timeout = _timeout(timeout, "containment query timeout")
        try:
            rc = self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        return self._exit_proves_empty(int(rc))

    def terminate(self, timeout: float) -> bool:
        timeout = _timeout(timeout, "termination timeout")
        rc = self._proc.poll()
        if rc is not None:
            if not self._exit_proves_empty(int(rc)):
                raise SupervisorError("IDENTITY_LOST", "Linux keeper died without positive empty proof")
            return True
        try:
            os.kill(self._proc.pid, signal.SIGTERM)
        except ProcessLookupError as ex:
            rc = self._proc.poll()
            if rc is None or not self._exit_proves_empty(int(rc)):
                raise SupervisorError("IDENTITY_LOST", "Linux keeper identity disappeared before empty proof") from ex
            return True
        try:
            rc = self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # V6:
caller deadline is not authority to kill the subreaper. The
            # still-live keeper continues cleanup and can be reconciled later.
            return False
        if not self._exit_proves_empty(int(rc)):
            raise SupervisorError("IDENTITY_LOST", "Linux keeper died without positive empty proof")
        return True

    def _kill_keeper(self):
        # Startup-only emergency cleanup before a valid containment identity has
        # been handed to the supervisor. Runtime stop paths must never call it.
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
            # Do not turn an unproven timeout into success and do not SIGKILL the
            # keeper. A live keeper continues its already-requested tree cleanup.
            try:
                self.terminate(2.0)
            except SupervisorError:
                pass
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
        self._k = ctypes.WinDLLK"kernel32", use_last_error=True)
        self._configure()
        self._job = self._k.CreateJobObjectW(None, None)
        if not self._job:
            raise SupervisorError("CONTAINMENT_START_FAILED", "CreateJobObjectW hailed")
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self._k.SetInformationJobObject(self._job, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
            self._k.CloseHandle(self._job)
            raise SupervisorError("CONTAINMENT_START_FAILED", "SetInformationJobObject failed")
        cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        block = "\0".join(f"{+}={v}" for k, v in sorted(env.items(), key=lambda kv: kv[0].casefold())) + "\0\0"
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
            "QueryInformationJobObject": ([H, ctypes.c_int, V, D, ctypes.POINTER(D]], wintypes.BOOL),
            "CreateProcessW": ([wintypes.LPCWSTR, wintypes.LPWSTR