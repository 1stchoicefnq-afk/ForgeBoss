from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence


class SupervisorError(RuntimeError):
    pass


@dataclass(frozen=True)
class SupervisedResult:
    exit_code: int | None
    revoked: bool
    escalated: bool
    quarantined: bool
    tree_terminated: bool
    reason: str
    pid: int
    started_at: float
    finished_at: float

    def as_dict(self) -> dict:
        return {
            "exitCode": self.exit_code,
            "revoked": self.revoked,
            "escalated": self.escalated,
            "quarantined": self.quarantined,
            "treeTerminated": self.tree_terminated,
            "reason": self.reason,
            "pid": self.pid,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
        }


def _posix_group_alive(pgid: int) -> bool:
    proc = "/proc"
    if os.path.isdir(proc):
        saw_group = False
        try:
            for name in os.listdir(proc):
                if not name.isdigit():
                    continue
                try:
                    with open(os.path.join(proc, name, "stat"), "r", encoding="utf-8") as fh:
                        raw = fh.read()
                    tail = raw[raw.rfind(")") + 2:].split()
                    state = tail[0]
                    process_group = int(tail[2])
                except (OSError, ValueError, IndexError):
                    continue
                if process_group == int(pgid):
                    saw_group = True
                    if state != "Z":
                        return True
            if saw_group:
                return False
        except OSError:
            pass
    try:
        os.killpg(int(pgid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait_until(predicate: Callable[[], bool], timeout: float, poll: float = 0.02) -> bool:
    end = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(max(0.005, float(poll)))
    return predicate()


def _configure_windows_api(kernel, ctypes, wintypes) -> None:
    kernel.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateJobObject.restype = wintypes.BOOL
    kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryInformationJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

class _WindowsJob:
    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes
        self.ctypes = ctypes
        self.wintypes = wintypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        _configure_windows_api(self.kernel, ctypes, wintypes)
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise SupervisorError("cannot create Windows Job Object")

        class BASIC(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]
        class IO(ctypes.Structure):
            _fields_ = [("ReadOperationCount", ctypes.c_uint64), ("WriteOperationCount", ctypes.c_uint64),
                        ("OtherOperationCount", ctypes.c_uint64), ("ReadTransferCount", ctypes.c_uint64),
                        ("WriteTransferCount", ctypes.c_uint64), ("OtherTransferCount", ctypes.c_uint64)]
        class EXT(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]
        info = EXT(); info.BasicLimitInformation.LimitFlags = 0x00002000
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            self.close(); raise SupervisorError("cannot configure Windows Job Object")

    def assign(self, pid: int) -> None:
        h = self.kernel.OpenProcess(0x0100 | 0x0001 | 0x1000, False, int(pid))
        if not h: raise SupervisorError("cannot open child process for Job Object assignment")
        try:
            if not self.kernel.AssignProcessToJobObject(self.handle, h):
                raise SupervisorError("cannot assign child process to Windows Job Object")
        finally: self.kernel.CloseHandle(h)

    def terminate(self, code: int = 75) -> None:
        if self.handle and not self.kernel.TerminateJobObject(self.handle, int(code)):
            raise SupervisorError("Windows Job Object termination failed")

    def empty(self) -> bool:
        import ctypes
        from ctypes import wintypes
        class A(ctypes.Structure):
            _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                        ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                        ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                        ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD)]
        info = A(); ret = wintypes.DWORD()
        if not self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(ret)):
            raise SupervisorError("cannot query Windows Job Object")
        return int(info.ActiveProcesses) == 0

    def close(self) -> None:
        if getattr(self, "handle", None):
            self.kernel.CloseHandle(self.handle); self.handle = None


def run_supervised(argv: Sequence[str], authority_check: Callable[[], bool], *, cwd=None,
                   env: Mapping[str, str] | None = None, poll_seconds: float = 0.10,
                   terminate_grace_seconds: float = 2.0, max_runtime_seconds: float | None = None) -> SupervisedResult:
    if not argv or any(not isinstance(x, str) or not x for x in argv):
        raise ValueError("argv must be a non-empty sequence of non-empty strings")
    if not os.path.isabs(argv[0]):
        raise ValueError("argv[0] must be an explicit absolute executable path")
    if not callable(authority_check): raise TypeError("authority_check must be callable")
    poll_seconds=float(poll_seconds); terminate_grace_seconds=float(terminate_grace_seconds)
    if poll_seconds <= 0 or terminate_grace_seconds < 0: raise ValueError("supervisor timing values are invalid")
    if max_runtime_seconds is not None and float(max_runtime_seconds) <= 0: raise ValueError("max_runtime_seconds must be positive")
    try:
        if authority_check() is not True: raise SupervisorError("paid worker authority is not active")
    except SupervisorError: raise
    except Exception as ex: raise SupervisorError("paid worker authority check failed before launch") from ex

    started=time.time(); job=None
    target_env = dict(env) if env is not None else dict(os.environ)
    target_cwd = os.fspath(cwd) if cwd is not None else None
    if target_cwd is not None and not os.path.isabs(target_cwd):
        raise ValueError("cwd must be absolute")
    if os.name == "nt":
        # Start only a trusted stdin-gated bootstrap. It cannot execute/spawn the paid
        # command until after the process is bound to the Job Object.
        proc=subprocess.Popen([sys.executable,"-m","forgeboss.executors.supervisor_child"],
                              cwd=None,env=dict(os.environ),stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              text=True,shell=False,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        pgid=None
    else:
        proc=subprocess.Popen(list(argv),cwd=target_cwd,env=target_env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              text=True,shell=False,start_new_session=True)
        pgid=proc.pid
    try:
        if os.name == "nt":
            job=_WindowsJob()
            try:
                job.assign(proc.pid)
                try:
                    if authority_check() is not True:
                        raise SupervisorError("paid worker authority revoked before gated launch")
                except SupervisorError:
                    raise
                except Exception as ex:
                    raise SupervisorError("paid worker authority check failed before gated launch") from ex
                payload={"argv":list(argv),"cwd":target_cwd,"env":target_env}
                proc.stdin.write(json.dumps(payload,separators=(",",":"))+"\n")
                proc.stdin.flush(); proc.stdin.close()
            except Exception:
                try: job.terminate(75)
                except Exception: pass
                try: proc.kill()
                except Exception: pass
                try: proc.wait(timeout=2)
                except Exception: pass
                job.close(); raise
        revoked=False; escalated=False; quarantined=False; reason="completed"
        deadline=None if max_runtime_seconds is None else time.monotonic()+float(max_runtime_seconds)
        while True:
            rc=proc.poll(); tree_alive=(not job.empty()) if os.name == "nt" else _posix_group_alive(int(pgid))
            if rc is not None:
                if not tree_alive: break
                quarantined=True; revoked=True; reason="orphan-descendant"; break
            if deadline is not None and time.monotonic() >= deadline:
                quarantined=True; revoked=True; reason="runtime-limit"; break
            try: active=authority_check() is True
            except Exception: active=False; reason="authority-check-failed"
            if not active:
                quarantined=True; revoked=True
                if reason == "completed": reason="authority-revoked"
                break
            time.sleep(poll_seconds)
        if revoked:
            if os.name == "nt":
                job.terminate(75)
                if not _wait_until(job.empty,terminate_grace_seconds,poll_seconds):
                    raise SupervisorError("Windows Job Object still contains live processes after termination")
            else:
                try: os.killpg(int(pgid),signal.SIGTERM)
                except ProcessLookupError: pass
                if not _wait_until(lambda:not _posix_group_alive(int(pgid)),terminate_grace_seconds,poll_seconds):
                    escalated=True
                    try: os.killpg(int(pgid),signal.SIGKILL)
                    except ProcessLookupError: pass
                    if not _wait_until(lambda:not _posix_group_alive(int(pgid)),max(1.0,terminate_grace_seconds),poll_seconds):
                        raise SupervisorError("POSIX process group survived SIGKILL")
            try: proc.wait(timeout=max(1.0,terminate_grace_seconds))
            except subprocess.TimeoutExpired as ex: raise SupervisorError("supervised process leader did not exit") from ex
        rc=proc.poll(); tree_terminated=job.empty() if os.name=="nt" else not _posix_group_alive(int(pgid))
        if not tree_terminated: quarantined=True; reason="tree-still-live"
        return SupervisedResult(rc,revoked,escalated,quarantined,tree_terminated,reason,int(proc.pid),started,time.time())
    finally:
        if job is not None: job.close()
