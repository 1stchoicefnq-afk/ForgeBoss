"""Native Windows owned-process containment for FB-052 Supervisor V5."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Mapping

from .process_supervisor import ContainmentError, ProcessIdentity

CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_NO_WINDOW = 0x08000000
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
STILL_ACTIVE = 259
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
PROCESS_TERMINATE = 0x0001


def _environment_block(env: Mapping[str, str]) -> str:
    seen = set()
    items = []
    for k, v in env.items():
        if (not isinstance(k, str) or not k or "=" in k or "\x00" in k
                or not isinstance(v, str) or "\x00" in v):
            raise ContainmentError("ENV_INVALID", "invalid Windows environment")
        folded = k.casefold()
        if folded in seen:
            raise ContainmentError("ENV_INVALID", "case-colliding Windows environment keys")
        seen.add(folded)
        items.append((k, v))
    items.sort(key=lambda item: item[0].casefold())
    return "".join(f"{k}={v}\x00" for k, v in items) + "\x00"


class WindowsOwnedProcess:
    @classmethod
    def launch(cls, argv: tuple[str, ...], cwd: str | None, env: dict[str, str],
               launch_timeout: float) -> "WindowsOwnedProcess":
        if os.name != "nt":
            raise ContainmentError("CONTAINMENT_UNAVAILABLE", "Windows Job containment requires Windows")
        return cls(argv, cwd, env, launch_timeout)

    def __init__(self, argv: tuple[str, ...], cwd: str | None,
                 env: dict[str, str], launch_timeout: float):
        import ctypes
        from ctypes import wintypes as W

        self.ctypes = ctypes
        self.W = W
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [
                ("cb", W.DWORD), ("lpReserved", W.LPWSTR), ("lpDesktop", W.LPWSTR),
                ("lpTitle", W.LPWSTR), ("dwX", W.DWORD), ("dwY", W.DWORD),
                ("dwXSize", W.DWORD), ("dwYSize", W.DWORD),
                ("dwXCountChars", W.DWORD), ("dwYCountChars", W.DWORD),
                ("dwFillAttribute", W.DWORD), ("dwFlags", W.DWORD),
                ("wShowWindow", W.WORD), ("cbReserved2", W.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
                ("hStdInput", W.HANDLE), ("hStdOutput", W.HANDLE), ("hStdError", W.HANDLE),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", W.HANDLE), ("hThread", W.HANDLE),
                ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64), ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64), ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64), ("OtherTransferCount", ctypes.c_uint64),
            ]

        class BASIC_LIMIT(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", W.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", W.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", W.DWORD),
                ("SchedulingClass", W.DWORD),
            ]

        class EXTENDED_LIMIT(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC_LIMIT),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class BASIC_ACCOUNTING(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                ("TotalPageFaultCount", W.DWORD), ("TotalProcesses", W.DWORD),
                ("ActiveProcesses", W.DWORD), ("TotalTerminatedProcesses", W.DWORD),
            ]

        self.STARTUPINFOW = STARTUPINFOW
        self.PROCESS_INFORMATION = PROCESS_INFORMATION
        self.EXTENDED_LIMIT = EXTENDED_LIMIT
        self.BASIC_ACCOUNTING = BASIC_ACCOUNTING
        self._configure_api()

        self.job = self.kernel.CreateJobObjectW(None, None)
        if not self.job:
            self._raise_last("CreateJobObjectW failed")
        self.process = None
        self.thread = None
        try:
            limits = EXTENDED_LIMIT()
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if limits.BasicLimitInformation.LimitFlags & (
                    JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK):
                raise ContainmentError("BREAKAWAY_POLICY_INVALID", "Job Object breakaway must remain disabled")
            if not self.kernel.SetInformationJobObject(
                    self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                self._raise_last("SetInformationJobObject failed")

            cmd = ctypes.create_unicode_buffer(__import__("subprocess").list2cmdline(list(argv)))
            env_block = ctypes.create_unicode_buffer(_environment_block(env))
            si = STARTUPINFOW()
            si.cb = ctypes.sizeof(si)
            pi = PROCESS_INFORMATION()
            flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
            # Deliberately no CREATE_BREAKAWAY_FROM_JOB.
            ok = self.kernel.CreateProcessW(
                str(argv[0]), cmd, None, None, False, flags,
                ctypes.cast(env_block, W.LPVOID), cwd, ctypes.byref(si), ctypes.byref(pi))
            if not ok:
                self._raise_last("CreateProcessW(CREATE_SUSPENDED) failed")
            self.process, self.thread = pi.hProcess, pi.hThread
            self.pid = int(pi.dwProcessId)

            if not self.kernel.AssignProcessToJobObject(self.job, self.process):
                self._raise_last("AssignProcessToJobObject failed")

            self.identity = self._identity_from_handle()
            if self.kernel.ResumeThread(self.thread) == 0xFFFFFFFF:
                self._raise_last("ResumeThread failed")

            # The first bounded job query proves our assigned child is visible to
            # the Job Object before launch is returned as trusted.
            deadline = time.monotonic() + launch_timeout
            while time.monotonic() < deadline:
                if self._active_processes() >= 1:
                    break
                if self.root_exit_code() is not None:
                    raise ContainmentError(
                        "LAUNCH_FAILED", f"worker exited during launch with {self.root_exit_code()}")
                time.sleep(0.005)
            else:
                raise ContainmentError("LAUNCH_TIMEOUT", "Job Object did not report active worker")
        except BaseException:
            try:
                if self.job:
                    self.kernel.TerminateJobObject(self.job, 0xC000013A)
            except BaseException:
                pass
            self.close()
            raise

    def _configure_api(self) -> None:
        c, W, k = self.ctypes, self.W, self.kernel
        V, D, H = W.LPVOID, W.DWORD, W.HANDLE
        specs = {
            "CreateJobObjectW": ([V, W.LPCWSTR], H),
            "SetInformationJobObject": ([H, c.c_int, V, D], W.BOOL),
            "AssignProcessToJobObject": ([H, H], W.BOOL),
            "TerminateJobObject": ([H, W.UINT], W.BOOL),
            "QueryInformationJobObject": ([H, c.c_int, V, D, c.POINTER(D)], W.BOOL),
            "CreateProcessW": ([W.LPCWSTR, W.LPWSTR, V, V, W.BOOL, D, V, W.LPCWSTR, V, V], W.BOOL),
            "ResumeThread": ([H], D),
            "WaitForSingleObject": ([H, D], D),
            "GetExitCodeProcess": ([H, c.POINTER(D)], W.BOOL),
            "GetProcessTimes": ([H, V, V, V, V], W.BOOL),
            "QueryFullProcessImageNameW": ([H, D, W.LPWSTR, c.POINTER(D)], W.BOOL),
            "CloseHandle": ([H], W.BOOL),
            "GetSystemDirectoryW": ([W.LPWSTR, W.UINT], W.UINT),
        }
        for name, (args, restype) in specs.items():
            fn = getattr(k, name)
            fn.argtypes = args
            fn.restype = restype

    def _raise_last(self, message: str):
        code = self.ctypes.get_last_error()
        raise ContainmentError("WINDOWS_API_FAILED", f"{message} (WinError {code})")

    def _identity_from_handle(self) -> ProcessIdentity:
        c, W = self.ctypes, self.W
        creation = W.FILETIME()
        exit_time = W.FILETIME()
        kernel_time = W.FILETIME()
        user_time = W.FILETIME()
        if not self.kernel.GetProcessTimes(
                self.process, c.byref(creation), c.byref(exit_time),
                c.byref(kernel_time), c.byref(user_time)):
            self._raise_last("GetProcessTimes failed")
        ticks = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
        size = W.DWORD(32768)
        buf = c.create_unicode_buffer(size.value)
        if not self.kernel.QueryFullProcessImageNameW(self.process, 0, buf, c.byref(size)):
            self._raise_last("QueryFullProcessImageNameW failed")
        image = str(Path(buf.value).resolve())
        return ProcessIdentity(self.pid, str(ticks), image)

    @classmethod
    def native_system_directory(cls) -> str:
        if os.name != "nt":
            raise ContainmentError("CONTAINMENT_UNAVAILABLE", "Windows API unavailable")
        import ctypes
        from ctypes import wintypes as W
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetSystemDirectoryW.argtypes = [W.LPWSTR, W.UINT]
        kernel.GetSystemDirectoryW.restype = W.UINT
        buf = ctypes.create_unicode_buffer(32768)
        size = kernel.GetSystemDirectoryW(buf, len(buf))
        if size <= 0 or size >= len(buf):
            raise ContainmentError("WINDOWS_API_FAILED", "GetSystemDirectoryW failed")
        return str(Path(buf.value).resolve())

    def _active_processes(self) -> int:
        info = self.BASIC_ACCOUNTING()
        returned = self.W.DWORD(0)
        if not self.kernel.QueryInformationJobObject(
                self.job, 1, self.ctypes.byref(info), self.ctypes.sizeof(info),
                self.ctypes.byref(returned)):
            self._raise_last("QueryInformationJobObject failed")
        return int(info.ActiveProcesses)

    def root_exit_code(self) -> int | None:
        code = self.W.DWORD(0)
        if not self.kernel.GetExitCodeProcess(self.process, self.ctypes.byref(code)):
            self._raise_last("GetExitCodeProcess failed")
        return None if int(code.value) == STILL_ACTIVE else int(code.value)

    def identity_valid(self) -> bool:
        if self.root_exit_code() is not None:
            return True
        try:
            current = self._identity_from_handle()
        except ContainmentError:
            return False
        return current.pid == self.identity.pid and current.start_token == self.identity.start_token and current.image == self.identity.image

    def members(self, query_timeout: float) -> tuple[int, ...]:
        # Job query is a synchronous kernel call, not a worker-controlled command.
        active = self._active_processes()
        # Individual PIDs are intentionally not enumerated or used as stop authority.
        return tuple(range(active))

    def empty(self, query_timeout: float) -> bool:
        return self._active_processes() == 0

    def terminate(self, grace: float, escalation: float, poll: float,
                  query_timeout: float) -> Mapping[str, Any]:
        before = self._active_processes()
        if before == 0:
            return {"reason": "already-empty", "escalated": False, "activeBefore": 0}
        # Windows has no safe generic graceful signal for arbitrary no-console
        # worker trees. Job termination is the owned-tree primitive.
        if not self.kernel.TerminateJobObject(self.job, 0xC000013A):
            self._raise_last("TerminateJobObject failed")
        deadline = time.monotonic() + escalation
        while time.monotonic() < deadline:
            active = self._active_processes()
            if active == 0:
                return {"reason": "job-terminated", "escalated": True,
                        "activeBefore": before, "activeAfter": 0}
            time.sleep(min(poll, max(0.001, deadline - time.monotonic())))
        active = self._active_processes()
        if active:
            raise ContainmentError("STOP_FAILED", f"Windows Job still has {active} active processes")
        return {"reason": "job-terminated", "escalated": True,
                "activeBefore": before, "activeAfter": 0}

    def close(self) -> None:
        for attr in ("thread", "process", "job"):
            handle = getattr(self, attr, None)
            if handle:
                try:
                    self.kernel.CloseHandle(handle)
                except BaseException:
                    pass
                setattr(self, attr, None)
