from __future__ import annotations

import ctypes
import os
import signal
import subprocess
from dataclasses import dataclass


class ProcessLifecycleError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    process_group_id: int | None = None
    job_handle_value: int | None = None


def _require_pid(pid: int) -> int:
    value = int(pid)
    if value <= 0:
        raise ProcessLifecycleError("invalid process pid")
    return value


def _windows_kernel32():
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    return kernel32, wintypes


def create_windows_job_for_pid(pid: int) -> int:
    """Create a Job Object, assign the exact live process, and return an owned HANDLE value.

    The caller owns the returned handle and must eventually call close_windows_job().
    This helper deliberately does not fall back to single-PID termination because Stage-1
    stop/reassign requires process-tree termination.
    """

    if os.name != "nt":
        raise ProcessLifecycleError("Windows Job Objects are unavailable on this platform")
    pid = _require_pid(pid)
    kernel32, _ = _windows_kernel32()
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    process = kernel32.OpenProcess(
        PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid,
    )
    if not process:
        raise ProcessLifecycleError(f"cannot open process {pid}: winerror={ctypes.get_last_error()}")
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        kernel32.CloseHandle(process)
        raise ProcessLifecycleError(f"cannot create Job Object: winerror={ctypes.get_last_error()}")
    try:
        if not kernel32.AssignProcessToJobObject(job, process):
            raise ProcessLifecycleError(
                f"cannot assign process {pid} to Job Object: winerror={ctypes.get_last_error()}"
            )
        return int(ctypes.cast(job, ctypes.c_void_p).value)
    except Exception:
        kernel32.CloseHandle(job)
        raise
    finally:
        kernel32.CloseHandle(process)


def terminate_windows_job(job_handle_value: int, exit_code: int = 1) -> None:
    if os.name != "nt":
        raise ProcessLifecycleError("Windows Job Objects are unavailable on this platform")
    value = int(job_handle_value)
    if value <= 0:
        raise ProcessLifecycleError("invalid Job Object handle")
    kernel32, wintypes = _windows_kernel32()
    handle = wintypes.HANDLE(value)
    if not kernel32.TerminateJobObject(handle, int(exit_code) & 0xFFFFFFFF):
        raise ProcessLifecycleError(f"TerminateJobObject failed: winerror={ctypes.get_last_error()}")


def close_windows_job(job_handle_value: int) -> None:
    if os.name != "nt":
        raise ProcessLifecycleError("Windows Job Objects are unavailable on this platform")
    value = int(job_handle_value)
    if value <= 0:
        raise ProcessLifecycleError("invalid Job Object handle")
    kernel32, wintypes = _windows_kernel32()
    if not kernel32.CloseHandle(wintypes.HANDLE(value)):
        raise ProcessLifecycleError(f"CloseHandle failed: winerror={ctypes.get_last_error()}")


def start_posix_process_group(argv: list[str], **kwargs) -> subprocess.Popen:
    """Start a subprocess in a fresh POSIX session/process group."""

    if os.name == "nt":
        raise ProcessLifecycleError("POSIX process groups are unavailable on Windows")
    if not argv or not all(isinstance(x, str) and x for x in argv):
        raise ProcessLifecycleError("argv must be a non-empty string list")
    if "start_new_session" in kwargs:
        raise ProcessLifecycleError("start_new_session is controlled by ForgeBoss")
    return subprocess.Popen(argv, start_new_session=True, **kwargs)


def terminate_posix_process_group(pgid: int, sig: int = signal.SIGTERM) -> None:
    if os.name == "nt":
        raise ProcessLifecycleError("POSIX process groups are unavailable on Windows")
    group = int(pgid)
    if group <= 1:
        raise ProcessLifecycleError("refusing unsafe process-group id")
    try:
        os.killpg(group, sig)
    except ProcessLookupError:
        return
    except PermissionError as ex:
        raise ProcessLifecycleError("permission denied terminating process group") from ex


def process_group_identity(proc: subprocess.Popen) -> ProcessIdentity:
    pid = _require_pid(proc.pid)
    if os.name == "nt":
        return ProcessIdentity(pid=pid)
    try:
        pgid = os.getpgid(pid)
    except ProcessLookupError as ex:
        raise ProcessLifecycleError("process exited before group identity could be captured") from ex
    if pgid != pid:
        raise ProcessLifecycleError("process is not leader of its ForgeBoss-owned process group")
    return ProcessIdentity(pid=pid, process_group_id=pgid)
