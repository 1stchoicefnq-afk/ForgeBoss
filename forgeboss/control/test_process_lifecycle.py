from __future__ import annotations

import signal
import unittest
from unittest.mock import Mock, patch

from forgeboss.control import process_lifecycle as lifecycle


class _Kernel32:
    def __init__(self, *, assign_ok=True, terminate_ok=True, close_ok=True):
        self.assign_ok = assign_ok
        self.terminate_ok = terminate_ok
        self.close_ok = close_ok
        self.closed = []

    def OpenProcess(self, _access, _inherit, _pid):
        return 101

    def CreateJobObjectW(self, _attrs, _name):
        return 202

    def AssignProcessToJobObject(self, _job, _process):
        return self.assign_ok

    def TerminateJobObject(self, _job, _code):
        return self.terminate_ok

    def CloseHandle(self, handle):
        self.closed.append(int(getattr(handle, "value", handle)))
        return self.close_ok


class _WinTypes:
    @staticmethod
    def HANDLE(value):
        return value


class ProcessLifecycleTests(unittest.TestCase):
    def test_rejects_invalid_pid(self):
        with self.assertRaises(lifecycle.ProcessLifecycleError):
            lifecycle._require_pid(0)
        with self.assertRaises(lifecycle.ProcessLifecycleError):
            lifecycle._require_pid(-1)

    def test_windows_job_assignment_is_fail_closed(self):
        kernel = _Kernel32(assign_ok=False)
        with patch.object(lifecycle.os, "name", "nt"), patch.object(
            lifecycle, "_windows_kernel32", return_value=(kernel, _WinTypes)
        ):
            with self.assertRaises(lifecycle.ProcessLifecycleError):
                lifecycle.create_windows_job_for_pid(1234)
        self.assertIn(202, kernel.closed)
        self.assertIn(101, kernel.closed)

    def test_windows_job_assignment_returns_owned_job_handle(self):
        kernel = _Kernel32(assign_ok=True)
        with patch.object(lifecycle.os, "name", "nt"), patch.object(
            lifecycle, "_windows_kernel32", return_value=(kernel, _WinTypes)
        ), patch.object(lifecycle.ctypes, "cast", return_value=Mock(value=202)):
            handle = lifecycle.create_windows_job_for_pid(1234)
        self.assertEqual(handle, 202)
        self.assertIn(101, kernel.closed)
        self.assertNotIn(202, kernel.closed)

    def test_windows_job_termination_has_no_single_pid_fallback(self):
        kernel = _Kernel32(terminate_ok=False)
        with patch.object(lifecycle.os, "name", "nt"), patch.object(
            lifecycle, "_windows_kernel32", return_value=(kernel, _WinTypes)
        ):
            with self.assertRaises(lifecycle.ProcessLifecycleError):
                lifecycle.terminate_windows_job(202)

    def test_posix_group_start_forces_new_session(self):
        fake = Mock(pid=4321)
        with patch.object(lifecycle.os, "name", "posix"), patch.object(
            lifecycle.subprocess, "Popen", return_value=fake
        ) as popen:
            got = lifecycle.start_posix_process_group(["python", "worker.py"], cwd="/tmp")
        self.assertIs(got, fake)
        popen.assert_called_once_with(
            ["python", "worker.py"], cwd="/tmp", start_new_session=True
        )

    def test_posix_group_termination_targets_group(self):
        with patch.object(lifecycle.os, "name", "posix"), patch.object(
            lifecycle.os, "killpg"
        ) as killpg:
            lifecycle.terminate_posix_process_group(4321, signal.SIGTERM)
        killpg.assert_called_once_with(4321, signal.SIGTERM)

    def test_posix_group_termination_rejects_unsafe_group(self):
        with patch.object(lifecycle.os, "name", "posix"):
            with self.assertRaises(lifecycle.ProcessLifecycleError):
                lifecycle.terminate_posix_process_group(1)

    def test_process_group_identity_requires_group_leader(self):
        proc = Mock(pid=4321)
        with patch.object(lifecycle.os, "name", "posix"), patch.object(
            lifecycle.os, "getpgid", return_value=9999
        ):
            with self.assertRaises(lifecycle.ProcessLifecycleError):
                lifecycle.process_group_identity(proc)


if __name__ == "__main__":
    unittest.main()
