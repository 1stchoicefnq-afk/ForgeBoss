from __future__ import annotations

import dataclasses
import errno
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from forgeboss.control.process_supervisor import (
    MAX_TIMEOUT, STATE_COMPLETED, STATE_FAILED, STATE_IDENTITY_LOST, STATE_ORPHANED,
    STATE_RUNNING, STATE_STOPPED, STATE_STOP_FAILED, STATE_STOPPING,
    ContainmentError, Evidence, GenerationConflict, ProcessIdentity, ProcessSupervisor,
    SupervisorError, TimeoutValidationError, UnknownAssignment, validated_timeout,
)

EXE = str(Path(sys.executable).resolve())
ARGS = (EXE, "-c", "import time; time.sleep(60)")
FAST = dict(timeout=0.05, escalation_timeout=0.05, poll_interval=0.005, query_timeout=0.05)


class FakeOwned:
    def __init__(self, pid: int, *, members=None, exit_code=None, identity_valid=True,
                 terminate_error=None, gate=None, spawn_during_terminate=False,
                 query_error=None):
        self.pid = pid
        self.identity = ProcessIdentity(pid, str(1000 + pid), f"/fake/{pid}")
        self._members = set(members if members is not None else {pid})
        self._exit = exit_code
        self._identity_valid = identity_valid
        self.terminate_error = terminate_error
        self.gate = gate
        self.spawn_during_terminate = spawn_during_terminate
        self.query_error = query_error
        self.terminate_calls = 0
        self.close_calls = 0

    def root_exit_code(self):
        return self._exit

    def identity_valid(self):
        return self._identity_valid

    def members(self, query_timeout):
        if self.query_error:
            raise self.query_error
        return tuple(sorted(self._members))

    def empty(self, query_timeout):
        return not self.members(query_timeout)

    def terminate(self, grace, escalation, poll, query_timeout):
        self.terminate_calls += 1
        if self.gate is not None:
            self.gate.entered.set()
            if not self.gate.release.wait(5):
                raise AssertionError("terminate gate not released")
        if self.spawn_during_terminate:
            self._members.add(self.pid + 10000)
        if self.terminate_error is not None:
            ex = self.terminate_error
            self.terminate_error = None
            raise ex
        before = tuple(sorted(self._members))
        self._members.clear()
        if self._exit is None:
            self._exit = -9
        return {"reason": "fake-owned-tree", "membersBefore": before,
                "membersAfter": (), "escalated": self.spawn_during_terminate}

    def close(self):
        self.close_calls += 1


class FakeLauncher:
    def __init__(self, *owned):
        self.queue = list(owned)
        self.calls = []

    def launch(self, argv, cwd, env, launch_timeout):
        self.calls.append((argv, cwd, launch_timeout))
        if not self.queue:
            raise AssertionError("fake launch queue empty")
        return self.queue.pop(0)


class Gate:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()


class Call(threading.Thread):
    def __init__(self, fn, *args, **kwargs):
        super().__init__(daemon=True)
        self.fn, self.args, self.kwargs = fn, args, kwargs
        self.result = None
        self.error = None

    def run(self):
        try:
            self.result = self.fn(*self.args, **self.kwargs)
        except BaseException as ex:
            self.error = ex

    def value(self):
        self.join(10)
        if self.is_alive():
            raise AssertionError("call did not finish")
        if self.error:
            raise self.error
        return self.result


def wait_until(fn, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if fn():
                return True
        except (ContainmentError, OSError):
            pass
        time.sleep(0.02)
    return bool(fn())


class ValidationTests(unittest.TestCase):
    def test_all_nonfinite_nonpositive_unbounded_timings_fail(self):
        bad = (True, False, "1", None, 0, -1, float("nan"), float("inf"), float("-inf"),
               MAX_TIMEOUT + 1)
        for value in bad:
            with self.assertRaises(TimeoutValidationError, msg=repr(value)):
                validated_timeout(value)

    def test_launch_timing_fails_before_launcher_mutation(self):
        launcher = FakeLauncher(FakeOwned(101))
        sup = ProcessSupervisor(launcher)
        for bad in (float("nan"), float("inf"), 0, "1", True):
            with self.assertRaises(TimeoutValidationError):
                sup.launch("w1", ARGS, launch_timeout=bad)
        self.assertEqual(launcher.calls, [])

    def test_stop_timing_and_root_only_downgrade_fail_before_termination(self):
        owned = FakeOwned(101)
        sup = ProcessSupervisor(FakeLauncher(owned))
        sup.launch("w1", ARGS)
        for kwargs in (
            {"timeout": float("nan")}, {"escalation_timeout": float("inf")},
            {"poll_interval": 0}, {"query_timeout": "1"}, {"join_timeout": True},
        ):
            with self.assertRaises(TimeoutValidationError):
                sup.stop("w1", expected_generation=1, **{**FAST, **kwargs})
        with self.assertRaises(SupervisorError) as cm:
            sup.stop("w1", expected_generation=1, include_tree=False, **FAST)
        self.assertEqual(cm.exception.code, "OWNED_TREE_REQUIRED")
        self.assertEqual(owned.terminate_calls, 0)

    def test_register_never_adopts_arbitrary_pid(self):
        sup = ProcessSupervisor(FakeLauncher())
        with self.assertRaises(SupervisorError) as cm:
            sup.register("w1", 1234)
        self.assertEqual(cm.exception.code, "ARGV_INVALID")


class GenerationAndExitTests(unittest.TestCase):
    def test_launch_binds_generation_one(self):
        owned = FakeOwned(101)
        sup = ProcessSupervisor(FakeLauncher(owned))
        view = sup.launch("w1", ARGS, task_id="T1")
        self.assertEqual((view.generation, view.state, view.identity.pid), (1, STATE_RUNNING, 101))
        self.assertEqual(sup.evidence()[0].outcome, "bound")

    def test_reassign_running_is_forbidden_without_launching_new_process(self):
        first, second = FakeOwned(101), FakeOwned(102)
        launcher = FakeLauncher(first, second)
        sup = ProcessSupervisor(launcher)
        sup.launch("w1", ARGS)
        with self.assertRaises(GenerationConflict) as cm:
            sup.reassign("w1", ARGS, expected_generation=1)
        self.assertEqual(cm.exception.code, "SLOT_RUNNING")
        self.assertEqual(len(launcher.calls), 1)

    def test_zero_exit_is_completed_and_verified_empty_before_reassign(self):
        first, second = FakeOwned(101), FakeOwned(102)
        launcher = FakeLauncher(first, second)
        sup = ProcessSupervisor(launcher)
        sup.launch("w1", ARGS)
        first._exit = 0
        first._members.clear()
        self.assertEqual(sup.get("w1").state, STATE_COMPLETED)
        v2 = sup.reassign("w1", ARGS, expected_generation=1)
        self.assertEqual((v2.generation, v2.state), (2, STATE_RUNNING))

    def test_nonzero_exit_is_failed_not_normal_completion(self):
        first, second = FakeOwned(101), FakeOwned(102)
        launcher = FakeLauncher(first, second)
        sup = ProcessSupervisor(launcher)
        sup.launch("w1", ARGS)
        first._exit = 7
        first._members.clear()
        view = sup.get("w1")
        self.assertEqual((view.state, view.exit_code), (STATE_FAILED, 7))
        exits = [e for e in sup.evidence("w1") if e.kind == "exit"]
        self.assertEqual(exits[-1].outcome, "failed")
        self.assertEqual(exits[-1].detail["exitCode"], 7)
        # A failed worker is reusable only after failure was positively observed
        # and the owned containment is proven empty.
        v2 = sup.reassign("w1", ARGS, expected_generation=1)
        self.assertEqual(v2.generation, 2)

    def test_root_exit_with_descendants_is_orphaned_not_reassignable(self):
        first, second = FakeOwned(101, members={102}, exit_code=0), FakeOwned(201)
        sup = ProcessSupervisor(FakeLauncher(first, second))
        sup.launch("w1", ARGS)
        self.assertEqual(sup.get("w1").state, STATE_ORPHANED)
        with self.assertRaises(GenerationConflict) as cm:
            sup.reassign("w1", ARGS, expected_generation=1)
        self.assertEqual(cm.exception.code, "SLOT_RUNNING")
        ev = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(ev.outcome, "stopped")
        self.assertEqual(sup.get("w1").state, STATE_STOPPED)

    def test_identity_lost_cannot_advance_until_owned_containment_stopped(self):
        first, second = FakeOwned(101, identity_valid=False), FakeOwned(102)
        sup = ProcessSupervisor(FakeLauncher(first, second))
        sup.launch("w1", ARGS)
        self.assertEqual(sup.get("w1").state, STATE_IDENTITY_LOST)
        with self.assertRaises(GenerationConflict) as cm:
            sup.reassign("w1", ARGS, expected_generation=1)
        self.assertEqual(cm.exception.code, "IDENTITY_LOST_UNRESOLVED")
        self.assertEqual(sup.stop("w1", expected_generation=1, **FAST).outcome, "stopped")
        self.assertEqual(sup.reassign("w1", ARGS, expected_generation=1).generation, 2)

    def test_generation_mismatch_fails_closed(self):
        owned = FakeOwned(101)
        sup = ProcessSupervisor(FakeLauncher(owned))
        sup.launch("w1", ARGS)
        with self.assertRaises(GenerationConflict):
            sup.stop("w1", expected_generation=2, **FAST)
        with self.assertRaises(GenerationConflict):
            sup.reassign("w1", ARGS, expected_generation=2)


class StopTests(unittest.TestCase):
    def test_duplicate_stop_serializes_and_returns_same_evidence(self):
        gate = Gate()
        owned = FakeOwned(101, gate=gate)
        sup = ProcessSupervisor(FakeLauncher(owned))
        sup.launch("w1", ARGS)
        a = Call(sup.stop, "w1", expected_generation=1, **FAST)
        a.start()
        self.assertTrue(gate.entered.wait(5))
        self.assertEqual(sup.get("w1").state, STATE_STOPPING)
        b = Call(sup.stop, "w1", expected_generation=1, **FAST)
        b.start()
        time.sleep(0.03)
        self.assertTrue(b.is_alive())
        gate.release.set()
        ea, eb = a.value(), b.value()
        self.assertIs(ea, eb)
        self.assertEqual(owned.terminate_calls, 1)
        self.assertEqual(ea.outcome, "stopped")

    def test_stop_vs_reassign_and_register_are_rejected(self):
        gate = Gate()
        first, second = FakeOwned(101, gate=gate), FakeOwned(102)
        launcher = FakeLauncher(first, second)
        sup = ProcessSupervisor(launcher)
        sup.launch("w1", ARGS)
        call = Call(sup.stop, "w1", expected_generation=1, **FAST)
        call.start()
        self.assertTrue(gate.entered.wait(5))
        with self.assertRaises(GenerationConflict) as cm:
            sup.reassign("w1", ARGS, expected_generation=1)
        self.assertEqual(cm.exception.code, "SLOT_STOPPING")
        with self.assertRaises(GenerationConflict):
            sup.register("w1", ARGS, expected_generation=1)
        self.assertEqual(len(launcher.calls), 1)
        gate.release.set()
        call.value()

    def test_stop_failed_blocks_reassign_until_successful_retry(self):
        first = FakeOwned(
            101, terminate_error=ContainmentError("STOP_FAILED", "simulated containment failure"))
        second = FakeOwned(102)
        sup = ProcessSupervisor(FakeLauncher(first, second))
        sup.launch("w1", ARGS)
        with self.assertRaises(ContainmentError):
            sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(sup.get("w1").state, STATE_STOP_FAILED)
        with self.assertRaises(GenerationConflict) as cm:
            sup.reassign("w1", ARGS, expected_generation=1)
        self.assertEqual(cm.exception.code, "STOP_FAILED_UNRESOLVED")
        self.assertEqual(sup.stop("w1", expected_generation=1, **FAST).outcome, "stopped")
        self.assertEqual(sup.reassign("w1", ARGS, expected_generation=1).generation, 2)

    def test_descendant_spawned_during_stop_is_inside_owned_termination(self):
        owned = FakeOwned(101, members={101, 102}, spawn_during_terminate=True)
        sup = ProcessSupervisor(FakeLauncher(owned))
        sup.launch("w1", ARGS)
        ev = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(ev.outcome, "stopped")
        self.assertTrue(ev.detail["escalated"])
        self.assertTrue(owned.empty(0.05))

    def test_query_failure_never_becomes_verified_dead(self):
        owned = FakeOwned(
            101, query_error=ContainmentError("CONTAINMENT_QUERY_TIMEOUT", "simulated"))
        # launch itself must fail closed because it cannot prove owned tree active.
        sup = ProcessSupervisor(FakeLauncher(owned))
        with self.assertRaises(ContainmentError):
            sup.launch("w1", ARGS, query_timeout=0.05)
        with self.assertRaises(UnknownAssignment):
            sup.get("w1")

    def test_evidence_is_immutable(self):
        owned = FakeOwned(101)
        sup = ProcessSupervisor(FakeLauncher(owned))
        sup.launch("w1", ARGS)
        ev = sup.stop("w1", expected_generation=1, **FAST)
        with self.assertRaises(TypeError):
            ev.detail["state"] = "running"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ev.outcome = "forged"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux native containment proof")
class LinuxNativeContainmentTests(unittest.TestCase):
    def test_worker_and_descendants_cannot_escape_owned_process_group(self):
        with tempfile.TemporaryDirectory() as td:
            result = Path(td) / "setsid.txt"
            code = (
                "import errno,os,time,pathlib;"
                f"p=pathlib.Path({str(result)!r});"
                "\ntry:\n os.setsid(); p.write_text('ESCAPED')\n"
                "except OSError as e:\n p.write_text('DENIED:'+str(e.errno))\n"
                "time.sleep(60)"
            )
            sup = ProcessSupervisor()
            view = sup.launch("w1", (EXE, "-c", code), launch_timeout=5)
            self.assertTrue(wait_until(result.exists))
            self.assertEqual(result.read_text(), f"DENIED:{errno.EPERM}")
            ev = sup.stop("w1", expected_generation=view.generation,
                          timeout=0.2, escalation_timeout=1.0,
                          poll_interval=0.01, query_timeout=1.0)
            self.assertEqual(ev.outcome, "stopped")

    def test_root_exit_while_descendant_remains_cannot_be_reassigned(self):
        code = (
            "import subprocess,sys,os;"
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
            "os._exit(0)"
        )
        sup = ProcessSupervisor()
        v1 = sup.launch("w1", (EXE, "-c", code), launch_timeout=5)
        self.assertTrue(wait_until(lambda: sup.get("w1", query_timeout=1).state == STATE_ORPHANED))
        with self.assertRaises(GenerationConflict):
            sup.reassign("w1", ARGS, expected_generation=v1.generation)
        ev = sup.stop("w1", expected_generation=v1.generation,
                      timeout=0.2, escalation_timeout=1.0,
                      poll_interval=0.01, query_timeout=1.0)
        self.assertEqual(ev.outcome, "stopped")

    def test_descendant_spawned_after_sigterm_is_caught_by_group_escalation(self):
        with tempfile.TemporaryDirectory() as td:
            ready = Path(td) / "ready"
            spawned = Path(td) / "spawned"
            code = (
                "import pathlib,signal,subprocess,sys,time;"
                f"ready=pathlib.Path({str(ready)!r});spawned=pathlib.Path({str(spawned)!r});"
                "\ndef h(*a):\n"
                " subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);spawned.write_text('yes')\n"
                "signal.signal(signal.SIGTERM,h);ready.write_text('yes')\n"
                "while True: time.sleep(1)"
            )
            sup = ProcessSupervisor()
            v = sup.launch("w1", (EXE, "-c", code), launch_timeout=5)
            self.assertTrue(wait_until(ready.exists))
            ev = sup.stop("w1", expected_generation=v.generation,
                          timeout=0.2, escalation_timeout=1.0,
                          poll_interval=0.01, query_timeout=1.0)
            self.assertTrue(spawned.exists(), "SIGTERM handler did not spawn the late descendant")
            self.assertEqual(ev.outcome, "stopped")
            self.assertTrue(ev.detail["escalated"])


@unittest.skipUnless(os.name == "nt", "native Windows Job Object proof")
class WindowsNativeContainmentTests(unittest.TestCase):
    def test_job_owns_and_terminates_full_tree(self):
        code = (
            "import subprocess,sys,time;"
            "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
            "time.sleep(60)"
        )
        sup = ProcessSupervisor()
        v = sup.launch("w1", (EXE, "-c", code), launch_timeout=10)
        ev = sup.stop("w1", expected_generation=v.generation,
                      timeout=0.2, escalation_timeout=3.0,
                      poll_interval=0.02, query_timeout=1.0)
        self.assertEqual(ev.outcome, "stopped")
        self.assertTrue(ev.detail["escalated"])

    def test_child_breakaway_attempt_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            result = Path(td) / "breakaway.txt"
            code = (
                "import pathlib,subprocess,sys,time;"
                f"p=pathlib.Path({str(result)!r});"
                "\ntry:\n"
                " q=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
                "creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB);p.write_text('ESCAPED:'+str(q.pid))\n"
                "except OSError as e:\n p.write_text('DENIED:'+str(getattr(e,'winerror',None)))\n"
                "time.sleep(60)"
            )
            sup = ProcessSupervisor()
            v = sup.launch("w1", (EXE, "-c", code), launch_timeout=10)
            self.assertTrue(wait_until(result.exists, 10))
            self.assertTrue(result.read_text().startswith("DENIED:"), result.read_text())
            sup.stop("w1", expected_generation=v.generation,
                     timeout=0.2, escalation_timeout=3.0,
                     poll_interval=0.02, query_timeout=1.0)

    def test_nonzero_exit_is_not_reported_as_completion(self):
        sup = ProcessSupervisor()
        sup.launch("w1", (EXE, "-c", "raise SystemExit(7)"), launch_timeout=10)
        self.assertTrue(wait_until(lambda: sup.get("w1").state == STATE_FAILED, 10))
        view = sup.get("w1")
        self.assertEqual(view.exit_code, 7)

    def test_system_directory_comes_from_native_api_not_environment(self):
        from forgeboss.control.process_supervisor_windows import WindowsOwnedProcess
        old = os.environ.get("SystemRoot")
        os.environ["SystemRoot"] = r"C:\attacker-controlled"
        try:
            path = WindowsOwnedProcess.native_system_directory()
        finally:
            if old is None:
                os.environ.pop("SystemRoot", None)
            else:
                os.environ["SystemRoot"] = old
        self.assertNotIn("attacker-controlled", path.lower())
        self.assertTrue(path.lower().endswith(r"\system32"))


if __name__ == "__main__":
    unittest.main()
