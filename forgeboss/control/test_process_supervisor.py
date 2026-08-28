"""FB-052 tests for forgeboss.control.process_supervisor.

Process operations are contained: every supervision test drives a fully
in-memory fake process world, and the platform layers are exercised through
injected runners/`/proc` fixtures so that no real system process outside this
test's own disposable child is ever signalled.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from forgeboss.control.process_supervisor import (
    EVIDENCE_SCHEMA,
    REJECT_FUTURE_GENERATION,
    REJECT_STALE_GENERATION,
    REJECT_UNKNOWN_ASSIGNMENT,
    STATE_ALREADY_EXITED,
    STATE_IDENTITY_MISMATCH,
    STATE_REGISTERED,
    STATE_STOPPED_FORCED,
    STATE_STOPPED_GRACEFUL,
    STATE_STOP_FAILED,
    PosixPlatform,
    ProcessPlatform,
    ProcessSupervisor,
    ReassignmentBlockedError,
    RegistrationError,
    WindowsPlatform,
    ancestors_of,
    descendants,
    posix_identity_command,
    posix_snapshot_command,
    windows_identity_command,
    windows_kill_command,
    windows_snapshot_command,
)


# ---------------------------------------------------------------------------
# In-memory process world
# ---------------------------------------------------------------------------

class FakeProc:
    def __init__(self, pid, ppid, token, ignore_graceful=False, ignore_force=False):
        self.pid = pid
        self.ppid = ppid
        self.token = token
        self.alive = True
        self.ignore_graceful = ignore_graceful
        self.ignore_force = ignore_force


class FakeWorld:
    """A tiny process table. Nothing here touches the real OS."""

    def __init__(self):
        self.procs = {}
        self.spawn(1, 0, "tok-init")

    def spawn(self, pid, ppid, token=None, ignore_graceful=False, ignore_force=False):
        proc = FakeProc(pid, ppid, token or ("tok-%d" % pid),
                        ignore_graceful, ignore_force)
        self.procs[pid] = proc
        return proc

    def exit(self, pid):
        if pid in self.procs:
            self.procs[pid].alive = False
            for other in self.procs.values():  # orphans reparent to init
                if other.alive and other.ppid == pid:
                    other.ppid = 1

    def recycle(self, pid, ppid=1, token=None):
        """Simulate PID reuse: same PID, brand new process instance."""
        self.procs[pid] = FakeProc(pid, ppid, token or ("tok-%d-reused" % pid))

    def snapshot(self):
        return {p.pid: p.ppid for p in self.procs.values() if p.alive}

    def alive_pids(self):
        return sorted(p.pid for p in self.procs.values() if p.alive)


class FakePlatform(ProcessPlatform):
    name = "fake"

    def __init__(self, world):
        self.world = world
        self.snapshot_calls = 0

    def snapshot_command(self):
        return ["fake-ps", "--pid-ppid"]

    def snapshot(self):
        self.snapshot_calls += 1
        return self.world.snapshot()

    def instance_token(self, pid):
        proc = self.world.procs.get(int(pid))
        return proc.token if proc is not None and proc.alive else None

    def is_alive(self, pid):
        proc = self.world.procs.get(int(pid))
        return bool(proc is not None and proc.alive)

    def signal_process(self, pid, force):
        cmd = ["fake-kill", str(int(pid)), "FORCE" if force else "TERM"]
        proc = self.world.procs.get(int(pid))
        if proc is None or not proc.alive:
            return {"pid": int(pid), "command": cmd, "delivered": False,
                    "error": "no_such_process"}
        ignores = proc.ignore_force if force else proc.ignore_graceful
        if not ignores:
            self.world.exit(int(pid))
        return {"pid": int(pid), "command": cmd, "delivered": True, "error": None}

    def signal_tree_backstop(self, root_pid, force):
        cmd = ["fake-killtree", str(int(root_pid)), "FORCE" if force else "TERM"]
        return {"pid": int(root_pid), "command": cmd, "delivered": True, "error": None}


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = float(start)

    def monotonic(self):
        return self.now

    def wall(self):
        return 1_700_000_000.0 + (self.now - 1000.0)

    def sleep(self, seconds):
        self.now += max(float(seconds), 0.001)


class SupervisorFixture(unittest.TestCase):
    """Shared world: supervisor pid 500, worker tree 900 -> 901 -> 902."""

    SELF_PID = 500

    def setUp(self):
        self.world = FakeWorld()
        self.world.spawn(400, 1, "tok-runner")            # supervisor's parent
        self.world.spawn(self.SELF_PID, 400, "tok-self")  # the supervisor itself
        self.world.spawn(700, 1, "tok-unrelated")         # unrelated tree
        self.world.spawn(701, 700, "tok-unrelated-child")
        self.world.spawn(501, self.SELF_PID, "tok-sibling")  # sibling worker
        self.world.spawn(900, self.SELF_PID, "tok-worker")
        self.world.spawn(901, 900, "tok-child")
        self.world.spawn(902, 901, "tok-grandchild")
        self.platform = FakePlatform(self.world)
        self.clock = FakeClock()
        self.ids = iter("ev%02d" % i for i in range(100))
        self.sup = ProcessSupervisor(
            platform=self.platform,
            clock=self.clock.monotonic,
            wall_clock=self.clock.wall,
            sleep=self.clock.sleep,
            grace_seconds=1.0,
            poll_seconds=0.05,
            self_pid=self.SELF_PID,
            evidence_ids=lambda: next(self.ids),
        )

    def register_worker(self, pid=900, generation=1, run_id="run-1"):
        return self.sup.register("task-1", run_id, pid, generation=generation)

    def signalled(self, evidence, force=None):
        out = []
        for record in evidence.signals:
            if record.get("backstop"):
                continue
            if force is None or (record["command"][-1] == ("FORCE" if force else "TERM")):
                out.append(record["pid"])
        return out


# ---------------------------------------------------------------------------
# Registration & identity
# ---------------------------------------------------------------------------

class RegistrationTests(SupervisorFixture):
    def test_register_captures_identity_and_metadata(self):
        assignment = self.sup.register("task-1", "run-1", 900, command_hint="agent run")
        self.assertEqual(assignment.task_id, "task-1")
        self.assertEqual(assignment.run_id, "run-1")
        self.assertEqual(assignment.generation, 1)
        self.assertEqual(assignment.identity.pid, 900)
        self.assertEqual(assignment.identity.start_token, "tok-worker")
        self.assertEqual(assignment.identity.command_hint, "agent run")
        self.assertEqual(assignment.state, STATE_REGISTERED)
        self.assertFalse(assignment.terminal)
        self.assertIs(self.sup.current("task-1"), assignment)

    def test_register_refuses_pid_1_and_self(self):
        with self.assertRaises(RegistrationError):
            self.sup.register("task-x", "run", 1)
        with self.assertRaises(RegistrationError):
            self.sup.register("task-y", "run", 0)
        with self.assertRaises(RegistrationError):
            self.sup.register("task-z", "run", self.SELF_PID)

    def test_register_refuses_pid_without_resolvable_instance_token(self):
        with self.assertRaises(RegistrationError):
            self.sup.register("task-1", "run-1", 4242)

    def test_register_blocked_while_generation_live(self):
        self.register_worker()
        with self.assertRaises(ReassignmentBlockedError):
            self.sup.register("task-1", "run-2", 901)
        self.assertEqual(self.sup.current("task-1").run_id, "run-1")


# ---------------------------------------------------------------------------
# Stop semantics
# ---------------------------------------------------------------------------

class NormalStopTests(SupervisorFixture):
    def test_normal_stop_is_graceful_and_terminal(self):
        self.register_worker()
        evidence = self.sup.stop("task-1", 1)
        self.assertTrue(evidence.accepted)
        self.assertIsNone(evidence.rejection)
        self.assertEqual(evidence.terminal_state, STATE_STOPPED_GRACEFUL)
        self.assertTrue(evidence.terminal)
        self.assertEqual(evidence.forced_signalled, [])
        self.assertEqual(evidence.survivors, [])
        self.assertEqual(self.sup.current("task-1").state, STATE_STOPPED_GRACEFUL)
        self.assertFalse(self.world.procs[900].alive)

    def test_normal_stop_signals_root_first_then_shallow_to_deep(self):
        self.register_worker()
        evidence = self.sup.stop("task-1", 1)
        self.assertEqual(self.signalled(evidence, force=False), [900, 901, 902])

    def test_evidence_object_is_deterministic_and_json_safe(self):
        self.register_worker()
        payload = self.sup.stop("task-1", 1).to_dict()
        json.dumps(payload)  # must not raise
        self.assertEqual(payload["schema"], EVIDENCE_SCHEMA)
        self.assertEqual(payload["evidenceId"], "ev00")
        self.assertEqual(payload["taskId"], "task-1")
        self.assertEqual(payload["runId"], "run-1")
        self.assertEqual(payload["generation"], 1)
        self.assertEqual(payload["platform"], "fake")
        self.assertEqual(payload["rootPid"], 900)
        self.assertEqual(payload["treePids"], [900, 901, 902])
        self.assertEqual(payload["gracefulSignalled"], [900, 901, 902])
        self.assertEqual(payload["expectedToken"], "tok-worker")
        self.assertEqual(payload["observedToken"], "tok-worker")
        self.assertEqual(payload["identityChecks"][0]["match"], True)
        self.assertEqual(payload["commands"][0], ["fake-ps", "--pid-ppid"])
        self.assertIn(["fake-kill", "902", "TERM"], payload["commands"])

    def test_process_group_owner_gets_tree_backstop(self):
        self.sup.register("task-1", "run-1", 900, owns_process_group=True)
        evidence = self.sup.stop("task-1", 1)
        backstops = [r for r in evidence.signals if r.get("backstop")]
        self.assertEqual([r["command"] for r in backstops],
                         [["fake-killtree", "900", "TERM"]])

    def test_no_backstop_when_group_not_owned(self):
        self.register_worker()
        evidence = self.sup.stop("task-1", 1)
        self.assertEqual([r for r in evidence.signals if r.get("backstop")], [])


class GraceExpiryTests(SupervisorFixture):
    def test_hung_worker_escalates_to_hard_kill_after_grace(self):
        self.world.procs[900].ignore_graceful = True
        self.world.procs[901].ignore_graceful = True
        self.world.procs[902].ignore_graceful = True
        self.register_worker()
        started = self.clock.now

        evidence = self.sup.stop("task-1", 1, grace_seconds=2.0)

        self.assertEqual(evidence.terminal_state, STATE_STOPPED_FORCED)
        self.assertEqual(evidence.graceful_signalled, [900, 901, 902])
        self.assertEqual(evidence.forced_signalled, [900, 901, 902])
        self.assertEqual(evidence.survivors, [])
        self.assertGreaterEqual(self.clock.now - started, 2.0)
        self.assertGreaterEqual(evidence.grace_elapsed, 2.0)
        self.assertEqual(self.world.alive_pids(), [1, 400, 500, 501, 700, 701])

    def test_force_phase_is_deepest_first(self):
        for pid in (900, 901, 902):
            self.world.procs[pid].ignore_graceful = True
        self.register_worker()
        evidence = self.sup.stop("task-1", 1, grace_seconds=0.5)
        self.assertEqual(self.signalled(evidence, force=True), [902, 901, 900])

    def test_grace_zero_still_checks_liveness_once_before_forcing(self):
        self.register_worker()
        evidence = self.sup.stop("task-1", 1, grace_seconds=0.0)
        # Everything died on TERM, so the single pre-deadline check succeeds.
        self.assertEqual(evidence.terminal_state, STATE_STOPPED_GRACEFUL)
        self.assertEqual(evidence.forced_signalled, [])

    def test_children_spawned_during_grace_are_still_killed(self):
        self.world.procs[900].ignore_graceful = True
        self.register_worker()

        original_is_alive = self.platform.is_alive
        state = {"spawned": False}

        def spawning_is_alive(pid):
            if not state["spawned"]:
                state["spawned"] = True
                self.world.spawn(950, 900, "tok-late-child")
            return original_is_alive(pid)

        self.platform.is_alive = spawning_is_alive
        evidence = self.sup.stop("task-1", 1, grace_seconds=0.3)

        self.assertIn(950, evidence.tree_pids)
        self.assertIn(950, evidence.forced_signalled)
        self.assertNotIn(950, evidence.graceful_signalled)
        self.assertFalse(self.world.procs[950].alive)

    def test_descendants_orphaned_during_grace_are_still_force_killed(self):
        # 901 dies on TERM, so 902 reparents to init and leaves the live tree.
        # It was captured in the first snapshot, so it must still be killed.
        self.world.procs[900].ignore_graceful = True
        self.world.procs[902].ignore_graceful = True
        self.register_worker()

        evidence = self.sup.stop("task-1", 1, grace_seconds=0.3)

        self.assertEqual(self.world.procs[902].ppid, 1)
        self.assertIn(902, evidence.tree_pids)
        self.assertIn(902, evidence.forced_signalled)
        self.assertEqual(evidence.terminal_state, STATE_STOPPED_FORCED)
        self.assertEqual(evidence.survivors, [])

    def test_unkillable_worker_is_stop_failed_and_blocks_reassignment(self):
        self.world.procs[900].ignore_graceful = True
        self.world.procs[900].ignore_force = True
        self.register_worker()

        evidence = self.sup.stop("task-1", 1, grace_seconds=0.2)

        self.assertEqual(evidence.terminal_state, STATE_STOP_FAILED)
        self.assertFalse(evidence.terminal)
        self.assertEqual(evidence.survivors, [900])
        self.assertIsNone(self.sup.evidence_for("task-1", 1))
        with self.assertRaises(ReassignmentBlockedError):
            self.sup.reassign("task-1", "run-2", 501)

    def test_stop_failed_can_be_retried(self):
        self.world.procs[900].ignore_graceful = True
        self.world.procs[900].ignore_force = True
        self.register_worker()
        self.assertEqual(self.sup.stop("task-1", 1, grace_seconds=0.2).terminal_state,
                         STATE_STOP_FAILED)
        self.world.procs[900].ignore_force = False
        retry = self.sup.stop("task-1", 1, grace_seconds=0.2)
        self.assertEqual(retry.terminal_state, STATE_STOPPED_FORCED)
        self.assertNotEqual(retry.evidence_id, "ev00")


class DescendantTerminationTests(SupervisorFixture):
    def test_full_owned_tree_is_terminated_not_just_direct_child(self):
        self.register_worker()
        evidence = self.sup.stop("task-1", 1)
        self.assertEqual(evidence.tree_pids, [900, 901, 902])
        self.assertFalse(self.world.procs[901].alive)
        self.assertFalse(self.world.procs[902].alive)

    def test_descendants_walk_is_breadth_first_and_cycle_safe(self):
        snapshot = {10: 1, 11: 10, 12: 10, 13: 11, 20: 1, 30: 30, 40: 41, 41: 40}
        self.assertEqual(descendants(snapshot, 10), [(1, 11), (1, 12), (2, 13)])
        self.assertEqual(descendants(snapshot, 20), [])
        self.assertEqual(descendants(snapshot, 30), [])
        self.assertEqual(descendants(snapshot, 40), [(1, 41)])

    def test_ancestor_chain_is_cycle_safe(self):
        self.assertEqual(ancestors_of({5: 4, 4: 3, 3: 1, 1: 0}, 5), [4, 3, 1, 0])
        self.assertEqual(ancestors_of({5: 4, 4: 5}, 5), [4])


class UnrelatedProcessProtectionTests(SupervisorFixture):
    def test_only_the_owned_subtree_is_signalled(self):
        self.register_worker()
        evidence = self.sup.stop("task-1", 1)
        self.assertEqual(sorted({r["pid"] for r in evidence.signals}), [900, 901, 902])
        for pid in (1, 400, 500, 501, 700, 701):
            self.assertTrue(self.world.procs[pid].alive, "pid %d was killed" % pid)

    def test_unrelated_tree_never_enters_target_set(self):
        self.register_worker()
        evidence = self.sup.stop("task-1", 1)
        self.assertNotIn(700, evidence.tree_pids)
        self.assertNotIn(701, evidence.tree_pids)
        self.assertNotIn(501, evidence.tree_pids)

    def test_supervisor_and_its_ancestors_are_protected(self):
        self.register_worker()
        evidence = self.sup.stop("task-1", 1)
        for pid in (0, 1, 400, self.SELF_PID):
            self.assertIn(pid, evidence.protected_pids)

    def test_root_that_is_an_ancestor_of_the_supervisor_fails_closed(self):
        # Pathological topology: the supervisor is itself inside the "worker"
        # tree. Nothing may be signalled.
        world = FakeWorld()
        world.spawn(900, 1, "tok-worker")
        world.spawn(901, 900, "tok-child")
        world.spawn(500, 901, "tok-self")
        platform = FakePlatform(world)
        clock = FakeClock()
        sup = ProcessSupervisor(platform=platform, clock=clock.monotonic,
                                wall_clock=clock.wall, sleep=clock.sleep,
                                grace_seconds=0.2, self_pid=500)
        sup.register("task-1", "run-1", 900)

        evidence = sup.stop("task-1", 1)

        self.assertEqual(evidence.terminal_state, STATE_STOP_FAILED)
        self.assertEqual(evidence.signals, [])
        self.assertEqual(world.alive_pids(), [1, 500, 900, 901])


class IdentityTests(SupervisorFixture):
    def test_already_exited_worker_is_terminal_without_signals(self):
        self.register_worker()
        self.world.exit(900)
        evidence = self.sup.stop("task-1", 1)
        self.assertEqual(evidence.terminal_state, STATE_ALREADY_EXITED)
        self.assertTrue(evidence.terminal)
        self.assertEqual(evidence.signals, [])
        self.assertEqual(evidence.commands, [])
        self.assertIsNone(evidence.observed_token)

    def test_pid_reuse_is_rejected_and_nothing_is_signalled(self):
        self.register_worker()
        self.world.exit(900)
        self.world.recycle(900, ppid=1, token="tok-somebody-else")

        evidence = self.sup.stop("task-1", 1)

        self.assertEqual(evidence.terminal_state, STATE_IDENTITY_MISMATCH)
        self.assertEqual(evidence.signals, [])
        self.assertEqual(evidence.observed_token, "tok-somebody-else")
        self.assertEqual(evidence.identity_checks[0]["match"], False)
        self.assertTrue(self.world.procs[900].alive, "recycled pid was killed")

    def test_identity_is_checked_before_the_process_snapshot(self):
        self.register_worker()
        self.world.recycle(900, ppid=1, token="tok-somebody-else")
        self.sup.stop("task-1", 1)
        self.assertEqual(self.platform.snapshot_calls, 0)


class GenerationTests(SupervisorFixture):
    def test_stale_generation_stop_is_rejected_without_signals(self):
        self.register_worker()
        self.sup.stop("task-1", 1)
        self.sup.reassign("task-1", "run-2", 501)
        self.assertEqual(self.sup.current("task-1").generation, 2)

        stale = self.sup.stop("task-1", 1, grace_seconds=5.0)

        # Generation 1 already stopped, so this replays recorded evidence.
        self.assertEqual(stale.generation, 1)
        self.assertEqual(stale.terminal_state, STATE_STOPPED_GRACEFUL)
        self.assertTrue(self.world.procs[501].alive)
        self.assertEqual(self.sup.current("task-1").state, STATE_REGISTERED)

    def test_stale_generation_never_seen_is_rejected(self):
        self.register_worker(generation=7)
        rejection = self.sup.stop("task-1", 3)
        self.assertFalse(rejection.accepted)
        self.assertEqual(rejection.rejection, REJECT_STALE_GENERATION)
        self.assertIsNone(rejection.terminal_state)
        self.assertEqual(rejection.signals, [])
        self.assertTrue(self.world.procs[900].alive)

    def test_future_generation_is_rejected(self):
        self.register_worker()
        rejection = self.sup.stop("task-1", 99)
        self.assertFalse(rejection.accepted)
        self.assertEqual(rejection.rejection, REJECT_FUTURE_GENERATION)
        self.assertTrue(self.world.procs[900].alive)

    def test_unknown_task_is_rejected(self):
        rejection = self.sup.stop("task-nope", 1)
        self.assertFalse(rejection.accepted)
        self.assertEqual(rejection.rejection, REJECT_UNKNOWN_ASSIGNMENT)
        self.assertEqual(rejection.signals, [])

    def test_duplicate_stop_replays_evidence_without_resignalling(self):
        self.register_worker()
        first = self.sup.stop("task-1", 1)
        snapshot_calls = self.platform.snapshot_calls

        second = self.sup.stop("task-1", 1)
        third = self.sup.stop("task-1", 1)

        self.assertIs(first, second)
        self.assertIs(first, third)
        self.assertEqual(second.evidence_id, first.evidence_id)
        self.assertEqual(self.platform.snapshot_calls, snapshot_calls)
        self.assertEqual(len(second.signals), len(first.signals))

    def test_duplicate_stop_of_old_generation_after_reassignment(self):
        self.register_worker()
        first = self.sup.stop("task-1", 1)
        self.sup.reassign("task-1", "run-2", 501)
        again = self.sup.stop("task-1", 1)
        self.assertIs(again, first)
        self.assertTrue(self.world.procs[501].alive)


class ReassignmentTests(SupervisorFixture):
    def test_reassignment_blocked_until_old_generation_is_terminal(self):
        self.register_worker()
        with self.assertRaises(ReassignmentBlockedError):
            self.sup.reassign("task-1", "run-2", 501)
        self.assertEqual(self.sup.current("task-1").generation, 1)
        self.assertEqual(self.sup.current("task-1").run_id, "run-1")

    def test_reassignment_after_verified_stop_bumps_generation(self):
        self.register_worker()
        self.sup.stop("task-1", 1)

        assignment = self.sup.reassign("task-1", "run-2", 501)

        self.assertEqual(assignment.generation, 2)
        self.assertEqual(assignment.run_id, "run-2")
        self.assertEqual(assignment.identity.pid, 501)
        self.assertEqual(assignment.identity.start_token, "tok-sibling")
        self.assertEqual(assignment.state, STATE_REGISTERED)

    def test_reassignment_allowed_after_already_exited(self):
        self.register_worker()
        self.world.exit(900)
        self.sup.stop("task-1", 1)
        self.assertEqual(self.sup.reassign("task-1", "run-2", 501).generation, 2)

    def test_reassignment_allowed_after_identity_mismatch(self):
        self.register_worker()
        self.world.recycle(900, ppid=1, token="tok-other")
        self.assertEqual(self.sup.stop("task-1", 1).terminal_state,
                         STATE_IDENTITY_MISMATCH)
        self.assertEqual(self.sup.reassign("task-1", "run-2", 501).generation, 2)

    def test_reassignment_generation_must_increase(self):
        self.register_worker(generation=4)
        self.sup.stop("task-1", 4)
        with self.assertRaises(ReassignmentBlockedError):
            self.sup.reassign("task-1", "run-2", 501, generation=4)
        with self.assertRaises(ReassignmentBlockedError):
            self.sup.reassign("task-1", "run-2", 501, generation=2)
        self.assertEqual(self.sup.reassign("task-1", "run-2", 501, generation=9).generation, 9)

    def test_new_generation_is_the_only_stoppable_one(self):
        self.register_worker()
        self.sup.stop("task-1", 1)
        self.sup.reassign("task-1", "run-2", 501)
        evidence = self.sup.stop("task-1", 2)
        self.assertEqual(evidence.terminal_state, STATE_STOPPED_GRACEFUL)
        self.assertEqual(evidence.run_id, "run-2")
        self.assertFalse(self.world.procs[501].alive)

    def test_register_after_terminal_state_delegates_to_reassign(self):
        self.register_worker()
        self.sup.stop("task-1", 1)
        assignment = self.sup.register("task-1", "run-2", 501)
        self.assertEqual(assignment.generation, 2)

    def test_tasks_are_independent(self):
        self.register_worker()
        self.sup.register("task-2", "run-a", 700)
        self.sup.stop("task-1", 1)
        self.assertTrue(self.world.procs[700].alive)
        self.assertEqual(self.sup.current("task-2").state, STATE_REGISTERED)


# ---------------------------------------------------------------------------
# Platform abstraction: command/argument construction
# ---------------------------------------------------------------------------

class CommandConstructionTests(unittest.TestCase):
    def test_posix_commands(self):
        self.assertEqual(posix_snapshot_command(), ["ps", "-A", "-o", "pid=,ppid="])
        self.assertEqual(posix_identity_command(4321),
                         ["ps", "-o", "lstart=,comm=", "-p", "4321"])

    def test_windows_snapshot_command(self):
        cmd = windows_snapshot_command()
        self.assertEqual(cmd[:4],
                         ["powershell", "-NoProfile", "-NonInteractive", "-Command"])
        self.assertIn("Get-CimInstance Win32_Process", cmd[4])
        self.assertIn("$_.ParentProcessId", cmd[4])

    def test_windows_identity_command_embeds_pid_filter(self):
        cmd = windows_identity_command(4321)
        self.assertEqual(cmd[:4],
                         ["powershell", "-NoProfile", "-NonInteractive", "-Command"])
        self.assertIn("ProcessId = 4321", cmd[4])
        self.assertIn("CreationDate", cmd[4])
        self.assertIn("'{0}|{1}'", cmd[4])

    def test_windows_kill_command_flags(self):
        self.assertEqual(windows_kill_command(77, force=False, tree=False),
                         ["taskkill", "/PID", "77"])
        self.assertEqual(windows_kill_command(77, force=True, tree=False),
                         ["taskkill", "/PID", "77", "/F"])
        self.assertEqual(windows_kill_command(77, force=False, tree=True),
                         ["taskkill", "/PID", "77", "/T"])
        self.assertEqual(windows_kill_command(77, force=True, tree=True),
                         ["taskkill", "/PID", "77", "/T", "/F"])


class RecordingRunner:
    def __init__(self, responses=None, default=(1, "")):
        self.responses = responses or {}
        self.default = default
        self.calls = []

    def __call__(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        for key, value in self.responses.items():
            if key in " ".join(argv):
                return value
        return self.default


class WindowsPlatformTests(unittest.TestCase):
    def test_snapshot_parses_pid_ppid_lines(self):
        runner = RecordingRunner({"Get-CimInstance Win32_Process |":
                                  (0, "4 0\r\n1000 4\r\n1001 1000\r\nbad line\r\n")})
        self.assertEqual(WindowsPlatform(runner=runner).snapshot(),
                         {4: 0, 1000: 4, 1001: 1000})

    def test_snapshot_returns_empty_on_failure(self):
        self.assertEqual(WindowsPlatform(runner=RecordingRunner(default=(1, ""))).snapshot(), {})

    def test_instance_token_uses_creation_date(self):
        runner = RecordingRunner({"ProcessId = 1000":
                                  (0, "1000|2026-08-28T04:00:00.1234567Z\r\n")})
        platform = WindowsPlatform(runner=runner)
        self.assertEqual(platform.instance_token(1000),
                         "created:2026-08-28T04:00:00.1234567Z")
        self.assertTrue(platform.is_alive(1000))

    def test_instance_token_none_when_process_absent(self):
        platform = WindowsPlatform(runner=RecordingRunner(default=(0, "")))
        self.assertIsNone(platform.instance_token(1000))
        self.assertFalse(platform.is_alive(1000))

    def test_instance_token_none_when_reported_pid_differs(self):
        runner = RecordingRunner(default=(0, "1001|2026-08-28T04:00:00Z"))
        self.assertIsNone(WindowsPlatform(runner=runner).instance_token(1000))

    def test_signal_process_builds_taskkill_argv(self):
        runner = RecordingRunner(default=(0, ""))
        platform = WindowsPlatform(runner=runner)
        graceful = platform.signal_process(1000, force=False)
        forced = platform.signal_process(1000, force=True)
        backstop = platform.signal_tree_backstop(1000, force=True)
        self.assertEqual(graceful["command"], ["taskkill", "/PID", "1000"])
        self.assertEqual(forced["command"], ["taskkill", "/PID", "1000", "/F"])
        self.assertEqual(backstop["command"], ["taskkill", "/PID", "1000", "/T", "/F"])
        self.assertTrue(all(r["delivered"] for r in (graceful, forced, backstop)))
        self.assertEqual(runner.calls[0], ["taskkill", "/PID", "1000"])

    def test_signal_process_reports_taskkill_failure(self):
        platform = WindowsPlatform(runner=RecordingRunner(default=(128, "")))
        record = platform.signal_process(1000, force=True)
        self.assertFalse(record["delivered"])
        self.assertEqual(record["error"], "taskkill_rc_128")


class PosixPlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.proc_root = Path(self.temp) / "proc"
        self.proc_root.mkdir()

    def write_stat(self, pid, state="S", starttime="998877", comm="my (weird) cmd"):
        fields = [state] + [str(i) for i in range(1, 19)] + [starttime]
        (self.proc_root / str(pid)).mkdir(exist_ok=True)
        (self.proc_root / str(pid) / "stat").write_text(
            "%d (%s) %s\n" % (pid, comm, " ".join(fields))
        )

    def platform(self, runner=None, killer=None, group_killer=None, proc_root=None):
        return PosixPlatform(
            runner=runner or RecordingRunner(default=(1, "")),
            proc_root=self.proc_root if proc_root is None else proc_root,
            killer=killer,
            group_killer=group_killer,
        )

    def test_instance_token_from_proc_starttime_with_awkward_comm(self):
        self.write_stat(1234)
        self.assertEqual(self.platform().instance_token(1234), "starttime:998877")

    def test_zombie_is_not_a_live_instance(self):
        self.write_stat(1234, state="Z")
        platform = self.platform()
        self.assertIsNone(platform.instance_token(1234))
        self.assertFalse(platform.is_alive(1234))

    def test_missing_proc_entry_is_dead(self):
        platform = self.platform()
        self.assertIsNone(platform.instance_token(1234))
        self.assertFalse(platform.is_alive(1234))

    def test_ps_fallback_when_proc_unavailable(self):
        runner = RecordingRunner(default=(0, "Fri Aug 28 04:00:00 2026   python3\n"))
        platform = self.platform(runner=runner, proc_root=None)
        self.assertEqual(platform.instance_token(1234),
                         "ps:Fri Aug 28 04:00:00 2026 python3")
        self.assertEqual(runner.calls[0],
                         ["ps", "-o", "lstart=,comm=", "-p", "1234"])

    def test_ps_fallback_reports_dead_on_nonzero_exit(self):
        platform = self.platform(runner=RecordingRunner(default=(1, "")), proc_root=None)
        self.assertIsNone(platform.instance_token(1234))

    def test_snapshot_parses_ps_table(self):
        runner = RecordingRunner({"ps -A": (0, "    1     0\n  900     1\n 901   900\n")})
        platform = self.platform(runner=runner)
        self.assertEqual(platform.snapshot(), {1: 0, 900: 1, 901: 900})
        self.assertEqual(runner.calls[0], posix_snapshot_command())
        self.assertEqual(platform.snapshot_command(), posix_snapshot_command())

    def test_signal_process_uses_sigterm_then_sigkill(self):
        sent = []
        platform = self.platform(killer=lambda pid, sig: sent.append((pid, sig)))
        graceful = platform.signal_process(900, force=False)
        forced = platform.signal_process(900, force=True)
        self.assertEqual(graceful["command"], ["os.kill", "900", "SIGTERM"])
        self.assertEqual(forced["command"], ["os.kill", "900", "SIGKILL"])
        self.assertTrue(graceful["delivered"] and forced["delivered"])
        self.assertEqual([s for _, s in sent],
                         [signal_sigterm(), signal_sigkill()])

    def test_signal_process_maps_errors(self):
        def missing(pid, sig):
            raise ProcessLookupError()

        def denied(pid, sig):
            raise PermissionError()

        self.assertEqual(self.platform(killer=missing).signal_process(900, False)["error"],
                         "no_such_process")
        self.assertEqual(self.platform(killer=denied).signal_process(900, False)["error"],
                         "permission_denied")

    def test_group_backstop_refuses_non_leader(self):
        calls = []
        platform = self.platform(group_killer=lambda pgid, sig: calls.append(pgid))
        with mock.patch.object(os, "getpgid", return_value=4242):
            record = platform.signal_tree_backstop(900, force=False)
        self.assertFalse(record["delivered"])
        self.assertEqual(record["error"], "not_group_leader")
        self.assertEqual(calls, [])

    def test_group_backstop_signals_group_leader(self):
        calls = []
        platform = self.platform(group_killer=lambda pgid, sig: calls.append((pgid, sig)))
        with mock.patch.object(os, "getpgid", return_value=900):
            record = platform.signal_tree_backstop(900, force=True)
        self.assertTrue(record["delivered"])
        self.assertEqual(record["command"], ["os.killpg", "900", "SIGKILL"])
        self.assertEqual(calls, [(900, signal_sigkill())])

    def test_group_backstop_reports_missing_process(self):
        platform = self.platform(group_killer=lambda pgid, sig: None)
        with mock.patch.object(os, "getpgid", side_effect=ProcessLookupError()):
            record = platform.signal_tree_backstop(900, force=False)
        self.assertFalse(record["delivered"])
        self.assertEqual(record["error"], "ProcessLookupError")

    def test_group_backstop_reports_unavailable(self):
        platform = PosixPlatform(runner=RecordingRunner(), proc_root=self.proc_root,
                                 group_killer=False)
        platform._group_killer = None
        record = platform.signal_tree_backstop(900, force=True)
        self.assertFalse(record["delivered"])
        self.assertEqual(record["error"], "killpg_unavailable")
        self.assertEqual(record["command"], ["os.killpg", "900", "SIGKILL"])


def signal_sigterm():
    import signal

    return signal.SIGTERM


def signal_sigkill():
    import signal

    return getattr(signal, "SIGKILL", signal.SIGTERM)


# ---------------------------------------------------------------------------
# Contained integration: one disposable child spawned by this test process
# ---------------------------------------------------------------------------

CHILD_SOURCE = (
    "import subprocess, sys, time\n"
    "grand = subprocess.Popen([sys.executable, '-c',\n"
    "    'import time\\nwhile True: time.sleep(0.05)'])\n"
    "sys.stdout.write(str(grand.pid) + '\\n')\n"
    "sys.stdout.flush()\n"
    "while True: time.sleep(0.05)\n"
)


@unittest.skipUnless(os.name == "posix", "POSIX-only integration test")
@unittest.skipUnless(os.path.isdir("/proc"), "requires procfs")
@unittest.skipUnless(shutil.which("ps"), "requires ps")
class DisposableChildIntegrationTests(unittest.TestCase):
    """Stops a throwaway process tree owned by this test process only."""

    def setUp(self):
        self.child = subprocess.Popen(
            [sys.executable, "-c", CHILD_SOURCE],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        self.addCleanup(self._cleanup)
        line = self.child.stdout.readline().strip()
        self.assertTrue(line.isdigit(), "child did not report its grandchild pid")
        self.grandchild_pid = int(line)

    def _cleanup(self):
        for pid in (getattr(self, "grandchild_pid", None), self.child.pid):
            if not pid:
                continue
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        try:
            self.child.wait(timeout=5)
        except Exception:
            pass
        if self.child.stdout:
            self.child.stdout.close()

    def test_stops_real_child_and_grandchild(self):
        platform = PosixPlatform()
        sup = ProcessSupervisor(platform=platform, grace_seconds=5.0, poll_seconds=0.02)
        assignment = sup.register("task-int", "run-int", self.child.pid)
        self.assertTrue(assignment.identity.start_token.startswith("starttime:"))

        evidence = sup.stop("task-int", 1)

        self.assertTrue(evidence.accepted, evidence.notes)
        self.assertIn(evidence.terminal_state,
                      (STATE_STOPPED_GRACEFUL, STATE_STOPPED_FORCED))
        self.assertIn(self.child.pid, evidence.tree_pids)
        self.assertIn(self.grandchild_pid, evidence.tree_pids)
        self.assertIn(self.child.pid, evidence.graceful_signalled)
        self.assertIn(self.grandchild_pid, evidence.graceful_signalled)
        self.assertEqual(evidence.survivors, [])
        self.assertNotIn(os.getpid(), evidence.tree_pids)
        self.assertIn(os.getpid(), evidence.protected_pids)

        self.child.wait(timeout=5)
        self.assertFalse(platform.is_alive(self.grandchild_pid))

    def test_stop_after_child_already_exited(self):
        sup = ProcessSupervisor(grace_seconds=5.0, poll_seconds=0.02)
        sup.register("task-int", "run-int", self.child.pid)
        os.kill(self.grandchild_pid, 9)
        self.child.kill()
        self.child.wait(timeout=5)

        evidence = sup.stop("task-int", 1)

        self.assertEqual(evidence.terminal_state, STATE_ALREADY_EXITED)
        self.assertEqual(evidence.signals, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
