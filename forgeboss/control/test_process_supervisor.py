"""Hostile tests for the generation-bound process supervisor.

The concurrency tests are deterministic: the fake process control blocks inside
`signal` on an explicit gate, so a racing caller is guaranteed to observe the
slot mid-stop rather than depending on thread scheduling.
"""
from __future__ import annotations

import dataclasses
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from forgeboss.control.process_supervisor import (
    MAX_TIMEOUT, STATE_IDENTITY_LOST, STATE_RUNNING, STATE_STOPPED,
    STATE_STOP_FAILED, STATE_STOPPING, AssignmentView, Evidence, GenerationConflict,
    NativeToolResolver, ProcProbe, ProcessIdentity, ProcessIdentityError, ProcessSupervisor,
    SupervisorError, TimeoutValidationError, ToolResolutionError, TopologyError,
    UnknownAssignment, WindowsProcessControl, validated_timeout,
)

BOOT = "11111111-2222-3333-4444-555555555555"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeProcess:
    def __init__(self, pid, ppid=7, start_ticks=1000, image="/opt/worker", alive=True,
                 resists_term=False, resists_kill=False):
        self.pid = pid
        self.ppid = ppid
        self.start_ticks = start_ticks
        self.image = image
        self.alive = alive
        self.resists_term = resists_term
        self.resists_kill = resists_kill


class FakeProbe:
    """Deterministic identity/topology source with injectable failures."""

    def __init__(self, processes=(), boot_id=BOOT):
        self.boot = boot_id
        self.procs = {p.pid: p for p in processes}
        self.identity_failures = {}   # pid -> (code, message)
        self.topology_failures = {}   # pid -> message
        self.lock = threading.RLock()
        self.identity_calls = []

    def add(self, proc):
        with self.lock:
            self.procs[proc.pid] = proc
        return proc

    def boot_id(self):
        return self.boot

    def identity(self, pid):
        with self.lock:
            self.identity_calls.append(pid)
            if pid in self.identity_failures:
                code, message = self.identity_failures[pid]
                raise ProcessIdentityError(code, message)
            proc = self.procs.get(pid)
            if proc is None or not proc.alive:
                raise ProcessIdentityError("PROCESS_GONE", f"pid {pid} does not exist")
            return ProcessIdentity(pid=proc.pid, ppid=proc.ppid, boot_id=self.boot,
                                   start_ticks=proc.start_ticks, image=proc.image,
                                   observed_at=1.0)

    def children(self, pid):
        with self.lock:
            if pid in self.topology_failures:
                raise TopologyError("TOPOLOGY_PROBE_FAILED", self.topology_failures[pid])
            return tuple(sorted(p.pid for p in self.procs.values() if p.alive and p.ppid == pid))


class FakeControl:
    """Mimics PosixProcessControl, including its own identity re-check."""

    def __init__(self, probe, gate=None):
        self.probe = probe
        self.calls = []
        self.lock = threading.RLock()
        self.gate = gate  # callable invoked once, on the first signal

    def signal(self, identity, probe, escalate=False):
        if self.gate is not None:
            gate, self.gate = self.gate, None
            gate()
        with self.lock:
            self.calls.append((identity.pid, "kill" if escalate else "term"))
        try:
            observed = probe.identity(identity.pid)
        except ProcessIdentityError as ex:
            if ex.code == "PROCESS_GONE":
                return "already-exited"
            raise
        if not identity.same_process(observed):
            raise ProcessIdentityError("PID_REUSED", f"pid {identity.pid} was recycled")
        proc = self.probe.procs[identity.pid]
        if escalate:
            if not proc.resists_kill:
                proc.alive = False
            return "escalated"
        if not proc.resists_term:
            proc.alive = False
        return "signalled"

    @property
    def signalled_pids(self):
        with self.lock:
            return [pid for pid, _ in self.calls]


def build(processes=(), gate=None, **kwargs):
    probe = FakeProbe(processes)
    control = FakeControl(probe, gate=gate)
    sup = ProcessSupervisor(probe=probe, control=control,
                            sleep=lambda s: time.sleep(min(s, 0.002)), **kwargs)
    return sup, probe, control


FAST = {"timeout": 0.05, "escalation_timeout": 0.05, "poll_interval": 0.005}


# ---------------------------------------------------------------------------
# Timeout validation
# ---------------------------------------------------------------------------


class TimeoutValidationTests(unittest.TestCase):
    def test_rejects_non_finite_and_non_positive(self):
        for bad in (float("nan"), float("inf"), float("-inf"), 0, -1, -0.0001):
            with self.assertRaises(TimeoutValidationError, msg=repr(bad)):
                validated_timeout(bad)

    def test_rejects_bool_string_and_none(self):
        for bad in (True, False, "5", "", None, object()):
            with self.assertRaises(TimeoutValidationError, msg=repr(bad)):
                validated_timeout(bad)

    def test_rejects_unbounded_upper_values(self):
        with self.assertRaises(TimeoutValidationError):
            validated_timeout(MAX_TIMEOUT + 1)
        self.assertEqual(validated_timeout(MAX_TIMEOUT), MAX_TIMEOUT)

    def test_stop_validates_every_timeout_before_touching_the_process(self):
        sup, probe, control = build([FakeProcess(4242)])
        sup.register("w1", 4242)
        for kwargs in ({"timeout": float("inf")}, {"escalation_timeout": float("nan")},
                       {"timeout": 0}, {"escalation_timeout": -3}, {"poll_interval": 0},
                       {"timeout": True}, {"join_timeout": float("inf")},
                       {"timeout": MAX_TIMEOUT * 2}, {"poll_interval": "1"}):
            with self.assertRaises(TimeoutValidationError, msg=repr(kwargs)):
                sup.stop("w1", expected_generation=1, **{**FAST, **kwargs})
        self.assertEqual(control.calls, [], "no signal may be sent for an invalid timeout")
        self.assertEqual(sup.get("w1").state, STATE_RUNNING)

    def test_poll_interval_cannot_exceed_the_grace_budget(self):
        sup, _, _ = build([FakeProcess(4242)])
        sup.register("w1", 4242)
        with self.assertRaises(TimeoutValidationError):
            sup.stop("w1", expected_generation=1, timeout=0.05, escalation_timeout=0.05,
                     poll_interval=10.0)


# ---------------------------------------------------------------------------
# Identity is observed, never caller-trusted
# ---------------------------------------------------------------------------


class ObservedIdentityTests(unittest.TestCase):
    def test_supervisor_observes_identity_and_ignores_caller_supplied_fields(self):
        sup, probe, _ = build([FakeProcess(4242, ppid=9, start_ticks=5150, image="/opt/worker")])
        view = sup.register("w1", 4242, task_id="T-1")
        self.assertEqual(view.identity.pid, 4242)
        self.assertEqual(view.identity.start_ticks, 5150)
        self.assertEqual(view.identity.image, "/opt/worker")
        self.assertEqual(view.identity.boot_id, BOOT)
        self.assertIn(4242, probe.identity_calls)

    def test_forged_identity_claim_is_rejected_and_never_stored(self):
        sup, _, _ = build([FakeProcess(4242, start_ticks=5150, image="/opt/worker")])
        forged = {"pid": 4242, "ppid": 9, "bootId": BOOT, "startTicks": 5150,
                  "image": "/opt/trusted-thing", "token": "0" * 64}
        with self.assertRaises(ProcessIdentityError) as ctx:
            sup.register("w1", 4242, claimed_identity=forged)
        self.assertEqual(ctx.exception.code, "IDENTITY_CLAIM_MISMATCH")
        with self.assertRaises(UnknownAssignment):
            sup.get("w1")
        rejected = [e for e in sup.evidence() if e.outcome == "identity-claim-rejected"]
        self.assertEqual(len(rejected), 1)
        self.assertIn("image", rejected[0].detail["mismatchedFields"])

    def test_claim_with_unknown_fields_is_rejected(self):
        sup, _, _ = build([FakeProcess(4242)])
        with self.assertRaises(ProcessIdentityError):
            sup.register("w1", 4242, claimed_identity={"pid": 4242, "trustMe": True})

    def test_matching_claim_is_accepted_but_observed_values_win(self):
        sup, _, _ = build([FakeProcess(4242, start_ticks=5150, image="/opt/worker")])
        view = sup.register("w1", 4242, claimed_identity={"pid": 4242, "image": "/opt/worker"})
        self.assertEqual(view.identity.start_ticks, 5150)

    def test_identity_probe_failure_fails_closed_on_register(self):
        sup, probe, _ = build([FakeProcess(4242)])
        probe.identity_failures[4242] = ("IDENTITY_PROBE_FAILED", "permission denied reading exe")
        with self.assertRaises(ProcessIdentityError) as ctx:
            sup.register("w1", 4242)
        self.assertEqual(ctx.exception.code, "IDENTITY_PROBE_FAILED")
        with self.assertRaises(UnknownAssignment):
            sup.get("w1")
        self.assertEqual([e.outcome for e in sup.evidence()], ["identity-probe-failed"])

    def test_identity_probe_failure_on_stop_never_signals(self):
        sup, probe, control = build([FakeProcess(4242)])
        sup.register("w1", 4242)
        probe.identity_failures[4242] = ("IDENTITY_PROBE_FAILED", "proc unreadable")
        evidence = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(evidence.outcome, "stop-failed")
        self.assertEqual(evidence.detail["reason"], "identity probe failed")
        self.assertEqual(control.calls, [])
        self.assertEqual(sup.get("w1").state, STATE_STOP_FAILED)

    def test_supervisor_refuses_to_supervise_itself_or_pid_one(self):
        sup, probe, _ = build([FakeProcess(os.getpid()), FakeProcess(1)])
        for pid in (os.getpid(), 1):
            with self.assertRaises(SupervisorError) as ctx:
                sup.register(f"w{pid}", pid)
            self.assertEqual(ctx.exception.code, "PID_FORBIDDEN")

    def test_invalid_pids_are_rejected(self):
        sup, _, _ = build()
        for bad in (0, -1, True, "4242", 4242.5, None, 2 ** 40):
            with self.assertRaises(SupervisorError, msg=repr(bad)):
                sup.register("w1", bad)


# ---------------------------------------------------------------------------
# PID reuse and tree identity
# ---------------------------------------------------------------------------


class PidReuseAndTreeIdentityTests(unittest.TestCase):
    def test_recycled_pid_is_never_signalled(self):
        sup, probe, control = build([FakeProcess(4242, start_ticks=1000, image="/opt/worker")])
        sup.register("w1", 4242)
        # Same PID, different process: the OS recycled it under the supervisor.
        probe.add(FakeProcess(4242, start_ticks=99000, image="/usr/bin/sshd"))
        evidence = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(evidence.outcome, "identity-lost")
        self.assertEqual(control.calls, [], "a recycled PID must never be signalled")
        self.assertEqual(sup.get("w1").state, STATE_IDENTITY_LOST)
        self.assertTrue(probe.procs[4242].alive)

    def test_identity_lost_slot_refuses_further_stops_until_reconciled(self):
        sup, probe, control = build([FakeProcess(4242, start_ticks=1000)])
        sup.register("w1", 4242)
        probe.add(FakeProcess(4242, start_ticks=99000, image="/usr/bin/sshd"))
        sup.stop("w1", expected_generation=1, **FAST)
        with self.assertRaises(ProcessIdentityError) as ctx:
            sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(ctx.exception.code, "IDENTITY_LOST")
        self.assertEqual(control.calls, [])
        # Reconciliation is an explicit, generation-bumping reassign.
        view = sup.reassign("w1", 4242, expected_generation=1)
        self.assertEqual((view.generation, view.state), (2, STATE_RUNNING))

    def test_tree_stop_excludes_a_child_that_started_before_its_parent(self):
        root = FakeProcess(100, ppid=7, start_ticks=1000)
        real_child = FakeProcess(101, ppid=100, start_ticks=1100)
        grandchild = FakeProcess(103, ppid=101, start_ticks=1200)
        # PID 102 claims `root` as parent but predates it: a recycled PID trap.
        impostor = FakeProcess(102, ppid=100, start_ticks=900, image="/usr/bin/sshd")
        sup, probe, control = build([root, real_child, grandchild, impostor])
        sup.register("w1", 100)
        evidence = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(evidence.outcome, "stopped")
        self.assertNotIn(102, control.signalled_pids)
        self.assertEqual(evidence.detail["skippedChildren"], (102,))
        self.assertTrue(probe.procs[102].alive)
        self.assertEqual({100, 101, 103}, set(control.signalled_pids))

    def test_tree_stop_signals_descendants_before_the_root(self):
        sup, probe, control = build([FakeProcess(100, ppid=7, start_ticks=1000),
                                     FakeProcess(101, ppid=100, start_ticks=1100),
                                     FakeProcess(103, ppid=101, start_ticks=1200)])
        sup.register("w1", 100)
        sup.stop("w1", expected_generation=1, **FAST)
        order = control.signalled_pids
        self.assertLess(order.index(103), order.index(101))
        self.assertLess(order.index(101), order.index(100))

    def test_topology_probe_failure_fails_closed_without_signalling(self):
        sup, probe, control = build([FakeProcess(100, ppid=7), FakeProcess(101, ppid=100)])
        sup.register("w1", 100)
        probe.topology_failures[100] = "cannot enumerate /proc"
        evidence = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(evidence.outcome, "stop-failed")
        self.assertEqual(evidence.detail["reason"], "topology probe failed")
        self.assertEqual(control.calls, [])
        self.assertTrue(probe.procs[100].alive)
        self.assertEqual(sup.get("w1").state, STATE_STOP_FAILED)

    def test_unreadable_child_identity_fails_the_whole_stop_closed(self):
        sup, probe, control = build([FakeProcess(100, ppid=7), FakeProcess(101, ppid=100)])
        sup.register("w1", 100)
        probe.identity_failures[101] = ("IDENTITY_PROBE_FAILED", "exe unreadable")
        evidence = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(evidence.outcome, "stop-failed")
        self.assertEqual(control.calls, [])

    def test_process_that_exits_before_stop_is_recorded_as_stopped(self):
        sup, probe, control = build([FakeProcess(4242)])
        sup.register("w1", 4242)
        probe.procs[4242].alive = False
        evidence = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(evidence.outcome, "stopped")
        self.assertFalse(evidence.detail["signalled"])
        self.assertEqual(control.calls, [])


# ---------------------------------------------------------------------------
# Generation CAS and hostile concurrency
# ---------------------------------------------------------------------------


class Gate:
    """One-shot rendezvous: the stop thread parks until the test releases it."""

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()

    def __call__(self):
        self.entered.set()
        if not self.release.wait(10):
            raise AssertionError("gate was never released")

    def wait_entered(self):
        assert self.entered.wait(10), "stop thread never reached the gate"


class _Call(threading.Thread):
    def __init__(self, fn, *a, **kw):
        super().__init__(daemon=True)
        self.fn, self.a, self.kw = fn, a, kw
        self.result = None
        self.error = None

    def run(self):
        try:
            self.result = self.fn(*self.a, **self.kw)
        except BaseException as ex:  # noqa: BLE001 - re-raised in the test thread
            self.error = ex

    def value(self):
        self.join(15)
        assert not self.is_alive(), "call did not finish"
        if self.error is not None:
            raise self.error
        return self.result


class GenerationCasTests(unittest.TestCase):
    def test_generation_mismatch_is_refused_for_stop_and_reassign(self):
        sup, _, control = build([FakeProcess(4242), FakeProcess(4343)])
        sup.register("w1", 4242)
        with self.assertRaises(GenerationConflict) as ctx:
            sup.stop("w1", expected_generation=7, **FAST)
        self.assertEqual(ctx.exception.code, "GENERATION_MISMATCH")
        with self.assertRaises(GenerationConflict):
            sup.reassign("w1", 4343, expected_generation=0)
        self.assertEqual(control.calls, [])

    def test_register_over_an_occupied_slot_requires_a_generation(self):
        sup, _, _ = build([FakeProcess(4242), FakeProcess(4343)])
        sup.register("w1", 4242)
        with self.assertRaises(GenerationConflict) as ctx:
            sup.register("w1", 4343)
        self.assertEqual(ctx.exception.code, "GENERATION_REQUIRED")
        with self.assertRaises(GenerationConflict) as ctx:
            sup.register("w1", 4343, expected_generation=1)
        self.assertEqual(ctx.exception.code, "SLOT_OCCUPIED")

    def test_generation_must_be_an_int_not_a_bool(self):
        sup, _, _ = build([FakeProcess(4242)])
        sup.register("w1", 4242)
        for bad in (True, "1", 1.0, None):
            with self.assertRaises(GenerationConflict, msg=repr(bad)):
                sup.stop("w1", expected_generation=bad, **FAST)

    def test_stop_vs_stop_signals_exactly_once_and_shares_evidence(self):
        gate = Gate()
        sup, probe, control = build([FakeProcess(4242)], gate=gate)
        sup.register("w1", 4242)
        first = _Call(sup.stop, "w1", expected_generation=1, **FAST)
        first.start()
        gate.wait_entered()
        self.assertEqual(sup.get("w1").state, STATE_STOPPING)
        second = _Call(sup.stop, "w1", expected_generation=1, **FAST)
        second.start()
        time.sleep(0.05)  # let the duplicate reach the join point
        self.assertTrue(second.is_alive(), "duplicate stop must join, not run in parallel")
        gate.release.set()
        a, b = first.value(), second.value()
        self.assertIs(a, b, "a joined duplicate stop must receive the same evidence object")
        self.assertEqual(a.outcome, "stopped")
        self.assertEqual(control.calls, [(4242, "term")], "the slot was signalled twice")
        self.assertEqual(sup.get("w1").state, STATE_STOPPED)
        self.assertEqual(len([e for e in sup.evidence("w1") if e.kind == "stop"]), 1)

    def test_stop_vs_stop_at_a_different_generation_is_refused(self):
        gate = Gate()
        sup, _, _ = build([FakeProcess(4242)], gate=gate)
        sup.register("w1", 4242)
        runner = _Call(sup.stop, "w1", expected_generation=1, **FAST)
        runner.start()
        gate.wait_entered()
        with self.assertRaises(GenerationConflict) as ctx:
            sup.stop("w1", expected_generation=2, **FAST)
        self.assertEqual(ctx.exception.code, "GENERATION_MISMATCH")
        gate.release.set()
        runner.value()

    def test_stop_vs_reassign_discards_the_stale_stop_completion(self):
        gate = Gate()
        sup, probe, control = build([FakeProcess(4242, image="/opt/old")], gate=gate)
        probe.add(FakeProcess(4343, start_ticks=7000, image="/opt/new"))
        sup.register("w1", 4242, task_id="T-1")
        runner = _Call(sup.stop, "w1", expected_generation=1, **FAST)
        runner.start()
        gate.wait_entered()
        # A newer authority decision lands while the stop is still in flight.
        replaced = sup.reassign("w1", 4343, expected_generation=1, task_id="T-2", force=True)
        self.assertEqual((replaced.generation, replaced.state), (2, STATE_RUNNING))
        gate.release.set()
        evidence = runner.value()
        self.assertEqual(evidence.outcome, "stale-discarded")
        self.assertTrue(evidence.detail["stale"])
        self.assertEqual(evidence.detail["attemptedOutcome"], "stopped")
        self.assertEqual(evidence.generation, 1)
        current = sup.get("w1")
        self.assertEqual((current.generation, current.state, current.task_id),
                         (2, STATE_RUNNING, "T-2"))
        self.assertEqual(current.identity.pid, 4343)
        self.assertIsNone(current.pending_stop, "the stale stop must not linger as pending")

    def test_reassign_during_a_stop_is_refused_without_force(self):
        gate = Gate()
        sup, probe, _ = build([FakeProcess(4242)], gate=gate)
        probe.add(FakeProcess(4343))
        sup.register("w1", 4242)
        runner = _Call(sup.stop, "w1", expected_generation=1, **FAST)
        runner.start()
        gate.wait_entered()
        with self.assertRaises(GenerationConflict) as ctx:
            sup.reassign("w1", 4343, expected_generation=1)
        self.assertEqual(ctx.exception.code, "SLOT_STOPPING")
        gate.release.set()
        self.assertEqual(runner.value().outcome, "stopped")
        self.assertEqual(sup.get("w1").identity.pid, 4242)

    def test_stop_vs_register_is_refused_without_force_and_stale_with_force(self):
        gate = Gate()
        sup, probe, _ = build([FakeProcess(4242)], gate=gate)
        probe.add(FakeProcess(4343, start_ticks=7000))
        sup.register("w1", 4242)
        runner = _Call(sup.stop, "w1", expected_generation=1, **FAST)
        runner.start()
        gate.wait_entered()
        with self.assertRaises(GenerationConflict) as ctx:
            sup.register("w1", 4343, expected_generation=1)
        self.assertEqual(ctx.exception.code, "SLOT_STOPPING")
        forced = sup.register("w1", 4343, expected_generation=1, force=True)
        self.assertEqual(forced.generation, 2)
        gate.release.set()
        self.assertEqual(runner.value().outcome, "stale-discarded")
        self.assertEqual(sup.get("w1").identity.pid, 4343)

    def test_register_after_a_completed_stop_reuses_the_slot(self):
        sup, probe, _ = build([FakeProcess(4242)])
        probe.add(FakeProcess(4343, start_ticks=7000))
        sup.register("w1", 4242)
        sup.stop("w1", expected_generation=1, **FAST)
        view = sup.register("w1", 4343, expected_generation=1)
        self.assertEqual((view.generation, view.state, view.identity.pid), (2, STATE_RUNNING, 4343))

    def test_stale_stop_completion_cannot_resurrect_a_dropped_slot_state(self):
        gate = Gate()
        sup, probe, _ = build([FakeProcess(4242, resists_term=True, resists_kill=True)], gate=gate)
        probe.add(FakeProcess(4343, start_ticks=7000))
        sup.register("w1", 4242)
        runner = _Call(sup.stop, "w1", expected_generation=1, **FAST)
        runner.start()
        gate.wait_entered()
        sup.reassign("w1", 4343, expected_generation=1, force=True)
        gate.release.set()
        evidence = runner.value()
        # The stop genuinely failed, but it must not stamp stop-failed onto gen 2.
        self.assertEqual(evidence.outcome, "stale-discarded")
        self.assertEqual(evidence.detail["attemptedOutcome"], "stop-failed")
        self.assertEqual(sup.get("w1").state, STATE_RUNNING)

    def test_stop_is_idempotent_once_the_slot_is_stopped(self):
        sup, _, control = build([FakeProcess(4242)])
        sup.register("w1", 4242)
        sup.stop("w1", expected_generation=1, **FAST)
        again = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(again.outcome, "already-stopped")
        self.assertEqual(control.calls, [(4242, "term")])

    def test_unknown_slot_operations_are_refused(self):
        sup, _, _ = build([FakeProcess(4242)])
        with self.assertRaises(UnknownAssignment):
            sup.stop("nope", expected_generation=1, **FAST)
        with self.assertRaises(UnknownAssignment):
            sup.reassign("nope", 4242, expected_generation=1)
        with self.assertRaises(UnknownAssignment):
            sup.get("nope")

    def test_concurrent_registers_on_one_empty_slot_produce_a_single_winner(self):
        sup, probe, _ = build([FakeProcess(p, start_ticks=1000 + p) for p in range(5000, 5008)])
        start = threading.Barrier(8)

        def attempt(pid):
            start.wait(10)
            try:
                return sup.register("w1", pid)
            except GenerationConflict:
                return None

        threads = [_Call(attempt, pid) for pid in range(5000, 5008)]
        for t in threads:
            t.start()
        winners = [t.value() for t in threads]
        self.assertEqual(sum(1 for w in winners if w is not None), 1)
        self.assertEqual(sup.get("w1").generation, 1)


# ---------------------------------------------------------------------------
# Failed stop and retry
# ---------------------------------------------------------------------------


class FailedStopRetryTests(unittest.TestCase):
    def test_survivor_records_stop_failed_and_keeps_the_generation_for_retry(self):
        proc = FakeProcess(4242, resists_term=True, resists_kill=True)
        sup, probe, control = build([proc])
        sup.register("w1", 4242)
        evidence = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(evidence.outcome, "stop-failed")
        self.assertEqual(evidence.detail["reason"], "process survived escalation")
        view = sup.get("w1")
        self.assertEqual((view.generation, view.state), (1, STATE_STOP_FAILED))
        self.assertIsNone(view.pending_stop)
        self.assertIn((4242, "term"), control.calls)
        self.assertIn((4242, "kill"), control.calls)

        proc.resists_kill = False
        retry = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(retry.outcome, "stopped")
        self.assertNotEqual(retry.operation_id, evidence.operation_id)
        self.assertEqual(sup.get("w1").state, STATE_STOPPED)

    def test_graceful_stop_does_not_escalate(self):
        sup, _, control = build([FakeProcess(4242)])
        sup.register("w1", 4242)
        evidence = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(evidence.detail["reason"], "graceful")
        self.assertFalse(evidence.detail["escalated"])
        self.assertEqual(control.calls, [(4242, "term")])

    def test_escalation_is_used_when_term_is_ignored(self):
        sup, _, control = build([FakeProcess(4242, resists_term=True)])
        sup.register("w1", 4242)
        evidence = sup.stop("w1", expected_generation=1, **FAST)
        self.assertEqual(evidence.outcome, "stopped")
        self.assertEqual(evidence.detail["reason"], "escalated")
        self.assertEqual(control.calls, [(4242, "term"), (4242, "kill")])

    def test_signal_failure_leaves_a_retryable_slot_and_clears_the_pending_stop(self):
        sup, probe, control = build([FakeProcess(4242)])
        sup.register("w1", 4242)

        def explode(identity, p, escalate=False):
            raise SupervisorError("SIGNAL_FAILED", "EPERM")

        control.signal = explode
        with self.assertRaises(SupervisorError):
            sup.stop("w1", expected_generation=1, **FAST)
        view = sup.get("w1")
        self.assertEqual((view.generation, view.state), (1, STATE_STOP_FAILED))
        self.assertIsNone(view.pending_stop, "a crashed stop must not leave the slot wedged")
        failures = [e for e in sup.evidence("w1") if e.outcome == "stop-failed"]
        self.assertEqual(failures[-1].detail["code"], "SIGNAL_FAILED")


# ---------------------------------------------------------------------------
# Returned objects must not expose internal authority state
# ---------------------------------------------------------------------------


class ExternalMutationTests(unittest.TestCase):
    def test_assignment_view_is_frozen(self):
        sup, _, _ = build([FakeProcess(4242)])
        view = sup.register("w1", 4242, task_id="T-1")
        self.assertIsInstance(view, AssignmentView)
        for field, value in (("state", STATE_STOPPED), ("generation", 99), ("task_id", "T-EVIL"),
                             ("identity", None), ("slot", "other")):
            with self.assertRaises(dataclasses.FrozenInstanceError, msg=field):
                setattr(view, field, value)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            view.identity.pid = 1
        fresh = sup.get("w1")
        self.assertEqual((fresh.state, fresh.generation, fresh.task_id), (STATE_RUNNING, 1, "T-1"))

    def test_pending_stop_mapping_is_read_only(self):
        gate = Gate()
        sup, _, _ = build([FakeProcess(4242)], gate=gate)
        sup.register("w1", 4242)
        runner = _Call(sup.stop, "w1", expected_generation=1, **FAST)
        runner.start()
        gate.wait_entered()
        pending = sup.get("w1").pending_stop
        with self.assertRaises(TypeError):
            pending["generation"] = 99
        with self.assertRaises(TypeError):
            del pending["operationId"]
        gate.release.set()
        runner.value()

    def test_evidence_detail_is_deeply_read_only(self):
        sup, _, _ = build([FakeProcess(100, ppid=7), FakeProcess(101, ppid=100, start_ticks=1100)])
        view = sup.register("w1", 100)
        bind = sup.evidence("w1")[0]
        self.assertIsInstance(bind, Evidence)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            bind.outcome = "tampered"
        with self.assertRaises(TypeError):
            bind.detail["pid"] = 1
        with self.assertRaises(TypeError):
            bind.detail["identity"]["image"] = "/opt/evil"
        stop = sup.stop("w1", expected_generation=1, **FAST)
        self.assertIsInstance(stop.detail["signalled"], tuple)
        with self.assertRaises(TypeError):
            stop.detail["signalled"][0]["outcome"] = "no"
        with self.assertRaises(TypeError):
            stop.detail["children"] = ()

    def test_identity_dict_and_collections_are_not_live_handles(self):
        sup, _, _ = build([FakeProcess(4242)])
        view = sup.register("w1", 4242)
        with self.assertRaises(TypeError):
            view.identity.as_dict()["pid"] = 9
        snapshot = sup.snapshot()
        self.assertIsInstance(snapshot, tuple)
        with self.assertRaises(AttributeError):
            snapshot.append(None)
        evidence = sup.evidence()
        self.assertIsInstance(evidence, tuple)
        self.assertEqual(sup.get("w1").identity.pid, 4242)

    def test_mutating_a_task_id_argument_after_register_does_not_affect_state(self):
        sup, _, _ = build([FakeProcess(4242)])
        sup.register("w1", 4242, task_id="T-1")
        self.assertEqual(sup.get("w1").task_id, "T-1")
        # Evidence detail is a copy, so a caller cannot rewrite recorded history.
        detail = sup.evidence("w1")[0].detail
        with self.assertRaises(TypeError):
            detail["taskId"] = "T-EVIL"
        self.assertEqual(sup.evidence("w1")[0].detail["taskId"], "T-1")


# ---------------------------------------------------------------------------
# Hostile tool resolution
# ---------------------------------------------------------------------------


class HostileToolResolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def _tool(self, name, mode=0o755):
        path = self.dir / name
        path.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
        path.chmod(mode)
        return path

    def test_rejects_path_traversal_and_separators_in_tool_names(self):
        resolver = NativeToolResolver(trusted_dirs=[str(self.dir)], windows=False,
                                      require_root_owned=False)
        for name in ("../../bin/sh", "sub/dir/tool", "..", ".", "", None, "a" * 200,
                     "tool;rm -rf /", "tool name", "\\evil"):
            with self.assertRaises(ToolResolutionError, msg=repr(name)) as ctx:
                resolver.resolve(name)
            self.assertIn(ctx.exception.code, ("TOOL_NAME_INVALID", "TOOL_NOT_TRUSTED"))

    def test_world_or_group_writable_tool_is_refused(self):
        for mode in (0o777, 0o775, 0o757):
            self._tool("taskkill", mode)
            resolver = NativeToolResolver(trusted_dirs=[str(self.dir)], windows=False,
                                          require_root_owned=False)
            with self.assertRaises(ToolResolutionError, msg=oct(mode)) as ctx:
                resolver.resolve("taskkill")
            self.assertEqual(ctx.exception.code, "TOOL_NOT_TRUSTED")

    def test_symlinked_tool_inside_a_trusted_directory_is_refused(self):
        real = self.dir / "real-tool"
        real.write_text("#!/bin/sh\n", encoding="utf-8")
        real.chmod(0o755)
        link = self.dir / "taskkill"
        link.symlink_to(real)
        resolver = NativeToolResolver(trusted_dirs=[str(self.dir)], windows=False,
                                      require_root_owned=False)
        with self.assertRaises(ToolResolutionError):
            resolver.resolve("taskkill")

    def test_non_executable_tool_is_refused(self):
        self._tool("taskkill", 0o644)
        resolver = NativeToolResolver(trusted_dirs=[str(self.dir)], windows=False,
                                      require_root_owned=False)
        with self.assertRaises(ToolResolutionError):
            resolver.resolve("taskkill")

    @unittest.skipIf(os.getuid() == 0, "cannot create a non-root-owned file as root")
    def test_non_root_owned_tool_is_refused_on_posix(self):
        self._tool("taskkill", 0o755)
        resolver = NativeToolResolver(trusted_dirs=[str(self.dir)], windows=False)
        with self.assertRaises(ToolResolutionError):
            resolver.resolve("taskkill")

    def test_path_is_never_consulted(self):
        hostile = self._tool("env", 0o755)
        trusted = Path("/usr/bin/env")
        if not trusted.is_file() or os.path.islink(str(trusted)):
            self.skipTest("/usr/bin/env is not a plain trusted binary here")
        info = trusted.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            self.skipTest("/usr/bin/env is not root-owned and unwritable here")
        old = os.environ.get("PATH")
        os.environ["PATH"] = str(self.dir)
        try:
            resolved = NativeToolResolver(windows=False).resolve("env")
        finally:
            if old is None:
                os.environ.pop("PATH", None)
            else:
                os.environ["PATH"] = old
        self.assertEqual(resolved, str(trusted))
        self.assertNotEqual(resolved, str(hostile))

    def test_unknown_tool_fails_closed_rather_than_falling_back(self):
        resolver = NativeToolResolver(trusted_dirs=[str(self.dir)], windows=False,
                                      require_root_owned=False)
        for _ in range(3):  # the cached negative result must keep failing closed
            with self.assertRaises(ToolResolutionError) as ctx:
                resolver.resolve("forgeboss-nonexistent-tool")
            self.assertEqual(ctx.exception.code, "TOOL_NOT_TRUSTED")
        # Planting the tool after a denial must not retroactively bless it via PATH.
        self._tool("forgeboss-nonexistent-tool", 0o777)
        with self.assertRaises(ToolResolutionError):
            resolver.resolve("forgeboss-nonexistent-tool")

    def test_untrusted_directory_is_ignored_even_if_the_tool_exists_there(self):
        self._tool("taskkill", 0o755)
        resolver = NativeToolResolver(trusted_dirs=["/usr/bin"], windows=False,
                                      require_root_owned=False)
        with self.assertRaises(ToolResolutionError):
            resolver.resolve("taskkill")

    def test_windows_control_refuses_to_kill_when_the_tool_is_untrusted(self):
        probe = FakeProbe([FakeProcess(4242)])
        calls = []
        control = WindowsProcessControl(
            resolver=NativeToolResolver(trusted_dirs=[], windows=True),
            runner=lambda argv, timeout: calls.append(argv))
        identity = probe.identity(4242)
        with self.assertRaises(ToolResolutionError):
            control.signal(identity, probe, escalate=True)
        self.assertEqual(calls, [], "no command may run when tool resolution fails")


# ---------------------------------------------------------------------------
# Real OS behaviour (Linux /proc + native signalling)
# ---------------------------------------------------------------------------


@unittest.skipUnless(ProcProbe().supported, "requires /proc")
class RealProcessTests(unittest.TestCase):
    def _spawn(self, code):
        proc = subprocess.Popen([sys.executable, "-c", code])
        self.addCleanup(self._reap, proc)
        return proc

    def _reap(self, proc):
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

    def test_probe_reports_a_stable_identity_and_detects_exit(self):
        proc = self._spawn("import time; time.sleep(30)")
        probe = ProcProbe()
        first = probe.identity(proc.pid)
        second = probe.identity(proc.pid)
        self.assertTrue(first.same_process(second))
        self.assertEqual(first.token, second.token)
        self.assertTrue(first.image)
        self.assertEqual(first.ppid, os.getpid())
        proc.kill()
        proc.wait(timeout=10)
        # A zombie still has a /proc entry, so reap before asserting absence.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                probe.identity(proc.pid)
            except ProcessIdentityError as ex:
                self.assertIn(ex.code, ("PROCESS_GONE", "IDENTITY_PROBE_FAILED"))
                return
            time.sleep(0.02)
        self.fail("exited process still reported a full identity")

    def test_probe_fails_closed_for_a_pid_that_does_not_exist(self):
        probe = ProcProbe()
        with self.assertRaises(ProcessIdentityError) as ctx:
            probe.identity(MAX_UNUSED_PID)
        self.assertEqual(ctx.exception.code, "PROCESS_GONE")

    def test_end_to_end_stop_of_a_real_process(self):
        proc = self._spawn("import time; time.sleep(120)")
        sup = ProcessSupervisor()
        view = sup.register("real", proc.pid, task_id="T-real")
        self.assertEqual(view.state, STATE_RUNNING)
        evidence = sup.stop("real", expected_generation=1, timeout=5.0,
                            escalation_timeout=5.0, poll_interval=0.02)
        self.assertEqual(evidence.outcome, "stopped")
        proc.wait(timeout=10)
        self.assertEqual(sup.get("real").state, STATE_STOPPED)

    def test_end_to_end_tree_stop_kills_a_real_child(self):
        parent = self._spawn(
            "import subprocess,sys,time;"
            "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']);"
            "print(c.pid,flush=True);time.sleep(120)")
        probe = ProcProbe()
        deadline = time.monotonic() + 10
        children = ()
        while time.monotonic() < deadline and not children:
            children = probe.children(parent.pid)
            time.sleep(0.05)
        self.assertTrue(children, "child process never appeared")
        child_pid = children[0]
        sup = ProcessSupervisor()
        sup.register("tree", parent.pid)
        evidence = sup.stop("tree", expected_generation=1, timeout=5.0,
                            escalation_timeout=5.0, poll_interval=0.02)
        self.assertEqual(evidence.outcome, "stopped")
        self.assertIn(child_pid, evidence.detail["children"])
        parent.wait(timeout=10)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                probe.identity(child_pid)
            except ProcessIdentityError:
                break
            time.sleep(0.05)
        else:
            self.fail("child survived the tree stop")


def _unused_pid():
    """A PID that is very unlikely to exist, for fail-closed probe assertions."""
    try:
        ceiling = int(Path("/proc/sys/kernel/pid_max").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        ceiling = 32768
    return min(ceiling - 1, 4194303)


MAX_UNUSED_PID = _unused_pid()


if __name__ == "__main__":
    unittest.main()
