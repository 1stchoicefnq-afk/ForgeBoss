"""FB-052 — immediate stop/reassign authority with process-tree termination.

This is a thin cross-engine supervisor primitive (per the FL1 architecture rule):
it owns *process identity* and *stop authority* only. It does not run, schedule,
retry or otherwise reimplement a coding-agent execution loop, and it performs no
daemon or durable-store integration; it emits a plain evidence object that a
later packet can persist.

Core invariants
---------------
* One live assignment per task at a time. Each assignment carries
  ``(task_id, run_id, generation)``.
* Stop is generation-bound. A stop request naming a generation other than the
  live one never signals anything, so a stale controller cannot kill a worker
  that has already been reassigned.
* Identity is verified before any signal. A registered worker is
  ``(pid, start_token)`` where ``start_token`` is a platform instance
  discriminator (POSIX ``/proc`` starttime, Windows CIM ``CreationDate``). If
  the token no longer matches, the supervisor fails closed: it signals nothing
  and reports ``identity_mismatch`` rather than risking a recycled PID.
* Termination targets the owned process tree, computed from a single process
  snapshot rooted at the registered PID. Every target must be reachable from
  that root; ancestors of the supervising process, PID 0 and PID 1 are never
  signalled.
* Stop is graceful-then-forced with a bounded grace period, and is idempotent:
  repeating a stop for a terminal generation replays the recorded evidence
  without re-signalling.
* Reassignment is blocked until the previous generation reached a terminal
  state.
"""

from __future__ import annotations

import os
import signal as signal_module
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

EVIDENCE_SCHEMA = "forgeboss.control.process_supervisor.stop_evidence/1"

STATE_REGISTERED = "registered"
STATE_STOPPED_GRACEFUL = "stopped_graceful"
STATE_STOPPED_FORCED = "stopped_forced"
STATE_ALREADY_EXITED = "already_exited"
STATE_IDENTITY_MISMATCH = "identity_mismatch"
STATE_STOP_FAILED = "stop_failed"

#: States after which a new generation may be trusted for the same task.
TERMINAL_STATES = frozenset(
    {
        STATE_STOPPED_GRACEFUL,
        STATE_STOPPED_FORCED,
        STATE_ALREADY_EXITED,
        STATE_IDENTITY_MISMATCH,
    }
)

REJECT_UNKNOWN_ASSIGNMENT = "unknown_assignment"
REJECT_STALE_GENERATION = "stale_generation"
REJECT_FUTURE_GENERATION = "future_generation"

PHASE_GRACEFUL = "graceful"
PHASE_FORCE = "force"

DEFAULT_GRACE_SECONDS = 10.0
DEFAULT_POLL_SECONDS = 0.05


class SupervisorError(Exception):
    """Base class for supervisor authority errors."""


class ReassignmentBlockedError(SupervisorError):
    """Raised when a new generation is requested before the old one is terminal."""


class RegistrationError(SupervisorError):
    """Raised for structurally invalid registrations (bad PID, self-supervision)."""


# ---------------------------------------------------------------------------
# Command construction (pure, so unit tests can assert exact argv)
# ---------------------------------------------------------------------------

def posix_snapshot_command() -> List[str]:
    """Full ``pid ppid`` table. One call gives a coherent tree snapshot."""
    return ["ps", "-A", "-o", "pid=,ppid="]


def posix_identity_command(pid: int) -> List[str]:
    """Fallback identity probe when ``/proc`` is unavailable (e.g. macOS)."""
    return ["ps", "-o", "lstart=,comm=", "-p", str(int(pid))]


_PS_WINDOWS_PREFIX = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]


def windows_snapshot_command() -> List[str]:
    return _PS_WINDOWS_PREFIX + [
        "Get-CimInstance Win32_Process | "
        "ForEach-Object { '{0} {1}' -f $_.ProcessId, $_.ParentProcessId }"
    ]


def windows_identity_command(pid: int) -> List[str]:
    return _PS_WINDOWS_PREFIX + [
        "$p = Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; "
        "if ($p) {{ '{{0}}|{{1}}' -f $p.ProcessId, "
        "$p.CreationDate.ToUniversalTime().ToString('o') }}".format(pid=int(pid))
    ]


def windows_kill_command(pid: int, force: bool, tree: bool) -> List[str]:
    """``taskkill`` argv.

    ``/F`` is the hard kill. ``/T`` is only used for the optional owned-tree
    backstop; per-PID signalling deliberately omits it so that the supervisor,
    not ``taskkill``, decides what is in scope.
    """
    cmd = ["taskkill", "/PID", str(int(pid))]
    if tree:
        cmd.append("/T")
    if force:
        cmd.append("/F")
    return cmd


# ---------------------------------------------------------------------------
# Platform abstraction
# ---------------------------------------------------------------------------

def _default_runner(argv: Sequence[str]) -> Tuple[int, str]:
    proc = subprocess.run(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout or ""


def _parse_pid_ppid_table(text: str) -> Dict[int, int]:
    table: Dict[int, int] = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        table[pid] = ppid
    return table


class ProcessPlatform:
    """Interface for the OS-specific half of process-tree supervision."""

    name = "abstract"

    def snapshot_command(self) -> List[str]:
        """Argv used to build the snapshot, recorded as evidence."""
        raise NotImplementedError

    def snapshot(self) -> Dict[int, int]:
        """Return ``{pid: ppid}`` for every visible process."""
        raise NotImplementedError

    def instance_token(self, pid: int) -> Optional[str]:
        """Opaque per-instance discriminator, or ``None`` if the PID is gone."""
        raise NotImplementedError

    def is_alive(self, pid: int) -> bool:
        raise NotImplementedError

    def signal_process(self, pid: int, force: bool) -> Dict[str, object]:
        """Signal one PID. Returns a record for the evidence object."""
        raise NotImplementedError

    def signal_tree_backstop(self, root_pid: int, force: bool) -> Dict[str, object]:
        """Whole-tree signal for workers that own their group/job."""
        raise NotImplementedError


class PosixPlatform(ProcessPlatform):
    """POSIX semantics: SIGTERM/SIGKILL, ``/proc`` starttime identity, killpg."""

    name = "posix"

    def __init__(self, runner=None, proc_root="/proc", killer=None, group_killer=None):
        self._runner = runner or _default_runner
        self._proc_root = Path(proc_root) if proc_root else None
        self._killer = killer or os.kill
        self._group_killer = group_killer or getattr(os, "killpg", None)
        self._term = signal_module.SIGTERM
        # Windows has no SIGKILL; PosixPlatform is not used there, but degrade
        # to SIGTERM rather than failing at import time.
        self._kill = getattr(signal_module, "SIGKILL", signal_module.SIGTERM)

    # -- identity ---------------------------------------------------------
    def _proc_stat_fields(self, pid: int) -> Optional[List[str]]:
        if self._proc_root is None:
            return None
        try:
            raw = (self._proc_root / str(int(pid)) / "stat").read_text()
        except OSError:
            return None
        # comm (field 2) is parenthesised and may itself contain ") ".
        close = raw.rfind(")")
        if close < 0:
            return None
        return raw[close + 1 :].split()

    def instance_token(self, pid: int) -> Optional[str]:
        fields = self._proc_stat_fields(pid)
        if fields is not None:
            # After comm, fields[0] is state (stat field 3); starttime is
            # field 22, i.e. index 22 - 3 = 19.
            if len(fields) > 19:
                if fields[0] == "Z":
                    return None  # reaped-pending zombie is not a live instance
                return "starttime:" + fields[19]
            return None
        rc, out = self._runner(posix_identity_command(pid))
        out = (out or "").strip()
        if rc != 0 or not out:
            return None
        return "ps:" + " ".join(out.split())

    def is_alive(self, pid: int) -> bool:
        fields = self._proc_stat_fields(pid)
        if fields is not None:
            return bool(fields) and fields[0] != "Z"
        if self._proc_root is not None:
            return False
        try:
            self._killer(int(pid), 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    # -- topology ---------------------------------------------------------
    def snapshot_command(self) -> List[str]:
        return posix_snapshot_command()

    def snapshot(self) -> Dict[int, int]:
        rc, out = self._runner(posix_snapshot_command())
        if rc != 0:
            return {}
        return _parse_pid_ppid_table(out)

    # -- signalling -------------------------------------------------------
    def signal_process(self, pid: int, force: bool) -> Dict[str, object]:
        sig = self._kill if force else self._term
        record = {
            "pid": int(pid),
            "command": ["os.kill", str(int(pid)), "SIGKILL" if force else "SIGTERM"],
            "delivered": False,
            "error": None,
        }
        try:
            self._killer(int(pid), sig)
        except ProcessLookupError:
            record["error"] = "no_such_process"
        except PermissionError:
            record["error"] = "permission_denied"
        except OSError as exc:  # pragma: no cover - platform dependent
            record["error"] = type(exc).__name__
        else:
            record["delivered"] = True
        return record

    def signal_tree_backstop(self, root_pid: int, force: bool) -> Dict[str, object]:
        sig = self._kill if force else self._term
        record = {
            "pid": int(root_pid),
            "command": ["os.killpg", str(int(root_pid)), "SIGKILL" if force else "SIGTERM"],
            "delivered": False,
            "error": None,
        }
        if self._group_killer is None:
            record["error"] = "killpg_unavailable"
            return record
        try:
            # Only ever signal a group the worker leads; never a borrowed group.
            if os.getpgid(int(root_pid)) != int(root_pid):
                record["error"] = "not_group_leader"
                return record
        except (ProcessLookupError, PermissionError, OSError) as exc:
            record["error"] = type(exc).__name__
            return record
        try:
            self._group_killer(int(root_pid), sig)
        except (ProcessLookupError, PermissionError, OSError) as exc:
            record["error"] = type(exc).__name__
        else:
            record["delivered"] = True
        return record


class WindowsPlatform(ProcessPlatform):
    """Windows semantics: ``taskkill`` and CIM ``CreationDate`` identity."""

    name = "windows"

    def __init__(self, runner=None):
        self._runner = runner or _default_runner

    def snapshot_command(self) -> List[str]:
        return windows_snapshot_command()

    def snapshot(self) -> Dict[int, int]:
        rc, out = self._runner(windows_snapshot_command())
        if rc != 0:
            return {}
        return _parse_pid_ppid_table(out)

    def instance_token(self, pid: int) -> Optional[str]:
        rc, out = self._runner(windows_identity_command(pid))
        out = (out or "").strip()
        if rc != 0 or not out or "|" not in out:
            return None
        observed_pid, _, created = out.partition("|")
        if observed_pid.strip() != str(int(pid)):
            return None
        created = created.strip()
        return ("created:" + created) if created else None

    def is_alive(self, pid: int) -> bool:
        return self.instance_token(pid) is not None

    def signal_process(self, pid: int, force: bool) -> Dict[str, object]:
        cmd = windows_kill_command(pid, force=force, tree=False)
        rc, _ = self._runner(cmd)
        return {"pid": int(pid), "command": cmd, "delivered": rc == 0,
                "error": None if rc == 0 else "taskkill_rc_%d" % rc}

    def signal_tree_backstop(self, root_pid: int, force: bool) -> Dict[str, object]:
        cmd = windows_kill_command(root_pid, force=force, tree=True)
        rc, _ = self._runner(cmd)
        return {"pid": int(root_pid), "command": cmd, "delivered": rc == 0,
                "error": None if rc == 0 else "taskkill_rc_%d" % rc}


def detect_platform() -> ProcessPlatform:
    return WindowsPlatform() if os.name == "nt" else PosixPlatform()


# ---------------------------------------------------------------------------
# Tree walk
# ---------------------------------------------------------------------------

def descendants(snapshot: Dict[int, int], root: int) -> List[Tuple[int, int]]:
    """Breadth-first ``(depth, pid)`` list of processes below ``root``.

    Cycle-safe. Only edges present in the snapshot are followed, so a process
    that is not reachable from ``root`` can never enter the target set.
    """
    children: Dict[int, List[int]] = {}
    for pid, ppid in snapshot.items():
        if pid == ppid:
            continue  # self-parented rows would loop
        children.setdefault(ppid, []).append(pid)
    out: List[Tuple[int, int]] = []
    seen = {int(root)}
    frontier = [(int(root), 0)]
    while frontier:
        pid, depth = frontier.pop(0)
        for child in sorted(children.get(pid, ())):
            if child in seen:
                continue
            seen.add(child)
            out.append((depth + 1, child))
            frontier.append((child, depth + 1))
    return out


def ancestors_of(snapshot: Dict[int, int], pid: int) -> List[int]:
    chain: List[int] = []
    seen = {int(pid)}
    current = snapshot.get(int(pid))
    while current is not None and current not in seen:
        chain.append(current)
        seen.add(current)
        current = snapshot.get(current)
    return chain


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProcessIdentity:
    """A specific process *instance*, not merely a PID."""

    pid: int
    start_token: str
    command_hint: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {"pid": self.pid, "startToken": self.start_token,
                "commandHint": self.command_hint}


@dataclass
class StopEvidence:
    """Deterministic, JSON-safe record of one stop decision.

    Shaped for later durable-store integration: it is self-describing
    (``schema``), carries its own id, and contains every command that was
    constructed plus every identity check that was performed.
    """

    evidence_id: str
    task_id: str
    run_id: str
    generation: int
    platform: str
    accepted: bool
    rejection: Optional[str]
    terminal_state: Optional[str]
    requested_at: float
    completed_at: float
    grace_seconds: float
    grace_elapsed: float
    root_pid: Optional[int]
    expected_token: Optional[str]
    observed_token: Optional[str]
    tree_pids: List[int] = field(default_factory=list)
    graceful_signalled: List[int] = field(default_factory=list)
    forced_signalled: List[int] = field(default_factory=list)
    survivors: List[int] = field(default_factory=list)
    protected_pids: List[int] = field(default_factory=list)
    commands: List[List[str]] = field(default_factory=list)
    signals: List[Dict[str, object]] = field(default_factory=list)
    identity_checks: List[Dict[str, object]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    schema: str = EVIDENCE_SCHEMA

    @property
    def terminal(self) -> bool:
        return self.terminal_state in TERMINAL_STATES

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": self.schema,
            "evidenceId": self.evidence_id,
            "taskId": self.task_id,
            "runId": self.run_id,
            "generation": self.generation,
            "platform": self.platform,
            "accepted": self.accepted,
            "rejection": self.rejection,
            "terminalState": self.terminal_state,
            "terminal": self.terminal,
            "requestedAt": self.requested_at,
            "completedAt": self.completed_at,
            "graceSeconds": self.grace_seconds,
            "graceElapsed": self.grace_elapsed,
            "rootPid": self.root_pid,
            "expectedToken": self.expected_token,
            "observedToken": self.observed_token,
            "treePids": list(self.tree_pids),
            "gracefulSignalled": list(self.graceful_signalled),
            "forcedSignalled": list(self.forced_signalled),
            "survivors": list(self.survivors),
            "protectedPids": list(self.protected_pids),
            "commands": [list(c) for c in self.commands],
            "signals": [dict(s) for s in self.signals],
            "identityChecks": [dict(c) for c in self.identity_checks],
            "notes": list(self.notes),
        }


@dataclass
class WorkerAssignment:
    """One generation of one worker process owned by one task."""

    task_id: str
    run_id: str
    generation: int
    identity: ProcessIdentity
    owns_process_group: bool
    registered_at: float
    state: str = STATE_REGISTERED
    stopped_at: Optional[float] = None
    evidence: Optional[StopEvidence] = None

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def to_dict(self) -> Dict[str, object]:
        return {
            "taskId": self.task_id,
            "runId": self.run_id,
            "generation": self.generation,
            "identity": self.identity.to_dict(),
            "ownsProcessGroup": self.owns_process_group,
            "registeredAt": self.registered_at,
            "state": self.state,
            "terminal": self.terminal,
            "stoppedAt": self.stopped_at,
            "evidence": self.evidence.to_dict() if self.evidence else None,
        }


# ---------------------------------------------------------------------------
# Supervisor
# ---------------------------------------------------------------------------

class ProcessSupervisor:
    """Stop/reassign authority over registered worker process instances."""

    def __init__(
        self,
        platform: Optional[ProcessPlatform] = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        grace_seconds: float = DEFAULT_GRACE_SECONDS,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        self_pid: Optional[int] = None,
        evidence_ids: Optional[Callable[[], str]] = None,
    ):
        self.platform = platform or detect_platform()
        self._clock = clock
        self._wall_clock = wall_clock
        self._sleep = sleep
        self.grace_seconds = float(grace_seconds)
        self.poll_seconds = float(poll_seconds)
        self._self_pid = int(self_pid if self_pid is not None else os.getpid())
        self._evidence_ids = evidence_ids or (lambda: uuid.uuid4().hex)
        self._assignments: Dict[str, WorkerAssignment] = {}
        self._history: Dict[Tuple[str, int], StopEvidence] = {}

    # -- registration -----------------------------------------------------
    def register(
        self,
        task_id: str,
        run_id: str,
        pid: int,
        start_token: Optional[str] = None,
        command_hint: str = "",
        owns_process_group: bool = False,
        generation: int = 1,
    ) -> WorkerAssignment:
        """Register the first generation of a worker for ``task_id``."""
        existing = self._assignments.get(task_id)
        if existing is not None and not existing.terminal:
            raise ReassignmentBlockedError(
                "task %s still has live generation %d in state %s"
                % (task_id, existing.generation, existing.state)
            )
        if existing is not None:
            return self.reassign(
                task_id,
                run_id,
                pid,
                start_token=start_token,
                command_hint=command_hint,
                owns_process_group=owns_process_group,
                generation=generation if generation > existing.generation else None,
            )
        return self._install(
            task_id, run_id, pid, start_token, command_hint,
            owns_process_group, int(generation),
        )

    def reassign(
        self,
        task_id: str,
        run_id: str,
        pid: int,
        start_token: Optional[str] = None,
        command_hint: str = "",
        owns_process_group: bool = False,
        generation: Optional[int] = None,
    ) -> WorkerAssignment:
        """Install the next generation. The previous one must be terminal."""
        existing = self._assignments.get(task_id)
        if existing is None:
            raise ReassignmentBlockedError("task %s has no prior assignment" % task_id)
        if not existing.terminal:
            raise ReassignmentBlockedError(
                "generation %d of task %s is %s, not terminal; stop it before reassigning"
                % (existing.generation, task_id, existing.state)
            )
        next_generation = int(generation) if generation is not None else existing.generation + 1
        if next_generation <= existing.generation:
            raise ReassignmentBlockedError(
                "generation must increase (have %d, requested %d)"
                % (existing.generation, next_generation)
            )
        return self._install(
            task_id, run_id, pid, start_token, command_hint,
            owns_process_group, next_generation,
        )

    def _install(self, task_id, run_id, pid, start_token, command_hint,
                 owns_process_group, generation) -> WorkerAssignment:
        pid = int(pid)
        if pid <= 1:
            raise RegistrationError("refusing to supervise pid %d" % pid)
        if pid == self._self_pid:
            raise RegistrationError("refusing to supervise the supervising process")
        token = start_token if start_token is not None else self.platform.instance_token(pid)
        if not token:
            raise RegistrationError(
                "cannot establish a process instance token for pid %d" % pid
            )
        assignment = WorkerAssignment(
            task_id=str(task_id),
            run_id=str(run_id),
            generation=int(generation),
            identity=ProcessIdentity(pid=pid, start_token=str(token),
                                     command_hint=str(command_hint)),
            owns_process_group=bool(owns_process_group),
            registered_at=self._wall_clock(),
        )
        self._assignments[str(task_id)] = assignment
        return assignment

    def current(self, task_id: str) -> Optional[WorkerAssignment]:
        return self._assignments.get(task_id)

    def evidence_for(self, task_id: str, generation: int) -> Optional[StopEvidence]:
        return self._history.get((str(task_id), int(generation)))

    # -- stop -------------------------------------------------------------
    def stop(
        self,
        task_id: str,
        generation: int,
        grace_seconds: Optional[float] = None,
    ) -> StopEvidence:
        """Stop generation ``generation`` of ``task_id``.

        Always returns evidence; never raises for authority failures. Rejected
        requests (unknown task, stale/future generation) signal nothing.
        """
        task_id = str(task_id)
        generation = int(generation)
        recorded = self._history.get((task_id, generation))
        if recorded is not None:
            return recorded  # idempotent replay: duplicate stop, no new signals

        assignment = self._assignments.get(task_id)
        if assignment is None:
            return self._reject(task_id, "", generation, REJECT_UNKNOWN_ASSIGNMENT)
        if generation != assignment.generation:
            reason = (
                REJECT_STALE_GENERATION
                if generation < assignment.generation
                else REJECT_FUTURE_GENERATION
            )
            return self._reject(task_id, assignment.run_id, generation, reason)

        return self._execute_stop(
            assignment,
            self.grace_seconds if grace_seconds is None else float(grace_seconds),
        )

    def _reject(self, task_id: str, run_id: str, generation: int, reason: str) -> StopEvidence:
        now = self._wall_clock()
        return StopEvidence(
            evidence_id=self._evidence_ids(),
            task_id=task_id,
            run_id=run_id,
            generation=generation,
            platform=self.platform.name,
            accepted=False,
            rejection=reason,
            terminal_state=None,
            requested_at=now,
            completed_at=now,
            grace_seconds=0.0,
            grace_elapsed=0.0,
            root_pid=None,
            expected_token=None,
            observed_token=None,
            notes=["rejected before any process operation"],
        )

    def _execute_stop(self, assignment: WorkerAssignment, grace: float) -> StopEvidence:
        started = self._clock()
        root = assignment.identity.pid
        evidence = StopEvidence(
            evidence_id=self._evidence_ids(),
            task_id=assignment.task_id,
            run_id=assignment.run_id,
            generation=assignment.generation,
            platform=self.platform.name,
            accepted=True,
            rejection=None,
            terminal_state=None,
            requested_at=self._wall_clock(),
            completed_at=0.0,
            grace_seconds=float(grace),
            grace_elapsed=0.0,
            root_pid=root,
            expected_token=assignment.identity.start_token,
            observed_token=None,
        )

        observed = self.platform.instance_token(root)
        evidence.observed_token = observed
        evidence.identity_checks.append(
            {
                "phase": "pre_stop",
                "pid": root,
                "expected": assignment.identity.start_token,
                "observed": observed,
                "match": observed == assignment.identity.start_token,
            }
        )
        if observed is None:
            evidence.notes.append("pid %d no longer exists; nothing signalled" % root)
            return self._finalise(assignment, evidence, STATE_ALREADY_EXITED, started)
        if observed != assignment.identity.start_token:
            evidence.notes.append(
                "pid %d hosts a different process instance (PID reuse); "
                "refusing to signal" % root
            )
            return self._finalise(assignment, evidence, STATE_IDENTITY_MISMATCH, started)

        targets, protected = self._owned_tree(root, evidence)
        evidence.tree_pids = sorted(targets.keys())
        evidence.protected_pids = sorted(protected)
        if root not in targets:
            # The registered root is protected (it is an ancestor of this
            # process, PID 1, ...). Fail closed rather than claim a stop.
            evidence.notes.append(
                "registered root pid %d is protected; refusing to signal" % root
            )
            return self._finalise(assignment, evidence, STATE_STOP_FAILED, started)

        # Graceful phase: root first, then shallow-to-deep descendants.
        for pid in self._graceful_order(targets):
            self._signal(evidence, pid, force=False, phase=PHASE_GRACEFUL)
        if assignment.owns_process_group:
            self._backstop(evidence, root, force=False)

        survivors = self._await_exit(targets, grace, started, evidence)
        if not survivors:
            evidence.grace_elapsed = self._clock() - started
            return self._finalise(assignment, evidence, STATE_STOPPED_GRACEFUL, started)

        evidence.grace_elapsed = self._clock() - started
        evidence.notes.append(
            "grace period expired with %d process(es) alive; escalating to hard kill"
            % len(survivors)
        )

        # Re-enumerate: a worker may have spawned children during the grace
        # window. Anything new must still be inside the owned tree.
        late_targets, late_protected = self._owned_tree(root, evidence)
        for pid, depth in late_targets.items():
            targets.setdefault(pid, depth)
        protected |= late_protected
        evidence.tree_pids = sorted(targets.keys())
        evidence.protected_pids = sorted(protected)

        for pid in self._force_order(targets):
            if not self.platform.is_alive(pid):
                continue
            self._signal(evidence, pid, force=True, phase=PHASE_FORCE)
        if assignment.owns_process_group:
            self._backstop(evidence, root, force=True)

        remaining = sorted(p for p in targets if self.platform.is_alive(p))
        evidence.survivors = remaining
        if remaining:
            evidence.notes.append(
                "hard kill did not clear pid(s) %s; stop is not verified"
                % ",".join(str(p) for p in remaining)
            )
            return self._finalise(assignment, evidence, STATE_STOP_FAILED, started)
        return self._finalise(assignment, evidence, STATE_STOPPED_FORCED, started)

    # -- helpers ----------------------------------------------------------
    def _owned_tree(self, root: int, evidence: StopEvidence) -> Tuple[Dict[int, int], set]:
        """Return ``({pid: depth}, protected_pids)`` for the tree rooted at ``root``."""
        evidence.commands.append(list(self.platform.snapshot_command()))
        snapshot = self.platform.snapshot()
        protected = {0, 1, self._self_pid}
        protected.update(ancestors_of(snapshot, self._self_pid))
        targets: Dict[int, int] = {int(root): 0}
        for depth, pid in descendants(snapshot, root):
            targets[pid] = depth
        dropped = sorted(p for p in targets if p in protected)
        for pid in dropped:
            targets.pop(pid, None)
            evidence.notes.append("protected pid %d excluded from target set" % pid)
        return targets, protected

    @staticmethod
    def _graceful_order(targets: Dict[int, int]) -> List[int]:
        # Root first so a well-behaved worker can wind its own children down,
        # then shallow-to-deep for anything it leaves behind.
        return [pid for pid, _ in sorted(targets.items(), key=lambda kv: (kv[1], kv[0]))]

    @staticmethod
    def _force_order(targets: Dict[int, int]) -> List[int]:
        # Deepest-first so children die before they are reparented away.
        return [pid for pid, _ in sorted(targets.items(), key=lambda kv: (-kv[1], kv[0]))]

    def _signal(self, evidence: StopEvidence, pid: int, force: bool, phase: str) -> None:
        record = self.platform.signal_process(pid, force=force)
        record["phase"] = phase
        evidence.signals.append(record)
        evidence.commands.append(list(record.get("command") or []))
        if force:
            evidence.forced_signalled.append(int(pid))
        else:
            evidence.graceful_signalled.append(int(pid))

    def _backstop(self, evidence: StopEvidence, root: int, force: bool) -> None:
        record = self.platform.signal_tree_backstop(root, force=force)
        record["phase"] = PHASE_FORCE if force else PHASE_GRACEFUL
        record["backstop"] = True
        evidence.signals.append(record)
        evidence.commands.append(list(record.get("command") or []))

    def _await_exit(self, targets, grace, started, evidence) -> List[int]:
        deadline = started + max(0.0, float(grace))
        while True:
            alive = sorted(p for p in targets if self.platform.is_alive(p))
            if not alive:
                return []
            if self._clock() >= deadline:
                return alive
            self._sleep(min(self.poll_seconds, max(0.0, deadline - self._clock())))

    def _finalise(self, assignment, evidence, state, started) -> StopEvidence:
        evidence.terminal_state = state
        evidence.completed_at = self._wall_clock()
        if not evidence.grace_elapsed:
            evidence.grace_elapsed = self._clock() - started
        evidence.graceful_signalled = sorted(set(evidence.graceful_signalled))
        evidence.forced_signalled = sorted(set(evidence.forced_signalled))
        assignment.state = state
        assignment.stopped_at = evidence.completed_at
        assignment.evidence = evidence
        if state in TERMINAL_STATES:
            # Only terminal outcomes are memoised, so a failed stop can be retried.
            self._history[(assignment.task_id, assignment.generation)] = evidence
        return evidence
