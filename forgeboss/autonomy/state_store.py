"""Crash- and concurrency-safe JSON state primitives for the autonomy lane.

Every autonomy state file is consumed by paid-repair decision logic: the history
DBs decide whether ForgeBoss may skip a known-dead strategy or replay a proven
patch instead of paying for a fresh model repair, and the funnel/evidence/feedback
artefacts are what a paid call is actually driven from. Any of the following is a
spend or correctness defect, so all of them fail closed here:

  * a torn write leaving invalid JSON on disk;
  * two workers colliding on a shared temp path so one publishes the other's
    payload (cross-run evidence attribution) or fails unpredictably;
  * an unserialised read-modify-write silently dropping another worker's update;
  * a corrupt DB being read as ``{}`` and mistaken for a legitimate first run;
  * a stale in-memory snapshot overwriting a newer committed generation.

Guarantees
----------
``atomic_write_json``   unique O_EXCL temp in the destination directory, fsync of
                        the temp, atomic replace, directory fsync on POSIX. No
                        two writers can ever share a temp path, so a writer only
                        ever publishes its own bytes.
``file_lock``           kernel-owned advisory lock (``fcntl`` / ``msvcrt``) on a
                        sibling ``.lock`` file. Released by the OS if the holder
                        dies, so a crashed worker cannot wedge the lane.
``update_db``           read-modify-write executed entirely under that lock, so
                        concurrent updates serialise instead of losing writes.
``commit_db``           generation-checked compare-and-set for callers that must
                        compute outside the lock; a stale snapshot is rejected.
``load_db``             latching corruption handling. A corrupt DB is quarantined
                        under a unique name and a durable recovery marker is
                        written; every later call keeps failing until an operator
                        explicitly reconciles, so a missing DB after corruption is
                        never mistaken for a fresh start.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import stat
import tempfile
import time
import uuid
from pathlib import Path

IS_WINDOWS = os.name == "nt"
if IS_WINDOWS:
    import msvcrt
else:
    import fcntl

LOCK_SUFFIX = ".lock"
RECOVERY_SUFFIX = ".recovery-required.json"
DEFAULT_LOCK_TIMEOUT = float(os.environ.get("FORGEBOSS_AUTONOMY_LOCK_TIMEOUT", "60") or 60)
GENERATION_KEY = "_generation"
WRITER_KEY = "_last_writer"

# Stable identity for this process, so a published artefact can always be traced
# back to the run that produced it even though the canonical path is shared.
RUN_ID = os.environ.get("FORGEBOSS_AUTONOMY_RUN_ID") or f"{os.getpid()}-{uuid.uuid4().hex[:12]}"


class StateError(RuntimeError):
    """Base class for fail-closed autonomy state failures."""


class StateLockTimeout(StateError):
    """Another worker held the state lock for longer than the timeout."""


class StateCorruptionError(StateError):
    """The canonical state file was present but not usable; it is now quarantined."""


class StateRecoveryRequiredError(StateError):
    """A prior corruption has not been reconciled; the state is not trustworthy."""


class StaleWriterError(StateError):
    """A compare-and-set commit lost to a newer generation written concurrently."""


def _utc():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# --------------------------------------------------------------------------- #
# locking
# --------------------------------------------------------------------------- #

def lock_path(target) -> Path:
    return Path(str(target) + LOCK_SUFFIX)


def _acquire(handle):
    if IS_WINDOWS:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release(handle):
    try:
        if IS_WINDOWS:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        # Closing the handle drops the lock anyway; never mask the real result.
        pass


class file_lock:
    """Exclusive cross-process lock guarding one state path.

    The lock lives on a sibling ``<state>.lock`` file rather than on the state
    file itself, so an atomic replace of the state file never disturbs it. The
    lock file is deliberately never deleted: unlinking it would let a second
    process lock a different inode under the same name.

    Because the lock is a kernel advisory lock, a worker killed mid-update
    releases it automatically -- crash recovery needs no stale-lock heuristics.
    """

    def __init__(self, target, timeout=None, poll=0.005):
        self.path = lock_path(target)
        self.timeout = DEFAULT_LOCK_TIMEOUT if timeout is None else float(timeout)
        self.poll = poll
        self._handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.path, "a+b")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                _acquire(handle)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    handle.close()
                    raise StateLockTimeout(
                        f"Timed out after {self.timeout}s waiting for autonomy state lock {self.path}"
                    )
                # Jittered backoff so a queue of waiters does not lockstep.
                time.sleep(self.poll + random.random() * self.poll)
        self._handle = handle
        return handle

    def __exit__(self, exc_type, exc, tb):
        if self._handle is not None:
            _release(self._handle)
            self._handle.close()
            self._handle = None
        return False


# --------------------------------------------------------------------------- #
# atomic publication
# --------------------------------------------------------------------------- #

def _fsync_dir(directory: Path):
    if IS_WINDOWS:
        return  # Windows cannot open a directory handle this way; replace is durable enough.
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _replace_with_retry(src: Path, dst: Path, attempts=40, delay=0.05):
    # On Windows os.replace fails while another process still has the destination
    # open for reading; retry briefly rather than leaving a stray temp behind.
    for i in range(attempts):
        try:
            os.replace(str(src), str(dst))
            return
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def atomic_write_bytes(path, data: bytes, fsync=True) -> Path:
    """Publish ``data`` at ``path`` via a unique, exclusively created temp file.

    ``tempfile.mkstemp`` creates the temp with ``O_CREAT|O_EXCL`` and a random
    name in the destination directory, so concurrent writers can never share a
    temp path. That is what makes it impossible for one process to replace()
    another process's payload and report success for its own.
    """
    path = Path(path)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    mode = None
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        mode = None
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(directory))
    tmp = Path(tmp_name)
    published = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            if fsync:
                os.fsync(handle.fileno())
        if mode is not None:
            try:
                os.chmod(str(tmp), mode)
            except OSError:
                pass
        _replace_with_retry(tmp, path)
        published = True
        if fsync:
            _fsync_dir(directory)
    finally:
        if not published:
            try:
                tmp.unlink()
            except OSError:
                pass
    return path


def atomic_write_json(path, obj, indent=2, fsync=True) -> Path:
    return atomic_write_bytes(path, json.dumps(obj, indent=indent).encode("utf-8"), fsync=fsync)


def publish_artifact(path, obj, indent=2):
    """Atomically publish a single-run artefact, stamped with writer identity.

    The canonical ``*-last.json`` paths are read by the orchestrator outside this
    lane, so they must keep their names. Stamping the writer means a reader can
    still tell which run's payload the shared path currently holds instead of
    silently attributing another worker's evidence to its own run.
    """
    obj = dict(obj)
    obj[WRITER_KEY] = {"run_id": RUN_ID, "pid": os.getpid(), "published_at": _utc()}
    atomic_write_json(path, obj, indent=indent)
    return obj


# --------------------------------------------------------------------------- #
# corruption latch
# --------------------------------------------------------------------------- #

def recovery_marker_path(path) -> Path:
    return Path(str(path) + RECOVERY_SUFFIX)


def recovery_state(path):
    """Return the recovery marker for ``path``, or None when the state is clean.

    An unreadable marker still counts as latched: a marker we cannot parse is not
    evidence that recovery happened.
    """
    marker = recovery_marker_path(path)
    if not marker.exists():
        return None
    try:
        parsed = json.loads(marker.read_text(encoding="utf-8-sig"))
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return {"reason": "unreadable-recovery-marker", "marker": str(marker)}


def _latch_corruption(path: Path, reason: str):
    """Quarantine a corrupt state file under a unique name and latch recovery.

    The quarantine name carries pid + uuid as well as a timestamp because two
    processes can hit the same corrupt file inside the same second; a shared
    name would let one overwrite the other's evidence. The marker records what
    actually happened -- if the rename failed, it says so rather than claiming a
    quarantine that does not exist.
    """
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    quarantine = Path(f"{path}.corrupt-{stamp}-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    quarantined = None
    quarantine_error = None
    if path.exists():
        try:
            os.replace(str(path), str(quarantine))
            quarantined = str(quarantine)
        except OSError as exc:
            quarantine_error = f"{type(exc).__name__}: {exc}"
    marker = {
        "schema": 1,
        "kind": "forgeboss-autonomy-state-recovery-required",
        "state_path": str(path),
        "reason": reason,
        "detected_at": _utc(),
        "detected_by": {"run_id": RUN_ID, "pid": os.getpid()},
        "quarantined_to": quarantined,
        "quarantine_error": quarantine_error,
        "resolution": (
            "Autonomy history is not trustworthy. Reconcile the quarantined file, then run "
            "`python -m forgeboss.autonomy.state_store recover --path <state_path> --confirm`. "
            "Until then every read fails closed so no paid repair runs against empty history."
        ),
    }
    atomic_write_json(recovery_marker_path(path), marker)
    return marker


def _load_locked(path: Path, default):
    latched = recovery_state(path)
    if latched is not None:
        raise StateRecoveryRequiredError(
            f"Autonomy state {path} requires explicit recovery "
            f"(reason={latched.get('reason')!r}, quarantined_to={latched.get('quarantined_to')!r})"
        )
    if not path.exists():
        # Genuine first run: no file and, checked above, no corruption history.
        return json.loads(json.dumps(default)) if default is not None else {}
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise StateError(f"Cannot read autonomy state {path}: {exc}") from exc
    if not raw.strip():
        marker = _latch_corruption(path, "empty-state-file")
        raise StateCorruptionError(
            f"Autonomy state {path} was empty; quarantined_to={marker['quarantined_to']!r}"
        )
    try:
        doc = json.loads(raw)
    except Exception as exc:
        marker = _latch_corruption(path, f"invalid-json: {type(exc).__name__}")
        raise StateCorruptionError(
            f"Autonomy state {path} is not valid JSON; quarantined_to={marker['quarantined_to']!r}"
        ) from exc
    if not isinstance(doc, dict):
        marker = _latch_corruption(path, f"unexpected-root-type: {type(doc).__name__}")
        raise StateCorruptionError(
            f"Autonomy state {path} root is not an object; quarantined_to={marker['quarantined_to']!r}"
        )
    return doc


def _write_locked(path: Path, doc):
    atomic_write_json(path, doc)


# --------------------------------------------------------------------------- #
# read / modify / write
# --------------------------------------------------------------------------- #

def load_db(path, default=None, timeout=None):
    """Read a state DB, failing closed on corruption or unreconciled recovery."""
    path = Path(path)
    with file_lock(path, timeout):
        return _load_locked(path, default)


read_db = load_db


def generation(doc) -> int:
    try:
        return int(doc.get(GENERATION_KEY, 0))
    except (TypeError, ValueError):
        return 0


def _stamp(doc, base_generation):
    doc[GENERATION_KEY] = base_generation + 1
    doc[WRITER_KEY] = {"run_id": RUN_ID, "pid": os.getpid(), "committed_at": _utc()}
    return doc


def update_db(path, mutate, default=None, timeout=None):
    """Serialised read-modify-write.

    ``mutate`` runs while this process holds the exclusive lock, so it always
    observes the newest committed state and no concurrent worker's update can be
    lost. Keep ``mutate`` cheap -- do expensive work (git, subprocess, model
    calls) before calling this, then merge the precomputed result here.
    """
    path = Path(path)
    with file_lock(path, timeout):
        doc = _load_locked(path, default)
        base = generation(doc)
        result = mutate(doc)
        if result is None:
            result = doc
        _write_locked(path, _stamp(result, base))
        return result


def commit_db(path, doc, expected_generation, timeout=None):
    """Compare-and-set commit for work computed outside the lock.

    Rejects a stale writer: if the on-disk generation moved on since the caller
    read it, another worker committed in between and this snapshot would silently
    erase that update.
    """
    path = Path(path)
    with file_lock(path, timeout):
        current = _load_locked(path, {})
        actual = generation(current)
        if actual != int(expected_generation):
            raise StaleWriterError(
                f"Stale write to {path}: expected generation {expected_generation}, found {actual}"
            )
        _write_locked(path, _stamp(dict(doc), actual))
        return doc


def clear_recovery(path, confirm=False):
    """Explicit operator reconciliation. Refuses to run implicitly."""
    if not confirm:
        raise StateError("clear_recovery requires explicit confirmation")
    marker = recovery_marker_path(path)
    state = recovery_state(path)
    if state is None:
        return None
    with file_lock(path):
        try:
            marker.unlink()
        except FileNotFoundError:
            pass
    return state


# --------------------------------------------------------------------------- #
# operator CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(description="Inspect or reconcile autonomy state files.")
    sp = ap.add_subparsers(dest="cmd", required=True)
    st = sp.add_parser("status");  st.add_argument("--path", required=True)
    rc = sp.add_parser("recover"); rc.add_argument("--path", required=True); rc.add_argument("--confirm", action="store_true")
    ns = ap.parse_args(argv)
    target = Path(ns.path)
    if ns.cmd == "status":
        state = recovery_state(target)
        print(json.dumps({
            "path": str(target),
            "exists": target.exists(),
            "recovery_required": state is not None,
            "marker": state,
        }, indent=2))
        return 9 if state is not None else 0
    if not ns.confirm:
        print(json.dumps({"ok": False, "reason": "refusing to clear recovery marker without --confirm"}))
        return 2
    cleared = clear_recovery(target, confirm=True)
    print(json.dumps({"ok": True, "cleared": cleared is not None, "marker": cleared}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
