"""Fail-closed shared-state primitives for the ForgeBoss autonomy lane.

The autonomy lane persists two authority documents -- ``repair-memory.json`` and
``repair-playbook.json`` -- that decide whether ForgeBoss may skip a known-dead
repair strategy or replay an already-proven patch instead of paying for a fresh
model call. Losing, truncating or silently emptying either document
re-authorises paid work that was already resolved, so every read and write in
this module is required to fail closed rather than degrade to "no history".

Guarantees provided here:

* **Publication is atomic and durable.** Every write goes to a fresh
  ``mkstemp`` file in the destination directory (never a shared ``<name>.tmp``
  sibling), is flushed and ``fsync``-ed, then ``os.replace``-d into place, with
  a directory ``fsync`` on POSIX. A writer can only ever publish its own bytes.

* **Read-modify-write is serialised across processes** by a kernel advisory
  lock. The kernel drops the lock when a worker dies, so a killed worker cannot
  wedge the lane.

* **The lock's identity is verified, not assumed.** The lock file is opened
  ``O_NOFOLLOW``; after acquisition -- and again immediately before any
  publication -- the locked inode is compared against the inode the lock path
  currently resolves to. A sibling that unlinks/replaces/symlinks the lock path
  can therefore no longer cause two processes to believe they hold the same
  lock and both commit.

* **Configuration is validated before it is used.** A non-finite, non-positive
  or out-of-range lock timeout is a configuration error, not an unbounded wait.

* **Generation is authority metadata.** A malformed ``_generation`` is state
  corruption; it is never coerced to ``0``.

* **Corruption latches.** A corrupt document is quarantined under a unique name
  and a durable recovery marker is written. Every later call keeps failing
  closed until an operator performs a real reconciliation -- recovery is a
  state transition that publishes a validated canonical document, not a marker
  deletion.
"""
from __future__ import annotations

import argparse
import copy
import errno
import hashlib
import json
import os
import stat
import sys
import tempfile
import time
import uuid
from pathlib import Path

SCHEMA = 1

# ---------------------------------------------------------------------------
# Errors. Every one of these means "stop", never "continue with empty history".
# ---------------------------------------------------------------------------


class StateStoreError(Exception):
    """Base class for every fail-closed condition in this module."""


class ConfigError(StateStoreError):
    """Operator/environment configuration is unusable."""


class LockTimeout(StateStoreError):
    """The state lock could not be acquired inside the validated timeout."""


class LockIdentityError(StateStoreError):
    """The lock path no longer names the inode this process locked."""


class StateCorruption(StateStoreError):
    """The canonical document is unreadable or its authority metadata is invalid."""


class RecoveryRequired(StateStoreError):
    """A corruption latch is active; an operator reconciliation is outstanding."""


class StaleRecoveryError(StateStoreError):
    """A recovery attempt is bound to a marker that is no longer current."""


class StaleWriterError(StateStoreError):
    """A compare-and-set commit was rejected because the document moved on."""


# ---------------------------------------------------------------------------
# Configuration validation (defect 1)
# ---------------------------------------------------------------------------

LOCK_TIMEOUT_MIN = 0.1
LOCK_TIMEOUT_MAX = 3600.0
LOCK_TIMEOUT_DEFAULT = 60.0
LOCK_POLL_MIN = 0.001
LOCK_POLL_MAX = 1.0
LOCK_POLL_DEFAULT = 0.02

LOCK_TIMEOUT_ENV = "FORGEBOSS_AUTONOMY_LOCK_TIMEOUT"
LOCK_POLL_ENV = "FORGEBOSS_AUTONOMY_LOCK_POLL"

_MAX_CONFIG_CHARS = 32


def parse_seconds(raw, *, name, low, high, default):
    """Return a finite float in ``[low, high]`` or raise :class:`ConfigError`.

    ``float("nan")`` makes every ``monotonic() >= deadline`` comparison false and
    ``float("inf")`` never expires, so either one turns a contended lock into an
    immortal wait. Both are rejected here, before any lock is attempted.
    """
    if raw is None:
        value = float(default)
    elif isinstance(raw, bool):
        # bool is an int subclass; accepting it would silently mean 0/1 seconds.
        raise ConfigError(f"{name} must be a number, not a boolean")
    elif isinstance(raw, (int, float)):
        value = float(raw)
    elif isinstance(raw, str):
        text = raw.strip()
        if not text:
            value = float(default)
        elif len(text) > _MAX_CONFIG_CHARS:
            raise ConfigError(f"{name} value is oversized ({len(text)} chars)")
        else:
            try:
                value = float(text)
            except ValueError:
                raise ConfigError(f"{name} is not a number: {text!r}") from None
    else:
        raise ConfigError(f"{name} has unsupported type {type(raw).__name__}")

    if value != value:  # NaN
        raise ConfigError(f"{name} must be finite, got NaN")
    if value in (float("inf"), float("-inf")):
        raise ConfigError(f"{name} must be finite, got {value}")
    if value <= 0:
        raise ConfigError(f"{name} must be positive, got {value}")
    if value < low or value > high:
        raise ConfigError(f"{name} must be within [{low}, {high}], got {value}")
    return value


def lock_timeout(explicit=None):
    raw = explicit if explicit is not None else os.environ.get(LOCK_TIMEOUT_ENV)
    return parse_seconds(raw, name=LOCK_TIMEOUT_ENV, low=LOCK_TIMEOUT_MIN,
                         high=LOCK_TIMEOUT_MAX, default=LOCK_TIMEOUT_DEFAULT)


def lock_poll(explicit=None):
    raw = explicit if explicit is not None else os.environ.get(LOCK_POLL_ENV)
    return parse_seconds(raw, name=LOCK_POLL_ENV, low=LOCK_POLL_MIN,
                         high=LOCK_POLL_MAX, default=LOCK_POLL_DEFAULT)


# ---------------------------------------------------------------------------
# Writer identity.
#
# NOTE (cross-lane): FORGEBOSS_AUTONOMY_RUN_ID is mutable environment text. It
# is recorded as a *claim* only -- two processes can assert the same value -- so
# it is stamped with run_id_authenticated=False. Authenticated run/assignment
# identity has to come from the controller, which is outside this lane.
# ---------------------------------------------------------------------------

RUN_ID_ENV = "FORGEBOSS_AUTONOMY_RUN_ID"


def claimed_run_id():
    raw = os.environ.get(RUN_ID_ENV) or ""
    text = str(raw).strip()[:200]
    return text or None


def writer_stamp():
    return {
        "pid": os.getpid(),
        "claimed_run_id": claimed_run_id(),
        "run_id_authenticated": False,
        "at": time.time(),
    }


# ---------------------------------------------------------------------------
# Strict JSON. Duplicate keys and NaN/Infinity are not valid authority state.
# ---------------------------------------------------------------------------


def _reject_duplicate_keys(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate object key: {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_constant(name):
    raise ValueError(f"non-finite JSON constant is not valid state: {name}")


def strict_loads(text):
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                      parse_constant=_reject_constant)


def _dumps(obj):
    # allow_nan=False keeps us from writing what strict_loads would refuse to read.
    return json.dumps(obj, indent=2, allow_nan=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Durable publication
# ---------------------------------------------------------------------------


def _fsync_dir(directory):
    if os.name == "nt":
        # Windows has no directory handle to fsync; pretending otherwise would
        # overstate the durability guarantee.
        return False
    fd = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def publish_bytes(path, data, *, lock=None):
    """Atomically and durably replace ``path`` with ``data``.

    A unique ``mkstemp`` temp is used so two concurrent writers can never share
    a temp path (which previously let one process publish another's payload and
    still report success). When ``lock`` is given its identity is re-verified
    immediately before the replace, so a writer whose lock was swapped out from
    under it aborts instead of committing.
    """
    path = Path(path)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp",
                                    dir=str(directory))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if lock is not None:
            lock.assert_held()
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    _fsync_dir(directory)
    return path


def publish_json(path, obj, *, lock=None):
    return publish_bytes(path, _dumps(obj).encode("utf-8"), lock=lock)


def publish_artifact(path, obj, *, lock=None):
    """Publish a single-run artefact with provenance attached.

    These artefacts live at a shared ``*-last.json`` path, so the producing
    writer is recorded to keep one run's evidence from being read as another's.
    """
    out = dict(obj)
    out["_provenance"] = writer_stamp()
    return publish_json(path, out, lock=lock)


# ---------------------------------------------------------------------------
# Lock with verified identity (defect 3)
# ---------------------------------------------------------------------------

_IDENTITY_RETRY_LIMIT = 8

if os.name == "nt":  # pragma: no cover - exercised on Windows only
    import msvcrt

    def _try_acquire(fd):
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EDEADLOCK):
                return False
            raise

    def _release(fd):
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
else:
    import fcntl

    def _try_acquire(fd):
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK):
                return False
            raise

    def _release(fd):
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass


def lock_path_for(path):
    return Path(str(path) + ".lock")


class FileLock:
    """Advisory inter-process lock whose inode identity is verified.

    The lock file is deliberately never unlinked by this implementation, but a
    sibling process could still unlink or replace the path. If that happens
    while we hold the kernel lock, a second process would lock the *new* inode
    and both would believe they hold exclusivity. Every acquisition and every
    subsequent :meth:`assert_held` therefore compares the locked inode against
    the inode the path currently names, and a mismatch fails closed.
    """

    def __init__(self, path, timeout=None, poll=None):
        self.path = Path(path)
        self.lock_path = lock_path_for(self.path)
        # Validated up front: a hostile/malformed timeout must never reach the
        # deadline arithmetic.
        self.timeout = lock_timeout(timeout)
        self.poll = lock_poll(poll)
        self.fd = None
        self.identity = None

    # -- identity ---------------------------------------------------------
    def _open_lock(self):
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        try:
            return os.open(str(self.lock_path), flags, 0o600)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise LockIdentityError(
                    f"lock path is a symlink: {self.lock_path}") from None
            raise

    def _identity_of(self, fd):
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise LockIdentityError(f"lock is not a regular file: {self.lock_path}")
        if getattr(st, "st_nlink", 1) != 1:
            raise LockIdentityError(
                f"lock file has {st.st_nlink} links; refusing hard-linked lock")
        getuid = getattr(os, "getuid", None)
        if getuid is not None and st.st_uid != getuid():
            raise LockIdentityError("lock file is owned by another user")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise LockIdentityError("lock file is group/world writable")
        try:
            current = os.lstat(str(self.lock_path))
        except FileNotFoundError:
            raise LockIdentityError(
                f"lock path was removed while held: {self.lock_path}") from None
        if stat.S_ISLNK(current.st_mode):
            raise LockIdentityError(f"lock path is a symlink: {self.lock_path}")
        if (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino):
            raise LockIdentityError(
                f"lock path was replaced while held: {self.lock_path}")
        return (st.st_dev, st.st_ino)

    def assert_held(self):
        """Re-verify that we still hold the lock on the inode the path names."""
        if self.fd is None:
            raise LockIdentityError("lock is not held")
        identity = self._identity_of(self.fd)
        if identity != self.identity:
            raise LockIdentityError("lock inode changed while held")
        return identity

    # -- context manager --------------------------------------------------
    def __enter__(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        identity_retries = 0
        while True:
            fd = self._open_lock()
            acquired = False
            try:
                acquired = _try_acquire(fd)
                if acquired:
                    identity = self._identity_of(fd)
                    self.fd = fd
                    self.identity = identity
                    return self
            except LockIdentityError:
                if acquired:
                    _release(fd)
                os.close(fd)
                identity_retries += 1
                if identity_retries >= _IDENTITY_RETRY_LIMIT:
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(self.poll)
                continue
            except BaseException:
                if acquired:
                    _release(fd)
                os.close(fd)
                raise
            os.close(fd)
            if time.monotonic() >= deadline:
                raise LockTimeout(
                    f"could not acquire {self.lock_path} within {self.timeout}s")
            time.sleep(self.poll)

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            _release(self.fd)
            os.close(self.fd)
            self.fd = None
            self.identity = None
        return False


def file_lock(path, timeout=None, poll=None):
    return FileLock(path, timeout=timeout, poll=poll)


# ---------------------------------------------------------------------------
# Generation as authority metadata (defect 2)
# ---------------------------------------------------------------------------

GENERATION_MAX = 2 ** 53 - 1
STORE_KEY = "_state_store"
GENERATION_KEY = "_generation"


def _is_managed(doc):
    """True once this document has been written by state_store at least once."""
    return isinstance(doc, dict) and isinstance(doc.get(STORE_KEY), dict)


def generation(doc):
    """Return the document's generation, or raise :class:`StateCorruption`.

    ``_generation`` decides which compare-and-set commits are allowed, so a
    malformed value is corruption. Coercing it to ``0`` (the previous
    behaviour) let tampered or damaged state be renormalised into a legitimate
    generation-zero authority object on the very next write.
    """
    if not isinstance(doc, dict):
        raise StateCorruption(f"state document must be an object, got {type(doc).__name__}")
    if GENERATION_KEY not in doc:
        if _is_managed(doc):
            raise StateCorruption("managed state is missing _generation")
        # Explicit legacy migration: a document written before this module
        # existed carries no store marker and starts at generation 0.
        return 0
    value = doc[GENERATION_KEY]
    if isinstance(value, bool) or not isinstance(value, int):
        raise StateCorruption(
            f"_generation must be an integer, got {type(value).__name__}: {value!r}")
    if value < 0:
        raise StateCorruption(f"_generation must be non-negative, got {value}")
    if value > GENERATION_MAX:
        raise StateCorruption(f"_generation is out of range: {value}")
    return value


def _stamp(doc, gen):
    out = dict(doc)
    out[GENERATION_KEY] = gen
    out[STORE_KEY] = {"schema": SCHEMA, "version": 1}
    out["_last_writer"] = writer_stamp()
    return out


# ---------------------------------------------------------------------------
# Corruption latch and recovery (defect 4)
# ---------------------------------------------------------------------------


def marker_path_for(path):
    return Path(str(path) + ".recovery-required.json")


def recovery_log_for(path):
    return Path(str(path) + ".recovery-log.jsonl")


def _read_marker(path):
    """Return ``(present, parsed_or_None)`` for the recovery marker."""
    marker = marker_path_for(path)
    try:
        raw = marker.read_bytes()
    except FileNotFoundError:
        return False, None
    try:
        parsed = strict_loads(raw.decode("utf-8-sig"))
    except Exception:
        return True, None
    if not isinstance(parsed, dict):
        return True, None
    return True, parsed


def _latch_corruption(path, raw, reason, lock, observed_generation=None):
    """Quarantine corrupt state and durably record that recovery is required.

    The first marker wins: a later corruption must not overwrite the evidence an
    operator is already reconciling.
    """
    present, existing = _read_marker(path)
    if present:
        return existing

    digest = hashlib.sha256(raw or b"").hexdigest()
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    quarantine = Path(str(path) + f".corrupt-{stamp}-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    quarantined_to = None
    quarantine_error = None
    try:
        os.replace(str(path), str(quarantine))
        quarantined_to = str(quarantine)
    except OSError as exc:
        # Report what actually happened; never claim a quarantine that failed.
        quarantine_error = f"{type(exc).__name__}: {exc}"

    marker = {
        "schema": SCHEMA,
        "kind": "forgeboss-autonomy-recovery-required",
        "marker_id": uuid.uuid4().hex,
        "state_path": str(path),
        "reason": str(reason),
        "corrupt_sha256": digest,
        "corrupt_bytes": len(raw or b""),
        "observed_generation": observed_generation,
        "quarantined_to": quarantined_to,
        "quarantine_error": quarantine_error,
        "created_at": time.time(),
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "writer": writer_stamp(),
    }
    publish_json(marker_path_for(path), marker, lock=lock)
    return marker


def _recovery_message(path, marker):
    if marker is None:
        return (f"state {path} is latched for recovery but the marker is unreadable; "
                "an operator must inspect it manually")
    return (
        f"state {path} requires operator recovery "
        f"(marker_id={marker.get('marker_id')} corrupt_sha256={marker.get('corrupt_sha256')}). "
        "Reconcile the quarantined file, then run: python -m forgeboss.autonomy.state_store "
        f"recover --path {path} --marker-id {marker.get('marker_id')} "
        f"--quarantine-sha256 {marker.get('corrupt_sha256')} --from <reconciled.json>"
    )


def _append_receipt(path, receipt):
    log = recovery_log_for(path)
    log.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(receipt, allow_nan=False, sort_keys=True) + "\n"
    fd = os.open(str(log), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(log.parent)


# ---------------------------------------------------------------------------
# Load / update / commit
# ---------------------------------------------------------------------------


def _default_doc(default):
    return copy.deepcopy(default) if default is not None else {}


def _load_locked(path, default, lock):
    path = Path(path)
    present, marker = _read_marker(path)
    # Checked BEFORE the missing-file branch: after a quarantine the canonical
    # path is absent, and treating that as a legitimate first run is exactly the
    # fail-open reset the latch exists to prevent.
    if present:
        raise RecoveryRequired(_recovery_message(path, marker))

    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        if recovery_log_for(path).exists():
            # State was reconciled at least once, so a missing canonical file is
            # not a genuine first run.
            raise StateCorruption(
                f"canonical state {path} is absent but a recovery log exists; "
                "refusing to treat previously reconciled history as a first run")
        return _default_doc(default)

    try:
        doc = strict_loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        marker = _latch_corruption(path, raw, f"unparseable state: {exc}", lock)
        raise StateCorruption(_recovery_message(path, marker)) from None

    if not isinstance(doc, dict):
        marker = _latch_corruption(path, raw,
                                   f"state root must be an object, got {type(doc).__name__}",
                                   lock)
        raise StateCorruption(_recovery_message(path, marker)) from None

    try:
        generation(doc)
    except StateCorruption as exc:
        marker = _latch_corruption(path, raw, str(exc), lock)
        raise StateCorruption(_recovery_message(path, marker)) from None

    return doc


def load_db(path, default=None, *, timeout=None):
    """Read the canonical document, failing closed on corruption or latch."""
    with file_lock(path, timeout=timeout) as lock:
        return _load_locked(path, default, lock)


def update_db(path, mutate, default=None, *, timeout=None):
    """Serialised read-modify-write. ``mutate`` receives and returns the document."""
    path = Path(path)
    with file_lock(path, timeout=timeout) as lock:
        current = _load_locked(path, default, lock)
        gen = generation(current)
        updated = mutate(copy.deepcopy(current))
        if not isinstance(updated, dict):
            raise StateStoreError("mutate() must return an object")
        out = _stamp(updated, gen + 1)
        publish_json(path, out, lock=lock)
        return out


def commit_db(path, doc, expected_generation, default=None, *, timeout=None):
    """Compare-and-set commit; rejects a stale snapshot overwriting newer state."""
    path = Path(path)
    if isinstance(expected_generation, bool) or not isinstance(expected_generation, int):
        raise StateStoreError("expected_generation must be an integer")
    with file_lock(path, timeout=timeout) as lock:
        current = _load_locked(path, default, lock)
        actual = generation(current)
        if actual != expected_generation:
            raise StaleWriterError(
                f"generation moved from {expected_generation} to {actual}")
        out = _stamp(doc, actual + 1)
        publish_json(path, out, lock=lock)
        return out


def recovery_state(path, *, timeout=None):
    """Return the active recovery marker (or ``None``) under the state lock."""
    with file_lock(path, timeout=timeout):
        present, marker = _read_marker(path)
        if not present:
            return None
        return marker if marker is not None else {"unreadable": True}


def recover(path, *, marker_id, quarantine_sha256=None, replacement=None,
            reset_empty=False, accept_history_loss=False, operator=None,
            timeout=None):
    """Reconcile a corruption latch. This is a state transition, not a delete.

    The whole operation -- read marker, verify binding, validate the replacement,
    publish canonical state, write the receipt, clear the marker -- runs inside a
    single lock acquisition and is bound to the exact ``marker_id`` (and
    optionally the quarantined digest). A recovery decided against an older
    marker therefore cannot erase a newer corruption latch, and clearing the
    marker without publishing validated state is not reachable.
    """
    path = Path(path)
    if replacement is None and not reset_empty:
        raise StaleRecoveryError(
            "recovery requires a reconciled replacement document (--from) or an "
            "explicit --reset-empty --accept-history-loss")
    if replacement is not None and reset_empty:
        raise StaleRecoveryError("--from and --reset-empty are mutually exclusive")
    if reset_empty and not accept_history_loss:
        raise StaleRecoveryError(
            "--reset-empty discards paid-repair history and requires "
            "--accept-history-loss")

    with file_lock(path, timeout=timeout) as lock:
        present, marker = _read_marker(path)
        if not present:
            raise StaleRecoveryError(f"no recovery is required for {path}")
        if marker is None:
            raise StaleRecoveryError(
                f"the recovery marker for {path} is unreadable; an operator must "
                "inspect and replace it before recovery can be bound to it")
        if str(marker.get("marker_id")) != str(marker_id):
            raise StaleRecoveryError(
                f"stale recovery: marker is {marker.get('marker_id')}, "
                f"not {marker_id}; a newer corruption must be reviewed first")
        if quarantine_sha256 is not None and \
                str(marker.get("corrupt_sha256")) != str(quarantine_sha256):
            raise StaleRecoveryError(
                "stale recovery: quarantined evidence digest does not match the "
                "current marker")

        if reset_empty:
            doc = {}
            source = None
            source_sha256 = None
            base_generation = 0
        else:
            source = Path(replacement)
            raw = source.read_bytes()
            source_sha256 = hashlib.sha256(raw).hexdigest()
            try:
                doc = strict_loads(raw.decode("utf-8-sig"))
            except Exception as exc:
                raise StaleRecoveryError(
                    f"replacement document is not strict JSON: {exc}") from None
            if not isinstance(doc, dict):
                raise StaleRecoveryError("replacement document must be an object")
            base_generation = generation(doc)

        observed = marker.get("observed_generation")
        if isinstance(observed, int) and not isinstance(observed, bool) and observed >= 0:
            base_generation = max(base_generation, observed)
        # Strictly ahead of anything a stale in-flight writer could hold.
        out = _stamp(doc, base_generation + 1)
        out["_recovered_from"] = {
            "marker_id": marker.get("marker_id"),
            "corrupt_sha256": marker.get("corrupt_sha256"),
            "quarantined_to": marker.get("quarantined_to"),
            "replacement": str(source) if source else None,
            "replacement_sha256": source_sha256,
            "history_discarded": bool(reset_empty),
            "operator": operator,
            "at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if reset_empty:
            # Downstream must be able to see that paid-repair history was wiped.
            out["_history_reset_unacknowledged"] = True

        publish_json(path, out, lock=lock)

        receipt = dict(out["_recovered_from"])
        receipt.update({
            "schema": SCHEMA,
            "kind": "forgeboss-autonomy-recovery-receipt",
            "state_path": str(path),
            "published_generation": out[GENERATION_KEY],
            "writer": writer_stamp(),
        })
        _append_receipt(path, receipt)

        lock.assert_held()
        try:
            marker_path_for(path).unlink()
        except FileNotFoundError:
            pass
        _fsync_dir(path.parent)
        return receipt


# ---------------------------------------------------------------------------
# Operator CLI
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_LOCK_IDENTITY = 7
EXIT_LOCK_TIMEOUT = 8
EXIT_RECOVERY = 9
EXIT_CONFIG = 10


def exit_code_for(exc):
    if isinstance(exc, ConfigError):
        return EXIT_CONFIG
    if isinstance(exc, LockTimeout):
        return EXIT_LOCK_TIMEOUT
    if isinstance(exc, LockIdentityError):
        return EXIT_LOCK_IDENTITY
    if isinstance(exc, (StateCorruption, RecoveryRequired, StaleRecoveryError,
                        StaleWriterError, StateStoreError)):
        return EXIT_RECOVERY
    return 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="state_store")
    sub = ap.add_subparsers(dest="cmd", required=True)

    st = sub.add_parser("status")
    st.add_argument("--path", required=True)

    rc = sub.add_parser("recover")
    rc.add_argument("--path", required=True)
    rc.add_argument("--marker-id", required=True)
    rc.add_argument("--quarantine-sha256")
    rc.add_argument("--from", dest="replacement")
    rc.add_argument("--reset-empty", action="store_true")
    rc.add_argument("--accept-history-loss", action="store_true")
    rc.add_argument("--operator")

    ns = ap.parse_args(argv)
    try:
        if ns.cmd == "status":
            marker = recovery_state(ns.path)
            print(json.dumps({
                "path": ns.path,
                "recovery_required": marker is not None,
                "marker": marker,
            }, separators=(",", ":")))
            return EXIT_RECOVERY if marker is not None else EXIT_OK
        receipt = recover(ns.path, marker_id=ns.marker_id,
                          quarantine_sha256=ns.quarantine_sha256,
                          replacement=ns.replacement,
                          reset_empty=ns.reset_empty,
                          accept_history_loss=ns.accept_history_loss,
                          operator=ns.operator)
        print(json.dumps({"ok": True, "receipt": receipt}, separators=(",", ":")))
        return EXIT_OK
    except StateStoreError as exc:
        print(json.dumps({"ok": False, "fail_closed": True,
                          "error": type(exc).__name__, "detail": str(exc)},
                         separators=(",", ":")), file=sys.stderr)
        return exit_code_for(exc)


if __name__ == "__main__":
    raise SystemExit(main())
