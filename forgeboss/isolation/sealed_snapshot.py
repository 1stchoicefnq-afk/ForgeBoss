"""FB-026 sealed immutable execution snapshot.

A thin ForgeBoss isolation boundary around upstream workers. It does three
things and nothing else:

1. ``create_sealed_snapshot`` materializes a disposable, worker-facing copy of
   an already-controller-validated source worktree. Host ``.git`` metadata,
   shared mutable refs and credential-bearing files are never copied in.
2. The copy is sealed by a deterministic ``Manifest`` (source identity, base
   identity, allowed-path set, per-file content digests, snapshot id). The
   manifest is authoritative about the *snapshot bytes*, not about the source,
   so later host-side source mutation cannot alter it.
3. ``SealedSnapshot.export_changes`` re-walks the snapshot after the worker has
   run and emits a bounded change-set. Any changed path outside the explicit
   allowed-path set fails closed.

Deliberately out of scope for this packet (Issue #16 architecture rule): no
network, no container orchestration, no daemon wiring, no Git plumbing or
commit creation, and no promotion/apply of an exported change-set.

Standard library only.

Known platform limitations
--------------------------
* This layer isolates *files*, not processes. It does not confine the worker
  process itself; a worker that writes outside ``work_root`` is out of reach
  here and is the container/process lane's problem. What this layer guarantees
  is that such writes never enter the change-set.
* ``O_NOFOLLOW`` does not exist on Win32, so the final-component race guard
  there degrades to the explicit ``islink``/``isjunction``/``realpath`` probes.
* Junction detection needs ``os.path.isjunction`` (CPython 3.12+). On older
  interpreters the ``realpath`` containment check is the remaining defence.
* Hardlinks to files outside the source root are indistinguishable from normal
  files and are copied by value; the snapshot is still a private copy.
* Concurrent host writes *during* the walk can produce a torn view of the
  source. The manifest stays exact with respect to the sealed bytes, which is
  the property later export decisions rely on.
* Refusals are strict by design: a source tree containing symlinks, FIFOs,
  device nodes, Win32 reserved names or components with leading/trailing dots
  or spaces is rejected outright rather than partially materialized.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence

SCHEMA = "forgeboss.isolation.sealed-snapshot/1"
SNAPSHOT_DIR_PREFIX = "fb-sealed-"
WORK_DIR_NAME = "work"
MANIFEST_FILE_NAME = "manifest.json"

# Isolation-layer metadata handed to the worker. Owned by this module: it is
# sealed like any other file, and it can never appear in an allowed-path set.
METADATA_DIR = ".forgeboss-isolation"
METADATA_PATH = METADATA_DIR + "/snapshot.json"

DEFAULT_MAX_FILES = 50_000
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_EXPORT_BYTES = 64 * 1024 * 1024

_CHUNK = 1024 * 1024

# Never materialized into the worker snapshot. VCS metadata (writable host
# .git, shared mutable refs) plus well-known credential stores.
EXCLUDED_DIR_NAMES = frozenset({
    ".git", ".hg", ".svn", ".bzr",
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker",
})
EXCLUDED_FILE_NAMES = frozenset({
    ".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials", ".gitconfig",
    ".htpasswd", ".pgpass", "credentials", "credentials.json",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
})
EXCLUDED_FILE_PREFIXES = (".env",)
EXCLUDED_FILE_SUFFIXES = (".pem", ".key", ".pfx", ".p12", ".keystore", ".jks", ".asc")

# Win32 device names are rejected in any path component, with or without an
# extension, because they resolve to devices rather than to files.
_WIN_RESERVED = frozenset(
    ["con", "prn", "aux", "nul"]
    + [f"com{i}" for i in range(1, 10)]
    + [f"lpt{i}" for i in range(1, 10)]
)
_BASE_IDENTITY_RE = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z._/@+-]{0,255}\Z")


class IsolationError(RuntimeError):
    """Base class. Every failure in this layer is a refusal, never a fallback."""


class SourceError(IsolationError):
    """Malformed or nonexistent source worktree / base identity."""


class UnsafePathError(IsolationError):
    """Symlink, junction, traversal, device or out-of-root path refused."""


class ScopeError(IsolationError):
    """A change touched a path outside the explicit allowed-path set."""


class SnapshotStateError(IsolationError):
    """The snapshot is gone or was tampered with."""


# --------------------------------------------------------------------------
# path handling
# --------------------------------------------------------------------------

def normalize_relative_path(value: object) -> str:
    """Normalize an untrusted relative path to a safe posix string.

    Refuses absolute, drive-qualified, UNC and ``\\\\?\\``/``\\\\.\\`` device
    paths, parent traversal, control characters, Win32 reserved device names
    and components with trailing dots or spaces (which Win32 silently strips,
    letting ``a.txt.`` alias ``a.txt``).
    """
    if not isinstance(value, str):
        raise UnsafePathError(f"path must be str, got {type(value).__name__}")
    raw = value.replace("\\", "/")
    if not raw:
        raise UnsafePathError("empty path")
    # Never silently strip: `" a.txt"` must not be allowed to alias `a.txt`.
    if raw != raw.strip():
        raise UnsafePathError(f"surrounding whitespace in path: {value!r}")
    if any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise UnsafePathError("control character in path")
    if raw.startswith(("/", "~")):
        raise UnsafePathError(f"absolute/home path denied: {value!r}")
    if len(raw) >= 2 and raw[1] == ":":
        raise UnsafePathError(f"drive-qualified path denied: {value!r}")
    parts = [p for p in PurePosixPath(raw).parts if p != "."]
    if not parts:
        raise UnsafePathError("empty normalized path")
    for part in parts:
        if part == "..":
            raise UnsafePathError(f"parent traversal denied: {value!r}")
        if part != part.strip(" ").rstrip("."):
            raise UnsafePathError(f"leading/trailing dot or space component denied: {value!r}")
        if part.split(".", 1)[0].casefold() in _WIN_RESERVED:
            raise UnsafePathError(f"reserved device name denied: {value!r}")
    return "/".join(parts)


def _path_key(rel: str) -> str:
    # Win32 and macOS default to case-insensitive filesystems; all scope
    # matching is casefolded so `SRC/a.py` cannot slip past an `src/` rule.
    return rel.casefold()


def _is_junction(path: str) -> bool:
    probe = getattr(os.path, "isjunction", None)
    if probe is None:
        return False
    try:
        return bool(probe(path))
    except OSError:
        return True


def _is_link_like(path: str) -> bool:
    try:
        if os.path.islink(path):
            return True
    except OSError:
        return True
    return _is_junction(path)


def _walk_error(exc: OSError) -> None:
    raise IsolationError(f"unreadable path during walk: {exc}") from exc


def _contained(root: str, candidate: str) -> bool:
    # normcase so a Win32 case or separator variant cannot dodge containment.
    root = os.path.normcase(root)
    candidate = os.path.normcase(candidate)
    if candidate == root:
        return True
    return candidate.startswith(root.rstrip(os.sep) + os.sep)


# --------------------------------------------------------------------------
# digests / canonical encoding
# --------------------------------------------------------------------------

def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _canonical_digest(payload: object) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _digest_file(path: str) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePathError(f"not a regular file: {path}")
        with os.fdopen(fd, "rb", closefd=True) as fh:
            fd = -1
            for chunk in iter(lambda: fh.read(_CHUNK), b""):
                h.update(chunk)
                size += len(chunk)
    finally:
        if fd >= 0:
            os.close(fd)
    return h.hexdigest(), size


# --------------------------------------------------------------------------
# manifest / change-set
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FileEntry:
    sha256: str
    size: int
    executable: bool

    def to_dict(self) -> dict:
        return {"sha256": self.sha256, "size": self.size, "executable": self.executable}


@dataclass(frozen=True)
class Manifest:
    """Deterministic record of exactly what was sealed.

    ``content_digest`` covers the project files only and is stable across two
    snapshots of identical source content. ``snapshot_id`` additionally mixes a
    fresh nonce, so distinct materializations are never confusable.
    """

    schema: str
    snapshot_id: str
    content_digest: str
    source_root: str
    base_identity: str
    allowed_paths: tuple[str, ...]
    files: Mapping[str, FileEntry]
    dirs: tuple[str, ...]
    excluded: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "snapshot_id": self.snapshot_id,
            "content_digest": self.content_digest,
            "source_root": self.source_root,
            "base_identity": self.base_identity,
            "allowed_paths": list(self.allowed_paths),
            "files": {k: v.to_dict() for k, v in sorted(self.files.items())},
            "dirs": list(self.dirs),
            "excluded": list(self.excluded),
        }

    @property
    def digest(self) -> str:
        """Accepted manifest identity. Frozen at seal time."""
        return _canonical_digest(self.to_dict())


@dataclass(frozen=True)
class ChangeEntry:
    path: str
    change: str  # "added" | "modified" | "deleted"
    sha256: str | None
    size: int | None
    executable: bool | None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "change": self.change,
            "sha256": self.sha256,
            "size": self.size,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class ChangeSet:
    """Bounded export. Renames appear as a ``deleted`` plus an ``added`` entry
    carrying the same digest; this layer deliberately does not infer renames."""

    schema: str
    snapshot_id: str
    base_identity: str
    manifest_digest: str
    entries: tuple[ChangeEntry, ...]
    blobs: Mapping[str, bytes]

    @property
    def digest(self) -> str:
        """Content identity of the change-set, independent of which snapshot
        produced it, so two runs over identical inputs compare equal."""
        return _canonical_digest({"schema": self.schema, "entries": [e.to_dict() for e in self.entries]})

    @property
    def added(self) -> tuple[str, ...]:
        return tuple(e.path for e in self.entries if e.change == "added")

    @property
    def modified(self) -> tuple[str, ...]:
        return tuple(e.path for e in self.entries if e.change == "modified")

    @property
    def deleted(self) -> tuple[str, ...]:
        return tuple(e.path for e in self.entries if e.change == "deleted")

    def is_empty(self) -> bool:
        return not self.entries

    def to_dict(self) -> dict:
        """JSON-safe view. Blobs are excluded; digests identify them."""
        return {
            "schema": self.schema,
            "snapshot_id": self.snapshot_id,
            "base_identity": self.base_identity,
            "manifest_digest": self.manifest_digest,
            "entries": [e.to_dict() for e in self.entries],
            "digest": self.digest,
        }


# --------------------------------------------------------------------------
# input validation
# --------------------------------------------------------------------------

def _validate_directory(value: object, label: str) -> str:
    if isinstance(value, bytes) or not isinstance(value, (str, os.PathLike)):
        raise SourceError(f"{label} must be a path, got {type(value).__name__}")
    text = os.fspath(value)
    if not isinstance(text, str) or not text.strip():
        raise SourceError(f"{label} is empty")
    if _is_link_like(text):
        raise UnsafePathError(f"{label} is a symlink/junction")
    real = os.path.realpath(text)
    if not os.path.exists(real):
        raise SourceError(f"{label} does not exist: {text}")
    if not os.path.isdir(real):
        raise SourceError(f"{label} is not a directory: {text}")
    return real


def _validate_base_identity(base_identity: object) -> str:
    if not isinstance(base_identity, str):
        raise SourceError(f"base_identity must be str, got {type(base_identity).__name__}")
    if base_identity != base_identity.strip() or not _BASE_IDENTITY_RE.match(base_identity):
        raise SourceError(f"malformed base_identity: {base_identity!r}")
    if ".." in PurePosixPath(base_identity).parts:
        raise SourceError(f"malformed base_identity: {base_identity!r}")
    return base_identity


def _validate_allowed_paths(allowed_paths: object) -> tuple[str, ...]:
    if isinstance(allowed_paths, (str, bytes)):
        raise SourceError("allowed_paths must be a collection of paths, not a single string")
    if not isinstance(allowed_paths, Iterable):
        raise SourceError(f"allowed_paths must be iterable, got {type(allowed_paths).__name__}")
    out: list[str] = []
    for raw in allowed_paths:
        rel = normalize_relative_path(raw)
        head = rel.split("/", 1)[0].casefold()
        if head in EXCLUDED_DIR_NAMES:
            raise ScopeError(f"allowed path targets excluded host metadata: {rel}")
        if head == METADATA_DIR.casefold():
            raise ScopeError(f"allowed path targets isolation-owned metadata: {rel}")
        out.append(rel)
    if len({_path_key(p) for p in out}) != len(out):
        raise SourceError("duplicate allowed_paths after casefold")
    return tuple(sorted(out))


def _within_allowed(rel: str, allowed: Sequence[str]) -> bool:
    key = _path_key(rel)
    for candidate in allowed:
        akey = _path_key(candidate)
        if key == akey or key.startswith(akey + "/"):
            return True
    return False


def _is_excluded_file(name: str) -> bool:
    low = name.casefold()
    return (
        # A linked Git worktree carries `.git` as a *file* pointing at the host
        # gitdir; it is excluded exactly like the directory form.
        low in EXCLUDED_DIR_NAMES
        or low in EXCLUDED_FILE_NAMES
        or low.startswith(EXCLUDED_FILE_PREFIXES)
        or low.endswith(EXCLUDED_FILE_SUFFIXES)
    )


# --------------------------------------------------------------------------
# deterministic, link-refusing tree removal
# --------------------------------------------------------------------------

def _remove_dir_entry(path: str) -> None:
    if _is_link_like(path):
        # Unlink the link itself; never recurse through it. Win32 directory
        # junctions need rmdir rather than unlink.
        try:
            os.unlink(path)
        except OSError:
            os.rmdir(path)
        return
    os.rmdir(path)


def _rmtree_nofollow(root: str) -> None:
    """Remove ``root`` without traversing symlinks or Win32 junctions."""
    if _is_link_like(root):
        raise UnsafePathError(f"refusing to recurse through link-like root: {root}")

    try:
        entries = sorted(os.scandir(root), key=lambda entry: entry.name)
    except OSError as ex:
        raise IsolationError(f"cannot scan cleanup directory {root}: {ex}") from ex

    for entry in entries:
        path = entry.path

        # Test link/junction status BEFORE asking whether this is a directory.
        # On Windows, a junction is a directory reparse point and os.walk can
        # otherwise enter its target even with followlinks=False.
        if _is_link_like(path):
            _remove_dir_entry(path)
            continue

        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError as ex:
            raise IsolationError(f"cannot inspect cleanup entry {path}: {ex}") from ex

        if is_dir:
            # Re-check immediately before recursion so a replaced directory
            # cannot silently become a link/junction between observations.
            if _is_link_like(path):
                _remove_dir_entry(path)
                continue

            if not _contained(root, os.path.realpath(path)):
                raise UnsafePathError(f"cleanup path resolves outside root: {path}")

            _rmtree_nofollow(path)
        else:
            os.unlink(path)

    os.rmdir(root)


# --------------------------------------------------------------------------
# snapshot
# --------------------------------------------------------------------------

class SealedSnapshot:
    """Handle to a materialized, sealed snapshot. Use as a context manager to
    guarantee deterministic cleanup."""

    def __init__(
        self,
        snapshot_dir: str,
        work_root: str,
        manifest: Manifest,
        *,
        max_files: int = DEFAULT_MAX_FILES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    ) -> None:
        self._snapshot_dir = snapshot_dir
        self._work_root = work_root
        self._manifest = manifest
        self._manifest_digest = manifest.digest
        self._max_files = max_files
        self._max_total_bytes = max_total_bytes
        self._cleaned = False

    # -- identity -----------------------------------------------------------
    @property
    def snapshot_id(self) -> str:
        return self._manifest.snapshot_id

    @property
    def manifest(self) -> Manifest:
        return self._manifest

    @property
    def manifest_digest(self) -> str:
        """Accepted manifest identity, captured at seal time."""
        return self._manifest_digest

    @property
    def work_root(self) -> Path:
        """Worker-facing root. Contains project files plus ``METADATA_PATH``."""
        return Path(self._work_root)

    @property
    def snapshot_dir(self) -> Path:
        """Private container. The manifest lives here, outside ``work_root``."""
        return Path(self._snapshot_dir)

    @property
    def allowed_paths(self) -> tuple[str, ...]:
        return self._manifest.allowed_paths

    @property
    def cleaned(self) -> bool:
        return self._cleaned

    # -- lifecycle ----------------------------------------------------------
    def __enter__(self) -> "SealedSnapshot":
        return self

    def __exit__(self, *_exc) -> None:
        self.cleanup()

    def _require_live(self) -> None:
        if self._cleaned:
            raise SnapshotStateError(f"snapshot {self.snapshot_id} already cleaned up")
        if not os.path.isdir(self._work_root):
            raise SnapshotStateError(f"snapshot work root missing: {self._work_root}")

    def cleanup(self) -> None:
        """Idempotent. Removes exactly this snapshot's directory and refuses to
        traverse links out of it, so a worker-planted link cannot be used to
        delete host state."""
        if self._cleaned:
            return
        root = self._snapshot_dir
        if not os.path.lexists(root):
            self._cleaned = True
            return
        if _is_link_like(root):
            raise UnsafePathError(f"snapshot root replaced by a link, refusing cleanup: {root}")
        if os.path.realpath(root) != root:
            raise UnsafePathError(f"snapshot root no longer resolves to itself: {root}")
        if not os.path.basename(root).startswith(SNAPSHOT_DIR_PREFIX):
            raise UnsafePathError(f"refusing to remove non-snapshot directory: {root}")
        _rmtree_nofollow(root)
        self._cleaned = True

    # -- export -------------------------------------------------------------
    def scan(self) -> dict[str, FileEntry]:
        """Current state of the worker snapshot, with the same link/traversal
        refusals used at seal time. No exclusions are applied here: hiding a
        worker-created path would be the opposite of fail-closed."""
        self._require_live()
        return _scan_tree(
            self._work_root,
            apply_exclusions=False,
            max_files=self._max_files,
            max_total_bytes=self._max_total_bytes,
        )[0]

    def export_changes(self, *, max_export_bytes: int = DEFAULT_MAX_EXPORT_BYTES) -> ChangeSet:
        """Compare the snapshot against the sealed manifest and emit a bounded
        change-set. Any change outside ``allowed_paths`` raises ``ScopeError``.
        """
        self._require_live()
        if self._manifest.digest != self._manifest_digest:
            raise SnapshotStateError("manifest identity drifted since seal time")

        current = self.scan()
        sealed = self._manifest.files
        entries: list[ChangeEntry] = []
        for rel in sorted(set(current) | set(sealed), key=_path_key):
            now, before = current.get(rel), sealed.get(rel)
            if now is None:
                entries.append(ChangeEntry(rel, "deleted", None, None, None))
            elif before is None:
                entries.append(ChangeEntry(rel, "added", now.sha256, now.size, now.executable))
            elif now != before:
                entries.append(ChangeEntry(rel, "modified", now.sha256, now.size, now.executable))

        # Fail closed before reading a single byte of an out-of-scope change.
        offenders = [e.path for e in entries if not _within_allowed(e.path, self._manifest.allowed_paths)]
        if offenders:
            raise ScopeError("changed paths outside allowed scope: " + ", ".join(sorted(offenders)))

        budget = 0
        blobs: dict[str, bytes] = {}
        for entry in entries:
            if entry.change == "deleted":
                continue
            budget += entry.size or 0
            if budget > max_export_bytes:
                raise IsolationError(f"export exceeds max_export_bytes={max_export_bytes}")
            data = _read_regular(os.path.join(self._work_root, *entry.path.split("/")))
            if hashlib.sha256(data).hexdigest() != entry.sha256:
                raise SnapshotStateError(f"content changed during export: {entry.path}")
            blobs[entry.path] = data

        return ChangeSet(
            schema=SCHEMA,
            snapshot_id=self.snapshot_id,
            base_identity=self._manifest.base_identity,
            manifest_digest=self._manifest_digest,
            entries=tuple(entries),
            blobs=blobs,
        )


def _read_regular(path: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise UnsafePathError(f"not a regular file: {path}")
        with os.fdopen(fd, "rb", closefd=True) as fh:
            fd = -1
            return fh.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _scan_tree(
    root: str,
    *,
    apply_exclusions: bool,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> tuple[dict[str, FileEntry], list[str], list[str]]:
    """Walk ``root`` refusing every escape primitive, returning
    ``(files, dirs, excluded)`` in deterministic order."""
    root = os.path.realpath(root)
    files: dict[str, FileEntry] = {}
    dirs: list[str] = []
    excluded: list[str] = []
    total = 0

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=_walk_error):
        if apply_exclusions:
            kept = []
            for name in sorted(dirnames):
                if name.casefold() in EXCLUDED_DIR_NAMES:
                    excluded.append(_rel_of(root, os.path.join(dirpath, name)) + "/")
                else:
                    kept.append(name)
            dirnames[:] = kept
        else:
            dirnames[:] = sorted(dirnames)

        for name in list(dirnames):
            child = os.path.join(dirpath, name)
            if _is_link_like(child):
                raise UnsafePathError(f"symlink/junction directory denied: {_rel_of(root, child)}")
            rel = _rel_of(root, child)
            if rel:
                dirs.append(rel)

        for name in sorted(filenames):
            child = os.path.join(dirpath, name)
            rel = _rel_of(root, child)
            if apply_exclusions and _is_excluded_file(name):
                excluded.append(rel)
                continue
            if _is_link_like(child):
                raise UnsafePathError(f"symlink/junction file denied: {rel}")
            st = os.lstat(child)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafePathError(f"non-regular file denied: {rel}")
            # Belt and braces: even with a link-free walk, confirm the entry
            # still resolves inside the root (catches junction/reparse and
            # bind-style escapes on platforms where the link probes are weak).
            if not _contained(root, os.path.realpath(child)):
                raise UnsafePathError(f"path resolves outside root: {rel}")
            digest, size = _digest_file(child)
            total += size
            if len(files) + 1 > max_files:
                raise IsolationError(f"tree exceeds max_files={max_files}")
            if total > max_total_bytes:
                raise IsolationError(f"tree exceeds max_total_bytes={max_total_bytes}")
            files[rel] = FileEntry(digest, size, bool(st.st_mode & stat.S_IXUSR))

    return files, sorted(dirs, key=_path_key), sorted(excluded, key=_path_key)


def _rel_of(root: str, path: str) -> str:
    rel = os.path.relpath(path, root)
    if rel == ".":
        return ""
    return normalize_relative_path(rel)


def create_sealed_snapshot(
    source_root,
    base_identity: str,
    allowed_paths: Iterable[str],
    *,
    parent_dir=None,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> SealedSnapshot:
    """Materialize a sealed, disposable worker snapshot.

    ``source_root`` must already have been validated by the controller;
    ``base_identity`` is the exact base revision the controller resolved (this
    layer records it, it never consults Git). ``allowed_paths`` is the explicit
    write scope enforced at export time.

    Raises a subclass of :class:`IsolationError` on any refusal, leaving no
    partial snapshot behind.
    """
    real_source = _validate_directory(source_root, "source_root")
    base = _validate_base_identity(base_identity)
    allowed = _validate_allowed_paths(allowed_paths)
    if max_files <= 0 or max_total_bytes <= 0:
        raise SourceError("max_files and max_total_bytes must be positive")

    if parent_dir is not None:
        parent = _validate_directory(parent_dir, "parent_dir")
    else:
        parent = os.path.realpath(tempfile.gettempdir())

    snapshot_dir = os.path.realpath(tempfile.mkdtemp(prefix=SNAPSHOT_DIR_PREFIX, dir=parent))
    try:
        os.chmod(snapshot_dir, 0o700)
        work_root = os.path.join(snapshot_dir, WORK_DIR_NAME)
        os.mkdir(work_root, 0o700)

        src_files, src_dirs, excluded = _scan_tree(
            real_source, apply_exclusions=True, max_files=max_files, max_total_bytes=max_total_bytes
        )

        for rel in src_dirs:
            os.makedirs(os.path.join(work_root, *rel.split("/")), mode=0o700, exist_ok=True)
        for rel, entry in sorted(src_files.items()):
            _copy_regular(
                os.path.join(real_source, *rel.split("/")),
                os.path.join(work_root, *rel.split("/")),
                entry.executable,
            )

        # The manifest describes the sealed bytes, so re-digest the copy rather
        # than trusting the source read. A source file mutated mid-copy yields
        # a manifest that still exactly matches what the worker will see.
        files, dirs, _ = _scan_tree(
            work_root, apply_exclusions=False, max_files=max_files, max_total_bytes=max_total_bytes
        )

        content_digest = _canonical_digest({
            "schema": SCHEMA,
            "source_root": real_source.replace("\\", "/"),
            "base_identity": base,
            "allowed_paths": list(allowed),
            "files": {k: v.to_dict() for k, v in sorted(files.items())},
            "dirs": list(dirs),
            "excluded": list(excluded),
        })
        snapshot_id = hashlib.sha256(content_digest.encode("ascii") + os.urandom(16)).hexdigest()[:32]

        # Worker-facing metadata: isolation-layer facts only. No host path, no
        # remotes, no credentials.
        meta_dir = os.path.join(work_root, METADATA_DIR)
        os.mkdir(meta_dir, 0o700)
        meta_path = os.path.join(work_root, *METADATA_PATH.split("/"))
        with open(meta_path, "wb") as fh:
            fh.write(_canonical({
                "schema": SCHEMA,
                "snapshot_id": snapshot_id,
                "base_identity": base,
                "allowed_paths": list(allowed),
            }))
        os.chmod(meta_path, 0o600)
        meta_digest, meta_size = _digest_file(meta_path)
        files[METADATA_PATH] = FileEntry(meta_digest, meta_size, False)
        dirs = sorted([*dirs, METADATA_DIR], key=_path_key)

        manifest = Manifest(
            schema=SCHEMA,
            snapshot_id=snapshot_id,
            content_digest=content_digest,
            source_root=real_source.replace("\\", "/"),
            base_identity=base,
            allowed_paths=allowed,
            files=dict(files),
            dirs=tuple(dirs),
            excluded=tuple(excluded),
        )
        # Manifest is stored beside the worker root, never inside it.
        with open(os.path.join(snapshot_dir, MANIFEST_FILE_NAME), "wb") as fh:
            fh.write(_canonical(manifest.to_dict()))

        return SealedSnapshot(
            snapshot_dir, work_root, manifest, max_files=max_files, max_total_bytes=max_total_bytes
        )
    except BaseException:
        _safe_discard(snapshot_dir)
        raise


def _copy_regular(src: str, dest: str, executable: bool) -> None:
    os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
    in_fd = os.open(src, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(in_fd).st_mode):
            raise UnsafePathError(f"not a regular file: {src}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        out_fd = os.open(dest, flags, 0o700 if executable else 0o600)
        try:
            with os.fdopen(in_fd, "rb", closefd=True) as fin:
                in_fd = -1
                with os.fdopen(out_fd, "wb", closefd=True) as fout:
                    out_fd = -1
                    for chunk in iter(lambda: fin.read(_CHUNK), b""):
                        fout.write(chunk)
        finally:
            if out_fd >= 0:
                os.close(out_fd)
    finally:
        if in_fd >= 0:
            os.close(in_fd)


def _safe_discard(snapshot_dir: str) -> None:
    """Best-effort removal of a partially built snapshot. Never raises over the
    original failure, and still refuses to follow links out of the root."""
    try:
        if os.path.lexists(snapshot_dir) and not _is_link_like(snapshot_dir):
            _rmtree_nofollow(snapshot_dir)
    except OSError:
        pass
