"""ForgeBoss worker isolation primitives.

FB-026: sealed immutable execution snapshot. A thin boundary that materializes
a disposable worker copy of a controller-validated worktree, seals it under a
deterministic manifest, and exports a scope-bounded change-set afterwards.
"""
from forgeboss.isolation.sealed_snapshot import (
    METADATA_PATH,
    SCHEMA,
    ChangeEntry,
    ChangeSet,
    FileEntry,
    IsolationError,
    Manifest,
    ScopeError,
    SealedSnapshot,
    SnapshotStateError,
    SourceError,
    UnsafePathError,
    create_sealed_snapshot,
    normalize_relative_path,
)

__all__ = [
    "METADATA_PATH",
    "SCHEMA",
    "ChangeEntry",
    "ChangeSet",
    "FileEntry",
    "IsolationError",
    "Manifest",
    "ScopeError",
    "SealedSnapshot",
    "SnapshotStateError",
    "SourceError",
    "UnsafePathError",
    "create_sealed_snapshot",
    "normalize_relative_path",
]
