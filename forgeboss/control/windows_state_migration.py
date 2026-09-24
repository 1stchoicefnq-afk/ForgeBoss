from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import time
from types import MappingProxyType
from typing import Mapping

from forgeboss.control.windows_service_sid import (
    ServiceSidConfigError,
    assert_service_sid_in_current_token,
    resolve_service_sid,
)
from forgeboss.control.windows_service_state import (
    ServicePrivateStateError,
    create_private_root_atomic,
    inspect_private_directory_acl,
    verify_private_acl_exact,
)


class StateMigrationError(RuntimeError):
    """Raised when service-private control-state migration cannot be proven safe."""


SOURCE_DB = "forgeboss.db"
SECRET_FILES = (
    "daemon-secret.bin",
    "policy-approval-secret.bin",
    "governed-launch-secret.bin",
)
CANDIDATE_DIR = "candidate-state-v1"
MANIFEST_FILE = "MIGRATION-MANIFEST.json"


@dataclass(frozen=True)
class SourceState:
    source_root: str
    db_sha256: str
    schema_version: int
    secret_sha256: Mapping[str, str]


@dataclass(frozen=True)
class VerifiedCopy:
    status: str
    source: SourceState
    candidate_root: str
    candidate_db_sha256: str
    candidate_secret_sha256: Mapping[str, str]
    manifest_sha256: str


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _linklike(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    try:
        if hasattr(path, "is_junction") and path.is_junction():
            return True
    except OSError:
        return True
    return False


def _regular_source(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as ex:
        raise StateMigrationError(f"{label} is missing") from ex
    if _linklike(path) or _linklike(resolved) or not resolved.is_file():
        raise StateMigrationError(f"{label} must be a regular non-link file")
    return resolved


def _require_offline_sqlite_files(source_root: Path) -> None:
    for suffix in ("-wal", "-shm"):
        path = source_root / f"{SOURCE_DB}{suffix}"
        if path.exists() or _linklike(path):
            raise StateMigrationError(
                f"source control DB is not offline/checkpointed: {path.name} exists"
            )


def _inspect_db(path: Path) -> tuple[int, int, int]:
    try:
        conn = sqlite3.connect(
            f"file:{path.as_posix()}?mode=ro",
            uri=True,
            timeout=5,
        )
        conn.row_factory = sqlite3.Row
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise StateMigrationError(
                    f"source SQLite integrity_check failed: {integrity}"
                )
            row = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                raise StateMigrationError("source DB schema_version is missing")
            schema_version = int(row["value"])
            live_leases = int(
                conn.execute(
                    "SELECT COUNT(*) FROM workspace_leases "
                    "WHERE released_at IS NULL AND expires_at>?",
                    (time.time(),),
                ).fetchone()[0]
            )
            running_tasks = int(
                conn.execute(
                    "SELECT COUNT(*) FROM tasks WHERE status='running'"
                ).fetchone()[0]
            )
            return schema_version, live_leases, running_tasks
        finally:
            conn.close()
    except StateMigrationError:
        raise
    except Exception as ex:
        raise StateMigrationError(
            f"unable to inspect source control DB: {type(ex).__name__}: {ex}"
        ) from ex


def inspect_source_state(source_root: str | Path) -> SourceState:
    root = Path(source_root).resolve(strict=True)
    if _linklike(root) or not root.is_dir():
        raise StateMigrationError("source control-state root must be a real directory")

    _require_offline_sqlite_files(root)
    db = _regular_source(root / SOURCE_DB, "source control DB")
    secret_paths = {
        name: _regular_source(root / name, f"source {name}")
        for name in SECRET_FILES
    }

    schema_version, live_leases, running_tasks = _inspect_db(db)
    if live_leases:
        raise StateMigrationError(
            f"source control DB still has {live_leases} live workspace lease(s)"
        )
    if running_tasks:
        raise StateMigrationError(
            f"source control DB still has {running_tasks} running task(s)"
        )

    return SourceState(
        source_root=str(root),
        db_sha256=_sha256_file(db),
        schema_version=schema_version,
        secret_sha256=MappingProxyType({
            name: _sha256_file(path)
            for name, path in secret_paths.items()
        }),
    )


def _copy_file_exclusive(source: Path, destination: Path) -> str:
    if destination.exists() or _linklike(destination):
        raise StateMigrationError(
            f"destination already exists: {destination.name}"
        )
    fd = os.open(
        str(destination),
        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        0o600,
    )
    try:
        with source.open("rb") as src, os.fdopen(fd, "wb", closefd=False) as dst:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return _sha256_file(destination)


def _backup_sqlite(source: Path, destination: Path) -> str:
    if destination.exists() or _linklike(destination):
        raise StateMigrationError("candidate control DB already exists")
    try:
        src = sqlite3.connect(
            f"file:{source.as_posix()}?mode=ro",
            uri=True,
            timeout=5,
        )
        dst = sqlite3.connect(str(destination), timeout=5)
        try:
            src.backup(dst)
            dst.commit()
            integrity = dst.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise StateMigrationError(
                    f"candidate SQLite integrity_check failed: {integrity}"
                )
        finally:
            dst.close()
            src.close()
    except StateMigrationError:
        raise
    except Exception as ex:
        raise StateMigrationError(
            f"SQLite backup failed: {type(ex).__name__}: {ex}"
        ) from ex
    return _sha256_file(destination)


def _atomic_manifest(path: Path, payload: Mapping[str, object]) -> str:
    if path.exists() or _linklike(path):
        raise StateMigrationError("migration manifest already exists")
    raw = json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(str(temp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    os.replace(temp, path)
    return hashlib.sha256(raw).hexdigest()


def copy_verified_state(
    *,
    source_root: str | Path,
    private_root: str | Path,
    desktop_sid: str,
) -> VerifiedCopy:
    if os.name != "nt":
        raise StateMigrationError(
            "Windows service-private migration is unavailable on this platform"
        )

    service_sid = resolve_service_sid(desktop_sid=desktop_sid)
    try:
        plan = create_private_root_atomic(
            service_sid,
            desktop_sid=desktop_sid,
            root=private_root,
        )
        inspection = inspect_private_directory_acl(plan.root)
        verify_private_acl_exact(plan, inspection)
    except ServicePrivateStateError as ex:
        raise StateMigrationError(str(ex)) from ex

    try:
        assert_service_sid_in_current_token(service_sid)
    except ServiceSidConfigError as ex:
        raise StateMigrationError(
            "state migration must run in a token containing the ForgeBossControl service SID"
        ) from ex

    source_before = inspect_source_state(source_root)
    source_root_path = Path(source_before.source_root)
    private = Path(plan.root).resolve(strict=True)
    candidate = private / CANDIDATE_DIR
    if candidate.exists() or _linklike(candidate):
        raise StateMigrationError("candidate service-private state already exists")

    staging = private / f".migration-stage-{secrets.token_hex(12)}"
    staging.mkdir(mode=0o700)
    try:
        db_hash = _backup_sqlite(
            source_root_path / SOURCE_DB,
            staging / SOURCE_DB,
        )

        secret_hashes: dict[str, str] = {}
        for name in SECRET_FILES:
            copied = _copy_file_exclusive(
                source_root_path / name,
                staging / name,
            )
            wanted = source_before.secret_sha256[name]
            if copied != wanted:
                raise StateMigrationError(
                    f"secret copy hash mismatch for {name}"
                )
            secret_hashes[name] = copied

        # Re-check source identity after the copy. Any writer/WAL appearing
        # invalidates this candidate.
        _require_offline_sqlite_files(source_root_path)
        source_after = inspect_source_state(source_root_path)
        if source_after.db_sha256 != source_before.db_sha256:
            raise StateMigrationError(
                "source control DB changed during migration copy"
            )
        if dict(source_after.secret_sha256) != dict(source_before.secret_sha256):
            raise StateMigrationError(
                "source control secret identity changed during migration copy"
            )
        if source_after.schema_version != source_before.schema_version:
            raise StateMigrationError(
                "source control schema version changed during migration copy"
            )

        manifest = {
            "schema": 1,
            "status": "VERIFIED_COPY",
            "sourceRoot": source_before.source_root,
            "sourceDbSha256": source_before.db_sha256,
            "candidateDbSha256": db_hash,
            "schemaVersion": source_before.schema_version,
            "sourceSecrets": dict(source_before.secret_sha256),
            "candidateSecrets": dict(secret_hashes),
            "serviceSid": service_sid,
            "desktopSid": desktop_sid.upper(),
            "createdAt": time.time(),
        }
        manifest_hash = _atomic_manifest(
            staging / MANIFEST_FILE,
            manifest,
        )

        os.rename(staging, candidate)
        staging = None

        return VerifiedCopy(
            status="VERIFIED_COPY",
            source=source_before,
            candidate_root=str(candidate),
            candidate_db_sha256=db_hash,
            candidate_secret_sha256=MappingProxyType(dict(secret_hashes)),
            manifest_sha256=manifest_hash,
        )
    except Exception:
        if staging is not None:
            try:
                shutil.rmtree(staging)
            except Exception:
                pass
        raise