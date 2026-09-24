from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from types import MappingProxyType
from typing import Mapping

from forgeboss.control.windows_service_sid import (
    ServiceSidConfigError,
    assert_service_sid_in_current_token,
    verify_unrestricted_service_sid,
)
from forgeboss.control.windows_service_state import (
    ServicePrivateStateError,
    build_private_acl_plan,
    inspect_private_directory_acl,
    validate_service_sid,
    verify_private_acl_exact,
)
from forgeboss.control.windows_state_migration import (
    CANDIDATE_DIR,
    MANIFEST_FILE,
    SECRET_FILES,
    SOURCE_DB,
    StateMigrationError,
    inspect_source_state,
)


class ActiveStateError(RuntimeError):
    """Raised when a service-private active-state selection cannot be proven."""


ACTIVE_STATE_FILE = "ACTIVE-STATE.json"
ACTIVE_STATE_SCHEMA = 1
ACTIVE_STATE_STATUS = "ACTIVE_VERIFIED_STATE"
_MIGRATION_SCHEMA = 1
_MIGRATION_STATUS = "VERIFIED_COPY"
_MAX_JSON_BYTES = 256 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_USER_SID = re.compile(r"^S-1-5-21-(?:\d+-){3}\d+$", re.IGNORECASE)

_MIGRATION_KEYS = frozenset({
    "schema",
    "status",
    "sourceRoot",
    "sourceDbSha256",
    "candidateDbSha256",
    "schemaVersion",
    "sourceSecrets",
    "candidateSecrets",
    "serviceSid",
    "desktopSid",
    "createdAt",
})
_ACTIVE_KEYS = frozenset({
    "schema",
    "status",
    "candidateDir",
    "migrationManifestSha256",
    "candidateDbSha256",
    "schemaVersion",
    "candidateSecrets",
    "serviceSid",
    "activatedAt",
})


@dataclass(frozen=True)
class VerifiedCandidate:
    private_root: str
    candidate_root: str
    source_root: str
    migration_manifest_sha256: str
    source_db_sha256: str
    candidate_db_sha256: str
    schema_version: int
    source_secret_sha256: Mapping[str, str]
    candidate_secret_sha256: Mapping[str, str]
    service_sid: str
    desktop_sid: str


@dataclass(frozen=True)
class ActiveState:
    status: str
    private_root: str
    candidate_root: str
    migration_manifest_sha256: str
    candidate_db_sha256: str
    schema_version: int
    candidate_secret_sha256: Mapping[str, str]
    service_sid: str
    activated_at: float


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _linklike_or_reparse(path: Path) -> bool:
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
    try:
        st = path.lstat()
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse and attrs & reparse)


def _real_directory(path: str | Path, label: str) -> Path:
    original = Path(path)
    if _linklike_or_reparse(original):
        raise ActiveStateError(f"{label} must not be a symlink/junction/reparse point")
    try:
        resolved = original.resolve(strict=True)
    except OSError as ex:
        raise ActiveStateError(f"{label} is missing") from ex
    if _linklike_or_reparse(resolved) or not resolved.is_dir():
        raise ActiveStateError(f"{label} must be a real directory")
    return resolved


def _regular_unlinked_file(path: Path, label: str) -> Path:
    if _linklike_or_reparse(path):
        raise ActiveStateError(f"{label} must not be linklike/reparse")
    try:
        resolved = path.resolve(strict=True)
        info = path.stat()
    except OSError as ex:
        raise ActiveStateError(f"{label} is missing") from ex
    if _linklike_or_reparse(resolved) or not resolved.is_file():
        raise ActiveStateError(f"{label} must be a regular file")
    if getattr(info, "st_nlink", 1) != 1:
        raise ActiveStateError(f"{label} must not be hard-linked")
    return resolved


def _strict_json_object(raw: bytes, *, label: str) -> dict[str, object]:
    if not isinstance(raw, (bytes, bytearray)):
        raise ActiveStateError(f"{label} must be bytes")
    raw = bytes(raw)
    if not raw or len(raw) > _MAX_JSON_BYTES:
        raise ActiveStateError(f"{label} size is invalid")

    def reject_pairs(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ActiveStateError(f"{label} contains duplicate JSON key {key!r}")
            out[key] = value
        return out

    def reject_constant(value: str):
        raise ActiveStateError(
            f"{label} contains forbidden non-standard JSON constant {value}"
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as ex:
        raise ActiveStateError(f"{label} is not valid UTF-8") from ex
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except ActiveStateError:
        raise
    except json.JSONDecodeError as ex:
        raise ActiveStateError(f"{label} is not valid JSON") from ex
    if not isinstance(value, dict):
        raise ActiveStateError(f"{label} root must be an object")
    return value


def _require_exact_keys(
    document: Mapping[str, object],
    expected: frozenset[str],
    label: str,
) -> None:
    actual = frozenset(document)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ActiveStateError(
            f"{label} fields mismatch: missing={missing!r} extra={extra!r}"
        )


def _require_hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ActiveStateError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _require_schema_version(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ActiveStateError(f"{label} must be a positive integer")
    return value


def _require_timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ActiveStateError(f"{label} must be a finite positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ActiveStateError(f"{label} must be a finite positive number")
    return result


def _require_secret_hashes(value: object, label: str) -> Mapping[str, str]:
    if not isinstance(value, dict):
        raise ActiveStateError(f"{label} must be an object")
    if frozenset(value) != frozenset(SECRET_FILES):
        raise ActiveStateError(f"{label} must contain exactly the expected secret files")
    return MappingProxyType({
        name: _require_hash(value[name], f"{label}.{name}")
        for name in SECRET_FILES
    })


def _require_desktop_sid(value: object) -> str:
    if not isinstance(value, str) or not _USER_SID.fullmatch(value.strip()):
        raise ActiveStateError("migration desktopSid is not one concrete user SID")
    clean = value.strip().upper()
    if clean != value:
        raise ActiveStateError("migration desktopSid is not canonical uppercase")
    return clean


def parse_migration_manifest_bytes(raw: bytes) -> Mapping[str, object]:
    document = _strict_json_object(raw, label="migration manifest")
    _require_exact_keys(document, _MIGRATION_KEYS, "migration manifest")

    if type(document["schema"]) is not int or document["schema"] != _MIGRATION_SCHEMA:
        raise ActiveStateError("migration manifest schema is unsupported")
    if document["status"] != _MIGRATION_STATUS:
        raise ActiveStateError("migration manifest status is not VERIFIED_COPY")

    source_root = document["sourceRoot"]
    if not isinstance(source_root, str) or not source_root:
        raise ActiveStateError("migration sourceRoot is invalid")
    if not Path(source_root).is_absolute():
        raise ActiveStateError("migration sourceRoot must be absolute")

    service_sid = document["serviceSid"]
    if not isinstance(service_sid, str):
        raise ActiveStateError("migration serviceSid is invalid")
    try:
        service_sid = validate_service_sid(service_sid)
    except ServicePrivateStateError as ex:
        raise ActiveStateError(str(ex)) from ex

    parsed = {
        "schema": _MIGRATION_SCHEMA,
        "status": _MIGRATION_STATUS,
        "sourceRoot": source_root,
        "sourceDbSha256": _require_hash(
            document["sourceDbSha256"],
            "migration sourceDbSha256",
        ),
        "candidateDbSha256": _require_hash(
            document["candidateDbSha256"],
            "migration candidateDbSha256",
        ),
        "schemaVersion": _require_schema_version(
            document["schemaVersion"],
            "migration schemaVersion",
        ),
        "sourceSecrets": _require_secret_hashes(
            document["sourceSecrets"],
            "migration sourceSecrets",
        ),
        "candidateSecrets": _require_secret_hashes(
            document["candidateSecrets"],
            "migration candidateSecrets",
        ),
        "serviceSid": service_sid,
        "desktopSid": _require_desktop_sid(document["desktopSid"]),
        "createdAt": _require_timestamp(document["createdAt"], "migration createdAt"),
    }
    if dict(parsed["sourceSecrets"]) != dict(parsed["candidateSecrets"]):
        raise ActiveStateError("migration secret hashes do not prove a byte-identical copy")
    return MappingProxyType(parsed)


def parse_active_state_bytes(raw: bytes) -> Mapping[str, object]:
    document = _strict_json_object(raw, label="active-state record")
    _require_exact_keys(document, _ACTIVE_KEYS, "active-state record")

    if type(document["schema"]) is not int or document["schema"] != ACTIVE_STATE_SCHEMA:
        raise ActiveStateError("active-state schema is unsupported")
    if document["status"] != ACTIVE_STATE_STATUS:
        raise ActiveStateError("active-state status is invalid")
    if document["candidateDir"] != CANDIDATE_DIR:
        raise ActiveStateError("active-state candidate directory is invalid")

    service_sid = document["serviceSid"]
    if not isinstance(service_sid, str):
        raise ActiveStateError("active-state serviceSid is invalid")
    try:
        service_sid = validate_service_sid(service_sid)
    except ServicePrivateStateError as ex:
        raise ActiveStateError(str(ex)) from ex

    return MappingProxyType({
        "schema": ACTIVE_STATE_SCHEMA,
        "status": ACTIVE_STATE_STATUS,
        "candidateDir": CANDIDATE_DIR,
        "migrationManifestSha256": _require_hash(
            document["migrationManifestSha256"],
            "active-state migrationManifestSha256",
        ),
        "candidateDbSha256": _require_hash(
            document["candidateDbSha256"],
            "active-state candidateDbSha256",
        ),
        "schemaVersion": _require_schema_version(
            document["schemaVersion"],
            "active-state schemaVersion",
        ),
        "candidateSecrets": _require_secret_hashes(
            document["candidateSecrets"],
            "active-state candidateSecrets",
        ),
        "serviceSid": service_sid,
        "activatedAt": _require_timestamp(
            document["activatedAt"],
            "active-state activatedAt",
        ),
    })


def _inspect_candidate_db(path: Path) -> int:
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
                raise ActiveStateError(
                    f"candidate SQLite integrity_check failed: {integrity}"
                )
            row = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                raise ActiveStateError("candidate DB schema_version is missing")
            return int(row["value"])
        finally:
            conn.close()
    except ActiveStateError:
        raise
    except Exception as ex:
        raise ActiveStateError(
            f"unable to inspect candidate control DB: {type(ex).__name__}: {ex}"
        ) from ex


def verify_candidate_copy(
    private_root: str | Path,
    *,
    expected_service_sid: str | None = None,
    expected_desktop_sid: str | None = None,
    verify_source: bool = True,
) -> VerifiedCandidate:
    private = _real_directory(private_root, "service-private root")
    candidate = _real_directory(private / CANDIDATE_DIR, "candidate state directory")
    if candidate.parent != private:
        raise ActiveStateError("candidate state escaped the service-private root")

    manifest_path = _regular_unlinked_file(
        candidate / MANIFEST_FILE,
        "migration manifest",
    )
    raw_manifest = manifest_path.read_bytes()
    manifest = parse_migration_manifest_bytes(raw_manifest)
    manifest_hash = _sha256_bytes(raw_manifest)

    service_sid = str(manifest["serviceSid"])
    desktop_sid = str(manifest["desktopSid"])
    if expected_service_sid is not None:
        try:
            wanted_service = validate_service_sid(expected_service_sid)
        except ServicePrivateStateError as ex:
            raise ActiveStateError(str(ex)) from ex
        if service_sid != wanted_service:
            raise ActiveStateError("migration service SID does not match live service SID")
    if expected_desktop_sid is not None:
        wanted_desktop = expected_desktop_sid.strip().upper()
        if desktop_sid != wanted_desktop:
            raise ActiveStateError("migration desktop SID does not match configured client SID")

    db_path = _regular_unlinked_file(
        candidate / SOURCE_DB,
        "candidate control DB",
    )
    db_hash = _sha256_file(db_path)
    if db_hash != manifest["candidateDbSha256"]:
        raise ActiveStateError("candidate control DB hash does not match migration manifest")
    db_schema = _inspect_candidate_db(db_path)
    if db_schema != manifest["schemaVersion"]:
        raise ActiveStateError("candidate control DB schema does not match migration manifest")

    candidate_hashes: dict[str, str] = {}
    for name in SECRET_FILES:
        secret_path = _regular_unlinked_file(
            candidate / name,
            f"candidate {name}",
        )
        digest = _sha256_file(secret_path)
        if digest != manifest["candidateSecrets"][name]:
            raise ActiveStateError(f"candidate secret hash mismatch for {name}")
        candidate_hashes[name] = digest

    if verify_source:
        source_root = _real_directory(
            str(manifest["sourceRoot"]),
            "migration source root",
        )
        try:
            source = inspect_source_state(source_root)
        except StateMigrationError as ex:
            raise ActiveStateError(str(ex)) from ex
        if source.db_sha256 != manifest["sourceDbSha256"]:
            raise ActiveStateError("source control DB changed after migration copy")
        if source.schema_version != manifest["schemaVersion"]:
            raise ActiveStateError("source schema changed after migration copy")
        if dict(source.secret_sha256) != dict(manifest["sourceSecrets"]):
            raise ActiveStateError("source secrets changed after migration copy")
        source_root_text = str(source_root)
    else:
        source_root_text = str(manifest["sourceRoot"])

    return VerifiedCandidate(
        private_root=str(private),
        candidate_root=str(candidate),
        source_root=source_root_text,
        migration_manifest_sha256=manifest_hash,
        source_db_sha256=str(manifest["sourceDbSha256"]),
        candidate_db_sha256=db_hash,
        schema_version=db_schema,
        source_secret_sha256=MappingProxyType(dict(manifest["sourceSecrets"])),
        candidate_secret_sha256=MappingProxyType(candidate_hashes),
        service_sid=service_sid,
        desktop_sid=desktop_sid,
    )


def _verify_windows_authority(
    private_root: str | Path,
    *,
    desktop_sid: str,
) -> str:
    if os.name != "nt":
        raise ActiveStateError(
            "Windows active-state selection is unavailable on this platform"
        )
    try:
        status = verify_unrestricted_service_sid(desktop_sid=desktop_sid)
        assert_service_sid_in_current_token(status.service_sid)
        plan = build_private_acl_plan(
            status.service_sid,
            desktop_sid=desktop_sid,
            root=private_root,
        )
        inspection = inspect_private_directory_acl(plan.root)
        verify_private_acl_exact(plan, inspection)
        return status.service_sid
    except (ServiceSidConfigError, ServicePrivateStateError) as ex:
        raise ActiveStateError(str(ex)) from ex


def _canonical_json_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as ex:
        raise ActiveStateError("active-state payload is not canonicalizable") from ex


def activate_verified_state(
    *,
    private_root: str | Path,
    desktop_sid: str,
) -> ActiveState:
    service_sid = _verify_windows_authority(
        private_root,
        desktop_sid=desktop_sid,
    )
    verified = verify_candidate_copy(
        private_root,
        expected_service_sid=service_sid,
        expected_desktop_sid=desktop_sid,
        verify_source=True,
    )

    private = Path(verified.private_root)
    active_path = private / ACTIVE_STATE_FILE
    if active_path.exists() or _linklike_or_reparse(active_path):
        raise ActiveStateError("active-state record already exists")

    activated_at = time.time()
    payload = {
        "schema": ACTIVE_STATE_SCHEMA,
        "status": ACTIVE_STATE_STATUS,
        "candidateDir": CANDIDATE_DIR,
        "migrationManifestSha256": verified.migration_manifest_sha256,
        "candidateDbSha256": verified.candidate_db_sha256,
        "schemaVersion": verified.schema_version,
        "candidateSecrets": dict(verified.candidate_secret_sha256),
        "serviceSid": verified.service_sid,
        "activatedAt": activated_at,
    }
    raw = _canonical_json_bytes(payload)
    # Parse our own payload through the same strict reader before committing it.
    parse_active_state_bytes(raw)

    # Reverify the entire copy immediately before the single activation rename.
    reverified = verify_candidate_copy(
        private_root,
        expected_service_sid=service_sid,
        expected_desktop_sid=desktop_sid,
        verify_source=True,
    )
    if reverified.migration_manifest_sha256 != verified.migration_manifest_sha256:
        raise ActiveStateError("migration manifest changed before activation")
    if reverified.candidate_db_sha256 != verified.candidate_db_sha256:
        raise ActiveStateError("candidate DB changed before activation")
    if dict(reverified.candidate_secret_sha256) != dict(
        verified.candidate_secret_sha256
    ):
        raise ActiveStateError("candidate secrets changed before activation")

    temp = private / f".{ACTIVE_STATE_FILE}.{secrets.token_hex(12)}.tmp"
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

    try:
        if active_path.exists() or _linklike_or_reparse(active_path):
            raise ActiveStateError("active-state record appeared during activation")
        # On Windows os.rename refuses to replace an existing destination.
        os.rename(temp, active_path)
        temp = None
    finally:
        if temp is not None:
            try:
                temp.unlink()
            except OSError:
                pass

    return ActiveState(
        status=ACTIVE_STATE_STATUS,
        private_root=verified.private_root,
        candidate_root=verified.candidate_root,
        migration_manifest_sha256=verified.migration_manifest_sha256,
        candidate_db_sha256=verified.candidate_db_sha256,
        schema_version=verified.schema_version,
        candidate_secret_sha256=MappingProxyType(
            dict(verified.candidate_secret_sha256)
        ),
        service_sid=verified.service_sid,
        activated_at=activated_at,
    )


def load_verified_active_state(
    *,
    private_root: str | Path,
    desktop_sid: str,
) -> ActiveState:
    service_sid = _verify_windows_authority(
        private_root,
        desktop_sid=desktop_sid,
    )
    private = _real_directory(private_root, "service-private root")
    active_path = _regular_unlinked_file(
        private / ACTIVE_STATE_FILE,
        "active-state record",
    )
    record = parse_active_state_bytes(active_path.read_bytes())
    if record["serviceSid"] != service_sid:
        raise ActiveStateError("active-state service SID does not match live service SID")

    verified = verify_candidate_copy(
        private,
        expected_service_sid=service_sid,
        expected_desktop_sid=desktop_sid,
        verify_source=False,
    )
    if record["migrationManifestSha256"] != verified.migration_manifest_sha256:
        raise ActiveStateError("active-state migration manifest identity is stale")
    if record["candidateDbSha256"] != verified.candidate_db_sha256:
        raise ActiveStateError("active-state candidate DB identity is stale")
    if record["schemaVersion"] != verified.schema_version:
        raise ActiveStateError("active-state schema identity is stale")
    if dict(record["candidateSecrets"]) != dict(verified.candidate_secret_sha256):
        raise ActiveStateError("active-state secret identity is stale")

    return ActiveState(
        status=ACTIVE_STATE_STATUS,
        private_root=verified.private_root,
        candidate_root=verified.candidate_root,
        migration_manifest_sha256=verified.migration_manifest_sha256,
        candidate_db_sha256=verified.candidate_db_sha256,
        schema_version=verified.schema_version,
        candidate_secret_sha256=MappingProxyType(
            dict(verified.candidate_secret_sha256)
        ),
        service_sid=verified.service_sid,
        activated_at=float(record["activatedAt"]),
    )


def load_optional_verified_active_state(
    *,
    private_root: str | Path,
    desktop_sid: str,
) -> ActiveState | None:
    """Load active state when present, while keeping pre-activation R0 bootstrap-safe.

    A genuinely absent record returns None. Any present, linklike, malformed,
    stale or authority-mismatched record remains a hard failure.
    """
    _verify_windows_authority(
        private_root,
        desktop_sid=desktop_sid,
    )
    private = _real_directory(private_root, "service-private root")
    active_path = private / ACTIVE_STATE_FILE
    if not active_path.exists():
        if _linklike_or_reparse(active_path):
            raise ActiveStateError("active-state path is linklike/reparse")
        return None
    return load_verified_active_state(
        private_root=private,
        desktop_sid=desktop_sid,
    )
