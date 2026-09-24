from __future__ import annotations

from pathlib import Path, PureWindowsPath
import ntpath
import os
import re
import stat
from types import MappingProxyType
from typing import Mapping

from forgeboss.control.windows_service_sid import (
    ServiceSidConfigError,
    verify_unrestricted_service_sid,
)
from forgeboss.control.windows_state_activation import (
    ActiveStateError,
    activate_verified_state,
    load_optional_verified_active_state,
    verify_candidate_copy,
)
from forgeboss.control.windows_state_migration import (
    CANDIDATE_DIR,
    StateMigrationError,
    copy_verified_state,
)


class ServiceBootstrapError(RuntimeError):
    """Raised when one-time Windows service state bootstrap cannot fail safely."""


BOOTSTRAP_SOURCE_ROOT_FILE = "bootstrap-source-root.txt"
BOOTSTRAP_STATUS = "ACTIVATED_RESTART_REQUIRED"
_MAX_SOURCE_ROOT_BYTES = 4096
_DRIVE = re.compile(r"^[A-Za-z]:$")


def _require_windows() -> None:
    if os.name != "nt":
        raise ServiceBootstrapError(
            "Windows service bootstrap is unavailable on this platform"
        )


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
        info = path.lstat()
    except OSError:
        return False
    attrs = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse and attrs & reparse)


def load_bootstrap_source_root(private_root: str | Path) -> str:
    root = Path(private_root)
    config = root / BOOTSTRAP_SOURCE_ROOT_FILE
    if _linklike_or_reparse(config):
        raise ServiceBootstrapError(
            "bootstrap source-root config must not be linklike/reparse"
        )
    try:
        info = config.stat()
    except OSError as ex:
        raise ServiceBootstrapError(
            "bootstrap source-root config is missing"
        ) from ex
    if not config.is_file():
        raise ServiceBootstrapError(
            "bootstrap source-root config must be a regular file"
        )
    if getattr(info, "st_nlink", 1) != 1:
        raise ServiceBootstrapError(
            "bootstrap source-root config must not be hard-linked"
        )
    if info.st_size < 1 or info.st_size > _MAX_SOURCE_ROOT_BYTES:
        raise ServiceBootstrapError(
            "bootstrap source-root config size is invalid"
        )
    try:
        raw = config.read_bytes()
    except OSError as ex:
        raise ServiceBootstrapError(
            "cannot read bootstrap source-root config"
        ) from ex
    if len(raw) != info.st_size:
        raise ServiceBootstrapError(
            "bootstrap source-root config changed while being read"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as ex:
        raise ServiceBootstrapError(
            "bootstrap source-root config must be UTF-8"
        ) from ex

    if text.endswith("\r\n"):
        value = text[:-2]
    elif text.endswith("\n"):
        value = text[:-1]
    else:
        value = text
    if not value or value != value.strip():
        raise ServiceBootstrapError(
            "bootstrap source-root config has invalid surrounding whitespace"
        )
    if "\n" in value or "\r" in value:
        raise ServiceBootstrapError(
            "bootstrap source-root config must contain exactly one path"
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ServiceBootstrapError(
            "bootstrap source-root config contains control characters"
        )

    parsed = PureWindowsPath(value)
    if (
        not parsed.is_absolute()
        or not _DRIVE.fullmatch(parsed.drive)
        or value.startswith("\\\\")
        or any(part in (".", "..") for part in parsed.parts)
    ):
        raise ServiceBootstrapError(
            "bootstrap source-root config must be one local absolute Windows path"
        )
    return value


def _same_windows_path(left: str, right: str) -> bool:
    return ntpath.normcase(ntpath.normpath(left)) == ntpath.normcase(
        ntpath.normpath(right)
    )


def _bootstrap_result(
    *,
    manifest_sha256: str,
    schema_version: int,
) -> Mapping[str, object]:
    return MappingProxyType({
        "status": BOOTSTRAP_STATUS,
        "candidateDir": CANDIDATE_DIR,
        "migrationManifestSha256": manifest_sha256,
        "schemaVersion": schema_version,
        "restartRequired": True,
    })


def perform_bootstrap_activation(
    *,
    private_root: str | Path,
    desktop_sid: str,
) -> Mapping[str, object]:
    _require_windows()

    try:
        active = load_optional_verified_active_state(
            private_root=private_root,
            desktop_sid=desktop_sid,
        )
        if active is not None:
            raise ServiceBootstrapError(
                "bootstrap activation is unavailable after active state exists"
            )

        status = verify_unrestricted_service_sid(
            desktop_sid=desktop_sid,
        )
        source_root = load_bootstrap_source_root(private_root)
        candidate = Path(private_root) / CANDIDATE_DIR

        if os.path.lexists(str(candidate)):
            verified = verify_candidate_copy(
                private_root,
                expected_service_sid=status.service_sid,
                expected_desktop_sid=desktop_sid,
                verify_source=True,
            )
        else:
            copy_verified_state(
                source_root=source_root,
                private_root=private_root,
                desktop_sid=desktop_sid,
            )
            verified = verify_candidate_copy(
                private_root,
                expected_service_sid=status.service_sid,
                expected_desktop_sid=desktop_sid,
                verify_source=True,
            )

        if not _same_windows_path(verified.source_root, source_root):
            raise ServiceBootstrapError(
                "verified migration source does not match protected bootstrap config"
            )

        activated = activate_verified_state(
            private_root=private_root,
            desktop_sid=desktop_sid,
        )
        if (
            activated.migration_manifest_sha256
            != verified.migration_manifest_sha256
        ):
            raise ServiceBootstrapError(
                "activation manifest identity changed unexpectedly"
            )
        if activated.schema_version != verified.schema_version:
            raise ServiceBootstrapError(
                "activation schema identity changed unexpectedly"
            )
        return _bootstrap_result(
            manifest_sha256=activated.migration_manifest_sha256,
            schema_version=activated.schema_version,
        )
    except ServiceBootstrapError:
        raise
    except (ActiveStateError, StateMigrationError, ServiceSidConfigError) as ex:
        raise ServiceBootstrapError(str(ex)) from ex
