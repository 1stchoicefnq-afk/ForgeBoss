from __future__ import annotations

from dataclasses import dataclass
import importlib.metadata
import os
from pathlib import Path
import re
from typing import Iterable

from forgeboss.control.windows_service_boundary import (
    EXPECTED_PYWIN32_VERSION,
    WindowsServiceBoundaryError,
)


class ServicePrivateStateError(RuntimeError):
    """Raised when the Windows service-private state boundary cannot be proven."""


SERVICE_NAME = "ForgeBossControl"
SERVICE_ACCOUNT_NAME = r"NT SERVICE\ForgeBossControl"
_SERVICE_SID = re.compile(r"^S-1-5-80-(?:\d+-){4}\d+$", re.IGNORECASE)
_BROAD_SIDS = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # Builtin Users
})


@dataclass(frozen=True)
class PrivateAclPlan:
    root: str
    service_sid: str
    allowed_sids: tuple[str, ...]
    denied_broad_sids: tuple[str, ...]
    inheritance_protected: bool


def _normalize_sid(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ServicePrivateStateError(f"{label} must be a SID string")
    clean = value.strip().upper()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
        raise ServicePrivateStateError(f"{label} contains control characters")
    if not re.fullmatch(r"S-\d+(?:-\d+)+", clean):
        raise ServicePrivateStateError(f"{label} is not a valid SID shape")
    return clean


def validate_service_sid(service_sid: str, *, desktop_sid: str | None = None) -> str:
    service = _normalize_sid(service_sid, "service_sid")
    if not _SERVICE_SID.fullmatch(service):
        raise ServicePrivateStateError(
            "ForgeBossControl must use a Windows service SID in S-1-5-80-..."
        )
    if service in _BROAD_SIDS:
        raise ServicePrivateStateError("service SID cannot be a broad principal")
    if desktop_sid is not None:
        desktop = _normalize_sid(desktop_sid, "desktop_sid")
        if service == desktop:
            raise ServicePrivateStateError(
                "service SID must differ from the desktop/worker SID"
            )
    return service


def default_private_root() -> Path:
    if os.name != "nt":
        raise ServicePrivateStateError(
            "Windows service-private state is unavailable on this platform"
        )
    program_data = os.environ.get("PROGRAMDATA")
    if not program_data:
        raise ServicePrivateStateError("PROGRAMDATA is unavailable")
    root = (Path(program_data) / "ForgeBoss" / "Control").resolve(strict=False)
    if not root.is_absolute():
        raise ServicePrivateStateError("service-private root must be absolute")
    return root


def build_private_acl_plan(
    service_sid: str,
    *,
    desktop_sid: str | None = None,
    root: str | Path | None = None,
) -> PrivateAclPlan:
    service = validate_service_sid(service_sid, desktop_sid=desktop_sid)
    target = default_private_root() if root is None else Path(root).resolve(strict=False)
    if not target.is_absolute():
        raise ServicePrivateStateError("service-private root must be absolute")

    # SYSTEM and Builtin Administrators remain recovery principals.
    allowed = (
        service,
        "S-1-5-18",      # LocalSystem
        "S-1-5-32-544",  # Builtin Administrators
    )
    if len(set(allowed)) != len(allowed):
        raise ServicePrivateStateError("private ACL contains duplicate principals")

    return PrivateAclPlan(
        root=str(target),
        service_sid=service,
        allowed_sids=allowed,
        denied_broad_sids=tuple(sorted(_BROAD_SIDS)),
        inheritance_protected=True,
    )


def _require_pywin32():
    if os.name != "nt":
        raise ServicePrivateStateError(
            "Windows service-private state is unavailable on this platform"
        )
    try:
        version = importlib.metadata.version("pywin32")
    except importlib.metadata.PackageNotFoundError as ex:
        raise ServicePrivateStateError("pywin32 is required") from ex
    if version != EXPECTED_PYWIN32_VERSION:
        raise ServicePrivateStateError(
            f"pywin32 version mismatch: expected {EXPECTED_PYWIN32_VERSION}, got {version}"
        )
    try:
        import ntsecuritycon
        import win32security
    except ImportError as ex:
        raise ServicePrivateStateError("required pywin32 security APIs are unavailable") from ex
    return ntsecuritycon, win32security


def apply_private_directory_acl(
    service_sid: str,
    *,
    desktop_sid: str | None = None,
    root: str | Path | None = None,
) -> PrivateAclPlan:
    plan = build_private_acl_plan(
        service_sid,
        desktop_sid=desktop_sid,
        root=root,
    )
    ntsecuritycon, win32security = _require_pywin32()

    target = Path(plan.root)
    target.mkdir(parents=True, exist_ok=True)

    acl = win32security.ACL()
    for sid_text in plan.allowed_sids:
        sid = win32security.ConvertStringSidToSid(sid_text)
        acl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            ntsecuritycon.FILE_ALL_ACCESS,
            sid,
        )

    info = (
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION
    )
    win32security.SetNamedSecurityInfo(
        str(target),
        win32security.SE_FILE_OBJECT,
        info,
        None,
        None,
        acl,
        None,
    )
    return plan


def inspect_private_directory_acl(path: str | Path) -> tuple[str, ...]:
    _, win32security = _require_pywin32()
    target = Path(path).resolve(strict=True)
    descriptor = win32security.GetNamedSecurityInfo(
        str(target),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        raise ServicePrivateStateError("service-private directory has a NULL DACL")

    out: list[str] = []
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        sid = ace[2]
        out.append(win32security.ConvertSidToStringSid(sid).upper())
    return tuple(sorted(out))


def verify_private_acl_exact(
    plan: PrivateAclPlan,
    actual_sids: Iterable[str],
) -> bool:
    if not isinstance(plan, PrivateAclPlan):
        raise ServicePrivateStateError("plan must be a PrivateAclPlan")
    normalized = tuple(sorted(_normalize_sid(v, "actual SID") for v in actual_sids))
    expected = tuple(sorted(plan.allowed_sids))
    if normalized != expected:
        raise ServicePrivateStateError(
            f"service-private DACL mismatch: expected={expected!r} actual={normalized!r}"
        )
    if any(sid in normalized for sid in plan.denied_broad_sids):
        raise ServicePrivateStateError("broad principal present in private DACL")
    return True
