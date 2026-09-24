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


@dataclass(frozen=True)
class PrivateAce:
    sid: str
    ace_type: int
    ace_flags: int
    access_mask: int


@dataclass(frozen=True)
class PrivateAclInspection:
    protected: bool
    entries: tuple[PrivateAce, ...]


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
        import win32con
        import win32security
    except ImportError as ex:
        raise ServicePrivateStateError("required pywin32 security APIs are unavailable") from ex
    return ntsecuritycon, win32con, win32security


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
    ntsecuritycon, win32con, win32security = _require_pywin32()

    target = Path(plan.root)
    target.mkdir(parents=True, exist_ok=True)

    acl = win32security.ACL()
    inherit_flags = win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE
    for sid_text in plan.allowed_sids:
        sid = win32security.ConvertStringSidToSid(sid_text)
        acl.AddAccessAllowedAceEx(
            win32security.ACL_REVISION,
            inherit_flags,
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


def inspect_private_directory_acl(path: str | Path) -> PrivateAclInspection:
    ntsecuritycon, win32con, win32security = _require_pywin32()
    target = Path(path).resolve(strict=True)
    descriptor = win32security.GetNamedSecurityInfo(
        str(target),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        raise ServicePrivateStateError("service-private directory has a NULL DACL")

    control, _revision = descriptor.GetSecurityDescriptorControl()
    protected = bool(control & win32security.SE_DACL_PROTECTED)

    entries: list[PrivateAce] = []
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        header, mask, sid = ace[0], ace[1], ace[2]
        ace_type = int(header[0])
        ace_flags = int(header[1])
        entries.append(
            PrivateAce(
                sid=win32security.ConvertSidToStringSid(sid).upper(),
                ace_type=ace_type,
                ace_flags=ace_flags,
                access_mask=int(mask),
            )
        )
    entries.sort(key=lambda item: (item.sid, item.ace_type, item.ace_flags, item.access_mask))
    return PrivateAclInspection(protected=protected, entries=tuple(entries))


def verify_private_acl_exact(
    plan: PrivateAclPlan,
    inspection: PrivateAclInspection,
) -> bool:
    if not isinstance(plan, PrivateAclPlan):
        raise ServicePrivateStateError("plan must be a PrivateAclPlan")
    if not isinstance(inspection, PrivateAclInspection):
        raise ServicePrivateStateError("inspection must be a PrivateAclInspection")
    if not inspection.protected:
        raise ServicePrivateStateError("service-private DACL inheritance is not protected")

    expected_sids = tuple(sorted(plan.allowed_sids))
    actual_sids = tuple(sorted(item.sid for item in inspection.entries))
    if actual_sids != expected_sids:
        raise ServicePrivateStateError(
            f"service-private DACL mismatch: expected={expected_sids!r} actual={actual_sids!r}"
        )
    if any(sid in actual_sids for sid in plan.denied_broad_sids):
        raise ServicePrivateStateError("broad principal present in private DACL")

    expected_flags = win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE
    for entry in inspection.entries:
        if entry.ace_type != win32con.ACCESS_ALLOWED_ACE_TYPE:
            raise ServicePrivateStateError("service-private DACL contains non-allow ACE")
        if entry.access_mask != ntsecuritycon.FILE_ALL_ACCESS:
            raise ServicePrivateStateError("service-private DACL ACE is not full control")
        if entry.ace_flags & expected_flags != expected_flags:
            raise ServicePrivateStateError("service-private DACL ACE is not inheritable")
    return True