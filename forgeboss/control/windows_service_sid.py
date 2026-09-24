from __future__ import annotations

from dataclasses import dataclass
import importlib.metadata
import os

from forgeboss.control.windows_service_boundary import EXPECTED_PYWIN32_VERSION
from forgeboss.control.windows_service_state import (
    SERVICE_ACCOUNT_NAME,
    SERVICE_NAME,
    ServicePrivateStateError,
    validate_service_sid,
)


class ServiceSidConfigError(RuntimeError):
    """Raised when the ForgeBossControl service SID cannot be configured or verified."""


@dataclass(frozen=True)
class ServiceSidStatus:
    service_name: str
    service_account_name: str
    service_sid: str
    sid_type: int
    unrestricted: bool


def _require_pywin32_service():
    if os.name != "nt":
        raise ServiceSidConfigError(
            "Windows service SID configuration is unavailable on this platform"
        )
    try:
        version = importlib.metadata.version("pywin32")
    except importlib.metadata.PackageNotFoundError as ex:
        raise ServiceSidConfigError("pywin32 is required") from ex
    if version != EXPECTED_PYWIN32_VERSION:
        raise ServiceSidConfigError(
            f"pywin32 version mismatch: expected {EXPECTED_PYWIN32_VERSION}, got {version}"
        )
    try:
        import win32service
        import win32security
    except ImportError as ex:
        raise ServiceSidConfigError(
            "required pywin32 service/security APIs are unavailable"
        ) from ex
    return win32service, win32security


def _open_service(win32service, *, access: int):
    scm = None
    service = None
    try:
        scm = win32service.OpenSCManager(
            None,
            None,
            win32service.SC_MANAGER_CONNECT,
        )
        service = win32service.OpenService(
            scm,
            SERVICE_NAME,
            access,
        )
        return scm, service
    except Exception:
        if service is not None:
            try:
                win32service.CloseServiceHandle(service)
            except Exception:
                pass
        if scm is not None:
            try:
                win32service.CloseServiceHandle(scm)
            except Exception:
                pass
        raise


def _close_service_handles(win32service, scm, service) -> tuple[Exception, ...]:
    errors = []
    try:
        if service is not None:
            win32service.CloseServiceHandle(service)
    except Exception as ex:
        errors.append(ex)
    try:
        if scm is not None:
            win32service.CloseServiceHandle(scm)
    except Exception as ex:
        errors.append(ex)
    return tuple(errors)


def configure_unrestricted_service_sid() -> None:
    win32service, _ = _require_pywin32_service()
    scm = service = None
    primary = None
    try:
        scm, service = _open_service(
            win32service,
            access=(
                win32service.SERVICE_CHANGE_CONFIG
                | win32service.SERVICE_QUERY_CONFIG
            ),
        )
        win32service.ChangeServiceConfig2(
            service,
            win32service.SERVICE_CONFIG_SERVICE_SID_INFO,
            win32service.SERVICE_SID_TYPE_UNRESTRICTED,
        )
    except Exception as ex:
        primary = ex
    close_errors = _close_service_handles(win32service, scm, service)
    if primary is not None:
        raise ServiceSidConfigError(
            "failed to configure ForgeBossControl service SID"
        ) from primary
    if close_errors:
        raise ServiceSidConfigError(
            "configured service SID but failed to close Windows service handles cleanly"
        ) from close_errors[0]


def query_service_sid_type() -> int:
    win32service, _ = _require_pywin32_service()
    scm = service = None
    primary = None
    value = None
    try:
        scm, service = _open_service(
            win32service,
            access=win32service.SERVICE_QUERY_CONFIG,
        )
        value = win32service.QueryServiceConfig2(
            service,
            win32service.SERVICE_CONFIG_SERVICE_SID_INFO,
        )
        if isinstance(value, bool) or not isinstance(value, int):
            raise ServiceSidConfigError(
                "Windows returned an invalid service SID type"
            )
    except Exception as ex:
        primary = ex
    close_errors = _close_service_handles(win32service, scm, service)
    if primary is not None:
        if isinstance(primary, ServiceSidConfigError):
            raise primary
        raise ServiceSidConfigError(
            "failed to query ForgeBossControl service SID type"
        ) from primary
    if close_errors:
        raise ServiceSidConfigError(
            "queried service SID but failed to close Windows service handles cleanly"
        ) from close_errors[0]
    return value


def current_process_token_sids() -> tuple[str, ...]:
    win32service, win32security = _require_pywin32_service()
    try:
        import ntsecuritycon
        import win32api
    except ImportError as ex:
        raise ServiceSidConfigError("required token inspection APIs are unavailable") from ex

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32security.TOKEN_QUERY,
    )
    try:
        user_sid = win32security.GetTokenInformation(
            token,
            win32security.TokenUser,
        )[0]
        groups = win32security.GetTokenInformation(
            token,
            win32security.TokenGroups,
        )
        values = {
            win32security.ConvertSidToStringSid(user_sid).upper()
        }
        for group_sid, attributes in groups:
            enabled = bool(attributes & ntsecuritycon.SE_GROUP_ENABLED)
            deny_only = bool(attributes & ntsecuritycon.SE_GROUP_USE_FOR_DENY_ONLY)
            if enabled and not deny_only:
                values.add(
                    win32security.ConvertSidToStringSid(group_sid).upper()
                )
        return tuple(sorted(values))
    except Exception as ex:
        raise ServiceSidConfigError(
            "failed to inspect current Windows process token"
        ) from ex
    finally:
        token.Close()


def assert_service_sid_in_current_token(
    service_sid: str,
) -> tuple[str, ...]:
    expected = service_sid.strip().upper()
    try:
        validate_service_sid(expected)
    except ServicePrivateStateError as ex:
        raise ServiceSidConfigError(str(ex)) from ex
    actual = current_process_token_sids()
    if expected not in actual:
        raise ServiceSidConfigError(
            "ForgeBossControl service SID is absent from the current process token"
        )
    return actual


def resolve_service_sid(*, desktop_sid: str | None = None) -> str:
    _, win32security = _require_pywin32_service()
    try:
        sid, _domain, _account_type = win32security.LookupAccountName(
            None,
            SERVICE_ACCOUNT_NAME,
        )
        text = win32security.ConvertSidToStringSid(sid).upper()
    except Exception as ex:
        raise ServiceSidConfigError(
            "failed to resolve ForgeBossControl service SID"
        ) from ex
    try:
        return validate_service_sid(text, desktop_sid=desktop_sid)
    except ServicePrivateStateError as ex:
        raise ServiceSidConfigError(str(ex)) from ex


def verify_unrestricted_service_sid(
    *,
    desktop_sid: str | None = None,
) -> ServiceSidStatus:
    win32service, _ = _require_pywin32_service()
    sid_type = query_service_sid_type()
    if sid_type != win32service.SERVICE_SID_TYPE_UNRESTRICTED:
        raise ServiceSidConfigError(
            f"ForgeBossControl service SID type is not unrestricted: {sid_type}"
        )
    sid = resolve_service_sid(desktop_sid=desktop_sid)
    return ServiceSidStatus(
        service_name=SERVICE_NAME,
        service_account_name=SERVICE_ACCOUNT_NAME,
        service_sid=sid,
        sid_type=sid_type,
        unrestricted=True,
    )


def configure_and_verify_service_sid(
    *,
    desktop_sid: str | None = None,
) -> ServiceSidStatus:
    configure_unrestricted_service_sid()
    return verify_unrestricted_service_sid(desktop_sid=desktop_sid)