from __future__ import annotations

from dataclasses import dataclass
import importlib.metadata
import json
import os
import re
from types import MappingProxyType
from typing import Mapping


class WindowsServiceBoundaryError(RuntimeError):
    """Raised when the Windows control-service boundary cannot fail safely."""


PIPE_NAME = r"\\.\pipe\ForgeBoss.Control.v1"
PROTOCOL_VERSION = 1
EXPECTED_PYWIN32_VERSION = "312"
MAX_MESSAGE_BYTES = 64 * 1024
MAX_REQUEST_ID_CHARS = 128

_SAFE_METHODS = frozenset({"health", "capabilities"})
_REQUEST_KEYS = frozenset({"version", "id", "method", "params"})
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_FORBIDDEN_METHOD_MARKERS = (
    "sign",
    "mint",
    "secret",
    "attestation",
    "envelope",
    "raw-launch",
    "raw_launch",
    "launch-secret",
    "policy-secret",
    "daemon-secret",
)


@dataclass(frozen=True)
class ServiceRequest:
    version: int
    request_id: str
    method: str
    params: Mapping[str, object]


def _load_json_no_duplicates(raw: bytes) -> object:
    def reject_pairs(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise WindowsServiceBoundaryError(
                    f"duplicate JSON object key: {key!r}"
                )
            out[key] = value
        return out

    def reject_constant(value: str):
        raise WindowsServiceBoundaryError(
            f"non-standard JSON constant is forbidden: {value}"
        )

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as ex:
        raise WindowsServiceBoundaryError("request is not valid UTF-8") from ex

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except WindowsServiceBoundaryError:
        raise
    except json.JSONDecodeError as ex:
        raise WindowsServiceBoundaryError("request is not valid JSON") from ex


def parse_service_request(raw: bytes) -> ServiceRequest:
    if not isinstance(raw, (bytes, bytearray)):
        raise WindowsServiceBoundaryError("service request must be bytes")
    raw = bytes(raw)
    if not raw:
        raise WindowsServiceBoundaryError("service request is empty")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise WindowsServiceBoundaryError("service request exceeds maximum size")

    document = _load_json_no_duplicates(raw)
    if not isinstance(document, dict):
        raise WindowsServiceBoundaryError("service request root must be an object")

    actual = frozenset(document)
    if actual != _REQUEST_KEYS:
        missing = sorted(_REQUEST_KEYS - actual)
        extra = sorted(actual - _REQUEST_KEYS)
        raise WindowsServiceBoundaryError(
            f"service request fields mismatch: missing={missing!r} extra={extra!r}"
        )

    if type(document.get("version")) is not int or document["version"] != PROTOCOL_VERSION:
        raise WindowsServiceBoundaryError("unsupported service protocol version")

    request_id = document.get("id")
    if not isinstance(request_id, str) or not _ID.fullmatch(request_id):
        raise WindowsServiceBoundaryError("request id is invalid")

    method = document.get("method")
    if not isinstance(method, str) or not method:
        raise WindowsServiceBoundaryError("method is invalid")
    if method != method.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in method):
        raise WindowsServiceBoundaryError("method is invalid")

    lowered = method.casefold()
    if any(marker in lowered for marker in _FORBIDDEN_METHOD_MARKERS):
        raise WindowsServiceBoundaryError("raw signing/minting methods are forbidden")
    if method not in _SAFE_METHODS:
        raise WindowsServiceBoundaryError("service method is not allowed in R0")

    params = document.get("params")
    if not isinstance(params, dict):
        raise WindowsServiceBoundaryError("params must be an object")
    if params:
        raise WindowsServiceBoundaryError(
            f"{method} does not accept parameters in service-boundary R0"
        )

    return ServiceRequest(
        version=PROTOCOL_VERSION,
        request_id=request_id,
        method=method,
        params=MappingProxyType({}),
    )


def dispatch_service_request(request: ServiceRequest) -> Mapping[str, object]:
    if not isinstance(request, ServiceRequest):
        raise WindowsServiceBoundaryError("request must be a validated ServiceRequest")

    if request.method == "health":
        return MappingProxyType({
            "ok": True,
            "service": "ForgeBossControl",
            "protocolVersion": PROTOCOL_VERSION,
            "authorityExposed": False,
        })

    if request.method == "capabilities":
        return MappingProxyType({
            "ok": True,
            "protocolVersion": PROTOCOL_VERSION,
            "methods": tuple(sorted(_SAFE_METHODS)),
            "rawSigning": False,
            "rawMinting": False,
            "secretExport": False,
            "governedLaunchStart": False,
        })

    raise WindowsServiceBoundaryError("service method is unavailable")


def _require_windows_pywin32():
    if os.name != "nt":
        raise WindowsServiceBoundaryError(
            "Windows service boundary is unavailable on this platform"
        )
    try:
        version = importlib.metadata.version("pywin32")
    except importlib.metadata.PackageNotFoundError as ex:
        raise WindowsServiceBoundaryError(
            "pywin32 is required for the Windows service boundary"
        ) from ex
    if version != EXPECTED_PYWIN32_VERSION:
        raise WindowsServiceBoundaryError(
            f"pywin32 version mismatch: expected {EXPECTED_PYWIN32_VERSION}, got {version}"
        )

    try:
        import pywintypes
        import ntsecuritycon
        import win32api
        import win32con
        import win32pipe
        import win32security
    except ImportError as ex:
        raise WindowsServiceBoundaryError(
            "required pywin32 modules are unavailable"
        ) from ex

    return {
        "pywintypes": pywintypes,
        "ntsecuritycon": ntsecuritycon,
        "win32api": win32api,
        "win32con": win32con,
        "win32pipe": win32pipe,
        "win32security": win32security,
    }


def current_process_sid() -> str:
    modules = _require_windows_pywin32()
    win32api = modules["win32api"]
    win32security = modules["win32security"]
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32security.TOKEN_QUERY,
    )
    try:
        sid = win32security.GetTokenInformation(
            token,
            win32security.TokenUser,
        )[0]
        return win32security.ConvertSidToStringSid(sid)
    finally:
        token.Close()


def assert_distinct_service_identity(allowed_client_sid: str) -> str:
    modules = _require_windows_pywin32()
    win32security = modules["win32security"]
    try:
        allowed = win32security.ConvertStringSidToSid(allowed_client_sid)
        normalized = win32security.ConvertSidToStringSid(allowed)
    except Exception as ex:
        raise WindowsServiceBoundaryError("allowed client SID is invalid") from ex

    current = current_process_sid()
    if current.casefold() == normalized.casefold():
        raise WindowsServiceBoundaryError(
            "control service must run under an identity distinct from the desktop client"
        )
    return current


def build_pipe_security(allowed_client_sid: str):
    """Create a restrictive named-pipe DACL.

    Allowed:
    - configured desktop/control client SID: read/write;
    - LocalSystem: full access;
    - Builtin Administrators: full access.

    No Everyone/Authenticated Users ACE is added.
    """
    modules = _require_windows_pywin32()
    pywintypes = modules["pywintypes"]
    ntsecuritycon = modules["ntsecuritycon"]
    win32security = modules["win32security"]

    try:
        client_sid = win32security.ConvertStringSidToSid(allowed_client_sid)
    except Exception as ex:
        raise WindowsServiceBoundaryError("allowed client SID is invalid") from ex

    system_sid = win32security.CreateWellKnownSid(
        win32security.WinLocalSystemSid,
        None,
    )
    admins_sid = win32security.CreateWellKnownSid(
        win32security.WinBuiltinAdministratorsSid,
        None,
    )

    acl = win32security.ACL()
    client_mask = ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_WRITE
    acl.AddAccessAllowedAce(win32security.ACL_REVISION, client_mask, client_sid)
    acl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        ntsecuritycon.FILE_ALL_ACCESS,
        system_sid,
    )
    acl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        ntsecuritycon.FILE_ALL_ACCESS,
        admins_sid,
    )

    descriptor = win32security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(1, acl, 0)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def create_r0_server_pipe(allowed_client_sid: str):
    """Create one message-mode server pipe for R0 health/capability requests only."""
    modules = _require_windows_pywin32()
    win32con = modules["win32con"]
    win32pipe = modules["win32pipe"]

    assert_distinct_service_identity(allowed_client_sid)
    security = build_pipe_security(allowed_client_sid)

    return win32pipe.CreateNamedPipe(
        PIPE_NAME,
        win32pipe.PIPE_ACCESS_DUPLEX | win32con.FILE_FLAG_FIRST_PIPE_INSTANCE,
        win32pipe.PIPE_TYPE_MESSAGE
        | win32pipe.PIPE_READMODE_MESSAGE
        | win32pipe.PIPE_WAIT
        | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
        1,
        MAX_MESSAGE_BYTES,
        MAX_MESSAGE_BYTES,
        5000,
        security,
    )
