from __future__ import annotations

import json
import os
from pathlib import Path
import re
import threading
from types import MappingProxyType
from typing import Callable, Mapping

from forgeboss.control.windows_state_activation import (
    ActiveStateError,
    load_optional_verified_active_state,
)

from forgeboss.control.windows_service_bootstrap import (
    ServiceBootstrapError,
    perform_bootstrap_activation,
)

from forgeboss.control.windows_service_boundary import (
    MAX_MESSAGE_BYTES,
    _require_windows_pywin32,
    PIPE_NAME,
    PROTOCOL_VERSION,
    WindowsServiceBoundaryError,
    create_r0_server_pipe,
    dispatch_service_request,
    parse_service_request,
)
from forgeboss.control.windows_service_state import (
    SERVICE_NAME,
    ServicePrivateStateError,
    default_private_root,
)


class WindowsControlServiceError(RuntimeError):
    """Raised when the R0 Windows service host cannot fail safely."""


ALLOWED_CLIENT_SID_FILE = "allowed-client-sid.txt"
MAX_RESPONSE_BYTES = 64 * 1024
_MAX_SID_FILE_BYTES = 256
_USER_SID = re.compile(r"^S-1-5-21-(?:\d+-){3}\d+$", re.IGNORECASE)
_BROAD_OR_PRIVILEGED = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-5-11",      # Authenticated Users
    "S-1-5-18",      # LocalSystem
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-545",  # Users
})


def _normalize_client_sid(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WindowsControlServiceError("allowed client SID is required")
    clean = value.strip().upper()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in clean):
        raise WindowsControlServiceError("allowed client SID contains control characters")
    if clean in _BROAD_OR_PRIVILEGED:
        raise WindowsControlServiceError("allowed client SID must be one specific desktop user")
    if not _USER_SID.fullmatch(clean):
        raise WindowsControlServiceError(
            "allowed client SID must be a concrete S-1-5-21 user SID"
        )
    return clean


def load_allowed_client_sid(path: str | Path | None = None) -> str:
    if path is None:
        try:
            path = default_private_root() / ALLOWED_CLIENT_SID_FILE
        except ServicePrivateStateError as ex:
            raise WindowsControlServiceError(str(ex)) from ex

    source = Path(path)
    try:
        resolved = source.resolve(strict=True)
    except OSError as ex:
        raise WindowsControlServiceError("allowed client SID file is missing") from ex

    if not resolved.is_file():
        raise WindowsControlServiceError("allowed client SID path must be a file")
    if source.is_symlink():
        raise WindowsControlServiceError("allowed client SID file must not be a symlink")

    try:
        raw = resolved.read_bytes()
    except OSError as ex:
        raise WindowsControlServiceError("cannot read allowed client SID file") from ex
    if not raw or len(raw) > _MAX_SID_FILE_BYTES:
        raise WindowsControlServiceError("allowed client SID file size is invalid")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as ex:
        raise WindowsControlServiceError("allowed client SID file must be ASCII") from ex
    return _normalize_client_sid(text)


def encode_service_response(
    *,
    request_id: str,
    ok: bool,
    result: Mapping[str, object] | None = None,
    error: str | None = None,
) -> bytes:
    if not isinstance(request_id, str) or not request_id:
        raise WindowsControlServiceError("response request id is invalid")
    if type(ok) is not bool:
        raise WindowsControlServiceError("response ok must be boolean")

    if ok:
        if result is None or error is not None:
            raise WindowsControlServiceError("successful response shape is invalid")
        payload = {
            "version": PROTOCOL_VERSION,
            "id": request_id,
            "ok": True,
            "result": dict(result),
        }
    else:
        if result is not None or not isinstance(error, str) or not error:
            raise WindowsControlServiceError("error response shape is invalid")
        payload = {
            "version": PROTOCOL_VERSION,
            "id": request_id,
            "ok": False,
            "error": error[:2048],
        }

    try:
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as ex:
        raise WindowsControlServiceError("service response is not serializable") from ex
    if len(raw) > MAX_RESPONSE_BYTES:
        raise WindowsControlServiceError("service response exceeds maximum size")
    return raw


def process_service_message(
    raw: bytes,
    *,
    bootstrap_handler: Callable[[], Mapping[str, object]] | None = None,
    active_state_present: bool = False,
) -> bytes:
    request_id = "unknown"
    try:
        request = parse_service_request(raw)
        request_id = request.request_id
        if request.method == "bootstrap.activate":
            if active_state_present:
                raise WindowsControlServiceError(
                    "bootstrap activation is unavailable after active state exists"
                )
            if bootstrap_handler is None:
                raise WindowsControlServiceError(
                    "bootstrap activation is unavailable outside the trusted service host"
                )
            result = bootstrap_handler()
        else:
            result = dispatch_service_request(request)
        return encode_service_response(
            request_id=request_id,
            ok=True,
            result=result,
        )
    except (
        WindowsServiceBoundaryError,
        WindowsControlServiceError,
        ServiceBootstrapError,
    ) as ex:
        return encode_service_response(
            request_id=request_id,
            ok=False,
            error=f"{type(ex).__name__}: {ex}",
        )


def _require_pipe_api():
    if os.name != "nt":
        raise WindowsControlServiceError(
            "Windows control service host is unavailable on this platform"
        )
    try:
        _require_windows_pywin32()
    except WindowsServiceBoundaryError as ex:
        raise WindowsControlServiceError(str(ex)) from ex
    try:
        import pywintypes
        import win32file
        import win32pipe
        import winerror
    except ImportError as ex:
        raise WindowsControlServiceError(
            "required pywin32 pipe APIs are unavailable"
        ) from ex
    return pywintypes, win32file, win32pipe, winerror


def serve_one_connection(
    pipe_handle,
    *,
    bootstrap_handler: Callable[[], Mapping[str, object]] | None = None,
    active_state_present: bool = False,
) -> None:
    pywintypes, win32file, win32pipe, winerror = _require_pipe_api()
    connected = False
    try:
        try:
            win32pipe.ConnectNamedPipe(pipe_handle, None)
            connected = True
        except pywintypes.error as ex:
            code = getattr(ex, "winerror", None)
            if code == winerror.ERROR_PIPE_CONNECTED:
                connected = True
            else:
                raise

        hr, data = win32file.ReadFile(pipe_handle, MAX_MESSAGE_BYTES)
        if hr == winerror.ERROR_MORE_DATA:
            response = encode_service_response(
                request_id="unknown",
                ok=False,
                error="WindowsControlServiceError: service request exceeds maximum size",
            )
        else:
            response = process_service_message(
                bytes(data),
                bootstrap_handler=bootstrap_handler,
                active_state_present=active_state_present,
            )

        win32file.WriteFile(pipe_handle, response)
        try:
            win32file.FlushFileBuffers(pipe_handle)
        except Exception:
            # The client may disconnect immediately after receiving the response.
            pass
    finally:
        if connected:
            try:
                win32pipe.DisconnectNamedPipe(pipe_handle)
            except Exception:
                pass
        try:
            win32file.CloseHandle(pipe_handle)
        except Exception:
            pass


def build_service_class():
    if os.name != "nt":
        raise WindowsControlServiceError(
            "Windows control service host is unavailable on this platform"
        )
    try:
        _require_windows_pywin32()
    except WindowsServiceBoundaryError as ex:
        raise WindowsControlServiceError(str(ex)) from ex
    try:
        import servicemanager
        import win32event
        import win32file
        import win32service
        import win32serviceutil
    except ImportError as ex:
        raise WindowsControlServiceError(
            "required pywin32 service APIs are unavailable"
        ) from ex

    class ForgeBossControlService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = "ForgeBoss Control Service"
        _svc_description_ = (
            "Isolated local control-plane service for ForgeBoss governed execution."
        )

        def __init__(self, args):
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, True, False, None)
            self._pipe_lock = threading.RLock()
            self._active_pipe = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            with self._pipe_lock:
                handle = self._active_pipe
                self._active_pipe = None
            if handle is not None:
                try:
                    win32file.CloseHandle(handle)
                except Exception:
                    pass

        def SvcDoRun(self):
            sid = load_allowed_client_sid()
            try:
                private_root = default_private_root()
                active_state = load_optional_verified_active_state(
                    private_root=private_root,
                    desktop_sid=sid,
                )
            except (ActiveStateError, ServicePrivateStateError) as ex:
                raise WindowsControlServiceError(
                    "service active-state verification failed"
                ) from ex
            if active_state is None:
                servicemanager.LogInfoMsg(
                    f"{SERVICE_NAME} bootstrap mode: no active-state record"
                )
            else:
                servicemanager.LogInfoMsg(
                    f"{SERVICE_NAME} active-state verified "
                    f"schema={active_state.schema_version} "
                    f"manifest={active_state.migration_manifest_sha256[:16]}"
                )
            bootstrap_handler = None
            if active_state is None:
                bootstrap_handler = lambda: perform_bootstrap_activation(
                    private_root=private_root,
                    desktop_sid=sid,
                    cancelled=lambda: (
                        win32event.WaitForSingleObject(self._stop_event, 0)
                        == win32event.WAIT_OBJECT_0
                    ),
                )
            servicemanager.LogInfoMsg(
                f"{SERVICE_NAME} R0 starting on {PIPE_NAME}"
            )
            while (
                win32event.WaitForSingleObject(self._stop_event, 0)
                != win32event.WAIT_OBJECT_0
            ):
                pipe = create_r0_server_pipe(sid)
                with self._pipe_lock:
                    if (
                        win32event.WaitForSingleObject(self._stop_event, 0)
                        == win32event.WAIT_OBJECT_0
                    ):
                        try:
                            win32file.CloseHandle(pipe)
                        except Exception:
                            pass
                        break
                    self._active_pipe = pipe
                try:
                    serve_one_connection(
                        pipe,
                        bootstrap_handler=bootstrap_handler,
                        active_state_present=active_state is not None,
                    )
                except Exception as ex:
                    if (
                        win32event.WaitForSingleObject(self._stop_event, 0)
                        != win32event.WAIT_OBJECT_0
                    ):
                        servicemanager.LogErrorMsg(
                            f"{SERVICE_NAME} R0 pipe failure: {type(ex).__name__}: {ex}"
                        )
                finally:
                    with self._pipe_lock:
                        if self._active_pipe == pipe:
                            self._active_pipe = None
            servicemanager.LogInfoMsg(f"{SERVICE_NAME} R0 stopped")

    return ForgeBossControlService


def service_command_line() -> int:
    if os.name != "nt":
        raise WindowsControlServiceError(
            "Windows control service host is unavailable on this platform"
        )
    try:
        import win32serviceutil
    except ImportError as ex:
        raise WindowsControlServiceError(
            "pywin32 service utilities are unavailable"
        ) from ex
    win32serviceutil.HandleCommandLine(build_service_class())
    return 0