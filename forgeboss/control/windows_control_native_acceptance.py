from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from typing import Mapping

from forgeboss.control.windows_control_service import (
    ALLOWED_CLIENT_SID_FILE,
    ForgeBossControlService,
)
from forgeboss.control.windows_service_bootstrap import BOOTSTRAP_SOURCE_ROOT_FILE
from forgeboss.control.windows_service_boundary import (
    MAX_MESSAGE_BYTES,
    PIPE_NAME,
    PROTOCOL_VERSION,
)
from forgeboss.control.windows_service_sid import verify_unrestricted_service_sid
from forgeboss.control.windows_service_state import (
    SERVICE_NAME,
    create_private_root_atomic,
    default_private_root,
    inspect_private_directory_acl,
    verify_private_acl_exact,
)
from forgeboss.control.windows_state_activation import (
    ACTIVE_STATE_FILE,
    ACTIVE_STATE_STATUS,
    parse_active_state_bytes,
    verify_candidate_copy,
)
from forgeboss.control.windows_state_migration import (
    CANDIDATE_DIR,
    MANIFEST_FILE,
    SECRET_FILES,
    SOURCE_DB,
)


class WindowsControlAcceptanceError(RuntimeError):
    """Raised when the native Windows acceptance harness cannot prove a check."""


OPT_IN_VALUE = "YES-I-AM-ON-A-DISPOSABLE-WINDOWS-HOST"
OPT_IN_ENV = "FORGEBOSS_WINDOWS_CONTROL_ACCEPTANCE"
_HEAD = re.compile(r"^[0-9a-f]{40}$")
_REPO_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE_DIRNAME = "ControlAcceptanceSource-v1"


def _emit(check: str, passed: bool, **details: object) -> None:
    payload = {
        "check": check,
        "passed": bool(passed),
        "candidateHead": details.pop("candidateHead", None),
        "windowsVersion": platform.platform(),
        **details,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False))


def _require_native_opt_in() -> None:
    if os.name != "nt":
        raise WindowsControlAcceptanceError(
            "native Windows acceptance is unavailable on this platform"
        )
    if os.environ.get(OPT_IN_ENV) != OPT_IN_VALUE:
        raise WindowsControlAcceptanceError(
            f"{OPT_IN_ENV} must equal {OPT_IN_VALUE!r}"
        )


def _git_head(expected: str) -> str:
    if not isinstance(expected, str) or not _HEAD.fullmatch(expected):
        raise WindowsControlAcceptanceError(
            "expected head must be one lowercase 40-character Git SHA"
        )
    git = shutil.which("git.exe") or shutil.which("git")
    if not git:
        raise WindowsControlAcceptanceError("git executable is unavailable")
    git_path = Path(git).resolve(strict=True)
    if not git_path.is_file():
        raise WindowsControlAcceptanceError("resolved git path is not a file")

    def run(args: list[str]) -> str:
        proc = subprocess.run(
            [str(git_path), *args],
            cwd=str(_REPO_ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30,
            check=False,
            shell=False,
        )
        if proc.returncode != 0:
            raise WindowsControlAcceptanceError(
                f"git {' '.join(args)} failed with exit {proc.returncode}"
            )
        return proc.stdout.strip()

    actual = run(["rev-parse", "HEAD"]).lower()
    if actual != expected:
        raise WindowsControlAcceptanceError(
            f"wrong candidate head: expected {expected}, got {actual}"
        )
    dirty = run(["status", "--porcelain=v1", "--untracked-files=all"])
    if dirty:
        raise WindowsControlAcceptanceError(
            "working tree is dirty; native evidence must use an exact clean head"
        )
    return actual


def _current_user_sid() -> str:
    try:
        import win32api
        import win32security
    except ImportError as ex:
        raise WindowsControlAcceptanceError("pywin32 security APIs are unavailable") from ex

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(),
        win32security.TOKEN_QUERY,
    )
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        return win32security.ConvertSidToStringSid(sid).upper()
    finally:
        token.Close()


def _write_exclusive(path: Path, raw: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise WindowsControlAcceptanceError(
            f"refusing to replace existing acceptance file: {path.name}"
        )
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
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


def _fixture_root() -> Path:
    program_data = os.environ.get("PROGRAMDATA")
    if not program_data:
        raise WindowsControlAcceptanceError("PROGRAMDATA is unavailable")
    return Path(program_data) / "ForgeBoss" / _FIXTURE_DIRNAME


def _create_fixture_source(root: Path) -> None:
    if root.exists() or root.is_symlink():
        raise WindowsControlAcceptanceError(
            "acceptance source fixture already exists; use a fresh disposable host"
        )
    root.mkdir(parents=True, mode=0o700)

    db_path = root / SOURCE_DB
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE tasks(task_id TEXT PRIMARY KEY,status TEXT);
            CREATE TABLE workspace_leases(
              task_id TEXT PRIMARY KEY,
              released_at REAL,
              expires_at REAL
            );
            INSERT INTO meta(key,value) VALUES('schema_version','1');
            CREATE TABLE acceptance_padding(id INTEGER PRIMARY KEY,payload BLOB);
            """
        )
        # Large enough to make stop-during-copy testing practical without
        # creating an enormous fixture.
        conn.execute(
            "INSERT INTO acceptance_padding(payload) VALUES(?)",
            (sqlite3.Binary(os.urandom(16 * 1024 * 1024)),),
        )
        conn.commit()
    finally:
        conn.close()

    for name in SECRET_FILES:
        _write_exclusive(root / name, os.urandom(32))


def _pipe_request(method: str) -> Mapping[str, object]:
    if method not in {"health", "capabilities", "bootstrap.activate"}:
        raise WindowsControlAcceptanceError("acceptance method is not allowed")
    try:
        import win32con
        import win32file
        import win32pipe
    except ImportError as ex:
        raise WindowsControlAcceptanceError("pywin32 pipe APIs are unavailable") from ex

    request = json.dumps(
        {
            "version": PROTOCOL_VERSION,
            "id": "native-acceptance",
            "method": method,
            "params": {},
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")

    try:
        handle = win32file.CreateFile(
            PIPE_NAME,
            win32con.GENERIC_READ | win32con.GENERIC_WRITE,
            0,
            None,
            win32con.OPEN_EXISTING,
            0,
            None,
        )
    except Exception as ex:
        raise WindowsControlAcceptanceError(
            f"cannot connect to ForgeBoss control pipe for {method}"
        ) from ex

    try:
        win32pipe.SetNamedPipeHandleState(
            handle,
            win32pipe.PIPE_READMODE_MESSAGE,
            None,
            None,
        )
        win32file.WriteFile(handle, request)
        hr, raw = win32file.ReadFile(handle, MAX_MESSAGE_BYTES)
        if hr not in (0,):
            raise WindowsControlAcceptanceError(
                f"pipe response read returned status {hr}"
            )
    finally:
        win32file.CloseHandle(handle)

    try:
        response = json.loads(bytes(raw).decode("utf-8"))
    except Exception as ex:
        raise WindowsControlAcceptanceError("pipe response is not valid JSON") from ex
    if not isinstance(response, dict):
        raise WindowsControlAcceptanceError("pipe response root is not an object")
    return response


def _wait_service_status(wanted: int, timeout: float = 15.0) -> None:
    try:
        import win32service
        import win32serviceutil
    except ImportError as ex:
        raise WindowsControlAcceptanceError("pywin32 service APIs are unavailable") from ex
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
        if last == wanted:
            return
        time.sleep(0.1)
    raise WindowsControlAcceptanceError(
        f"service did not reach status {wanted}; last={last}"
    )


def _start_service() -> None:
    import win32service
    import win32serviceutil

    status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
    if status == win32service.SERVICE_RUNNING:
        return
    win32serviceutil.StartService(SERVICE_NAME)
    _wait_service_status(win32service.SERVICE_RUNNING)


def _stop_service() -> None:
    import win32service
    import win32serviceutil

    status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
    if status == win32service.SERVICE_STOPPED:
        return
    win32serviceutil.StopService(SERVICE_NAME)
    _wait_service_status(win32service.SERVICE_STOPPED)


def command_preflight(args) -> None:
    _require_native_opt_in()
    head = _git_head(args.expected_head)
    try:
        import importlib
        import win32serviceutil
    except ImportError as ex:
        raise WindowsControlAcceptanceError("pywin32 service utilities are unavailable") from ex

    cls = ForgeBossControlService
    class_string = win32serviceutil.GetServiceClassString(cls)
    module_name, class_name = class_string.rsplit(".", 1)
    reloaded = getattr(importlib.import_module(module_name), class_name)
    if reloaded is not cls:
        raise WindowsControlAcceptanceError(
            "registered pywin32 class string does not resolve to the live service class"
        )

    desktop_sid = _current_user_sid()
    service = verify_unrestricted_service_sid(desktop_sid=desktop_sid)
    _emit(
        "preflight",
        True,
        candidateHead=head,
        serviceName=SERVICE_NAME,
        serviceSid=service.service_sid,
        serviceSidUnrestricted=service.unrestricted,
        desktopSid=desktop_sid,
        serviceClass=class_string,
    )


def command_provision(args) -> None:
    _require_native_opt_in()
    head = _git_head(args.expected_head)
    desktop_sid = _current_user_sid()
    service = verify_unrestricted_service_sid(desktop_sid=desktop_sid)

    private_root = default_private_root()
    plan = create_private_root_atomic(
        service.service_sid,
        desktop_sid=desktop_sid,
        root=private_root,
    )
    inspection = inspect_private_directory_acl(plan.root)
    verify_private_acl_exact(plan, inspection)

    active = private_root / ACTIVE_STATE_FILE
    candidate = private_root / CANDIDATE_DIR
    if active.exists() or active.is_symlink() or candidate.exists() or candidate.is_symlink():
        raise WindowsControlAcceptanceError(
            "existing active/candidate state found; acceptance requires a fresh disposable host"
        )

    fixture = _fixture_root()
    _create_fixture_source(fixture)
    _write_exclusive(
        private_root / ALLOWED_CLIENT_SID_FILE,
        (desktop_sid + "\n").encode("ascii"),
    )
    _write_exclusive(
        private_root / BOOTSTRAP_SOURCE_ROOT_FILE,
        (str(fixture.resolve()) + "\r\n").encode("utf-8"),
    )

    _emit(
        "provision",
        True,
        candidateHead=head,
        privateAclExact=True,
        desktopSid=desktop_sid,
        serviceSid=service.service_sid,
        sourceFixture=str(fixture.resolve()),
        sourceStillPresent=fixture.exists(),
    )


def command_bootstrap(args) -> None:
    _require_native_opt_in()
    head = _git_head(args.expected_head)
    health = _pipe_request("health")
    if not health.get("ok") or not health.get("result", {}).get("ok"):
        raise WindowsControlAcceptanceError("pre-bootstrap health failed")
    caps = _pipe_request("capabilities")
    methods = tuple(caps.get("result", {}).get("methods", ()))
    if set(methods) != {"health", "capabilities"}:
        raise WindowsControlAcceptanceError(
            "bootstrap R0 capabilities expose an unexpected method set"
        )

    response = _pipe_request("bootstrap.activate")
    if not response.get("ok"):
        raise WindowsControlAcceptanceError(
            f"bootstrap.activate failed: {response.get('error', 'unknown error')}"
        )
    result = response.get("result")
    if not isinstance(result, dict):
        raise WindowsControlAcceptanceError("bootstrap result is not an object")
    if result.get("status") != "ACTIVATED_RESTART_REQUIRED":
        raise WindowsControlAcceptanceError("bootstrap status is unexpected")
    if result.get("restartRequired") is not True:
        raise WindowsControlAcceptanceError("bootstrap did not require restart")
    if any("secret" in str(key).casefold() for key in result):
        raise WindowsControlAcceptanceError("bootstrap response exposes secret metadata")

    # The same process must remain R0-only until restart.
    after = _pipe_request("capabilities")
    after_methods = tuple(after.get("result", {}).get("methods", ()))
    if set(after_methods) != {"health", "capabilities"}:
        raise WindowsControlAcceptanceError(
            "running service hot-loaded authority after bootstrap"
        )

    _emit(
        "bootstrap",
        True,
        candidateHead=head,
        status="ACTIVATED_RESTART_REQUIRED",
        restartRequired=True,
        currentProcessAuthorityExposed=False,
    )


def command_restart_verify(args) -> None:
    _require_native_opt_in()
    head = _git_head(args.expected_head)
    _stop_service()
    _start_service()

    health = _pipe_request("health")
    if not health.get("ok") or not health.get("result", {}).get("ok"):
        raise WindowsControlAcceptanceError("post-restart health failed")

    private_root = default_private_root()
    active_path = private_root / ACTIVE_STATE_FILE
    if not active_path.is_file():
        raise WindowsControlAcceptanceError("ACTIVE-STATE is missing after restart")
    active = parse_active_state_bytes(active_path.read_bytes())
    if active["status"] != ACTIVE_STATE_STATUS:
        raise WindowsControlAcceptanceError("ACTIVE-STATE status is invalid")

    service = verify_unrestricted_service_sid(desktop_sid=_current_user_sid())
    verified = verify_candidate_copy(
        private_root,
        expected_service_sid=service.service_sid,
        expected_desktop_sid=_current_user_sid(),
        verify_source=True,
    )
    if not Path(verified.source_root).is_dir():
        raise WindowsControlAcceptanceError("old source state is missing after cutover")

    _emit(
        "restart-verify",
        True,
        candidateHead=head,
        activeState=ACTIVE_STATE_STATUS,
        schemaVersion=verified.schema_version,
        sourceStillPresent=True,
        healthAfterRestart=True,
    )


def command_desktop_denial(args) -> None:
    _require_native_opt_in()
    head = _git_head(args.expected_head)
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise WindowsControlAcceptanceError(
            "desktop-denial must be run from a non-elevated desktop PowerShell"
        )

    health = _pipe_request("health")
    if not health.get("ok"):
        raise WindowsControlAcceptanceError(
            "configured desktop SID cannot reach the control pipe"
        )

    candidate = default_private_root() / CANDIDATE_DIR
    denied = []
    for name in SECRET_FILES:
        path = candidate / name
        try:
            with path.open("rb") as handle:
                handle.read(1)
        except PermissionError:
            denied.append(name)
        except OSError as ex:
            if getattr(ex, "winerror", None) == 5:
                denied.append(name)
            else:
                raise
        else:
            raise WindowsControlAcceptanceError(
                f"desktop token could read authority-bearing file {name}"
            )

    _emit(
        "desktop-denial",
        True,
        candidateHead=head,
        pipeHealth=True,
        authorityFileReadsDenied=len(denied),
        expectedDenied=len(SECRET_FILES),
    )


def _tamper_bytes(target: str, original: bytes) -> bytes:
    if target == "active":
        marker = b"ACTIVE_VERIFIED_STATE"
        if marker not in original:
            raise WindowsControlAcceptanceError("ACTIVE-STATE status marker is absent")
        return original.replace(marker, b"XCTIVE_VERIFIED_STATE", 1)
    # For manifest/DB/secret, changing bytes without updating bound hashes must
    # be enough to make startup refuse the selected state.
    return original + b"\nACCEPTANCE-TAMPER"


def command_tamper_matrix(args) -> None:
    _require_native_opt_in()
    head = _git_head(args.expected_head)
    private = default_private_root()
    targets = {
        "active": private / ACTIVE_STATE_FILE,
        "manifest": private / CANDIDATE_DIR / MANIFEST_FILE,
        "db": private / CANDIDATE_DIR / SOURCE_DB,
        "secret": private / CANDIDATE_DIR / SECRET_FILES[0],
    }
    checks = []

    for label, path in targets.items():
        if not path.is_file():
            raise WindowsControlAcceptanceError(
                f"tamper target is missing: {label}"
            )
        original = path.read_bytes()
        _stop_service()
        path.write_bytes(_tamper_bytes(label, original))
        startup_refused = False
        try:
            try:
                _start_service()
            except Exception:
                startup_refused = True
            if not startup_refused:
                time.sleep(0.5)
                try:
                    _pipe_request("health")
                except WindowsControlAcceptanceError:
                    startup_refused = True
        finally:
            try:
                _stop_service()
            except Exception:
                pass
            path.write_bytes(original)
            _start_service()

        if not startup_refused:
            raise WindowsControlAcceptanceError(
                f"service accepted tampered {label} state"
            )
        restored = _pipe_request("health")
        if not restored.get("ok"):
            raise WindowsControlAcceptanceError(
                f"service did not recover after restoring {label}"
            )
        checks.append(label)

    _emit(
        "tamper-matrix",
        True,
        candidateHead=head,
        tamperRefused=checks,
        restoredAfterEach=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Native Windows acceptance harness for ForgeBoss control-service cutover."
    )
    parser.add_argument(
        "--expected-head",
        required=True,
        help="Exact clean 40-character Git head under test.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    sub.add_parser("provision")
    sub.add_parser("bootstrap")
    sub.add_parser("restart-verify")
    sub.add_parser("desktop-denial")
    sub.add_parser("tamper-matrix")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    commands = {
        "preflight": command_preflight,
        "provision": command_provision,
        "bootstrap": command_bootstrap,
        "restart-verify": command_restart_verify,
        "desktop-denial": command_desktop_denial,
        "tamper-matrix": command_tamper_matrix,
    }
    try:
        commands[args.command](args)
        return 0
    except WindowsControlAcceptanceError as ex:
        _emit(
            args.command,
            False,
            candidateHead=args.expected_head,
            error=str(ex),
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
