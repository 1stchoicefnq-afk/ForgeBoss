from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import math
import os
import socket
import stat
import struct
from pathlib import Path

from forgeboss.security import executor_guard as guard


class IsolationBrokerError(guard.SecurityError):
    pass


_MAX_REPLY = 16 * 1024 * 1024
_WIN_PIPE = r"\\.\pipe\ForgeBossIsolationBroker.v3"
_LINUX_SOCKET = Path("/run/forgeboss/isolation-broker-v3.sock")
_LINUX_TRUST = Path("/etc/forgeboss/isolation-broker-trust.json")
_WIN_TRUST_KEY = r"SOFTWARE\ForgeBoss\IsolationBroker"
_TRUST_VALUE_KEY = "Ed25519PublicKeyBase64"
_TRUST_VALUE_SID = "ServiceSid"
_TRUST_VALUE_SERVICE = "ServiceName"
_TRUST_VALUE_IMAGE = "ImagePath"
_SE_GROUP_ENABLED = 0x00000004
_SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010


def _positive_budget(raw):
    if isinstance(raw, bool):
        raise IsolationBrokerError("paid budget must be a finite positive number")
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError) as ex:
        raise IsolationBrokerError("paid budget must be a finite positive number") from ex
    if not math.isfinite(value) or value <= 0:
        raise IsolationBrokerError("paid budget must be a finite positive number")
    return value


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _decode_public_key(raw: str) -> bytes:
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as ex:
        raise IsolationBrokerError("broker trust public key is invalid base64") from ex
    if len(key) != 32:
        raise IsolationBrokerError("broker trust public key must be Ed25519/32-byte")
    return key


def _windows_trust():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WIN_TRUST_KEY, 0, winreg.KEY_READ) as key:
            pub, typ1 = winreg.QueryValueEx(key, _TRUST_VALUE_KEY)
            sid, typ2 = winreg.QueryValueEx(key, _TRUST_VALUE_SID)
            service, typ3 = winreg.QueryValueEx(key, _TRUST_VALUE_SERVICE)
            image, typ4 = winreg.QueryValueEx(key, _TRUST_VALUE_IMAGE)
        if any(t != winreg.REG_SZ for t in (typ1, typ2, typ3, typ4)):
            raise IsolationBrokerError("broker HKLM trust values have invalid type")
        if not isinstance(sid, str) or not sid.startswith("S-1-5-80-"):
            raise IsolationBrokerError("broker ServiceSid must be a Windows per-service SID")
        if not isinstance(service, str) or service.strip() != service or not service:
            raise IsolationBrokerError("broker ServiceName trust value is invalid")
        if not isinstance(image, str) or not image.strip() or not os.path.isabs(image):
            raise IsolationBrokerError("broker ImagePath trust value must be absolute")
        return {
            "publicKey": _decode_public_key(pub),
            "serviceSid": sid,
            "serviceName": service,
            "imagePath": os.path.normcase(os.path.normpath(image)),
        }
    except IsolationBrokerError:
        raise
    except Exception as ex:
        raise IsolationBrokerError("OS-pinned broker trust is unavailable in HKLM") from ex


def _linux_trust():
    try:
        st = _LINUX_TRUST.stat()
        if st.st_uid != 0 or (stat.S_IMODE(st.st_mode) & 0o022):
            raise IsolationBrokerError("broker trust file is not root-owned/write-protected")
        obj = json.loads(_LINUX_TRUST.read_text(encoding="utf-8"))
        uid = int(obj.get("serviceUid"))
        if uid < 0:
            raise ValueError("uid")
        return {"publicKey": _decode_public_key(str(obj.get("ed25519PublicKeyBase64") or "")), "serviceUid": uid}
    except IsolationBrokerError:
        raise
    except Exception as ex:
        raise IsolationBrokerError("OS-pinned broker trust file is unavailable") from ex


def _trust_anchor():
    return _windows_trust() if os.name == "nt" else _linux_trust()


def _verify_signed_reply(envelope: dict, public_key: bytes) -> dict:
    if not isinstance(envelope, dict):
        raise IsolationBrokerError("broker returned invalid signed envelope")
    signed = envelope.get("signedReceipt")
    signature = envelope.get("receiptSignature")
    if not isinstance(signed, dict) or not isinstance(signature, str):
        raise IsolationBrokerError("broker response is missing signed receipt")
    try:
        sig = base64.b64decode(signature, validate=True)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as ex:
        raise IsolationBrokerError("protected host prerequisite missing: pinned cryptography package for Ed25519 verification") from ex
    except Exception as ex:
        raise IsolationBrokerError("broker receipt signature encoding is invalid") from ex
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, _canonical(signed))
    except Exception as ex:
        raise IsolationBrokerError("broker receipt signature verification failed") from ex
    return signed


def _linux_exchange(request: dict, trust: dict) -> dict:
    try:
        st = _LINUX_SOCKET.stat()
        if st.st_uid != trust["serviceUid"] or (stat.S_IMODE(st.st_mode) & 0o022):
            raise IsolationBrokerError("broker socket owner/mode differs from pinned service identity")
        if not stat.S_ISSOCK(st.st_mode):
            raise IsolationBrokerError("broker endpoint is not a Unix socket")
        raw = _canonical(request)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(3600)
            sock.connect(str(_LINUX_SOCKET))
            if not hasattr(socket, "SO_PEERCRED"):
                raise IsolationBrokerError("kernel peer credentials unavailable for broker socket")
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
            if uid != trust["serviceUid"]:
                raise IsolationBrokerError("broker Unix peer UID differs from pinned service identity")
            sock.sendall(struct.pack("!I", len(raw)) + raw)
            header = _recv_exact(sock, 4)
            length = struct.unpack("!I", header)[0]
            if length <= 0 or length > _MAX_REPLY:
                raise IsolationBrokerError("broker reply length is invalid")
            payload = _recv_exact(sock, length)
    except IsolationBrokerError:
        raise
    except Exception as ex:
        raise IsolationBrokerError("protected Unix broker IPC failed") from ex
    return json.loads(payload.decode("utf-8"))


def _recv_exact(sock, size: int) -> bytes:
    chunks = []
    left = size
    while left:
        chunk = sock.recv(left)
        if not chunk:
            raise IsolationBrokerError("broker IPC closed early")
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def _win_libs():
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    HANDLE = wintypes.HANDLE
    DWORD = wintypes.DWORD
    BOOL = wintypes.BOOL
    LPVOID = wintypes.LPVOID
    LPDWORD = ctypes.POINTER(DWORD)
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE]
    kernel32.CreateFileW.restype = HANDLE
    kernel32.GetNamedPipeServerProcessId.argtypes = [HANDLE, LPDWORD]
    kernel32.GetNamedPipeServerProcessId.restype = BOOL
    kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
    kernel32.OpenProcess.restype = HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [HANDLE, DWORD, wintypes.LPWSTR, LPDWORD]
    kernel32.QueryFullProcessImageNameW.restype = BOOL
    kernel32.ReadFile.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD, LPVOID]
    kernel32.ReadFile.restype = BOOL
    kernel32.WriteFile.argtypes = [HANDLE, LPVOID, DWORD, LPDWORD, LPVOID]
    kernel32.WriteFile.restype = BOOL
    kernel32.CloseHandle.argtypes = [HANDLE]
    kernel32.CloseHandle.restype = BOOL
    kernel32.LocalFree.argtypes = [LPVOID]
    kernel32.LocalFree.restype = LPVOID
    advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD, ctypes.POINTER(HANDLE)]
    advapi32.OpenProcessToken.restype = BOOL
    advapi32.GetTokenInformation.argtypes = [HANDLE, ctypes.c_int, LPVOID, DWORD, LPDWORD]
    advapi32.GetTokenInformation.restype = BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = BOOL
    advapi32.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, DWORD]
    advapi32.OpenSCManagerW.restype = HANDLE
    advapi32.OpenServiceW.argtypes = [HANDLE, wintypes.LPCWSTR, DWORD]
    advapi32.OpenServiceW.restype = HANDLE
    advapi32.QueryServiceStatusEx.argtypes = [HANDLE, ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), DWORD, LPDWORD]
    advapi32.QueryServiceStatusEx.restype = BOOL
    advapi32.CloseServiceHandle.argtypes = [HANDLE]
    advapi32.CloseServiceHandle.restype = BOOL
    return kernel32, advapi32, wintypes


def _sid_to_text(advapi32, kernel32, sid_ptr) -> str:
    from ctypes import wintypes
    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(text)):
        raise IsolationBrokerError("cannot stringify broker token SID")
    try:
        return ctypes.wstring_at(text)
    finally:
        kernel32.LocalFree(text)


def _token_group_sids(process_handle):
    kernel32, advapi32, wintypes = _win_libs()
    TOKEN_QUERY = 0x0008
    TokenGroups = 2
    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]
    class TOKEN_GROUPS_ONE(ctypes.Structure):
        _fields_ = [("GroupCount", wintypes.DWORD), ("Groups", SID_AND_ATTRIBUTES * 1)]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(process_handle, TOKEN_QUERY, ctypes.byref(token)):
        raise IsolationBrokerError("cannot query broker process token")
    try:
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, TokenGroups, None, 0, ctypes.byref(needed))
        if needed.value <= 0:
            raise IsolationBrokerError("cannot size broker token groups")
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TokenGroups, buf, needed, ctypes.byref(needed)):
            raise IsolationBrokerError("cannot read broker token groups")
        count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
        if count > 65536:
            raise IsolationBrokerError("broker token group count is unreasonable")
        groups_type = SID_AND_ATTRIBUTES * count
        groups = groups_type.from_address(ctypes.addressof(buf) + TOKEN_GROUPS_ONE.Groups.offset)
        return [(_sid_to_text(advapi32, kernel32, g.Sid), int(g.Attributes)) for g in groups]
    finally:
        kernel32.CloseHandle(token)


def _has_enabled_service_sid(groups, expected_sid: str) -> bool:
    wanted = expected_sid.casefold()
    for sid, attrs in groups:
        if sid.casefold() == wanted and (attrs & _SE_GROUP_ENABLED) and not (attrs & _SE_GROUP_USE_FOR_DENY_ONLY):
            return True
    return False


def _pipe_server_pid(kernel32, handle) -> int:
    from ctypes import wintypes
    pid = wintypes.DWORD(0)
    if not kernel32.GetNamedPipeServerProcessId(handle, ctypes.byref(pid)) or pid.value <= 0:
        raise IsolationBrokerError("cannot authenticate named-pipe server PID")
    return int(pid.value)


def _process_image(kernel32, process_handle) -> str:
    from ctypes import wintypes
    size = wintypes.DWORD(32768)
    buf = ctypes.create_unicode_buffer(size.value)
    if not kernel32.QueryFullProcessImageNameW(process_handle, 0, buf, ctypes.byref(size)):
        raise IsolationBrokerError("cannot query broker server process image")
    return os.path.normcase(os.path.normpath(buf.value))


def _registered_service_pid(advapi32, service_name: str) -> int:
    from ctypes import wintypes
    SC_MANAGER_CONNECT = 0x0001
    SERVICE_QUERY_STATUS = 0x0004
    SC_STATUS_PROCESS_INFO = 0
    class SERVICE_STATUS_PROCESS(ctypes.Structure):
        _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD), ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD), ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD), ("dwWaitHint", wintypes.DWORD), ("dwProcessId", wintypes.DWORD), ("dwServiceFlags", wintypes.DWORD)]
    scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        raise IsolationBrokerError("cannot open Windows service control manager")
    try:
        service = advapi32.OpenServiceW(scm, service_name, SERVICE_QUERY_STATUS)
        if not service:
            raise IsolationBrokerError("pinned ForgeBoss broker service is not registered")
        try:
            status = SERVICE_STATUS_PROCESS()
            needed = wintypes.DWORD(0)
            ok = advapi32.QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, ctypes.cast(ctypes.byref(status), ctypes.POINTER(ctypes.c_ubyte)), ctypes.sizeof(status), ctypes.byref(needed))
            if not ok or status.dwProcessId <= 0:
                raise IsolationBrokerError("cannot authenticate pinned broker service process")
            return int(status.dwProcessId)
        finally:
            advapi32.CloseServiceHandle(service)
    finally:
        advapi32.CloseServiceHandle(scm)


def _authenticate_windows_server(handle, trust: dict):
    kernel32, advapi32, _wintypes = _win_libs()
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    first_pid = _pipe_server_pid(kernel32, handle)
    if first_pid != _registered_service_pid(advapi32, trust["serviceName"]):
        raise IsolationBrokerError("named-pipe server PID is not the pinned broker service instance")
    proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, first_pid)
    if not proc:
        raise IsolationBrokerError("cannot open broker server process")
    try:
        if _process_image(kernel32, proc) != trust["imagePath"]:
            raise IsolationBrokerError("broker process image differs from HKLM-pinned service image")
        if not _has_enabled_service_sid(_token_group_sids(proc), trust["serviceSid"]):
            raise IsolationBrokerError("broker process lacks enabled HKLM-pinned Windows service SID")
        if _pipe_server_pid(kernel32, handle) != first_pid:
            raise IsolationBrokerError("named-pipe server changed during authentication")
        if _registered_service_pid(advapi32, trust["serviceName"]) != first_pid:
            raise IsolationBrokerError("pinned broker service process changed during authentication")
        if _process_image(kernel32, proc) != trust["imagePath"]:
            raise IsolationBrokerError("broker process image changed during authentication")
    finally:
        kernel32.CloseHandle(proc)


def _windows_exchange(request: dict, trust: dict) -> dict:
    kernel32, _advapi32, _wintypes = _win_libs()
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_FLAG_WRITE_THROUGH = 0x80000000
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    handle = kernel32.CreateFileW(_WIN_PIPE, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, None)
    if ctypes.cast(handle, ctypes.c_void_p).value in (None, INVALID_HANDLE_VALUE):
        raise IsolationBrokerError("fixed protected broker named pipe is unavailable")
    try:
        _authenticate_windows_server(handle, trust)
        raw = _canonical(request)
        _win_write_all(kernel32, handle, struct.pack("!I", len(raw)) + raw)
        header = _win_read_exact(kernel32, handle, 4)
        length = struct.unpack("!I", header)[0]
        if length <= 0 or length > _MAX_REPLY:
            raise IsolationBrokerError("broker reply length is invalid")
        payload = _win_read_exact(kernel32, handle, length)
    finally:
        kernel32.CloseHandle(handle)
    return json.loads(payload.decode("utf-8"))


def _win_write_all(kernel32, handle, data: bytes):
    from ctypes import wintypes
    offset = 0
    while offset < len(data):
        written = wintypes.DWORD(0)
        chunk = data[offset:]
        buf = ctypes.create_string_buffer(chunk)
        if not kernel32.WriteFile(handle, buf, len(chunk), ctypes.byref(written), None) or written.value <= 0:
            raise IsolationBrokerError("broker named-pipe write failed")
        offset += written.value


def _win_read_exact(kernel32, handle, size: int) -> bytes:
    from ctypes import wintypes
    out = bytearray()
    while len(out) < size:
        want = size - len(out)
        buf = ctypes.create_string_buffer(want)
        got = wintypes.DWORD(0)
        if not kernel32.ReadFile(handle, buf, want, ctypes.byref(got), None) or got.value <= 0:
            raise IsolationBrokerError("broker named-pipe read failed")
        out.extend(buf.raw[:got.value])
    return bytes(out)


def _file_state(path: Path):
    if not path.exists():
        return {"kind": "missing"}
    if guard.is_linklike(path) or not path.is_file():
        return {"kind": "unsafe"}
    data = path.read_bytes()
    return {"kind": "file", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _capture_targets(host: Path, packet: dict):
    allowed, _ = guard.validate_packet(packet)
    result = {}
    for rel in allowed:
        guard.assert_paths_contained(host, [rel])
        state = _file_state(host / rel)
        if state.get("kind") == "unsafe":
            raise IsolationBrokerError("host target is unsafe before broker run: " + rel)
        result[rel] = state
    return result


def _capture_authority(host: Path):
    return {"ordinary": guard.snapshot(host), "git": guard.git_metadata_snapshot(host), "head": guard.git(host, "rev-parse", "HEAD"), "worktree": guard.git(host, "rev-parse", "--show-toplevel")}


def _expected_authority(lease_path, control_envelope, workspace, executor, cli_budget):
    lease = json.loads(Path(lease_path).read_text(encoding="utf-8"))
    authority = guard._control_authority(control_envelope, lease, Path(workspace).resolve(), executor)
    budget = _positive_budget(cli_budget)
    if budget != float(authority["budgetUsd"]):
        raise IsolationBrokerError("runner budget differs from signed control authority")
    for key in ("taskId", "runId", "ownerEpoch", "envelopeSha256"):
        if not authority.get(key):
            raise IsolationBrokerError("signed control authority is incomplete: " + key)
    return authority


def _call_broker(request: dict) -> dict:
    trust = _trust_anchor()
    envelope = _windows_exchange(request, trust) if os.name == "nt" else _linux_exchange(request, trust)
    reply = _verify_signed_reply(envelope, trust["publicKey"])
    if reply.get("schema") != 3 or reply.get("ok") is not True:
        raise IsolationBrokerError("broker returned invalid authenticated result")
    for field in ("isolated", "paidConsumed", "reintegrated", "reintegrationProtected", "ordinaryWorkersDeniedDirectWrite", "preopenedWritableHandlesExcluded"):
        if reply.get(field) is not True:
            raise IsolationBrokerError("broker did not prove protected reintegration: " + field)
    if reply.get("hostWorkspaceMounted") is not False or reply.get("workerHasRuntimeControl") is not False or reply.get("localCopybackRequired") is not False:
        raise IsolationBrokerError("broker boundary exposed or delegated protected state")
    if reply.get("changes") not in (None, []):
        raise IsolationBrokerError("authenticated broker returned local file payloads")
    return reply


def _validate_reply_authority(reply: dict, expected: dict) -> None:
    actual = reply.get("authority")
    if not isinstance(actual, dict):
        raise IsolationBrokerError("broker result is missing exact authority binding")
    for key in ("taskId", "runId", "ownerEpoch", "envelopeSha256"):
        if actual.get(key) != expected.get(key):
            raise IsolationBrokerError("broker authority mismatch: " + key)
    if _positive_budget(actual.get("budgetUsd")) != float(expected["budgetUsd"]):
        raise IsolationBrokerError("broker authority mismatch: budgetUsd")


def _verify_receipt(reply: dict, request: dict, host: Path, packet: dict, pre_authority: dict, pre_targets: dict):
    receipt = reply.get("reintegrationReceipt")
    if not isinstance(receipt, dict) or receipt.get("schema") != 2:
        raise IsolationBrokerError("authenticated broker result lacks reintegration receipt")
    bindings = {"requestSha256": _digest(request), "preAuthoritySha256": _digest(pre_authority), "preTargetsSha256": _digest(pre_targets), "authoritySha256": _digest(reply.get("authority"))}
    for key, expected in bindings.items():
        if receipt.get(key) != expected:
            raise IsolationBrokerError("reintegration receipt binding mismatch: " + key)
    allowed, _ = guard.validate_packet(packet)
    allowed_keys = {p.casefold(): p for p in allowed}
    applied = receipt.get("appliedPaths")
    if not isinstance(applied, list) or any(not isinstance(x, str) or x.casefold() not in allowed_keys for x in applied) or len(applied) != len({x.casefold() for x in applied}):
        raise IsolationBrokerError("reintegration receipt applied path set is invalid")
    post_targets = receipt.get("postTargets")
    if not isinstance(post_targets, dict):
        raise IsolationBrokerError("reintegration receipt missing post-target state")
    canonical_post = {}
    for rel in allowed:
        expected = post_targets.get(rel, pre_targets[rel])
        if not isinstance(expected, dict):
            raise IsolationBrokerError("reintegration receipt post-target state is invalid: " + rel)
        actual = _file_state(host / rel)
        if actual != expected:
            raise IsolationBrokerError("host target does not match authenticated broker receipt: " + rel)
        canonical_post[rel] = actual
    current = _capture_authority(host)
    if current["git"] != pre_authority["git"] or current["head"] != pre_authority["head"] or current["worktree"] != pre_authority["worktree"]:
        raise IsolationBrokerError("host Git authority changed across authenticated broker reintegration")
    expected_ordinary = dict(pre_authority["ordinary"])
    for rel in allowed:
        state = canonical_post[rel]
        if state.get("kind") == "missing":
            expected_ordinary.pop(rel, None)
        else:
            expected_ordinary[rel] = state
    if current["ordinary"] != expected_ordinary:
        raise IsolationBrokerError("host ordinary state differs from authenticated broker receipt")
    if receipt.get("postAuthoritySha256") != _digest(current) or receipt.get("postTargetsSha256") != _digest(canonical_post):
        raise IsolationBrokerError("reintegration receipt post-state digest mismatch")
    return [allowed_keys[x.casefold()] for x in applied]


def run_isolated_mini_swe(lease_path, token, packet_path, workspace, control_envelope, cli_budget, model_name, image):
    host = Path(workspace).resolve()
    packet_path = Path(packet_path)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    guard.validate_packet(packet)
    guard.assert_no_link_escape(host)
    authority = _expected_authority(lease_path, control_envelope, host, "mini-swe", cli_budget)
    pre_authority = _capture_authority(host)
    pre_targets = _capture_targets(host, packet)
    request = {"schema": 3, "operation": "run-mini-swe-v3", "workspace": str(host), "packetPath": str(packet_path.resolve()), "leasePath": str(Path(lease_path).resolve()), "leaseToken": str(token), "controlEnvelope": control_envelope, "budgetUsd": float(authority["budgetUsd"]), "model": str(model_name), "image": str(image), "expectedAuthority": {k: authority[k] for k in ("taskId", "runId", "ownerEpoch", "envelopeSha256", "budgetUsd")}, "preAuthority": pre_authority, "preAuthoritySha256": _digest(pre_authority), "preTargets": pre_targets, "preTargetsSha256": _digest(pre_targets)}
    reply = _call_broker(request)
    _validate_reply_authority(reply, authority)
    applied = _verify_receipt(reply, request, host, packet, pre_authority, pre_targets)
    return {"completed": reply.get("completed") is True, "cost_usd": reply.get("cost_usd"), "calls": reply.get("calls"), "error": reply.get("error"), "applied": applied, "authority": authority}
