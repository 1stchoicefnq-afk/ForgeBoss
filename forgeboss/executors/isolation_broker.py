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
        if typ1 != winreg.REG_SZ or typ2 != winreg.REG_SZ:
            raise IsolationBrokerError("broker HKLM trust values have invalid type")
        if not isinstance(sid, str) or not sid.startswith("S-1-5-"):
            raise IsolationBrokerError("broker service SID trust value is invalid")
        return {"publicKey": _decode_public_key(pub), "serviceSid": sid}
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


def _sid_for_process(process_handle) -> str:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    TOKEN_QUERY = 0x0008
    TokenUser = 1
    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(process_handle, TOKEN_QUERY, ctypes.byref(token)):
        raise IsolationBrokerError("cannot query broker process token")
    try:
        needed = ctypes.c_ulong(0)
        advapi32.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, TokenUser, buf, needed, ctypes.byref(needed)):
            raise IsolationBrokerError("cannot read broker token user")
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        text = ctypes.c_void_p()
        if not advapi32.ConvertSidToStringSidW(sid_ptr, ctypes.byref(text)):
            raise IsolationBrokerError("cannot stringify broker SID")
        try:
            return ctypes.wstring_at(text)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.CloseHandle(token)


def _windows_exchange(request: dict, trust: dict) -> dict:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_FLAG_WRITE_THROUGH = 0x80000000
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    handle = kernel32.CreateFileW(_WIN_PIPE, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, None)
    if handle == INVALID_HANDLE_VALUE:
        raise IsolationBrokerError("fixed protected broker named pipe is unavailable")
    try:
        server_pid = ctypes.c_ulong(0)
        if not kernel32.GetNamedPipeServerProcessId(handle, ctypes.byref(server_pid)):
            raise IsolationBrokerError("cannot authenticate named-pipe server PID")
        proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, server_pid.value)
        if not proc:
            raise IsolationBrokerError("cannot open broker server process")
        try:
            sid = _sid_for_process(proc)
            if sid != trust["serviceSid"]:
                raise IsolationBrokerError("broker process SID differs from HKLM-pinned service identity")
        finally:
            kernel32.CloseHandle(proc)
        raw = _canonical(request)
        framed = struct.pack("!I", len(raw)) + raw
        _win_write_all(kernel32, handle, framed)
        header = _win_read_exact(kernel32, handle, 4)
        length = struct.unpack("!I", header)[0]
        if length <= 0 or length > _MAX_REPLY:
            raise IsolationBrokerError("broker reply length is invalid")
        payload = _win_read_exact(kernel32, handle, length)
    finally:
        kernel32.CloseHandle(handle)
    return json.loads(payload.decode("utf-8"))


def _win_write_all(kernel32, handle, data: bytes):
    offset = 0
    while offset < len(data):
        written = ctypes.c_ulong(0)
        chunk = data[offset:]
        buf = ctypes.create_string_buffer(chunk)
        if not kernel32.WriteFile(handle, buf, len(chunk), ctypes.byref(written), None) or written.value <= 0:
            raise IsolationBrokerError("broker named-pipe write failed")
        offset += written.value


def _win_read_exact(kernel32, handle, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        want = size - len(out)
        buf = ctypes.create_string_buffer(want)
        got = ctypes.c_ulong(0)
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
    bindings = {
        "requestSha256": _digest(request),
        "preAuthoritySha256": _digest(pre_authority),
        "preTargetsSha256": _digest(pre_targets),
        "authoritySha256": _digest(reply.get("authority")),
    }
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
        if state.get("kind") == "missing": expected_ordinary.pop(rel, None)
        else: expected_ordinary[rel] = state
    if current["ordinary"] != expected_ordinary:
        raise IsolationBrokerError("host ordinary state differs from authenticated broker receipt")
    if receipt.get("postAuthoritySha256") != _digest(current) or receipt.get("postTargetsSha256") != _digest(canonical_post):
        raise IsolationBrokerError("reintegration receipt post-state digest mismatch")
    return [allowed_keys[x.casefold()] for x in applied]


def run_isolated_mini_swe(lease_path, token, packet_path, workspace, control_envelope, cli_budget, model_name, image):
    host = Path(workspace).resolve(); packet_path = Path(packet_path); packet = json.loads(packet_path.read_text(encoding="utf-8"))
    guard.validate_packet(packet); guard.assert_no_link_escape(host)
    authority = _expected_authority(lease_path, control_envelope, host, "mini-swe", cli_budget)
    pre_authority = _capture_authority(host); pre_targets = _capture_targets(host, packet)
    request = {"schema":3,"operation":"run-mini-swe-v3","workspace":str(host),"packetPath":str(packet_path.resolve()),"leasePath":str(Path(lease_path).resolve()),"leaseToken":str(token),"controlEnvelope":control_envelope,"budgetUsd":float(authority["budgetUsd"]),"model":str(model_name),"image":str(image),"expectedAuthority":{k:authority[k] for k in ("taskId","runId","ownerEpoch","envelopeSha256","budgetUsd")},"preAuthority":pre_authority,"preAuthoritySha256":_digest(pre_authority),"preTargets":pre_targets,"preTargetsSha256":_digest(pre_targets)}
    reply = _call_broker(request); _validate_reply_authority(reply, authority); applied = _verify_receipt(reply, request, host, packet, pre_authority, pre_targets)
    return {"completed":reply.get("completed") is True,"cost_usd":reply.get("cost_usd"),"calls":reply.get("calls"),"error":reply.get("error"),"applied":applied,"authority":authority}
