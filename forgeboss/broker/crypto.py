from __future__ import annotations

import base64
import ctypes
import json
import os
import socket
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from forgeboss.executors.isolation_broker import _canonical


class BrokerCryptoError(RuntimeError):
    pass


WIN_ROOT = Path(r"C:\ProgramData\ForgeBoss\IsolationBroker")
LINUX_ROOT = Path("/var/lib/forgeboss/isolation-broker")
WIN_TRUST_KEY = r"SOFTWARE\ForgeBoss\IsolationBroker"
WIN_AUTH_PIPE = r"\\.\pipe\ForgeBossControllerAuthority.v1"
LINUX_AUTH_SOCKET = Path("/run/forgeboss/controller-authority-v1.sock")
LINUX_AUTH_TRUST = Path("/etc/forgeboss/controller-authority.json")
LINUX_BROKER_TRUST = Path("/etc/forgeboss/isolation-broker-trust.json")


def _linklike(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(hasattr(path, "is_junction") and path.is_junction())
    except OSError:
        return True


def broker_root() -> Path:
    path = WIN_ROOT if os.name == "nt" else LINUX_ROOT
    try:
        if not path.exists() or _linklike(path) or not path.is_dir():
            raise BrokerCryptoError("protected broker root missing/unsafe; service setup prerequisite not satisfied")
        if os.name != "nt":
            st = path.stat()
            if st.st_uid != 0 or (stat.S_IMODE(st.st_mode) & 0o022):
                raise BrokerCryptoError("protected broker root is not root-owned/write-protected")
        return path.resolve()
    except BrokerCryptoError:
        raise
    except Exception as ex:
        raise BrokerCryptoError("cannot validate protected broker root") from ex


def _b64key(raw, label: str) -> bytes:
    try:
        value = base64.b64decode(str(raw), validate=True)
    except Exception as ex:
        raise BrokerCryptoError(label + " invalid base64") from ex
    if len(value) != 32:
        raise BrokerCryptoError(label + " must be 32-byte Ed25519 key")
    return value


def _read_protected(path: Path, root_owned: bool = False) -> bytes:
    try:
        if _linklike(path) or not path.is_file():
            raise BrokerCryptoError("protected file is not regular: " + str(path))
        st = path.stat()
        if root_owned and st.st_uid != 0:
            raise BrokerCryptoError("protected file is not root-owned: " + str(path))
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise BrokerCryptoError("protected file is writable by group/world: " + str(path))
        return path.read_bytes()
    except BrokerCryptoError:
        raise
    except Exception as ex:
        raise BrokerCryptoError("cannot read protected file: " + str(path)) from ex


def _protected_json(path: Path) -> dict:
    try:
        obj = json.loads(_read_protected(path, root_owned=True).decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("object")
        return obj
    except BrokerCryptoError:
        raise
    except Exception as ex:
        raise BrokerCryptoError("protected trust JSON invalid: " + str(path)) from ex


def load_receipt_private_key() -> bytes:
    raw = _read_protected(broker_root() / "receipt-ed25519-private.key", root_owned=(os.name != "nt"))
    if len(raw) != 32:
        raise BrokerCryptoError("receipt private key must be exactly 32 raw bytes")
    return raw


def load_controller_public_key() -> bytes:
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WIN_TRUST_KEY, 0, winreg.KEY_READ) as key:
                raw, typ = winreg.QueryValueEx(key, "ControllerEd25519PublicKeyBase64")
            if typ != winreg.REG_SZ:
                raise BrokerCryptoError("controller public key trust has invalid type")
            return _b64key(raw, "controller public key")
        except BrokerCryptoError:
            raise
        except Exception as ex:
            raise BrokerCryptoError("controller public key trust unavailable in HKLM") from ex
    return _b64key(_protected_json(LINUX_AUTH_TRUST).get("ed25519PublicKeyBase64") or "", "controller public key")


def load_service_gid() -> int:
    if os.name == "nt":
        raise BrokerCryptoError("service GID is Linux-only")
    try:
        gid = int(_protected_json(LINUX_BROKER_TRUST).get("serviceGid"))
    except BrokerCryptoError:
        raise
    except Exception as ex:
        raise BrokerCryptoError("broker serviceGid trust unavailable") from ex
    if gid < 0:
        raise BrokerCryptoError("broker serviceGid trust invalid")
    return gid


class ReceiptSigner:
    def __init__(self, private_key=None):
        self.private_key = private_key

    def sign(self, receipt: dict) -> dict:
        key = self.private_key if self.private_key is not None else load_receipt_private_key()
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            signature = Ed25519PrivateKey.from_private_bytes(key).sign(_canonical(receipt))
        except ImportError as ex:
            raise BrokerCryptoError("protected host prerequisite missing: cryptography Ed25519 support") from ex
        except Exception as ex:
            raise BrokerCryptoError("broker receipt signing failed") from ex
        return {"signedReceipt": receipt, "receiptSignature": base64.b64encode(signature).decode("ascii")}


def _verify_attestation(envelope: dict, public_key: bytes) -> dict:
    signed = envelope.get("signedAuthority") if isinstance(envelope, dict) else None
    signature = envelope.get("authoritySignature") if isinstance(envelope, dict) else None
    if not isinstance(signed, dict) or not isinstance(signature, str):
        raise BrokerCryptoError("protected controller authority response is unsigned")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(public_key).verify(base64.b64decode(signature, validate=True), _canonical(signed))
    except ImportError as ex:
        raise BrokerCryptoError("protected host prerequisite missing: cryptography Ed25519 support") from ex
    except Exception as ex:
        raise BrokerCryptoError("protected controller authority signature verification failed") from ex
    return signed


def _recv(sock, count: int) -> bytes:
    out = b""
    while len(out) < count:
        chunk = sock.recv(count - len(out))
        if not chunk:
            raise BrokerCryptoError("protected authority IPC closed early")
        out += chunk
    return out


def _linux_exchange(request: dict) -> dict:
    try:
        st = LINUX_AUTH_SOCKET.stat()
        if st.st_uid != 0 or (stat.S_IMODE(st.st_mode) & 0o022) or not stat.S_ISSOCK(st.st_mode):
            raise BrokerCryptoError("controller authority socket trust invalid")
        raw = _canonical(request)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(10); sock.connect(str(LINUX_AUTH_SOCKET))
            if not hasattr(socket, "SO_PEERCRED"):
                raise BrokerCryptoError("SO_PEERCRED unavailable")
            _pid, uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid != 0:
                raise BrokerCryptoError("controller authority peer is not protected root service")
            sock.sendall(struct.pack("!I", len(raw)) + raw); length = struct.unpack("!I", _recv(sock, 4))[0]
            if length <= 0 or length > 1024 * 1024:
                raise BrokerCryptoError("controller authority response length invalid")
            return json.loads(_recv(sock, length).decode("utf-8"))
    except BrokerCryptoError:
        raise
    except Exception as ex:
        raise BrokerCryptoError("protected controller authority IPC failed") from ex


def _windows_exchange(request: dict) -> dict:
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True); H = wintypes.HANDLE; D = wintypes.DWORD; B = wintypes.BOOL; V = wintypes.LPVOID; PD = ctypes.POINTER(D)
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, D, D, V, D, D, H]; kernel32.CreateFileW.restype = H
    kernel32.ReadFile.argtypes = [H, V, D, PD, V]; kernel32.ReadFile.restype = B
    kernel32.WriteFile.argtypes = [H, V, D, PD, V]; kernel32.WriteFile.restype = B
    kernel32.CloseHandle.argtypes = [H]
    handle = kernel32.CreateFileW(WIN_AUTH_PIPE, 0xC0000000, 0, None, 3, 0, None); bad = ctypes.c_void_p(-1).value
    if ctypes.cast(handle, ctypes.c_void_p).value in (None, bad):
        raise BrokerCryptoError("protected controller authority named pipe unavailable")
    def write(data):
        offset = 0
        while offset < len(data):
            written = D(); buf = ctypes.create_string_buffer(data[offset:])
            if not kernel32.WriteFile(handle, buf, len(data) - offset, ctypes.byref(written), None) or written.value <= 0:
                raise BrokerCryptoError("authority pipe write failed")
            offset += written.value
    def read(count):
        out = bytearray()
        while len(out) < count:
            buf = ctypes.create_string_buffer(count - len(out)); got = D()
            if not kernel32.ReadFile(handle, buf, count - len(out), ctypes.byref(got), None) or got.value <= 0:
                raise BrokerCryptoError("authority pipe read failed")
            out.extend(buf.raw[:got.value])
        return bytes(out)
    try:
        raw = _canonical(request); write(struct.pack("!I", len(raw)) + raw); length = struct.unpack("!I", read(4))[0]
        if length <= 0 or length > 1024 * 1024:
            raise BrokerCryptoError("authority response length invalid")
        return json.loads(read(length).decode("utf-8"))
    finally:
        kernel32.CloseHandle(handle)


@dataclass(frozen=True)
class ProtectedAuthority:
    envelope_sha256: str
    task_id: str
    run_id: str
    owner_epoch: int
    base_sha: str
    worktree_path: str
    budget_usd: float
    expires_at: float
    allowed_paths: tuple[str, ...]
    runtime: dict
    result_ref: str
    paid_lease: dict
    spend_consume_id: str
    attestation_id: str


class ProtectedAuthorityVerifier:
    """Protected authority service must atomically consume the real spend grant."""

    def __init__(self, exchange=None, public_key=None):
        self.exchange = exchange
        self.public_key = public_key

    def verify(self, request: dict) -> ProtectedAuthority:
        paid_lease = request.get("paidLease")
        if not isinstance(paid_lease, dict):
            raise BrokerCryptoError("protected controller authority missing paid-lease binding")
        query = {
            "schema": 2,
            "operation": "consume-forgeboss-paid-authority",
            "envelopeSha256": request["envelopeSha256"],
            "taskId": request["taskId"],
            "runId": request["runId"],
            "ownerEpoch": request["ownerEpoch"],
            "baseSha": request["baseSha"],
            "worktreePath": request["worktreePath"],
            "budgetUsd": request["budgetUsd"],
            "expiresAt": request["expiresAt"],
            "allowedPaths": request["allowedPaths"],
            "runtime": request["runtime"],
            "resultRef": request["resultRef"],
            "paidLease": paid_lease,
        }
        envelope = self.exchange(query) if self.exchange else (_windows_exchange(query) if os.name == "nt" else _linux_exchange(query))
        signed = _verify_attestation(envelope, self.public_key or load_controller_public_key())
        for key, value in query.items():
            if key not in ("schema", "operation") and signed.get(key) != value:
                raise BrokerCryptoError("protected controller authority mismatch: " + key)
        attestation_id = str(signed.get("attestationId") or "")
        spend_consume_id = str(signed.get("spendConsumeId") or "")
        if not attestation_id or not spend_consume_id or signed.get("protected") is not True or signed.get("paidConsumed") is not True:
            raise BrokerCryptoError("protected paid authority consume prerequisite not satisfied")
        return ProtectedAuthority(
            query["envelopeSha256"], query["taskId"], query["runId"], int(query["ownerEpoch"]),
            query["baseSha"], query["worktreePath"], float(query["budgetUsd"]), float(query["expiresAt"]),
            tuple(query["allowedPaths"]), dict(query["runtime"]), query["resultRef"], dict(query["paidLease"]),
            spend_consume_id, attestation_id,
        )
