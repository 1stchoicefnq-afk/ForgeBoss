from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path


class VaultUnavailable(RuntimeError):
    pass


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _configure_dpapi():
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.c_wchar_p, ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(DATA_BLOB)
    ]
    crypt32.CryptProtectData.restype = wt.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(DATA_BLOB)
    ]
    crypt32.CryptUnprotectData.restype = wt.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def _blob(data: bytes):
    buf = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte))), buf


def _dpapi_protect(data: bytes) -> bytes:
    if os.name != "nt":
        raise VaultUnavailable("Windows DPAPI is unavailable on this platform; insecure fallback is refused")
    crypt32, kernel32 = _configure_dpapi()
    in_blob, keep = _blob(data)
    out_blob = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(in_blob), "ForgeBoss Vault", None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise VaultUnavailable("Windows DPAPI is unavailable on this platform; insecure fallback is refused")
    crypt32, kernel32 = _configure_dpapi()
    in_blob, keep = _blob(data)
    out_blob = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def default_vault_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise VaultUnavailable("LOCALAPPDATA is unavailable; refusing to store secrets in project directories")
    return Path(base) / "ForgeBoss" / "Vault"


@dataclass
class SecretLease:
    ref: str
    provider: str
    project_id: str
    run_id: str
    expires_at: float
    _value: str

    def reveal(self, project_id: str, run_id: str) -> str:
        if time.time() >= self.expires_at:
            raise PermissionError("secret lease expired")
        if project_id != self.project_id or run_id != self.run_id:
            raise PermissionError("secret lease scope mismatch")
        return self._value

    def __repr__(self) -> str:
        return f"SecretLease(ref={self.ref!r}, provider={self.provider!r}, expires_at={self.expires_at!r}, value=[REDACTED])"

    def __getstate__(self):
        raise TypeError("SecretLease must not be serialized or pickled")


class WindowsVault:
    """DPAPI-backed user vault. Raw secrets never enter project state."""

    def __init__(self, root: str | Path | None = None):
        if os.name != "nt":
            raise VaultUnavailable("WindowsVault requires Windows DPAPI")
        self.root = Path(root) if root else default_vault_root()
        self.root.mkdir(parents=True, exist_ok=True)
        self.meta = self.root / "metadata.json"

    def _load_meta(self) -> dict:
        if not self.meta.exists():
            return {"schema": 1, "secrets": {}}
        return json.loads(self.meta.read_text(encoding="utf-8"))

    def _save_meta(self, data: dict) -> None:
        tmp = self.meta.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.meta)

    def store(self, provider: str, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("secret must not be empty")
        ref = "sec_" + secrets.token_hex(16)
        encrypted = _dpapi_protect(value.encode("utf-8"))
        (self.root / f"{ref}.secret").write_bytes(encrypted)
        meta = self._load_meta()
        meta["secrets"][ref] = {"provider": provider, "last4": value[-4:], "created_at": time.time()}
        self._save_meta(meta)
        return ref

    def status(self, ref: str) -> dict:
        meta = self._load_meta().get("secrets", {}).get(ref)
        if not meta:
            raise KeyError(ref)
        return {"ref": ref, "provider": meta["provider"], "display": f"••••{meta['last4']}"}

    def lease(self, ref: str, *, project_id: str, run_id: str, ttl_seconds: int = 300) -> SecretLease:
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise ValueError("lease ttl must be between 1 and 3600 seconds")
        meta = self._load_meta().get("secrets", {}).get(ref)
        if not meta:
            raise KeyError(ref)
        value = _dpapi_unprotect((self.root / f"{ref}.secret").read_bytes()).decode("utf-8")
        return SecretLease(ref, meta["provider"], project_id, run_id, time.time()+ttl_seconds, value)

    def delete(self, ref: str) -> None:
        meta = self._load_meta()
        if ref not in meta.get("secrets", {}):
            return
        p = self.root / f"{ref}.secret"
        if p.exists():
            p.unlink()
        del meta["secrets"][ref]
        self._save_meta(meta)
