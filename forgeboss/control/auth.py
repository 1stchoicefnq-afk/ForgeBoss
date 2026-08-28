from __future__ import annotations
import hashlib
import hmac
import math
import os
import secrets
import time
from pathlib import Path
from .envelope import canonical
from forgeboss.security.local_acl import harden_private_dir, harden_private_path

ROOT = Path(__file__).resolve().parents[2]
AUTH_WINDOW_SECONDS = 30
NONCE_HEX_LEN = 32
CLIENT_AUTH_DOMAIN = b"forgeboss/client-auth/v1\x00"
CLIENT_AUTH_PREFIX = "client-hmac-sha256:"


def client_auth_file(root: Path = ROOT):
    """Dedicated low-authority client/session credential; never launch-signing material."""
    path = Path(root) / "state" / "forgebossd" / "client-auth-secret.bin"
    harden_private_dir(path.parent)
    if not path.exists():
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, secrets.token_bytes(32))
                os.fsync(fd)
            finally:
                os.close(fd)
        except FileExistsError:
            pass
    harden_private_path(path)
    data = path.read_bytes()
    if len(data) != 32:
        raise RuntimeError("client auth credential is invalid")
    return path, data


def derive_client_auth_key(client_secret: bytes) -> bytes:
    if not isinstance(client_secret, (bytes, bytearray)) or len(client_secret) != 32:
        raise ValueError("client auth credential invalid")
    return hmac.new(bytes(client_secret), CLIENT_AUTH_DOMAIN, hashlib.sha256).digest()


def _strict_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} invalid")
    return value


def material(params):
    if not isinstance(params, dict):
        raise ValueError("connect params invalid")
    caps = params.get("capabilities")
    if not isinstance(caps, list) or any(not isinstance(x, str) or not x for x in caps):
        raise ValueError("connect capabilities invalid")
    if len({x.casefold() for x in caps}) != len(caps):
        raise ValueError("connect capabilities duplicate")
    nonce = params.get("nonce")
    if not isinstance(nonce, str) or len(nonce) != NONCE_HEX_LEN or any(c not in "0123456789abcdef" for c in nonce):
        raise PermissionError("connect nonce invalid")
    client = params.get("client")
    if not isinstance(client, str) or not client or len(client) > 128:
        raise ValueError("connect client invalid")
    return {
        "protocolVersion": _strict_int(params.get("protocolVersion"), "protocolVersion"),
        "client": client,
        "capabilities": caps,
        "timestamp": _strict_int(params.get("timestamp"), "timestamp"),
        "nonce": nonce,
    }


def make_connect_proof(params, client_secret):
    key = derive_client_auth_key(client_secret)
    return CLIENT_AUTH_PREFIX + hmac.new(key, canonical(material(params)), hashlib.sha256).hexdigest()


def verify_connect_proof(params, legacy_launch_secret_unused=None, now=None, credential_root=None):
    """Phase-A daemon-compatible verifier: ignore legacy launch secret and load client credential."""
    current = time.time() if now is None else float(now)
    if not math.isfinite(current):
        raise ValueError("verification time invalid")
    timestamp = _strict_int(params.get("timestamp"), "timestamp")
    proof = params.get("authProof")
    material(params)
    if abs(current - timestamp) > AUTH_WINDOW_SECONDS:
        raise PermissionError("connect authentication timestamp expired")
    if not isinstance(proof, str) or not proof.startswith(CLIENT_AUTH_PREFIX):
        raise PermissionError("connect authentication proof missing")
    _, client_secret = client_auth_file(ROOT if credential_root is None else Path(credential_root))
    if not hmac.compare_digest(proof, make_connect_proof(params, client_secret)):
        raise PermissionError("connect authentication proof mismatch")
    return True
