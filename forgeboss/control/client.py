from __future__ import annotations
import json
import secrets
import socket
import time
import uuid
from pathlib import Path
from .auth import make_connect_proof
from .envelope import secret_file

ROOT = Path(__file__).resolve().parents[2]
HOST = "127.0.0.1"
PORT = 18765
MAX_RESPONSE_BYTES = 256 * 1024


class Client:
    def __init__(self, host=HOST, port=PORT, timeout=5):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.f = self.s.makefile("rwb")
        # Phase-A migration compatibility: daemon still loads daemon-secret.bin.
        # make_connect_proof() domain-separates this source secret from launch HMAC.
        _, shared_secret = secret_file(ROOT)
        connect = {
            "protocolVersion": 1,
            "client": "forgeboss-cli",
            "capabilities": ["tasks", "leases"],
            "timestamp": int(time.time()),
            "nonce": secrets.token_hex(16),
        }
        connect["authProof"] = make_connect_proof(connect, shared_secret)
        self.call("connect", connect, mutation=False)

    def call(self, method, params=None, mutation=None):
        if mutation is None:
            mutation = method in {
                "task.create",
                "workspace.claim",
                "workspace.heartbeat",
                "workspace.release",
                "worker.admit",
            }
        request_id = uuid.uuid4().hex
        obj = {"type": "req", "id": request_id, "method": method, "params": params or {}}
        if mutation:
            obj["idempotencyKey"] = uuid.uuid4().hex
        self.f.write((json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"))
        self.f.flush()
        raw = self.f.readline(MAX_RESPONSE_BYTES + 1)
        if not raw:
            raise RuntimeError("control connection closed before response")
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("control response frame too large")
        try:
            response = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError("control response is invalid JSON") from exc
        if not isinstance(response, dict) or response.get("type") != "res" or response.get("id") != request_id:
            raise RuntimeError("control response correlation failure")
        if response.get("ok") is not True:
            error = response.get("error")
            if not isinstance(error, dict):
                error = {}
            raise RuntimeError(f"{error.get('code')}: {error.get('message')}")
        payload = response.get("payload", {})
        if not isinstance(payload, dict):
            raise RuntimeError("control response payload must be object")
        return payload

    def close(self):
        try:
            self.f.close()
        finally:
            self.s.close()
