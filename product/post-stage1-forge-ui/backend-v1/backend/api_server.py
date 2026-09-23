from __future__ import annotations

import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .project_bootstrap import create_project_scaffold
from .project_memory import ProjectMemoryStore
from .vault_windows import VaultUnavailable, WindowsVault

MAX_BODY = 65536
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def default_data_root() -> Path:
    override = os.environ.get("FORGEBOSS_DATA_ROOT")
    if override:
        return Path(override).resolve()
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_STATE_HOME")
    if not base:
        base = str(Path.home() / ".forgeboss")
    return Path(base).resolve() / "ForgeBoss" / "Product"


class ProductBackend:
    def __init__(self, data_root: str | Path | None = None):
        self.data_root = Path(data_root).resolve() if data_root else default_data_root()
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.memory = ProjectMemoryStore(self.data_root / "memory.db")
        self.vault = None
        try:
            self.vault = WindowsVault()
        except VaultUnavailable:
            self.vault = None

    def close(self):
        self.memory.close()


class ProductServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, backend: ProductBackend):
        self.backend = backend
        self.rpc_token = secrets.token_urlsafe(32)
        super().__init__(address, ProductHandler)


class ProductHandler(BaseHTTPRequestHandler):
    server: ProductServer
    server_version = "ForgeBossProduct/0.1"

    def log_message(self, fmt, *args):
        pass

    def _host_ok(self) -> bool:
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        return host in ALLOWED_HOSTS

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        return parsed.scheme in {"http", "https"} and (parsed.hostname or "").lower() in ALLOWED_HOSTS

    def _json(self, value, status=200):
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict:
        ctype = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            raise ValueError("Content-Type must be application/json")
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n < 0 or n > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(n)
        obj = json.loads(raw.decode("utf-8") if raw else "{}")
        if not isinstance(obj, dict):
            raise ValueError("JSON body must be an object")
        return obj

    def _authorized_post(self) -> tuple[bool, str]:
        if not self._host_ok():
            return False, "invalid Host"
        if not self._origin_ok():
            return False, "invalid Origin"
        supplied = self.headers.get("X-ForgeBoss-Token", "")
        if not secrets.compare_digest(supplied, self.server.rpc_token):
            return False, "invalid local RPC token"
        return True, ""

    def do_GET(self):
        if not self._host_ok():
            self._json({"ok": False, "error": "invalid Host"}, 403)
            return
        u = urlparse(self.path)
        if u.path == "/api/session-token":
            self._json({"token": self.server.rpc_token})
            return
        if u.path == "/api/health":
            self._json({"ok": True, "vault": bool(self.server.backend.vault)})
            return
        if u.path == "/api/project/context":
            q = parse_qs(u.query)
            project_id = (q.get("project_id") or [""])[0]
            if not project_id:
                self._json({"ok": False, "error": "project_id required"}, 400)
                return
            bundle = self.server.backend.memory.context_bundle(project_id)
            self._json({
                "ok": True,
                "project_id": project_id,
                "bible": bundle.bible,
                "validated_memory": bundle.validated_memory,
                "recent_messages": bundle.recent_messages,
            })
            return
        self._json({"ok": False, "error": "not found"}, 404)

    def do_POST(self):
        ok, why = self._authorized_post()
        if not ok:
            self._json({"ok": False, "error": why}, 403)
            return
        try:
            body = self._read_json()
            path = urlparse(self.path).path
            if path == "/api/project/register":
                name = str(body.get("name") or "").strip()
                project_root = str(body.get("project_root") or "").strip()
                if not name or not project_root:
                    raise ValueError("name and project_root are required")
                pid = self.server.backend.memory.create_project(name)
                self.server.backend.memory.set_project_root(pid, project_root)
                cid = self.server.backend.memory.create_conversation(pid)
                self._json({"ok": True, "project_id": pid, "conversation_id": cid}, 201)
                return
            if path == "/api/project/create":
                name = str(body.get("name") or "").strip()
                idea = str(body.get("idea") or "")
                parent = str(body.get("parent") or "").strip()
                answers = body.get("answers") or {}
                if not name or not parent:
                    raise ValueError("name and parent are required")
                if not isinstance(answers, dict):
                    raise ValueError("answers must be an object")
                project_path = create_project_scaffold(parent, name, idea, answers)
                pid = self.server.backend.memory.create_project(name)
                self.server.backend.memory.set_project_root(pid, str(project_path))
                cid = self.server.backend.memory.create_conversation(pid)
                mid = self.server.backend.memory.add_message(pid, cid, "user", idea)
                self.server.backend.memory.propose_memory(pid, "project-idea", idea, mid, 1.0)
                self._json({"ok": True, "project_id": pid, "conversation_id": cid, "project_root": str(project_path)}, 201)
                return
            if path == "/api/chat/message":
                pid = str(body.get("project_id") or "")
                cid = str(body.get("conversation_id") or "")
                role = str(body.get("role") or "user")
                content = str(body.get("content") or "")
                if not pid or not cid or not content:
                    raise ValueError("project_id, conversation_id and content are required")
                mid = self.server.backend.memory.add_message(pid, cid, role, content)
                self._json({"ok": True, "message_id": mid}, 201)
                return
            if path == "/api/bible/propose":
                pid = str(body.get("project_id") or "")
                key = str(body.get("bible_key") or "")
                content = str(body.get("content") or "")
                if not pid or not key or not content:
                    raise ValueError("project_id, bible_key and content are required")
                eid = self.server.backend.memory.propose_bible_entry(pid, key, content, str(body.get("source_ref") or "") or None)
                self._json({"ok": True, "entry_id": eid}, 201)
                return
            if path == "/api/bible/activate":
                eid = str(body.get("entry_id") or "")
                if not eid:
                    raise ValueError("entry_id required")
                self.server.backend.memory.activate_bible_entry(eid, owner_approved=body.get("owner_approved") is True)
                self._json({"ok": True})
                return
            if path == "/api/vault/store":
                if not self.server.backend.vault:
                    self._json({"ok": False, "error": "OS-protected Vault unavailable"}, 503)
                    return
                provider = str(body.get("provider") or "").strip()
                value = str(body.get("secret") or "")
                if not provider or not value:
                    raise ValueError("provider and secret are required")
                ref = self.server.backend.vault.store(provider, value)
                self._json({"ok": True, "credential": self.server.backend.vault.status(ref)}, 201)
                return
            self._json({"ok": False, "error": "not found"}, 404)
        except (ValueError, KeyError, PermissionError, json.JSONDecodeError) as exc:
            self._json({"ok": False, "error": str(exc)}, 400)
        except FileExistsError as exc:
            self._json({"ok": False, "error": str(exc)}, 409)


def serve(host: str = "127.0.0.1", port: int = 0, data_root: str | Path | None = None):
    backend = ProductBackend(data_root)
    return ProductServer((host, port), backend)
