from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_secrets(text: str) -> tuple[str, bool]:
    value = str(text or "")
    redacted = False
    for pattern in _SECRET_PATTERNS:
        value, count = pattern.subn("[REDACTED-SECRET]", value)
        redacted = redacted or count > 0
    return value, redacted


def content_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ContextBundle:
    bible: list[dict]
    validated_memory: list[dict]
    recent_messages: list[dict]


class ProjectMemoryStore:
    """Thread-safe project conversation, memory and Bible authority store."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA journal_mode=WAL")
            self._init_schema()

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def _init_schema(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects(
              project_id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS project_locations(
              project_id TEXT PRIMARY KEY REFERENCES projects(project_id) ON DELETE CASCADE,
              root_path TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversations(
              conversation_id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
              title TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages(
              message_id TEXT PRIMARY KEY,
              conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
              project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
              role TEXT NOT NULL CHECK(role IN ('user','assistant','system','tool')),
              content TEXT NOT NULL,
              redacted INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_project_time ON messages(project_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS memory_facts(
              memory_id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
              category TEXT NOT NULL,
              summary TEXT NOT NULL,
              source_message_id TEXT REFERENCES messages(message_id) ON DELETE SET NULL,
              status TEXT NOT NULL CHECK(status IN ('candidate','validated','rejected')),
              confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
              created_at TEXT NOT NULL,
              validated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_memory_project_status ON memory_facts(project_id, status, created_at DESC);
            CREATE TABLE IF NOT EXISTS bible_entries(
              entry_id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
              bible_key TEXT NOT NULL,
              content TEXT NOT NULL,
              content_sha256 TEXT NOT NULL,
              version INTEGER NOT NULL,
              active INTEGER NOT NULL DEFAULT 0,
              source_ref TEXT,
              approved_by TEXT,
              approved_at TEXT,
              created_at TEXT NOT NULL,
              UNIQUE(project_id, bible_key, version)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_bible_key
              ON bible_entries(project_id, bible_key) WHERE active=1;
            """
        )
        self.db.commit()

    def create_project(self, name: str, project_id: str | None = None) -> str:
        pid = project_id or f"prj_{uuid.uuid4().hex}"
        now = utc_now()
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO projects(project_id,name,created_at,updated_at) VALUES(?,?,?,?)",
                (pid, str(name).strip() or "Untitled Project", now, now),
            )
        return pid

    def set_project_root(self, project_id: str, root_path: str) -> None:
        root = str(Path(root_path).resolve())
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO project_locations(project_id,root_path) VALUES(?,?) ON CONFLICT(project_id) DO UPDATE SET root_path=excluded.root_path",
                (project_id, root),
            )

    def get_project_root(self, project_id: str) -> str | None:
        with self.lock:
            row = self.db.execute("SELECT root_path FROM project_locations WHERE project_id=?", (project_id,)).fetchone()
            return str(row["root_path"]) if row else None

    def create_conversation(self, project_id: str, title: str = "Forge Chat") -> str:
        cid = f"chat_{uuid.uuid4().hex}"
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO conversations(conversation_id,project_id,title,created_at) VALUES(?,?,?,?)",
                (cid, project_id, title, utc_now()),
            )
        return cid

    def add_message(self, project_id: str, conversation_id: str, role: str, content: str) -> str:
        if role not in {"user", "assistant", "system", "tool"}:
            raise ValueError("invalid role")
        safe, was_redacted = redact_secrets(content)
        mid = f"msg_{uuid.uuid4().hex}"
        now = utc_now()
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO messages(message_id,conversation_id,project_id,role,content,redacted,created_at) VALUES(?,?,?,?,?,?,?)",
                (mid, conversation_id, project_id, role, safe, int(was_redacted), now),
            )
            self.db.execute("UPDATE projects SET updated_at=? WHERE project_id=?", (now, project_id))
        return mid

    def propose_memory(self, project_id: str, category: str, summary: str, source_message_id: str | None = None, confidence: float = 0.5) -> str:
        if not 0 <= confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        safe, _ = redact_secrets(summary)
        memory_id = f"mem_{uuid.uuid4().hex}"
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO memory_facts(memory_id,project_id,category,summary,source_message_id,status,confidence,created_at) VALUES(?,?,?,?,?,'candidate',?,?)",
                (memory_id, project_id, category, safe, source_message_id, confidence, utc_now()),
            )
        return memory_id

    def validate_memory(self, memory_id: str, accepted: bool) -> None:
        with self.lock, self.db:
            self.db.execute(
                "UPDATE memory_facts SET status=?,validated_at=? WHERE memory_id=?",
                ("validated" if accepted else "rejected", utc_now(), memory_id),
            )

    def propose_bible_entry(self, project_id: str, bible_key: str, content: str, source_ref: str | None = None) -> str:
        safe, redacted = redact_secrets(content)
        if redacted:
            raise ValueError("Bible content contained secret material and was refused")
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT COALESCE(MAX(version),0) AS v FROM bible_entries WHERE project_id=? AND bible_key=?",
                (project_id, bible_key),
            ).fetchone()
            version = int(row["v"]) + 1
            eid = f"bible_{uuid.uuid4().hex}"
            self.db.execute(
                "INSERT INTO bible_entries(entry_id,project_id,bible_key,content,content_sha256,version,active,source_ref,created_at) VALUES(?,?,?,?,?,?,0,?,?)",
                (eid, project_id, bible_key, safe, content_hash(safe), version, source_ref, utc_now()),
            )
        return eid

    def activate_bible_entry(self, entry_id: str, *, owner_approved: bool, approved_by: str = "human-owner") -> None:
        if not owner_approved or approved_by != "human-owner":
            raise PermissionError("canonical Bible activation requires explicit Human Owner approval")
        with self.lock, self.db:
            row = self.db.execute("SELECT project_id,bible_key FROM bible_entries WHERE entry_id=?", (entry_id,)).fetchone()
            if not row:
                raise KeyError(entry_id)
            self.db.execute(
                "UPDATE bible_entries SET active=0 WHERE project_id=? AND bible_key=?",
                (row["project_id"], row["bible_key"]),
            )
            self.db.execute(
                "UPDATE bible_entries SET active=1,approved_by=?,approved_at=? WHERE entry_id=?",
                (approved_by, utc_now(), entry_id),
            )

    def context_bundle(self, project_id: str, recent_limit: int = 30) -> ContextBundle:
        with self.lock:
            bible = [dict(r) for r in self.db.execute(
                "SELECT bible_key,content,content_sha256,version,approved_at FROM bible_entries WHERE project_id=? AND active=1 ORDER BY bible_key",
                (project_id,),
            )]
            memory = [dict(r) for r in self.db.execute(
                "SELECT category,summary,confidence,source_message_id,validated_at FROM memory_facts WHERE project_id=? AND status='validated' ORDER BY created_at DESC",
                (project_id,),
            )]
            messages = [dict(r) for r in self.db.execute(
                "SELECT message_id,role,content,redacted,created_at FROM messages WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
                (project_id, int(recent_limit)),
            )]
        messages.reverse()
        return ContextBundle(bible=bible, validated_memory=memory, recent_messages=messages)

    def search_messages(self, project_id: str, needle: str, limit: int = 50) -> list[dict]:
        q = f"%{needle.replace('%','')}%"
        with self.lock:
            return [dict(r) for r in self.db.execute(
                "SELECT message_id,role,content,redacted,created_at FROM messages WHERE project_id=? AND content LIKE ? ORDER BY created_at DESC LIMIT ?",
                (project_id, q, int(limit)),
            )]

    def export_safe_snapshot(self, project_id: str) -> dict:
        bundle = self.context_bundle(project_id, recent_limit=1000)
        return {
            "schema": 1,
            "project_id": project_id,
            "bible": bundle.bible,
            "validated_memory": bundle.validated_memory,
            "messages": bundle.recent_messages,
            "note": "Vault secrets are intentionally excluded.",
        }
