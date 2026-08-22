from __future__ import annotations
import json, os, sqlite3, threading, time
from pathlib import Path
from forgeboss.security.local_acl import harden_private_dir,harden_private_path

SCHEMA_VERSION=2
def canonical_worktree_path(path,root):
    raw=str(path or "")
    if not raw:raise ValueError("worktreePath required")
    p=Path(raw)
    if not p.is_absolute():raise ValueError("worktreePath must be absolute")
    if raw.startswith("\\\\") or raw.startswith("//") or raw.startswith("\\\\.\\") or raw.startswith("\\\\?\\"):raise ValueError("UNC/device worktree paths are denied")
    root=Path(root).resolve();resolved=p.resolve(strict=False)
    try:common=Path(os.path.commonpath([str(root),str(resolved)]))
    except ValueError:raise ValueError("worktreePath escapes ForgeBoss worktree root")
    if common!=root:raise ValueError("worktreePath escapes ForgeBoss worktree root")
    return str(resolved)

class ControlStore:
    def __init__(self,path:Path):
        self.path=Path(path);harden_private_dir(self.path.parent)
        self._lock=threading.RLock()
        self.db=sqlite3.connect(str(self.path),check_same_thread=False,timeout=15,isolation_level=None)
        harden_private_path(self.path)
        self.db.row_factory=sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA synchronous=FULL")
        self._migrate()

    def _migrate(self):
        with self._lock:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks(
              task_id TEXT PRIMARY KEY,
              repository TEXT NOT NULL,
              purpose TEXT NOT NULL,
              base_sha TEXT NOT NULL,
              branch TEXT,
              status TEXT NOT NULL,
              revision INTEGER NOT NULL DEFAULT 1,
              current_step TEXT,
              assigned_runtime TEXT,
              allowed_paths_json TEXT NOT NULL DEFAULT '[]',
              required_tests_json TEXT NOT NULL DEFAULT '[]',
              budget_allocated REAL NOT NULL DEFAULT 0,
              budget_spent REAL NOT NULL DEFAULT 0,
              cancel_requested_at REAL,
              result_head TEXT,
              terminal_outcome TEXT,
              created_at REAL NOT NULL,
              updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS task_runs(
              run_id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL REFERENCES tasks(task_id),
              attempt INTEGER NOT NULL,
              owner_epoch INTEGER NOT NULL,
              runtime_id TEXT,
              status TEXT NOT NULL,
              started_at REAL NOT NULL,
              finished_at REAL
            );
            CREATE TABLE IF NOT EXISTS task_events(
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              task_id TEXT,
              run_id TEXT,
              event_type TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              state_version INTEGER NOT NULL,
              created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workspace_leases(
              task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
              worktree_path TEXT NOT NULL,
              branch TEXT,
              owner_run_id TEXT NOT NULL,
              owner_epoch INTEGER NOT NULL,
              claimed_at REAL NOT NULL,
              heartbeat_at REAL NOT NULL,
              expires_at REAL NOT NULL,
              released_at REAL,
              current_head TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS worker_instances(
              worker_id TEXT PRIMARY KEY,
              task_id TEXT,
              run_id TEXT,
              owner_epoch INTEGER,
              runtime_id TEXT NOT NULL,
              envelope_hash TEXT NOT NULL,
              status TEXT NOT NULL,
              last_seen_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS validation_receipts(
              receipt_id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL,
              run_id TEXT,
              result_json TEXT NOT NULL,
              created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artefacts(
              artefact_id TEXT PRIMARY KEY,
              task_id TEXT,
              type TEXT NOT NULL,
              path TEXT NOT NULL,
              sha256 TEXT NOT NULL,
              size INTEGER NOT NULL,
              created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS provider_usage(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              task_id TEXT,
              run_id TEXT,
              provider TEXT,
              model TEXT,
              input_tokens INTEGER,
              output_tokens INTEGER,
              cost_usd REAL NOT NULL DEFAULT 0,
              created_at REAL NOT NULL
            );
            """)
            self.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",(str(SCHEMA_VERSION),))

    def _state_version(self):
        row=self.db.execute("SELECT COALESCE(MAX(state_version),0)+1 AS v FROM task_events").fetchone()
        return int(row["v"])

    def event(self,event_type,payload,task_id=None,run_id=None):
        with self._lock:
            version=self._state_version()
            cur=self.db.execute("INSERT INTO task_events(task_id,run_id,event_type,payload_json,state_version,created_at) VALUES(?,?,?,?,?,?)",
                (task_id,run_id,event_type,json.dumps(payload,separators=(",",":")),version,time.time()))
            return {"seq":int(cur.lastrowid),"stateVersion":version}

    def create_task(self,t):
        now=time.time()
        with self._lock:
            self.db.execute("""INSERT INTO tasks(task_id,repository,purpose,base_sha,branch,status,allowed_paths_json,required_tests_json,budget_allocated,created_at,updated_at)
              VALUES(?,?,?,?,?,'queued',?,?,?,?,?)""",
              (t["taskId"],t["repository"],t["purpose"],t["baseSha"],t.get("branch"),
               json.dumps(t.get("allowedPaths",[])),json.dumps(t.get("requiredTests",[])),float(t.get("budgetUsd",0)),now,now))
            self.event("task.created",{"status":"queued"},t["taskId"])
        return self.get_task(t["taskId"])

    def get_task(self,task_id):
        row=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
        return dict(row) if row else None

    def claim_workspace(self,task_id,run_id,worktree,branch,current_head,ttl_seconds=1200,runtime_id=None,worktree_root=None):
        if worktree_root is None:raise ValueError("worktree_root required")
        worktree=canonical_worktree_path(worktree,worktree_root)
        now=time.time()
        with self._lock:
            task=self.get_task(task_id)
            if not task: raise KeyError("task not found")
            row=self.db.execute("SELECT owner_epoch,released_at,expires_at FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone()
            next_epoch=(int(row["owner_epoch"])+1) if row else 1
            if row and row["released_at"] is None and float(row["expires_at"])>now:
                raise RuntimeError("workspace lease is already active")
            self.db.execute("""INSERT INTO workspace_leases(task_id,worktree_path,branch,owner_run_id,owner_epoch,claimed_at,heartbeat_at,expires_at,released_at,current_head)
              VALUES(?,?,?,?,?,?,?,?,NULL,?)
              ON CONFLICT(task_id) DO UPDATE SET worktree_path=excluded.worktree_path,branch=excluded.branch,owner_run_id=excluded.owner_run_id,
              owner_epoch=excluded.owner_epoch,claimed_at=excluded.claimed_at,heartbeat_at=excluded.heartbeat_at,expires_at=excluded.expires_at,released_at=NULL,current_head=excluded.current_head""",
              (task_id,worktree,branch,run_id,next_epoch,now,now,now+ttl_seconds,current_head))
            self.db.execute("INSERT INTO task_runs(run_id,task_id,attempt,owner_epoch,runtime_id,status,started_at) VALUES(?,?,?,?,?,'running',?)",
                            (run_id,task_id,1,next_epoch,runtime_id,now))
            self.db.execute("UPDATE tasks SET status='running',revision=revision+1,current_step='workspace-claimed',assigned_runtime=?,updated_at=? WHERE task_id=?",
                            (runtime_id,now,task_id))
            self.event("workspace.claimed",{"ownerEpoch":next_epoch,"worktreePath":worktree,"head":current_head},task_id,run_id)
            return self.get_lease(task_id)

    def get_lease(self,task_id):
        row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone()
        return dict(row) if row else None

    def assert_writer(self,task_id,run_id,owner_epoch,expected_head=None):
        with self._lock:
            row=self.db.execute("""SELECT * FROM workspace_leases WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL""",
                                (task_id,run_id,int(owner_epoch))).fetchone()
            if not row: raise PermissionError("writer authority lost: lease/epoch mismatch")
            if float(row["expires_at"])<=time.time(): raise PermissionError("writer authority lost: lease expired")
            if expected_head and row["current_head"]!=expected_head:
                raise PermissionError("writer authority lost: expected head mismatch")
            return dict(row)

    def heartbeat(self,task_id,run_id,owner_epoch,ttl_seconds=1200,current_head=None):
        self.assert_writer(task_id,run_id,owner_epoch)
        now=time.time()
        with self._lock:
            cur=self.db.execute("""UPDATE workspace_leases SET heartbeat_at=?,expires_at=?,current_head=COALESCE(?,current_head)
                WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL""",
                (now,now+ttl_seconds,current_head,task_id,run_id,int(owner_epoch)))
            if cur.rowcount!=1: raise PermissionError("writer authority lost during heartbeat")
            self.event("workspace.heartbeat",{"ownerEpoch":int(owner_epoch)},task_id,run_id)
            return self.get_lease(task_id)

    def release(self,task_id,run_id,owner_epoch,result_head=None,outcome="released"):
        self.assert_writer(task_id,run_id,owner_epoch)
        now=time.time()
        with self._lock:
            self.db.execute("UPDATE workspace_leases SET released_at=?,current_head=COALESCE(?,current_head) WHERE task_id=? AND owner_run_id=? AND owner_epoch=?",
                            (now,result_head,task_id,run_id,int(owner_epoch)))
            self.db.execute("UPDATE task_runs SET status=?,finished_at=? WHERE run_id=?",(outcome,now,run_id))
            self.db.execute("UPDATE tasks SET status=?,revision=revision+1,result_head=COALESCE(?,result_head),updated_at=? WHERE task_id=?",
                            (outcome,result_head,now,task_id))
            self.event("workspace.released",{"ownerEpoch":int(owner_epoch),"outcome":outcome,"resultHead":result_head},task_id,run_id)

    def snapshot(self):
        return {
          "schemaVersion":SCHEMA_VERSION,
          "tasks":[dict(r) for r in self.db.execute("SELECT * FROM tasks ORDER BY updated_at DESC LIMIT 100")],
          "leases":[dict(r) for r in self.db.execute("SELECT * FROM workspace_leases WHERE released_at IS NULL ORDER BY heartbeat_at DESC")],
          "workers":[dict(r) for r in self.db.execute("SELECT * FROM worker_instances ORDER BY last_seen_at DESC LIMIT 100")],
          "lastEventSeq":int(self.db.execute("SELECT COALESCE(MAX(seq),0) v FROM task_events").fetchone()["v"])
        }
