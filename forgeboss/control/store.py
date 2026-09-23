from __future__ import annotations
import json,math,os,re,sqlite3,threading,time
from decimal import Decimal,InvalidOperation
from pathlib import Path
from forgeboss.security.local_acl import harden_private_dir,harden_private_path
from forgeboss.control.scheduler import _canonical_path

SCHEMA_VERSION=4
class BudgetReservationError(RuntimeError):
    def __init__(self,code,message): super().__init__(message);self.code=code
class WorkspaceCollisionError(RuntimeError):
    def __init__(self,code,message): super().__init__(message);self.code=code

def canonical_worktree_path(path,root):
    raw=str(path or "")
    if not raw: raise ValueError("worktreePath required")
    p=Path(raw)
    if not p.is_absolute(): raise ValueError("worktreePath must be absolute")
    if raw.startswith("\\\\") or raw.startswith("//") or raw.startswith("\\\\.\\") or raw.startswith("\\\\?\\"): raise ValueError("UNC/device worktree paths are denied")
    root=Path(root).resolve();resolved=p.resolve(strict=False)
    try: common=Path(os.path.commonpath([str(root),str(resolved)]))
    except ValueError: raise ValueError("worktreePath escapes ForgeBoss worktree root")
    if common!=root: raise ValueError("worktreePath escapes ForgeBoss worktree root")
    return str(resolved)

def _physical_worktree_identity(path):
    value=_canonical_path(str(path))
    if not value: raise ValueError("canonical worktree identity is empty")
    return value

_OWNER_RE=re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_RE=re.compile(r"^[A-Za-z0-9._-]+$")
_GIT_OBJECT_ID_RE=re.compile(r"^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$")
def _repository_identity(repository):
    if not isinstance(repository,str): raise WorkspaceCollisionError("REPOSITORY_STATE_INVALID","task repository authority must be owner/name")
    raw=repository
    if not raw or raw!=raw.strip() or any(ord(ch)<32 or ord(ch)==127 for ch in raw):
        raise WorkspaceCollisionError("REPOSITORY_STATE_INVALID","task repository authority must be owner/name")
    lowered=raw.casefold()
    if "://" in lowered or lowered.startswith("git@") or ":" in raw or raw.startswith(("\\\\","//","\\\\.\\","\\\\?\\")):
        raise WorkspaceCollisionError("REPOSITORY_STATE_INVALID","task repository authority must be owner/name")
    value=raw.replace("\\","/")
    parts=value.split("/")
    if len(parts)!=2 or any(part in ("",".","..") for part in parts):
        raise WorkspaceCollisionError("REPOSITORY_STATE_INVALID","task repository authority must be owner/name")
    owner,repo=parts
    if not _OWNER_RE.fullmatch(owner) or not _REPO_RE.fullmatch(repo):
        raise WorkspaceCollisionError("REPOSITORY_STATE_INVALID","task repository authority must be owner/name")
    return f"{owner.casefold()}/{repo.casefold()}"

def _git_object_id(value):
    if not isinstance(value,str) or value!=value.strip() or not _GIT_OBJECT_ID_RE.fullmatch(value):
        raise WorkspaceCollisionError("BASE_SHA_INVALID","task baseSha authority must be an exact 40-hex SHA-1 or 64-hex SHA-256 object id")
    return value.lower()

def _scope_authorities(raw):
    if isinstance(raw,str):
        try: raw=json.loads(raw)
        except Exception as ex: raise WorkspaceCollisionError("SCOPE_STATE_INVALID","task writable scope JSON is invalid") from ex
    if raw is None: raw=[]
    if not isinstance(raw,list): raise WorkspaceCollisionError("SCOPE_STATE_INVALID","task writable scope must be a list")
    out=[];seen=set()
    for value in raw:
        if not isinstance(value,str) or not value.strip(): raise WorkspaceCollisionError("SCOPE_STATE_INVALID","task writable scope contains invalid path")
        canonical=_canonical_path(value)
        if not canonical: raise WorkspaceCollisionError("SCOPE_STATE_INVALID","task writable scope contains empty/root authority")
        if canonical not in seen: seen.add(canonical);out.append(canonical)
    return tuple(out)

def _scope_overlap(a,b):
    return any(x==y or x.startswith(y+"/") or y.startswith(x+"/") for x in a for y in b)

def _budget_decimal(value,code,message):
    if isinstance(value,bool): raise BudgetReservationError(code,message)
    try: amount=Decimal(str(value))
    except (InvalidOperation,TypeError,ValueError) as ex: raise BudgetReservationError(code,message) from ex
    if not amount.is_finite() or amount<0: raise BudgetReservationError(code,message)
    try: as_float=float(amount)
    except (OverflowError,ValueError) as ex: raise BudgetReservationError(code,message) from ex
    if not math.isfinite(as_float): raise BudgetReservationError(code,message)
    return amount

def _validated_budget_request(task,requested):
    try: allocated_raw=task["budget_allocated"];spent_raw=task["budget_spent"]
    except (KeyError,TypeError) as ex: raise BudgetReservationError("BUDGET_STATE_INVALID","task budget state is missing or invalid") from ex
    allocated=_budget_decimal(allocated_raw,"BUDGET_STATE_INVALID","task budget state is missing or invalid")
    spent=_budget_decimal(spent_raw,"BUDGET_STATE_INVALID","task budget state is missing or invalid")
    if spent>allocated: raise BudgetReservationError("BUDGET_STATE_INVALID","task budget state is overspent")
    value=_budget_decimal(requested,"BUDGET_INVALID","workspace claim budget must be a finite non-negative number")
    remaining=allocated-spent
    if value>remaining: raise BudgetReservationError("BUDGET_EXCEEDED",f"workspace claim budget {value} exceeds remaining task budget {remaining}")
    return float(value),float(spent+value)

def _governance_fields(task):
    mode=task.get("governanceMode")
    governed_keys=("workKind","subsystem","reuseReviewSha256","reuseReviewReceiptSha256","smallRepairExemptionSha256")
    if mode is None:
        if any(task.get(name) is not None for name in governed_keys):
            raise ValueError("governance evidence requires governanceMode")
        return (None,None,None,None,None,None)
    if mode!="reuse-v1": raise ValueError("unsupported governanceMode")
    work_kind=task.get("workKind")
    if work_kind not in ("small-repair","substantial-subsystem"): raise ValueError("governed task workKind invalid")
    subsystem=task.get("subsystem")
    if not isinstance(subsystem,str) or not subsystem.strip() or subsystem!=subsystem.strip(): raise ValueError("governed task subsystem required")
    def digest(name):
        value=task.get(name)
        if value is None:return None
        if not isinstance(value,str) or not re.fullmatch(r"[0-9a-f]{64}",value): raise ValueError(f"{name} must be lowercase SHA-256")
        return value
    review=digest("reuseReviewSha256");receipt=digest("reuseReviewReceiptSha256");exemption=digest("smallRepairExemptionSha256")
    if work_kind=="small-repair":
        if not exemption or review is not None or receipt is not None: raise ValueError("small-repair governance evidence invalid")
    else:
        if not review or not receipt or exemption is not None: raise ValueError("substantial governance evidence invalid")
    return (mode,work_kind,subsystem,review,receipt,exemption)

def _ttl(value):
    if isinstance(value,bool): raise ValueError("ttl_seconds must be finite positive")
    try: x=float(value)
    except Exception as ex: raise ValueError("ttl_seconds must be finite positive") from ex
    if not math.isfinite(x) or x<=0: raise ValueError("ttl_seconds must be finite positive")
    return x

class ControlStore:
    def __init__(self,path:Path):
        self.path=Path(path);harden_private_dir(self.path.parent)
        self._lock=threading.RLock()
        self.db=sqlite3.connect(str(self.path),check_same_thread=False,timeout=15,isolation_level=None)
        harden_private_path(self.path);self.db.row_factory=sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL");self.db.execute("PRAGMA foreign_keys=ON");self.db.execute("PRAGMA synchronous=FULL");self._migrate()

    def _migrate(self):
        with self._lock:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tasks(task_id TEXT PRIMARY KEY,repository TEXT NOT NULL,purpose TEXT NOT NULL,base_sha TEXT NOT NULL,branch TEXT,status TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,current_step TEXT,assigned_runtime TEXT,allowed_paths_json TEXT NOT NULL DEFAULT '[]',required_tests_json TEXT NOT NULL DEFAULT '[]',budget_allocated REAL NOT NULL DEFAULT 0,budget_spent REAL NOT NULL DEFAULT 0,cancel_requested_at REAL,result_head TEXT,terminal_outcome TEXT,governance_mode TEXT,work_kind TEXT,subsystem TEXT,reuse_review_sha256 TEXT,reuse_review_receipt_sha256 TEXT,small_repair_exemption_sha256 TEXT,created_at REAL NOT NULL,updated_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS task_runs(run_id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(task_id),attempt INTEGER NOT NULL,owner_epoch INTEGER NOT NULL,runtime_id TEXT,status TEXT NOT NULL,started_at REAL NOT NULL,finished_at REAL);
            CREATE TABLE IF NOT EXISTS task_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT,run_id TEXT,event_type TEXT NOT NULL,payload_json TEXT NOT NULL,state_version INTEGER NOT NULL,created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS workspace_leases(task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),worktree_path TEXT NOT NULL,branch TEXT,owner_run_id TEXT NOT NULL,owner_epoch INTEGER NOT NULL,claimed_at REAL NOT NULL,heartbeat_at REAL NOT NULL,expires_at REAL NOT NULL,released_at REAL,current_head TEXT NOT NULL,budget_reserved REAL NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS worker_instances(worker_id TEXT PRIMARY KEY,task_id TEXT,run_id TEXT,owner_epoch INTEGER,runtime_id TEXT NOT NULL,envelope_hash TEXT NOT NULL,status TEXT NOT NULL,last_seen_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS validation_receipts(receipt_id TEXT PRIMARY KEY,task_id TEXT NOT NULL,run_id TEXT,result_json TEXT NOT NULL,created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS artefacts(artefact_id TEXT PRIMARY KEY,task_id TEXT,type TEXT NOT NULL,path TEXT NOT NULL,sha256 TEXT NOT NULL,size INTEGER NOT NULL,created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS provider_usage(id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT,run_id TEXT,provider TEXT,model TEXT,input_tokens INTEGER,output_tokens INTEGER,cost_usd REAL NOT NULL DEFAULT 0,created_at REAL NOT NULL);
            """)
            cols={str(r[1]) for r in self.db.execute("PRAGMA table_info(workspace_leases)")}
            if "budget_reserved" not in cols: self.db.execute("ALTER TABLE workspace_leases ADD COLUMN budget_reserved REAL NOT NULL DEFAULT 0")
            task_cols={str(r[1]) for r in self.db.execute("PRAGMA table_info(tasks)")}
            for name,decl in (
                ("governance_mode","TEXT"),
                ("work_kind","TEXT"),
                ("subsystem","TEXT"),
                ("reuse_review_sha256","TEXT"),
                ("reuse_review_receipt_sha256","TEXT"),
                ("small_repair_exemption_sha256","TEXT"),
            ):
                if name not in task_cols:self.db.execute(f"ALTER TABLE tasks ADD COLUMN {name} {decl}")
            self.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",(str(SCHEMA_VERSION),))

    def _state_version(self):
        return int(self.db.execute("SELECT COALESCE(MAX(state_version),0)+1 AS v FROM task_events").fetchone()["v"])

    def _event_locked(self,event_type,payload,task_id=None,run_id=None):
        version=self._state_version()
        cur=self.db.execute("INSERT INTO task_events(task_id,run_id,event_type,payload_json,state_version,created_at) VALUES(?,?,?,?,?,?)",(task_id,run_id,event_type,json.dumps(payload,separators=(",",":")),version,time.time()))
        return {"seq":int(cur.lastrowid),"stateVersion":version}

    def event(self,event_type,payload,task_id=None,run_id=None):
        with self._lock: return self._event_locked(event_type,payload,task_id,run_id)

    def create_task(self,t):
        _scope_authorities(t.get("allowedPaths",[]));_repository_identity(t.get("repository"));base_sha=_git_object_id(t.get("baseSha"))
        governance=_governance_fields(t)
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                self.db.execute("""INSERT INTO tasks(task_id,repository,purpose,base_sha,branch,status,allowed_paths_json,required_tests_json,budget_allocated,governance_mode,work_kind,subsystem,reuse_review_sha256,reuse_review_receipt_sha256,small_repair_exemption_sha256,created_at,updated_at)
                  VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?,?,?,?,?,?)""",(t["taskId"],t["repository"],t["purpose"],base_sha,t.get("branch"),json.dumps(t.get("allowedPaths",[])),json.dumps(t.get("requiredTests",[])),float(t.get("budgetUsd",0)),*governance,now,now))
                event={"status":"queued"}
                if governance[0] is not None:event.update({"governanceMode":governance[0],"workKind":governance[1],"subsystem":governance[2],"reuseReviewSha256":governance[3],"reuseReviewReceiptSha256":governance[4],"smallRepairExemptionSha256":governance[5]})
                self._event_locked("task.created",event,t["taskId"])
                self.db.execute("COMMIT");begun=False
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise
        return self.get_task(t["taskId"])

    def get_task(self,task_id):
        row=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone();return dict(row) if row else None

    def request_cancel(self,task_id):
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True
                row=self.db.execute("SELECT cancel_requested_at FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                if not row: raise KeyError("task not found")
                existing=row["cancel_requested_at"]
                if existing is not None:
                    self.db.execute("COMMIT");begun=False
                    return {"taskId":task_id,"cancelRequestedAt":float(existing),"alreadyRequested":True}
                now=time.time()
                cur=self.db.execute("UPDATE tasks SET cancel_requested_at=?,updated_at=? WHERE task_id=? AND cancel_requested_at IS NULL",(now,now,task_id))
                if cur.rowcount!=1: raise RuntimeError("task cancellation state changed during request")
                self._event_locked("task.cancel_requested",{"cancelRequestedAt":now},task_id)
                self.db.execute("COMMIT");begun=False
                return {"taskId":task_id,"cancelRequestedAt":now,"alreadyRequested":False}
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def _live_cross_task_conflicts_locked(self,task_id,repository,base_sha,worktree,scope,now):
        worktree_id=_physical_worktree_identity(worktree);repository_id=_repository_identity(repository);base_id=_git_object_id(base_sha)
        rows=self.db.execute("""SELECT wl.task_id,wl.worktree_path,t.repository,t.base_sha,t.allowed_paths_json
          FROM workspace_leases wl JOIN tasks t ON t.task_id=wl.task_id
          WHERE wl.task_id<>? AND wl.released_at IS NULL AND wl.expires_at>?""",(task_id,now)).fetchall()
        for row in rows:
            other_task=str(row["task_id"])
            if _physical_worktree_identity(row["worktree_path"])==worktree_id: raise WorkspaceCollisionError("WORKTREE_COLLISION",f"physical worktree already owned by live task {other_task}")
            if _repository_identity(row["repository"])!=repository_id or _git_object_id(row["base_sha"])!=base_id: continue
            if _scope_overlap(scope,_scope_authorities(row["allowed_paths_json"])): raise WorkspaceCollisionError("WRITABLE_SCOPE_COLLISION",f"writable scope overlaps live task {other_task}")

    def claim_workspace(self,task_id,run_id,worktree,branch,current_head,ttl_seconds=1200,runtime_id=None,worktree_root=None,budget_reserved=0.0):
        if worktree_root is None: raise ValueError("worktree_root required")
        worktree=canonical_worktree_path(worktree,worktree_root);ttl_seconds=_ttl(ttl_seconds)
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                task_row=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                if not task_row: raise KeyError("task not found")
                task=dict(task_row);scope=_scope_authorities(task["allowed_paths_json"])
                if task.get("cancel_requested_at") is not None: raise PermissionError("task cancellation requested")
                row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone()
                next_epoch=(int(row["owner_epoch"])+1) if row else 1
                if row and row["released_at"] is None and float(row["expires_at"])>now: raise RuntimeError("workspace lease is already active")
                expected_head=str(row["current_head"]) if row else str(task.get("result_head") or task.get("base_sha") or "")
                if expected_head and str(current_head)!=expected_head: raise PermissionError("workspace claim head mismatch")
                self._live_cross_task_conflicts_locked(task_id,task["repository"],task["base_sha"],worktree,scope,now)
                reserved,new_spent=_validated_budget_request(task,budget_reserved)
                cur=self.db.execute("UPDATE tasks SET budget_spent=? WHERE task_id=? AND revision=?",(new_spent,task_id,int(task["revision"])))
                if cur.rowcount!=1: raise BudgetReservationError("BUDGET_STATE_INVALID","task state changed during reservation")
                attempt=int(self.db.execute("SELECT COALESCE(MAX(attempt),0)+1 v FROM task_runs WHERE task_id=?",(task_id,)).fetchone()["v"])
                self.db.execute("""INSERT INTO workspace_leases(task_id,worktree_path,branch,owner_run_id,owner_epoch,claimed_at,heartbeat_at,expires_at,released_at,current_head,budget_reserved)
                  VALUES(?,?,?,?,?,?,?,?,NULL,?,?)
                  ON CONFLICT(task_id) DO UPDATE SET worktree_path=excluded.worktree_path,branch=excluded.branch,owner_run_id=excluded.owner_run_id,owner_epoch=excluded.owner_epoch,claimed_at=excluded.claimed_at,heartbeat_at=excluded.heartbeat_at,expires_at=excluded.expires_at,released_at=NULL,current_head=excluded.current_head,budget_reserved=excluded.budget_reserved""",(task_id,worktree,branch,run_id,next_epoch,now,now,now+ttl_seconds,current_head,reserved))
                self.db.execute("INSERT INTO task_runs(run_id,task_id,attempt,owner_epoch,runtime_id,status,started_at) VALUES(?,?,?,?,?,'running',?)",(run_id,task_id,attempt,next_epoch,runtime_id,now))
                cur=self.db.execute("UPDATE tasks SET status='running',revision=revision+1,current_step='workspace-claimed',assigned_runtime=?,updated_at=? WHERE task_id=? AND revision=?",(runtime_id,now,task_id,int(task["revision"])))
                if cur.rowcount!=1: raise PermissionError("task authority changed during workspace claim")
                self._event_locked("workspace.claimed",{"ownerEpoch":next_epoch,"worktreePath":worktree,"head":current_head,"budgetReserved":reserved},task_id,run_id)
                self.db.execute("COMMIT");begun=False
                return self.get_lease(task_id)
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def get_lease(self,task_id):
        row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone();return dict(row) if row else None

    def assert_writer(self,task_id,run_id,owner_epoch,expected_head=None):
        with self._lock:
            row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL",(task_id,run_id,int(owner_epoch))).fetchone()
            if not row: raise PermissionError("writer authority lost: lease/epoch mismatch")
            if float(row["expires_at"])<=time.time(): raise PermissionError("writer authority lost: lease expired")
            if expected_head and row["current_head"]!=expected_head: raise PermissionError("writer authority lost: expected head mismatch")
            return dict(row)

    def heartbeat(self,task_id,run_id,owner_epoch,ttl_seconds=1200,current_head=None,expected_head=None):
        ttl_seconds=_ttl(ttl_seconds)
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL",(task_id,run_id,int(owner_epoch))).fetchone()
                if not row: raise PermissionError("writer authority lost: lease/epoch mismatch")
                if float(row["expires_at"])<=now: raise PermissionError("writer authority lost: lease expired")
                old_head=str(row["current_head"])
                if expected_head is not None and old_head!=str(expected_head): raise PermissionError("writer authority lost: expected head mismatch")
                new_head=old_head if current_head is None else str(current_head)
                cur=self.db.execute("""UPDATE workspace_leases SET heartbeat_at=?,expires_at=?,current_head=?
                  WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL AND expires_at>? AND current_head=?""",(now,now+ttl_seconds,new_head,task_id,run_id,int(owner_epoch),now,old_head))
                if cur.rowcount!=1: raise PermissionError("writer authority lost during heartbeat")
                self._event_locked("workspace.heartbeat",{"ownerEpoch":int(owner_epoch),"head":new_head},task_id,run_id)
                self.db.execute("COMMIT");begun=False
                return self.get_lease(task_id)
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def release(self,task_id,run_id,owner_epoch,result_head=None,outcome="released",expected_head=None):
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL",(task_id,run_id,int(owner_epoch))).fetchone()
                if not row: raise PermissionError("writer authority lost: lease/epoch mismatch")
                if float(row["expires_at"])<=now: raise PermissionError("writer authority lost: lease expired")
                old_head=str(row["current_head"])
                if expected_head is not None and old_head!=str(expected_head): raise PermissionError("writer authority lost: expected head mismatch")
                final_head=old_head if result_head is None else str(result_head)
                cur=self.db.execute("""UPDATE workspace_leases SET released_at=?,current_head=?
                  WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL AND expires_at>? AND current_head=?""",(now,final_head,task_id,run_id,int(owner_epoch),now,old_head))
                if cur.rowcount!=1: raise PermissionError("writer authority lost during release")
                cur=self.db.execute("UPDATE task_runs SET status=?,finished_at=? WHERE run_id=? AND task_id=? AND owner_epoch=? AND status='running'",(outcome,now,run_id,task_id,int(owner_epoch)))
                if cur.rowcount!=1: raise PermissionError("run authority lost during release")
                cur=self.db.execute("UPDATE tasks SET status=?,revision=revision+1,result_head=?,updated_at=? WHERE task_id=? AND status='running'",(outcome,final_head,now,task_id))
                if cur.rowcount!=1: raise PermissionError("task authority lost during release")
                self._event_locked("workspace.released",{"ownerEpoch":int(owner_epoch),"outcome":outcome,"resultHead":final_head},task_id,run_id)
                self.db.execute("COMMIT");begun=False
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def snapshot(self):
        return {"schemaVersion":SCHEMA_VERSION,
          "tasks":[dict(r) for r in self.db.execute("SELECT * FROM tasks ORDER BY updated_at DESC LIMIT 100")],
          "leases":[dict(r) for r in self.db.execute("SELECT * FROM workspace_leases WHERE released_at IS NULL ORDER BY heartbeat_at DESC")],
          "workers":[dict(r) for r in self.db.execute("SELECT * FROM worker_instances ORDER BY last_seen_at DESC LIMIT 100")],
          "lastEventSeq":int(self.db.execute("SELECT COALESCE(MAX(seq),0) v FROM task_events").fetchone()["v"])}