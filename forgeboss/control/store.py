from __future__ import annotations
import hashlib,json,math,os,re,sqlite3,threading,time
from decimal import Decimal,InvalidOperation
from pathlib import Path
from forgeboss.security.local_acl import harden_private_dir,harden_private_path
from forgeboss.control.scheduler import _canonical_path

SCHEMA_VERSION=4
class BudgetReservationError(RuntimeError):
    def __init__(self,code,message): super().__init__(message);self.code=code
class WorkspaceCollisionError(RuntimeError):
    def __init__(self,code,message): super().__init__(message);self.code=code
class AssignmentAuthorityError(RuntimeError):
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
_HEX64_RE=re.compile(r"^[0-9a-f]{64}$")
_PRINCIPAL_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$")

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

def _ttl(value):
    if isinstance(value,bool): raise ValueError("ttl_seconds must be finite positive")
    try: x=float(value)
    except Exception as ex: raise ValueError("ttl_seconds must be finite positive") from ex
    if not math.isfinite(x) or x<=0: raise ValueError("ttl_seconds must be finite positive")
    return x

def _principal(value):
    if not isinstance(value,str) or value!=value.strip() or not _PRINCIPAL_RE.fullmatch(value):
        raise AssignmentAuthorityError("ASSIGNMENT_PRINCIPAL_INVALID","builder principal is invalid")
    return value

def _positive_int(value,code):
    if isinstance(value,bool) or not isinstance(value,int) or value<=0:
        raise AssignmentAuthorityError(code,"assignment generation must be a positive integer")
    return value

def _workspace_generation(value):
    if isinstance(value,bool) or not isinstance(value,(str,int)) or not str(value) or str(value)!=str(value).strip():
        raise AssignmentAuthorityError("WORKSPACE_GENERATION_INVALID","workspace generation identity is invalid")
    return str(value)

def _workspace_content_identity(value):
    if not isinstance(value,str) or value!=value.lower() or not _HEX64_RE.fullmatch(value):
        raise AssignmentAuthorityError("WORKSPACE_CONTENT_IDENTITY_INVALID","workspace content identity must be exact lowercase sha256")
    return value

def _canonical_assignment_json(identity):
    required=("builderPrincipal","assignmentGeneration","taskId","runId","attempt","ownerEpoch","repository","baseSha","workspaceGeneration","workspaceContentIdentity")
    if not isinstance(identity,dict) or set(identity)!=set(required):
        raise AssignmentAuthorityError("ASSIGNMENT_IDENTITY_INVALID","assignment identity shape is invalid")
    canonical={
      "assignmentGeneration":_positive_int(identity["assignmentGeneration"],"ASSIGNMENT_GENERATION_INVALID"),
      "attempt":_positive_int(identity["attempt"],"ASSIGNMENT_ATTEMPT_INVALID"),
      "baseSha":_git_object_id(identity["baseSha"]),
      "builderPrincipal":_principal(identity["builderPrincipal"]),
      "ownerEpoch":_positive_int(identity["ownerEpoch"],"ASSIGNMENT_OWNER_EPOCH_INVALID"),
      "repository":_repository_identity(identity["repository"]),
      "runId":str(identity["runId"]),
      "taskId":str(identity["taskId"]),
      "workspaceContentIdentity":_workspace_content_identity(identity["workspaceContentIdentity"]),
      "workspaceGeneration":_workspace_generation(identity["workspaceGeneration"]),
    }
    if not canonical["taskId"] or not canonical["runId"]:
        raise AssignmentAuthorityError("ASSIGNMENT_IDENTITY_INVALID","task/run identity is invalid")
    return json.dumps(canonical,sort_keys=True,separators=(",",":"),ensure_ascii=False),canonical

def _assignment_digest(identity):
    raw,canonical=_canonical_assignment_json(identity)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest(),raw,canonical

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
            CREATE TABLE IF NOT EXISTS tasks(task_id TEXT PRIMARY KEY,repository TEXT NOT NULL,purpose TEXT NOT NULL,base_sha TEXT NOT NULL,branch TEXT,status TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,current_step TEXT,assigned_runtime TEXT,allowed_paths_json TEXT NOT NULL DEFAULT '[]',required_tests_json TEXT NOT NULL DEFAULT '[]',budget_allocated REAL NOT NULL DEFAULT 0,budget_spent REAL NOT NULL DEFAULT 0,cancel_requested_at REAL,result_head TEXT,terminal_outcome TEXT,created_at REAL NOT NULL,updated_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS task_runs(run_id TEXT PRIMARY KEY,task_id TEXT NOT NULL REFERENCES tasks(task_id),attempt INTEGER NOT NULL,owner_epoch INTEGER NOT NULL,runtime_id TEXT,status TEXT NOT NULL,started_at REAL NOT NULL,finished_at REAL);
            CREATE TABLE IF NOT EXISTS task_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT,run_id TEXT,event_type TEXT NOT NULL,payload_json TEXT NOT NULL,state_version INTEGER NOT NULL,created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS workspace_leases(task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),worktree_path TEXT NOT NULL,branch TEXT,owner_run_id TEXT NOT NULL,owner_epoch INTEGER NOT NULL,claimed_at REAL NOT NULL,heartbeat_at REAL NOT NULL,expires_at REAL NOT NULL,released_at REAL,current_head TEXT NOT NULL,budget_reserved REAL NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS worker_instances(worker_id TEXT PRIMARY KEY,task_id TEXT,run_id TEXT,owner_epoch INTEGER,runtime_id TEXT NOT NULL,envelope_hash TEXT NOT NULL,status TEXT NOT NULL,last_seen_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS validation_receipts(receipt_id TEXT PRIMARY KEY,task_id TEXT NOT NULL,run_id TEXT,result_json TEXT NOT NULL,created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS artefacts(artefact_id TEXT PRIMARY KEY,task_id TEXT,type TEXT NOT NULL,path TEXT NOT NULL,sha256 TEXT NOT NULL,size INTEGER NOT NULL,created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS provider_usage(id INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT,run_id TEXT,provider TEXT,model TEXT,input_tokens INTEGER,output_tokens INTEGER,cost_usd REAL NOT NULL DEFAULT 0,created_at REAL NOT NULL);
            """)
            task_cols={str(r[1]) for r in self.db.execute("PRAGMA table_info(tasks)")}
            if "assignment_bound_ever" not in task_cols:self.db.execute("ALTER TABLE tasks ADD COLUMN assignment_bound_ever INTEGER NOT NULL DEFAULT 0")
            if "assignment_generation" not in task_cols:self.db.execute("ALTER TABLE tasks ADD COLUMN assignment_generation INTEGER NOT NULL DEFAULT 0")
            cols={str(r[1]) for r in self.db.execute("PRAGMA table_info(workspace_leases)")}
            if "budget_reserved" not in cols:self.db.execute("ALTER TABLE workspace_leases ADD COLUMN budget_reserved REAL NOT NULL DEFAULT 0")
            additions=(("builder_principal","TEXT"),("assignment_generation","INTEGER"),("assignment_digest","TEXT"),("assignment_identity_json","TEXT"),("workspace_generation","TEXT"),("workspace_content_identity","TEXT"))
            for name,typ in additions:
                if name not in cols:self.db.execute(f"ALTER TABLE workspace_leases ADD COLUMN {name} {typ}")
            self.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",(str(SCHEMA_VERSION),))

    def _state_version(self):
        return int(self.db.execute("SELECT COALESCE(MAX(state_version),0)+1 AS v FROM task_events").fetchone()["v"])

    def _event_locked(self,event_type,payload,task_id=None,run_id=None):
        version=self._state_version()
        cur=self.db.execute("INSERT INTO task_events(task_id,run_id,event_type,payload_json,state_version,created_at) VALUES(?,?,?,?,?,?)",(task_id,run_id,event_type,json.dumps(payload,separators=(",",":")),version,time.time()))
        return {"seq":int(cur.lastrowid),"stateVersion":version}

    def event(self,event_type,payload,task_id=None,run_id=None):
        with self._lock:return self._event_locked(event_type,payload,task_id,run_id)

    def create_task(self,t):
        _scope_authorities(t.get("allowedPaths",[]));_repository_identity(t.get("repository"));base_sha=_git_object_id(t.get("baseSha"))
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                self.db.execute("""INSERT INTO tasks(task_id,repository,purpose,base_sha,branch,status,allowed_paths_json,required_tests_json,budget_allocated,created_at,updated_at)
                  VALUES(?,?,?,?,?,'queued',?,?,?,?,?)""",(t["taskId"],t["repository"],t["purpose"],base_sha,t.get("branch"),json.dumps(t.get("allowedPaths",[])),json.dumps(t.get("requiredTests",[])),float(t.get("budgetUsd",0)),now,now))
                self._event_locked("task.created",{"status":"queued"},t["taskId"])
                self.db.execute("COMMIT");begun=False
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise
        return self.get_task(t["taskId"])

    def get_task(self,task_id):
        row=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone();return dict(row) if row else None

    def _live_cross_task_conflicts_locked(self,task_id,repository,base_sha,worktree,scope,now):
        worktree_id=_physical_worktree_identity(worktree);repository_id=_repository_identity(repository);base_id=_git_object_id(base_sha)
        rows=self.db.execute("""SELECT wl.task_id,wl.worktree_path,t.repository,t.base_sha,t.allowed_paths_json FROM workspace_leases wl JOIN tasks t ON t.task_id=wl.task_id WHERE wl.task_id<>? AND wl.released_at IS NULL AND wl.expires_at>?""",(task_id,now)).fetchall()
        for row in rows:
            other_task=str(row["task_id"])
            if _physical_worktree_identity(row["worktree_path"])==worktree_id:raise WorkspaceCollisionError("WORKTREE_COLLISION",f"physical worktree already owned by live task {other_task}")
            if _repository_identity(row["repository"])!=repository_id or _git_object_id(row["base_sha"])!=base_id:continue
            if _scope_overlap(scope,_scope_authorities(row["allowed_paths_json"])):raise WorkspaceCollisionError("WRITABLE_SCOPE_COLLISION",f"writable scope overlaps live task {other_task}")

    def claim_workspace(self,task_id,run_id,worktree,branch,current_head,ttl_seconds=1200,runtime_id=None,worktree_root=None,budget_reserved=0.0,builder_principal=None,assignment_generation=None,workspace_generation=None,workspace_content_identity=None):
        if worktree_root is None:raise ValueError("worktree_root required")
        worktree=canonical_worktree_path(worktree,worktree_root);ttl_seconds=_ttl(ttl_seconds)
        bound_args=(builder_principal,assignment_generation,workspace_generation,workspace_content_identity)
        partially_bound=any(value is not None for value in bound_args) and not all(value is not None for value in bound_args)
        if partially_bound:raise AssignmentAuthorityError("ASSIGNMENT_IDENTITY_INVALID","bound assignment fields must be provided together")
        requested_bound=all(value is not None for value in bound_args)
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                task_row=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                if not task_row:raise KeyError("task not found")
                task=dict(task_row);scope=_scope_authorities(task["allowed_paths_json"]);was_bound=bool(int(task.get("assignment_bound_ever",0)))
                if was_bound and not requested_bound:raise AssignmentAuthorityError("ASSIGNMENT_DOWNGRADE_DENIED","assignment-bound task cannot return to legacy reclaim")
                row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone();next_epoch=(int(row["owner_epoch"])+1) if row else 1
                if row and row["released_at"] is None and float(row["expires_at"])>now:raise RuntimeError("workspace lease is already active")
                expected_head=str(row["current_head"]) if row else str(task.get("result_head") or task.get("base_sha") or "")
                if expected_head and str(current_head)!=expected_head:raise PermissionError("workspace claim head mismatch")
                self._live_cross_task_conflicts_locked(task_id,task["repository"],task["base_sha"],worktree,scope,now)
                reserved,new_spent=_validated_budget_request(task,budget_reserved);attempt=int(self.db.execute("SELECT COALESCE(MAX(attempt),0)+1 v FROM task_runs WHERE task_id=?",(task_id,)).fetchone()["v"])
                assignment_digest=assignment_json=principal=workspace_gen=workspace_content=None;next_assignment_generation=int(task.get("assignment_generation",0))
                if requested_bound:
                    principal=_principal(builder_principal);requested_generation=_positive_int(assignment_generation,"ASSIGNMENT_GENERATION_INVALID");next_assignment_generation=int(task.get("assignment_generation",0))+1
                    if requested_generation!=next_assignment_generation:raise AssignmentAuthorityError("ASSIGNMENT_GENERATION_STALE","assignment generation must advance exactly once")
                    workspace_gen=_workspace_generation(workspace_generation);workspace_content=_workspace_content_identity(workspace_content_identity)
                    identity={"builderPrincipal":principal,"assignmentGeneration":requested_generation,"taskId":task_id,"runId":run_id,"attempt":attempt,"ownerEpoch":next_epoch,"repository":task["repository"],"baseSha":task["base_sha"],"workspaceGeneration":workspace_gen,"workspaceContentIdentity":workspace_content}
                    assignment_digest,assignment_json,_=_assignment_digest(identity)
                cur=self.db.execute("UPDATE tasks SET budget_spent=?,assignment_bound_ever=?,assignment_generation=? WHERE task_id=? AND revision=?",(new_spent,1 if (was_bound or requested_bound) else 0,next_assignment_generation,task_id,int(task["revision"])))
                if cur.rowcount!=1:raise BudgetReservationError("BUDGET_STATE_INVALID","task state changed during reservation")
                self.db.execute("""INSERT INTO workspace_leases(task_id,worktree_path,branch,owner_run_id,owner_epoch,claimed_at,heartbeat_at,expires_at,released_at,current_head,budget_reserved,builder_principal,assignment_generation,assignment_digest,assignment_identity_json,workspace_generation,workspace_content_identity) VALUES(?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET worktree_path=excluded.worktree_path,branch=excluded.branch,owner_run_id=excluded.owner_run_id,owner_epoch=excluded.owner_epoch,claimed_at=excluded.claimed_at,heartbeat_at=excluded.heartbeat_at,expires_at=excluded.expires_at,released_at=NULL,current_head=excluded.current_head,budget_reserved=excluded.budget_reserved,builder_principal=excluded.builder_principal,assignment_generation=excluded.assignment_generation,assignment_digest=excluded.assignment_digest,assignment_identity_json=excluded.assignment_identity_json,workspace_generation=excluded.workspace_generation,workspace_content_identity=excluded.workspace_content_identity""",(task_id,worktree,branch,run_id,next_epoch,now,now,now+ttl_seconds,current_head,reserved,principal,next_assignment_generation if requested_bound else None,assignment_digest,assignment_json,workspace_gen,workspace_content))
                self.db.execute("INSERT INTO task_runs(run_id,task_id,attempt,owner_epoch,runtime_id,status,started_at) VALUES(?,?,?,?,?,'running',?)",(run_id,task_id,attempt,next_epoch,runtime_id,now))
                cur=self.db.execute("UPDATE tasks SET status='running',revision=revision+1,current_step='workspace-claimed',assigned_runtime=?,updated_at=? WHERE task_id=? AND revision=?",(runtime_id,now,task_id,int(task["revision"])))
                if cur.rowcount!=1:raise PermissionError("task authority changed during workspace claim")
                payload={"ownerEpoch":next_epoch,"worktreePath":worktree,"head":current_head,"budgetReserved":reserved}
                if requested_bound:payload.update({"assignmentGeneration":next_assignment_generation,"assignmentDigest":assignment_digest,"builderPrincipal":principal})
                self._event_locked("workspace.claimed",payload,task_id,run_id);self.db.execute("COMMIT");begun=False;return self.get_lease(task_id)
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def get_lease(self,task_id):
        row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone();return dict(row) if row else None

    def get_assignment_authority(self,task_id,require_active=True):
        with self._lock:
            row=self.db.execute("""SELECT wl.*,t.repository,t.base_sha,t.assignment_bound_ever,t.assignment_generation AS task_assignment_generation FROM workspace_leases wl JOIN tasks t ON t.task_id=wl.task_id WHERE wl.task_id=?""",(task_id,)).fetchone()
            if not row:raise AssignmentAuthorityError("ASSIGNMENT_UNKNOWN","assignment authority is unavailable")
            row=dict(row)
            if not bool(int(row["assignment_bound_ever"])) or not row.get("assignment_digest") or not row.get("assignment_identity_json"):raise AssignmentAuthorityError("ASSIGNMENT_UNBOUND","task has no bound assignment authority")
            if require_active and (row["released_at"] is not None or float(row["expires_at"])<=time.time()):raise AssignmentAuthorityError("ASSIGNMENT_INACTIVE","assignment authority is no longer active")
            try:identity=json.loads(row["assignment_identity_json"])
            except Exception as ex:raise AssignmentAuthorityError("ASSIGNMENT_STATE_INVALID","stored assignment identity is malformed") from ex
            digest,raw,canonical=_assignment_digest(identity)
            if digest!=row["assignment_digest"]:raise AssignmentAuthorityError("ASSIGNMENT_STATE_INVALID","stored assignment digest does not match identity")
            checks=(canonical["taskId"]==str(row["task_id"]),canonical["runId"]==str(row["owner_run_id"]),canonical["ownerEpoch"]==int(row["owner_epoch"]),canonical["repository"]==_repository_identity(row["repository"]),canonical["baseSha"]==_git_object_id(row["base_sha"]),canonical["builderPrincipal"]==row["builder_principal"],canonical["assignmentGeneration"]==int(row["assignment_generation"]),canonical["assignmentGeneration"]==int(row["task_assignment_generation"]),canonical["workspaceGeneration"]==row["workspace_generation"],canonical["workspaceContentIdentity"]==row["workspace_content_identity"])
            if not all(checks):raise AssignmentAuthorityError("ASSIGNMENT_STATE_INVALID","stored assignment identity no longer matches durable authority")
            return {"digest":digest,"identity":canonical,"canonicalJson":raw}

    def assert_assignment_authority(self,task_id,assignment_digest,**expected):
        if not isinstance(assignment_digest,str) or not _HEX64_RE.fullmatch(assignment_digest):raise AssignmentAuthorityError("ASSIGNMENT_DIGEST_INVALID","assignment digest must be exact lowercase sha256")
        authority=self.get_assignment_authority(task_id,require_active=True)
        if authority["digest"]!=assignment_digest:raise AssignmentAuthorityError("ASSIGNMENT_STALE","assignment digest is stale or belongs to another assignment")
        allowed={"builderPrincipal","assignmentGeneration","runId","attempt","ownerEpoch","repository","baseSha","workspaceGeneration","workspaceContentIdentity"}
        if set(expected)-allowed:raise AssignmentAuthorityError("ASSIGNMENT_EXPECTATION_INVALID","unknown assignment expectation")
        for key,value in expected.items():
            actual=authority["identity"].get(key)
            if key in {"assignmentGeneration","attempt","ownerEpoch"} and (isinstance(value,bool) or not isinstance(value,int)):raise AssignmentAuthorityError("ASSIGNMENT_EXPECTATION_INVALID","numeric expectation is invalid")
            if actual!=value:raise AssignmentAuthorityError("ASSIGNMENT_MISMATCH",f"assignment {key} mismatch")
        return authority

    def assert_writer(self,task_id,run_id,owner_epoch,expected_head=None,assignment_digest=None):
        with self._lock:
            row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL",(task_id,run_id,int(owner_epoch))).fetchone()
            if not row:raise PermissionError("writer authority lost: lease/epoch mismatch")
            if float(row["expires_at"])<=time.time():raise PermissionError("writer authority lost: lease expired")
            if expected_head and row["current_head"]!=expected_head:raise PermissionError("writer authority lost: expected head mismatch")
            bound=bool(row["assignment_digest"])
        if bound:
            if assignment_digest is None:raise AssignmentAuthorityError("ASSIGNMENT_DIGEST_REQUIRED","bound writer requires assignment digest")
            self.assert_assignment_authority(task_id,assignment_digest,runId=run_id,ownerEpoch=int(owner_epoch))
        elif assignment_digest is not None:raise AssignmentAuthorityError("ASSIGNMENT_UNBOUND","legacy writer has no assignment digest")
        return dict(row)

    def heartbeat(self,task_id,run_id,owner_epoch,ttl_seconds=1200,current_head=None,expected_head=None,assignment_digest=None):
        ttl_seconds=_ttl(ttl_seconds)
        if assignment_digest is not None:self.assert_assignment_authority(task_id,assignment_digest,runId=run_id,ownerEpoch=int(owner_epoch))
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time();row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL",(task_id,run_id,int(owner_epoch))).fetchone()
                if not row:raise PermissionError("writer authority lost: lease/epoch mismatch")
                if row["assignment_digest"] and assignment_digest!=row["assignment_digest"]:raise AssignmentAuthorityError("ASSIGNMENT_DIGEST_REQUIRED","bound heartbeat requires exact assignment digest")
                if float(row["expires_at"])<=now:raise PermissionError("writer authority lost: lease expired")
                old_head=str(row["current_head"])
                if expected_head is not None and old_head!=str(expected_head):raise PermissionError("writer authority lost: expected head mismatch")
                new_head=old_head if current_head is None else str(current_head)
                cur=self.db.execute("""UPDATE workspace_leases SET heartbeat_at=?,expires_at=?,current_head=? WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL AND expires_at>? AND current_head=?""",(now,now+ttl_seconds,new_head,task_id,run_id,int(owner_epoch),now,old_head))
                if cur.rowcount!=1:raise PermissionError("writer authority lost during heartbeat")
                self._event_locked("workspace.heartbeat",{"ownerEpoch":int(owner_epoch),"head":new_head},task_id,run_id);self.db.execute("COMMIT");begun=False;return self.get_lease(task_id)
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def release(self,task_id,run_id,owner_epoch,result_head=None,outcome="released",expected_head=None,assignment_digest=None):
        if assignment_digest is not None:self.assert_assignment_authority(task_id,assignment_digest,runId=run_id,ownerEpoch=int(owner_epoch))
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time();row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL",(task_id,run_id,int(owner_epoch))).fetchone()
                if not row:raise PermissionError("writer authority lost: lease/epoch mismatch")
                if row["assignment_digest"] and assignment_digest!=row["assignment_digest"]:raise AssignmentAuthorityError("ASSIGNMENT_DIGEST_REQUIRED","bound release requires exact assignment digest")
                if float(row["expires_at"])<=now:raise PermissionError("writer authority lost: lease expired")
                old_head=str(row["current_head"])
                if expected_head is not None and old_head!=str(expected_head):raise PermissionError("writer authority lost: expected head mismatch")
                final_head=old_head if result_head is None else str(result_head)
                cur=self.db.execute("""UPDATE workspace_leases SET released_at=?,current_head=? WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL AND expires_at>? AND current_head=?""",(now,final_head,task_id,run_id,int(owner_epoch),now,old_head))
                if cur.rowcount!=1:raise PermissionError("writer authority lost during release")
                cur=self.db.execute("UPDATE task_runs SET status=?,finished_at=? WHERE run_id=? AND task_id=? AND owner_epoch=? AND status='running'",(outcome,now,run_id,task_id,int(owner_epoch)))
                if cur.rowcount!=1:raise PermissionError("run authority lost during release")
                cur=self.db.execute("UPDATE tasks SET status=?,revision=revision+1,result_head=?,updated_at=? WHERE task_id=? AND status='running'",(outcome,final_head,now,task_id))
                if cur.rowcount!=1:raise PermissionError("task authority lost during release")
                self._event_locked("workspace.released",{"ownerEpoch":int(owner_epoch),"outcome":outcome,"resultHead":final_head},task_id,run_id);self.db.execute("COMMIT");begun=False
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def snapshot(self):
        return {"schemaVersion":SCHEMA_VERSION,"tasks":[dict(r) for r in self.db.execute("SELECT * FROM tasks ORDER BY updated_at DESC LIMIT 100")],"leases":[dict(r) for r in self.db.execute("SELECT * FROM workspace_leases WHERE released_at IS NULL ORDER BY heartbeat_at DESC")],"workers":[dict(r) for r in self.db.execute("SELECT * FROM worker_instances ORDER BY last_seen_at DESC LIMIT 100")],"lastEventSeq":int(self.db.execute("SELECT COALESCE(MAX(seq),0) v FROM task_events").fetchone()["v"])}