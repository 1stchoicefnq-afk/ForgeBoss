from __future__ import annotations
import hashlib,hmac,json,math,os,re,secrets,sqlite3,threading,time
from decimal import Decimal,InvalidOperation
from pathlib import Path
from forgeboss.security.local_acl import harden_private_dir,harden_private_path
from forgeboss.control.scheduler import _canonical_path

SCHEMA_VERSION=5
class BudgetReservationError(RuntimeError):
    def __init__(self,code,message): super().__init__(message);self.code=code
class WorkspaceCollisionError(RuntimeError):
    def __init__(self,code,message): super().__init__(message);self.code=code
class StoreAuthorityError(RuntimeError):
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
    value=raw.replace("\\","/");parts=value.split("/")
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

def _money_text(value):
    amount=value if isinstance(value,Decimal) else _budget_decimal(value,"BUDGET_STATE_INVALID","money authority is invalid")
    if amount==0:return "0"
    text=format(amount,"f")
    if "." in text:text=text.rstrip("0").rstrip(".")
    return text

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
    try:x=float(value)
    except Exception as ex:raise ValueError("ttl_seconds must be finite positive") from ex
    if not math.isfinite(x) or x<=0:raise ValueError("ttl_seconds must be finite positive")
    return x

def _opaque(value,name):
    if not isinstance(value,str) or not value or value!=value.strip() or len(value)>256 or any(ord(ch)<32 or ord(ch)==127 for ch in value):
        raise StoreAuthorityError("AUTHORITY_ID_INVALID",f"{name} must be a non-empty opaque identifier")
    return value

def _branch_identity(value):
    if not isinstance(value,str) or not value or value!=value.strip() or len(value)>255:
        raise StoreAuthorityError("BRANCH_INVALID","branch authority must be a canonical Git branch name")
    if value.startswith(("-","/")) or value.endswith(("/",".")) or "\\" in value or "//" in value or ".." in value or "@{" in value:
        raise StoreAuthorityError("BRANCH_INVALID","branch authority must be a canonical Git branch name")
    if any(ord(ch)<32 or ord(ch)==127 or ch in " ~^:?*[" for ch in value):
        raise StoreAuthorityError("BRANCH_INVALID","branch authority must be a canonical Git branch name")
    parts=value.split("/")
    if any(not part or part.startswith(".") or part.endswith(".lock") for part in parts):
        raise StoreAuthorityError("BRANCH_INVALID","branch authority must be a canonical Git branch name")
    return value

def _token_hash(raw):
    if not isinstance(raw,str) or not raw:return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

_WORKER_OUTCOMES=frozenset({"released","failed","cancelled"})
_TERMINAL_RETRY_REQUIRED=frozenset({"released","failed","cancelled","completed","review-rejected","revoked","accepted","approved","validated"})

class ControlStore:
    def __init__(self,path:Path):
        self.path=Path(path);harden_private_dir(self.path.parent)
        self._lock=threading.RLock()
        self.db=sqlite3.connect(str(self.path),check_same_thread=False,timeout=15,isolation_level=None)
        harden_private_path(self.path);self.db.row_factory=sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL");self.db.execute("PRAGMA foreign_keys=ON");self.db.execute("PRAGMA synchronous=FULL");self._migrate()

    def _ensure_column(self,table,name,definition):
        cols={str(r[1]) for r in self.db.execute(f"PRAGMA table_info({table})")}
        if name not in cols:self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

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
            CREATE TABLE IF NOT EXISTS budget_runs(run_id TEXT PRIMARY KEY,cap_exact TEXT NOT NULL,reserved_exact TEXT NOT NULL DEFAULT '0',status TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,created_at REAL NOT NULL,updated_at REAL NOT NULL,closed_at REAL);
            """)
            self._ensure_column("workspace_leases","budget_reserved","REAL NOT NULL DEFAULT 0")
            task_cols_before={str(r[1]) for r in self.db.execute("PRAGMA table_info(tasks)")}
            had_budget_cap_exact="budget_cap_exact" in task_cols_before
            had_budget_reserved_exact="budget_reserved_exact" in task_cols_before
            for name,definition in (
                ("budget_cap_exact","TEXT"),("budget_reserved_exact","TEXT NOT NULL DEFAULT '0'"),("budget_run_id","TEXT"),
                ("assigned_builder_id","TEXT"),("assignment_generation","INTEGER NOT NULL DEFAULT 0"),("assignment_token_hash","TEXT"),
                ("assignment_sha256","TEXT"),("retry_reason","TEXT"),("assignment_mode","TEXT NOT NULL DEFAULT 'legacy'")):
                self._ensure_column("tasks",name,definition)
            for table in ("task_runs","workspace_leases"):
                for name,definition in (
                    ("builder_id","TEXT"),("assignment_generation","INTEGER NOT NULL DEFAULT 0"),("assignment_sha256","TEXT"),
                    ("revoked_at","REAL"),("revoke_reason","TEXT")):
                    self._ensure_column(table,name,definition)
            self._ensure_column("workspace_leases","attempt","INTEGER")
            self.db.execute("""UPDATE tasks
                SET assignment_mode='controller-bound'
                WHERE assignment_mode='legacy'
                  AND (
                    budget_run_id IS NOT NULL OR
                    assigned_builder_id IS NOT NULL OR
                    assignment_token_hash IS NOT NULL OR
                    assignment_sha256 IS NOT NULL
                  )""")
            rows=self.db.execute("SELECT task_id,budget_allocated,budget_spent,budget_cap_exact,budget_reserved_exact FROM tasks").fetchall()
            for row in rows:
                cap=row["budget_cap_exact"]
                reserved=row["budget_reserved_exact"]
                if not had_budget_cap_exact or cap is None:
                    cap=_money_text(_budget_decimal(row["budget_allocated"],"BUDGET_STATE_INVALID","task budget state is invalid"))
                if not had_budget_reserved_exact or reserved is None:
                    reserved=_money_text(_budget_decimal(row["budget_spent"],"BUDGET_STATE_INVALID","task budget state is invalid"))
                self.db.execute("UPDATE tasks SET budget_cap_exact=?,budget_reserved_exact=? WHERE task_id=?",(cap,reserved,row["task_id"]))
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
        branch=t.get("branch");branch=_branch_identity(branch) if branch is not None else None
        cap=_budget_decimal(t.get("budgetUsd",0),"BUDGET_INVALID","task budget must be a finite non-negative number")
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                self.db.execute("""INSERT INTO tasks(task_id,repository,purpose,base_sha,branch,status,allowed_paths_json,required_tests_json,budget_allocated,budget_spent,budget_cap_exact,budget_reserved_exact,created_at,updated_at)
                  VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?,?,?)""",(t["taskId"],t["repository"],t["purpose"],base_sha,branch,json.dumps(t.get("allowedPaths",[])),json.dumps(t.get("requiredTests",[])),float(cap),0.0,_money_text(cap),"0",now,now))
                self._event_locked("task.created",{"status":"queued"},t["taskId"])
                self.db.execute("COMMIT");begun=False
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise
        return self.get_task(t["taskId"])

    def get_task(self,task_id):
        with self._lock:
            row=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone();return dict(row) if row else None

    def create_budget_run(self,run_id,cap):
        run_id=_opaque(run_id,"budget run id");amount=_budget_decimal(cap,"GLOBAL_BUDGET_INVALID","global budget cap must be finite and non-negative")
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                self.db.execute("INSERT INTO budget_runs(run_id,cap_exact,reserved_exact,status,revision,created_at,updated_at) VALUES(?,?,?,'active',1,?,?)",(run_id,_money_text(amount),"0",now,now))
                self._event_locked("budget_run.created",{"budgetRunId":run_id,"capUsd":_money_text(amount),"revision":1})
                self.db.execute("COMMIT");begun=False
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise
        return self.get_budget_run(run_id)

    def get_budget_run(self,run_id):
        with self._lock:
            row=self.db.execute("SELECT * FROM budget_runs WHERE run_id=?",(run_id,)).fetchone()
            if not row:return None
            out=dict(row);cap=_budget_decimal(out["cap_exact"],"GLOBAL_BUDGET_STATE_INVALID","global budget state invalid");reserved=_budget_decimal(out["reserved_exact"],"GLOBAL_BUDGET_STATE_INVALID","global budget state invalid")
            out["remaining_exact"]=_money_text(cap-reserved);return out

    def close_budget_run(self,run_id,expected_revision=None):
        run_id=_opaque(run_id,"budget run id")
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                row=self.db.execute("SELECT * FROM budget_runs WHERE run_id=?",(run_id,)).fetchone()
                if not row:raise StoreAuthorityError("GLOBAL_BUDGET_UNKNOWN","unknown budget run")
                if expected_revision is not None and int(expected_revision)!=int(row["revision"]):raise StoreAuthorityError("GLOBAL_BUDGET_REVISION_MISMATCH","global budget revision mismatch")
                if row["status"]=="closed":
                    self.db.execute("COMMIT");begun=False;return self.get_budget_run(run_id)
                cur=self.db.execute("UPDATE budget_runs SET status='closed',revision=revision+1,updated_at=?,closed_at=? WHERE run_id=? AND revision=? AND status='active'",(now,now,run_id,int(row["revision"])))
                if cur.rowcount!=1:raise StoreAuthorityError("GLOBAL_BUDGET_REVISION_MISMATCH","global budget authority changed")
                self._event_locked("budget_run.closed",{"budgetRunId":run_id})
                self.db.execute("COMMIT");begun=False
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise
        return self.get_budget_run(run_id)

    def _assignment_digest_locked(self,task,builder_id,budget_run_id,generation):
        allowed=sorted(_scope_authorities(task["allowed_paths_json"]))
        try:tests=json.loads(task["required_tests_json"])
        except Exception as ex:raise StoreAuthorityError("ASSIGNMENT_STATE_INVALID","required test authority is invalid") from ex
        if not isinstance(tests,list):raise StoreAuthorityError("ASSIGNMENT_STATE_INVALID","required test authority is invalid")
        branch=_branch_identity(task["branch"])
        payload={"taskId":str(task["task_id"]),"repository":_repository_identity(task["repository"]),"baseSha":_git_object_id(task["base_sha"]),
                 "branch":branch,"allowedPaths":allowed,"requiredTests":sorted(str(x) for x in tests),
                 "taskBudgetUsd":str(task["budget_cap_exact"]),"budgetRunId":budget_run_id,"builderId":builder_id,"assignmentGeneration":int(generation)}
        encoded=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def assign_builder(self,task_id,builder_id,budget_run_id,expected_task_revision=None):
        builder_id=_opaque(builder_id,"builder id");budget_run_id=_opaque(budget_run_id,"budget run id")
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                task_row=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                if not task_row:raise KeyError("task not found")
                task=dict(task_row);_branch_identity(task["branch"])
                if expected_task_revision is not None and int(expected_task_revision)!=int(task["revision"]):raise StoreAuthorityError("TASK_REVISION_MISMATCH","task revision mismatch")
                lease=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone()
                if lease and lease["released_at"] is None and lease["revoked_at"] is None and float(lease["expires_at"])>now:
                    raise StoreAuthorityError("ASSIGNMENT_ACTIVE_WRITER","cannot rotate assignment while writer is live")
                budget=self.db.execute("SELECT * FROM budget_runs WHERE run_id=?",(budget_run_id,)).fetchone()
                if not budget:raise StoreAuthorityError("GLOBAL_BUDGET_UNKNOWN","unknown budget run")
                if budget["status"]!="active":raise StoreAuthorityError("GLOBAL_BUDGET_CLOSED","budget run is closed")
                if task["budget_run_id"] is not None and str(task["budget_run_id"])!=budget_run_id:
                    raise StoreAuthorityError("BUDGET_RUN_BINDING_MISMATCH","task budget run binding is immutable")
                generation=int(task["assignment_generation"] or 0)+1
                raw=secrets.token_urlsafe(32);token_hash=_token_hash(raw)
                digest=self._assignment_digest_locked(task,builder_id,budget_run_id,generation)
                cur=self.db.execute("""UPDATE tasks SET budget_run_id=?,assigned_builder_id=?,assignment_generation=?,assignment_token_hash=?,assignment_sha256=?,
                    assignment_mode='controller-bound',revision=revision+1,updated_at=? WHERE task_id=? AND revision=?""",(budget_run_id,builder_id,generation,token_hash,digest,now,task_id,int(task["revision"])))
                if cur.rowcount!=1:raise StoreAuthorityError("TASK_REVISION_MISMATCH","task authority changed during assignment")
                self._event_locked("task.assigned",{"builderId":builder_id,"assignmentGeneration":generation,"assignmentSha256":digest,"budgetRunId":budget_run_id},task_id)
                self.db.execute("COMMIT");begun=False
                return {"taskId":task_id,"builderId":builder_id,"budgetRunId":budget_run_id,"budgetRunRevision":int(budget["revision"]),
                        "assignmentGeneration":generation,"assignmentToken":raw,"assignmentSha256":digest}
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def retry_task(self,task_id,reason):
        if not isinstance(reason,str) or not reason.strip():raise StoreAuthorityError("RETRY_REASON_REQUIRED","retry reason required")
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                task=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                if not task:raise KeyError("task not found")
                if str(task["status"]) not in _TERMINAL_RETRY_REQUIRED:raise StoreAuthorityError("RETRY_NOT_ALLOWED","task is not in a retry-required terminal state")
                lease=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone()
                if lease and lease["released_at"] is None and lease["revoked_at"] is None and float(lease["expires_at"])>now:
                    raise StoreAuthorityError("RETRY_ACTIVE_WRITER","cannot retry while writer is live")
                bound=str(task["assignment_mode"] or "legacy")=="controller-bound"
                generation=int(task["assignment_generation"] or 0)+(1 if bound else 0)
                cur=self.db.execute("""UPDATE tasks SET status='queued',current_step='retry-authorized',retry_reason=?,assigned_builder_id=NULL,
                    assignment_generation=?,assignment_token_hash=NULL,assignment_sha256=NULL,revision=revision+1,updated_at=? WHERE task_id=? AND revision=?""",
                    (reason.strip(),generation,now,task_id,int(task["revision"])))
                if cur.rowcount!=1:raise StoreAuthorityError("TASK_REVISION_MISMATCH","task authority changed during retry")
                self._event_locked("task.retry_authorized",{"reason":reason.strip(),"assignmentGeneration":generation},task_id)
                self.db.execute("COMMIT");begun=False
                return self.get_task(task_id)
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def _live_cross_task_conflicts_locked(self,task_id,repository,base_sha,worktree,scope,now):
        worktree_id=_physical_worktree_identity(worktree);repository_id=_repository_identity(repository);base_id=_git_object_id(base_sha)
        rows=self.db.execute("""SELECT wl.task_id,wl.worktree_path,t.repository,t.base_sha,t.allowed_paths_json
          FROM workspace_leases wl JOIN tasks t ON t.task_id=wl.task_id
          WHERE wl.task_id<>? AND wl.released_at IS NULL AND wl.revoked_at IS NULL AND wl.expires_at>?""",(task_id,now)).fetchall()
        for row in rows:
            other_task=str(row["task_id"])
            if _physical_worktree_identity(row["worktree_path"])==worktree_id:raise WorkspaceCollisionError("WORKTREE_COLLISION",f"physical worktree already owned by live task {other_task}")
            if _repository_identity(row["repository"])!=repository_id or _git_object_id(row["base_sha"])!=base_id:continue
            if _scope_overlap(scope,_scope_authorities(row["allowed_paths_json"])):raise WorkspaceCollisionError("WRITABLE_SCOPE_COLLISION",f"writable scope overlaps live task {other_task}")

    def _validate_assignment_locked(self,task,builder_id,assignment_token,assignment_generation,assignment_sha256):
        bound=str(task["assignment_mode"] or "legacy")=="controller-bound"
        if not bound:return False
        if not task["assigned_builder_id"] or not task["assignment_token_hash"] or not task["assignment_sha256"]:
            raise StoreAuthorityError("ASSIGNMENT_REQUIRED","bound task requires fresh controller assignment authority")
        if builder_id is None or assignment_token is None or assignment_generation is None or assignment_sha256 is None:
            raise StoreAuthorityError("ASSIGNMENT_REQUIRED","bound task requires exact builder assignment authority")
        if str(builder_id)!=str(task["assigned_builder_id"]):raise StoreAuthorityError("BUILDER_MISMATCH","builder identity mismatch")
        if int(assignment_generation)!=int(task["assignment_generation"]):raise StoreAuthorityError("ASSIGNMENT_GENERATION_MISMATCH","assignment generation mismatch")
        if not hmac.compare_digest(_token_hash(assignment_token),str(task["assignment_token_hash"] or "")):raise StoreAuthorityError("ASSIGNMENT_TOKEN_MISMATCH","assignment token mismatch")
        if not hmac.compare_digest(str(assignment_sha256),str(task["assignment_sha256"] or "")):raise StoreAuthorityError("ASSIGNMENT_DIGEST_MISMATCH","assignment digest mismatch")
        expected=self._assignment_digest_locked(task,str(builder_id),str(task["budget_run_id"]),int(task["assignment_generation"]))
        if not hmac.compare_digest(expected,str(task["assignment_sha256"] or "")):raise StoreAuthorityError("ASSIGNMENT_STATE_INVALID","stored assignment digest does not match task authority")
        return True

    def _reserve_bound_budget_locked(self,task,requested,budget_run_revision):
        value=_budget_decimal(requested,"BUDGET_INVALID","workspace claim budget must be a finite non-negative number")
        cap=_budget_decimal(task["budget_cap_exact"],"BUDGET_STATE_INVALID","task exact budget state invalid")
        spent=_budget_decimal(task["budget_reserved_exact"],"BUDGET_STATE_INVALID","task exact budget state invalid")
        if spent>cap:raise BudgetReservationError("BUDGET_STATE_INVALID","task exact budget state is overspent")
        if value>cap-spent:raise BudgetReservationError("BUDGET_EXCEEDED",f"workspace claim budget {value} exceeds remaining task budget {cap-spent}")
        budget=self.db.execute("SELECT * FROM budget_runs WHERE run_id=?",(task["budget_run_id"],)).fetchone()
        if not budget:raise StoreAuthorityError("GLOBAL_BUDGET_UNKNOWN","unknown budget run")
        if budget["status"]!="active":raise StoreAuthorityError("GLOBAL_BUDGET_CLOSED","budget run is closed")
        if budget_run_revision is None or int(budget_run_revision)!=int(budget["revision"]):raise StoreAuthorityError("GLOBAL_BUDGET_REVISION_MISMATCH","global budget revision mismatch")
        gcap=_budget_decimal(budget["cap_exact"],"GLOBAL_BUDGET_STATE_INVALID","global budget state invalid")
        gres=_budget_decimal(budget["reserved_exact"],"GLOBAL_BUDGET_STATE_INVALID","global budget state invalid")
        if gres>gcap:raise BudgetReservationError("GLOBAL_BUDGET_STATE_INVALID","global budget state is overspent")
        if value>gcap-gres:raise BudgetReservationError("GLOBAL_BUDGET_EXCEEDED",f"workspace claim budget {value} exceeds remaining global budget {gcap-gres}")
        new_g=gres+value
        cur=self.db.execute("UPDATE budget_runs SET reserved_exact=?,revision=revision+1,updated_at=? WHERE run_id=? AND status='active' AND revision=?",(_money_text(new_g),time.time(),task["budget_run_id"],int(budget["revision"])))
        if cur.rowcount!=1:raise StoreAuthorityError("GLOBAL_BUDGET_REVISION_MISMATCH","global budget authority changed during reservation")
        new_task=spent+value
        return value,new_task,int(budget["revision"])+1

    def claim_workspace(self,task_id,run_id,worktree,branch,current_head,ttl_seconds=1200,runtime_id=None,worktree_root=None,budget_reserved=0.0,
                        builder_id=None,assignment_token=None,assignment_generation=None,assignment_sha256=None,budget_run_revision=None):
        if worktree_root is None:raise ValueError("worktree_root required")
        worktree=canonical_worktree_path(worktree,worktree_root);ttl_seconds=_ttl(ttl_seconds)
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                task_row=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                if not task_row:raise KeyError("task not found")
                task=dict(task_row);scope=_scope_authorities(task["allowed_paths_json"])
                assignment_mode=str(task["assignment_mode"] or "legacy")
                if assignment_mode=="controller-bound" and str(task["status"]) in _TERMINAL_RETRY_REQUIRED:
                    raise StoreAuthorityError("TASK_RETRY_REQUIRED","terminal controller-bound task requires explicit controller retry")
                bound=self._validate_assignment_locked(task,builder_id,assignment_token,assignment_generation,assignment_sha256)
                if bound:
                    assigned_branch=_branch_identity(task["branch"]);claim_branch=_branch_identity(branch)
                    if claim_branch!=assigned_branch:raise StoreAuthorityError("ASSIGNMENT_BRANCH_MISMATCH","workspace claim branch does not match durable assignment branch")
                    branch=assigned_branch
                row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone()
                next_epoch=(int(row["owner_epoch"])+1) if row else 1
                if row and row["released_at"] is None and row["revoked_at"] is None and float(row["expires_at"])>now:raise RuntimeError("workspace lease is already active")
                expected_head=str(row["current_head"]) if row else str(task.get("result_head") or task.get("base_sha") or "")
                if expected_head and str(current_head)!=expected_head:raise PermissionError("workspace claim head mismatch")
                self._live_cross_task_conflicts_locked(task_id,task["repository"],task["base_sha"],worktree,scope,now)
                if bound:
                    value,new_exact,new_global_rev=self._reserve_bound_budget_locked(task,budget_reserved,budget_run_revision)
                    reserved=float(value);new_spent=float(new_exact)
                    cur=self.db.execute("UPDATE tasks SET budget_reserved_exact=?,budget_spent=? WHERE task_id=? AND revision=?",(_money_text(new_exact),new_spent,task_id,int(task["revision"])))
                else:
                    reserved,new_spent=_validated_budget_request(task,budget_reserved);new_global_rev=None
                    exact=_budget_decimal(new_spent,"BUDGET_STATE_INVALID","task budget state invalid")
                    cur=self.db.execute("UPDATE tasks SET budget_reserved_exact=?,budget_spent=? WHERE task_id=? AND revision=?",(_money_text(exact),new_spent,task_id,int(task["revision"])))
                if cur.rowcount!=1:raise BudgetReservationError("BUDGET_STATE_INVALID","task state changed during reservation")
                attempt=int(self.db.execute("SELECT COALESCE(MAX(attempt),0)+1 v FROM task_runs WHERE task_id=?",(task_id,)).fetchone()["v"])
                if row and row["released_at"] is None and row["revoked_at"] is None and float(row["expires_at"])<=now:
                    self.db.execute("UPDATE task_runs SET status='superseded',finished_at=? WHERE run_id=? AND task_id=? AND owner_epoch=? AND status='running'",(now,row["owner_run_id"],task_id,int(row["owner_epoch"])))
                gen=int(task["assignment_generation"] or 0);digest=task["assignment_sha256"] if bound else None;bid=task["assigned_builder_id"] if bound else None
                self.db.execute("""INSERT INTO workspace_leases(task_id,worktree_path,branch,owner_run_id,owner_epoch,claimed_at,heartbeat_at,expires_at,released_at,current_head,budget_reserved,builder_id,assignment_generation,assignment_sha256,revoked_at,revoke_reason,attempt)
                  VALUES(?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,NULL,NULL,?)
                  ON CONFLICT(task_id) DO UPDATE SET worktree_path=excluded.worktree_path,branch=excluded.branch,owner_run_id=excluded.owner_run_id,owner_epoch=excluded.owner_epoch,claimed_at=excluded.claimed_at,heartbeat_at=excluded.heartbeat_at,expires_at=excluded.expires_at,released_at=NULL,current_head=excluded.current_head,budget_reserved=excluded.budget_reserved,builder_id=excluded.builder_id,assignment_generation=excluded.assignment_generation,assignment_sha256=excluded.assignment_sha256,revoked_at=NULL,revoke_reason=NULL,attempt=excluded.attempt""",
                  (task_id,worktree,branch,run_id,next_epoch,now,now,now+ttl_seconds,current_head,reserved,bid,gen,digest,attempt))
                self.db.execute("""INSERT INTO task_runs(run_id,task_id,attempt,owner_epoch,runtime_id,status,started_at,builder_id,assignment_generation,assignment_sha256,revoked_at,revoke_reason)
                    VALUES(?,?,?,?,?,'running',?,?,?,?,NULL,NULL)""",(run_id,task_id,attempt,next_epoch,runtime_id,now,bid,gen,digest))
                cur=self.db.execute("UPDATE tasks SET status='running',revision=revision+1,current_step='workspace-claimed',assigned_runtime=?,updated_at=? WHERE task_id=? AND revision=?",(runtime_id,now,task_id,int(task["revision"])))
                if cur.rowcount!=1:raise PermissionError("task authority changed during workspace claim")
                payload={"ownerEpoch":next_epoch,"attempt":attempt,"worktreePath":worktree,"head":current_head,"budgetReserved":reserved}
                if bound:payload.update({"builderId":bid,"assignmentGeneration":gen,"assignmentSha256":digest,"budgetRunId":task["budget_run_id"],"budgetRunRevision":new_global_rev})
                self._event_locked("workspace.claimed",payload,task_id,run_id)
                self.db.execute("COMMIT");begun=False
                return self.get_lease(task_id)
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def get_lease(self,task_id):
        with self._lock:
            row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone();return dict(row) if row else None

    def _writer_locked(self,task_id,run_id,owner_epoch,now):
        row=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL",(task_id,run_id,int(owner_epoch))).fetchone()
        if not row:raise PermissionError("writer authority lost: lease/epoch mismatch")
        if row["revoked_at"] is not None:raise PermissionError("writer authority lost: writer revoked")
        if float(row["expires_at"])<=now:raise PermissionError("writer authority lost: lease expired")
        run=self.db.execute("SELECT * FROM task_runs WHERE run_id=? AND task_id=? AND owner_epoch=?",(run_id,task_id,int(owner_epoch))).fetchone()
        if not run or run["revoked_at"] is not None or run["status"]!="running":raise PermissionError("run authority lost")
        return row,run

    def assert_writer(self,task_id,run_id,owner_epoch,expected_head=None):
        with self._lock:
            row,_=self._writer_locked(task_id,run_id,owner_epoch,time.time())
            if expected_head and row["current_head"]!=expected_head:raise PermissionError("writer authority lost: expected head mismatch")
            return dict(row)

    def heartbeat(self,task_id,run_id,owner_epoch,ttl_seconds=1200,current_head=None,expected_head=None):
        ttl_seconds=_ttl(ttl_seconds)
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                row,_=self._writer_locked(task_id,run_id,owner_epoch,now)
                old_head=str(row["current_head"])
                if expected_head is not None and old_head!=str(expected_head):raise PermissionError("writer authority lost: expected head mismatch")
                new_head=old_head if current_head is None else str(current_head)
                cur=self.db.execute("""UPDATE workspace_leases SET heartbeat_at=?,expires_at=?,current_head=?
                  WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL AND revoked_at IS NULL AND expires_at>? AND current_head=?""",(now,now+ttl_seconds,new_head,task_id,run_id,int(owner_epoch),now,old_head))
                if cur.rowcount!=1:raise PermissionError("writer authority lost during heartbeat")
                self._event_locked("workspace.heartbeat",{"ownerEpoch":int(owner_epoch),"head":new_head},task_id,run_id)
                self.db.execute("COMMIT");begun=False
                return self.get_lease(task_id)
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def release(self,task_id,run_id,owner_epoch,result_head=None,outcome="released",expected_head=None):
        if not isinstance(outcome,str) or outcome not in _WORKER_OUTCOMES:
            raise StoreAuthorityError("WORKER_OUTCOME_INVALID","worker outcome is not an allowed neutral/failure outcome")
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                row,_=self._writer_locked(task_id,run_id,owner_epoch,now)
                task=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                if not task:raise KeyError("task not found")
                old_head=str(row["current_head"])
                if expected_head is not None and old_head!=str(expected_head):raise PermissionError("writer authority lost: expected head mismatch")
                final_head=old_head if result_head is None else str(result_head)
                cur=self.db.execute("""UPDATE workspace_leases SET released_at=?,current_head=?
                  WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL AND revoked_at IS NULL AND expires_at>? AND current_head=?""",(now,final_head,task_id,run_id,int(owner_epoch),now,old_head))
                if cur.rowcount!=1:raise PermissionError("writer authority lost during release")
                cur=self.db.execute("UPDATE task_runs SET status=?,finished_at=? WHERE run_id=? AND task_id=? AND owner_epoch=? AND status='running' AND revoked_at IS NULL",(outcome,now,run_id,task_id,int(owner_epoch)))
                if cur.rowcount!=1:raise PermissionError("run authority lost during release")
                generation=int(task["assignment_generation"] or 0)+(1 if str(task["assignment_mode"] or "legacy")=="controller-bound" else 0)
                cur=self.db.execute("""UPDATE tasks SET status=?,revision=revision+1,result_head=?,terminal_outcome=?,assigned_builder_id=NULL,
                    assignment_generation=?,assignment_token_hash=NULL,assignment_sha256=NULL,updated_at=? WHERE task_id=? AND status='running' AND revision=?""",
                    (outcome,final_head,None if outcome=="released" else outcome,generation,now,task_id,int(task["revision"])))
                if cur.rowcount!=1:raise PermissionError("task authority lost during release")
                self._event_locked("workspace.released",{"ownerEpoch":int(owner_epoch),"outcome":outcome,"resultHead":final_head,"assignmentGeneration":generation},task_id,run_id)
                self.db.execute("COMMIT");begun=False
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise

    def revoke_writer(self,task_id,run_id,owner_epoch,reason):
        if not isinstance(reason,str) or not reason.strip():raise StoreAuthorityError("REVOKE_REASON_REQUIRED","revoke reason required")
        with self._lock:
            begun=False
            try:
                self.db.execute("BEGIN IMMEDIATE");begun=True;now=time.time()
                run=self.db.execute("SELECT * FROM task_runs WHERE run_id=? AND task_id=? AND owner_epoch=?",(run_id,task_id,int(owner_epoch))).fetchone()
                if not run:raise StoreAuthorityError("REVOKE_STALE_AUTHORITY","run/epoch does not identify durable writer authority")
                if run["revoked_at"] is not None:
                    self.db.execute("COMMIT");begun=False
                    return dict(run)
                lease=self.db.execute("SELECT * FROM workspace_leases WHERE task_id=?",(task_id,)).fetchone()
                if not lease or str(lease["owner_run_id"])!=str(run_id) or int(lease["owner_epoch"])!=int(owner_epoch):
                    raise StoreAuthorityError("REVOKE_STALE_AUTHORITY","stale writer cannot revoke newer owner")
                if lease["released_at"] is not None:raise StoreAuthorityError("REVOKE_STALE_AUTHORITY","released writer cannot be revoked")
                task=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                if not task:raise KeyError("task not found")
                cur=self.db.execute("UPDATE task_runs SET status='revoked',revoked_at=?,revoke_reason=?,finished_at=? WHERE run_id=? AND task_id=? AND owner_epoch=? AND revoked_at IS NULL",(now,reason.strip(),now,run_id,task_id,int(owner_epoch)))
                if cur.rowcount!=1:raise StoreAuthorityError("REVOKE_STALE_AUTHORITY","run authority changed during revoke")
                cur=self.db.execute("UPDATE workspace_leases SET revoked_at=?,revoke_reason=? WHERE task_id=? AND owner_run_id=? AND owner_epoch=? AND released_at IS NULL AND revoked_at IS NULL",(now,reason.strip(),task_id,run_id,int(owner_epoch)))
                if cur.rowcount!=1:raise StoreAuthorityError("REVOKE_STALE_AUTHORITY","lease authority changed during revoke")
                generation=int(task["assignment_generation"] or 0)+(1 if str(task["assignment_mode"] or "legacy")=="controller-bound" else 0)
                cur=self.db.execute("""UPDATE tasks SET status='revoked',terminal_outcome='revoked',assigned_builder_id=NULL,assignment_generation=?,
                    assignment_token_hash=NULL,assignment_sha256=NULL,revision=revision+1,updated_at=? WHERE task_id=? AND status='running' AND revision=?""",
                    (generation,now,task_id,int(task["revision"])))
                if cur.rowcount!=1:raise StoreAuthorityError("REVOKE_STALE_AUTHORITY","task authority changed during revoke")
                self._event_locked("workspace.revoked",{"ownerEpoch":int(owner_epoch),"reason":reason.strip(),"assignmentGeneration":generation},task_id,run_id)
                self.db.execute("COMMIT");begun=False
                return dict(self.db.execute("SELECT * FROM task_runs WHERE run_id=?",(run_id,)).fetchone())
            except Exception:
                if begun:
                    try:self.db.execute("ROLLBACK")
                    except Exception:pass
                raise


    def assignment_identity(self,task_id,run_id,owner_epoch):
        task_id=_opaque(task_id,"task id")
        run_id=_opaque(run_id,"run id")
        try:
            owner_epoch=int(owner_epoch)
        except Exception as ex:
            raise StoreAuthorityError("ASSIGNMENT_IDENTITY_INVALID","owner epoch invalid") from ex
        if owner_epoch<=0:
            raise StoreAuthorityError("ASSIGNMENT_IDENTITY_INVALID","owner epoch invalid")

        with self._lock:
            task_row=self.db.execute(
                "SELECT * FROM tasks WHERE task_id=?",
                (task_id,)
            ).fetchone()
            if not task_row:
                raise StoreAuthorityError("ASSIGNMENT_UNKNOWN","unknown task")

            task=dict(task_row)

            if str(task.get("assignment_mode") or "legacy")!="controller-bound":
                raise StoreAuthorityError(
                    "ASSIGNMENT_REQUIRED",
                    "task is not controller-bound"
                )

            run_row=self.db.execute(
                "SELECT * FROM task_runs WHERE task_id=? AND run_id=? AND owner_epoch=?",
                (task_id,run_id,owner_epoch)
            ).fetchone()
            if not run_row:
                raise StoreAuthorityError(
                    "ASSIGNMENT_IDENTITY_STALE",
                    "run/epoch is not authoritative"
                )

            run=dict(run_row)

            lease_row=self.db.execute(
                "SELECT * FROM workspace_leases WHERE task_id=?",
                (task_id,)
            ).fetchone()
            if not lease_row:
                raise StoreAuthorityError(
                    "ASSIGNMENT_IDENTITY_STALE",
                    "workspace authority missing"
                )

            lease=dict(lease_row)

            if str(lease["owner_run_id"])!=run_id or int(lease["owner_epoch"])!=owner_epoch:
                raise StoreAuthorityError(
                    "ASSIGNMENT_IDENTITY_STALE",
                    "workspace owner changed"
                )

            if lease.get("released_at") is not None or lease.get("revoked_at") is not None:
                raise StoreAuthorityError(
                    "ASSIGNMENT_IDENTITY_STALE",
                    "workspace authority is terminal"
                )

            builder=str(run.get("builder_id") or "")
            generation=int(run.get("assignment_generation") or 0)

            if not builder or builder!=str(task.get("assigned_builder_id") or ""):
                raise StoreAuthorityError(
                    "ASSIGNMENT_STATE_INVALID",
                    "builder authority mismatch"
                )

            if generation!=int(task.get("assignment_generation") or 0):
                raise StoreAuthorityError(
                    "ASSIGNMENT_STATE_INVALID",
                    "assignment generation mismatch"
                )

            policy_sha=str(task.get("assignment_sha256") or "")
            if not re.fullmatch(r"[0-9a-f]{64}",policy_sha):
                raise StoreAuthorityError(
                    "ASSIGNMENT_STATE_INVALID",
                    "assignment policy digest missing"
                )

            expected=self._assignment_digest_locked(
                task,
                builder,
                str(task["budget_run_id"]),
                generation
            )

            if not hmac.compare_digest(expected,policy_sha):
                raise StoreAuthorityError(
                    "ASSIGNMENT_STATE_INVALID",
                    "stored assignment policy digest invalid"
                )

            base_sha=_git_object_id(task["base_sha"])
            current_head=_git_object_id(lease["current_head"])

            # Workspace generation is the durable ownership epoch.
            identity={
                "taskId":task_id,
                "runId":run_id,
                "attempt":int(run["attempt"]),
                "ownerEpoch":owner_epoch,
                "builderPrincipal":builder,
                "assignmentGeneration":generation,
                "assignmentPolicySha256":policy_sha,
                "repository":_repository_identity(task["repository"]),
                "baseSha":base_sha,
                "branch":_branch_identity(lease["branch"]),
                "worktreePath":str(lease["worktree_path"]),
                "workspaceGeneration":owner_epoch,
                "workspaceContentIdentity":current_head,
                "budgetRunId":str(task["budget_run_id"]),
            }

            encoded=json.dumps(
                identity,
                sort_keys=True,
                separators=(",",":"),
                ensure_ascii=False
            ).encode("utf-8")

            return {
                "identity":identity,
                "assignmentIdentitySha256":hashlib.sha256(encoded).hexdigest(),
            }

    def snapshot(self):
        with self._lock:
            budgets=[]
            for r in self.db.execute("SELECT * FROM budget_runs ORDER BY created_at DESC LIMIT 100"):
                d=dict(r)
                try:
                    cap=_budget_decimal(d["cap_exact"],"GLOBAL_BUDGET_STATE_INVALID","global budget state invalid");reserved=_budget_decimal(d["reserved_exact"],"GLOBAL_BUDGET_STATE_INVALID","global budget state invalid")
                    d["remaining_exact"]=_money_text(cap-reserved)
                except Exception:d["remaining_exact"]=None
                budgets.append(d)
            tasks=[]
            for r in self.db.execute("SELECT * FROM tasks ORDER BY updated_at DESC LIMIT 100"):
                d=dict(r);d.pop("assignment_token_hash",None)
                d.pop("budget_spent",None)
                d["budgetCapExact"]=d.get("budget_cap_exact")
                d["budgetReservedExact"]=d.get("budget_reserved_exact")
                tasks.append(d)
            return {"schemaVersion":SCHEMA_VERSION,
              "tasks":tasks,
              "leases":[dict(r) for r in self.db.execute("SELECT * FROM workspace_leases WHERE released_at IS NULL ORDER BY heartbeat_at DESC")],
              "workers":[dict(r) for r in self.db.execute("SELECT * FROM worker_instances ORDER BY last_seen_at DESC LIMIT 100")],
              "budgetRuns":budgets,
              "lastEventSeq":int(self.db.execute("SELECT COALESCE(MAX(seq),0) v FROM task_events").fetchone()["v"])}
