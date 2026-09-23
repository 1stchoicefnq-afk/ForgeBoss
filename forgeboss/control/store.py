from __future__ import annotations
import hashlib,json,math,os,re,sqlite3,threading,time
from decimal import Decimal,InvalidOperation
from pathlib import Path
from forgeboss.security.local_acl import harden_private_dir,harden_private_path
from forgeboss.control.scheduler import _canonical_path
from forgeboss.control.project_admission import verify_project_build_admission

SCHEMA_VERSION=3
class BudgetReservationError(RuntimeError):
    def __init__(self,code,message): super().__init__(message);self.code=code
class WorkspaceCollisionError(RuntimeError):
    def __init__(self,code,message): super().__init__(message);self.code=code
class ProjectAdmissionReplayError(RuntimeError):
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