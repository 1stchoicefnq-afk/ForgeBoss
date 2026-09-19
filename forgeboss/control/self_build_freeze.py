from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath

_SHA_RE=re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_TEST_RE=re.compile(r"^python -m unittest ([A-Za-z_][A-Za-z0-9_.]*) -v$")
_SECRET_PREFIXES=("GITHUB_","GH_","FORGEBOSS_AUTHORITY_")
_SECRET_NAMES={
    "OPENAI_API_KEY","LLM_API_KEY","ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY","GEMINI_API_KEY",
}
_MAX_RESULT_BYTES=256*1024


class SelfBuildFreezeError(RuntimeError):
    def __init__(self,code:str,message:str):
        super().__init__(message);self.code=code


def _is_linklike(path:Path)->bool:
    try:
        if path.is_symlink():return True
        if hasattr(path,"is_junction") and path.is_junction():return True
    except OSError:return True
    return False


def _inside(child:Path,parent:Path)->bool:
    try:
        return os.path.normcase(os.path.commonpath([str(child),str(parent)]))==os.path.normcase(str(parent))
    except ValueError:
        return False


def _pairs(values):
    out={}
    for k,v in values:
        if k in out:raise SelfBuildFreezeError("RESULT_JSON_INVALID","duplicate result key")
        out[k]=v
    return out


def load_result_file(path,*,state_root)->dict:
    root=Path(state_root).expanduser().resolve(strict=True)
    raw_path=Path(path).expanduser()
    if _is_linklike(raw_path):raise SelfBuildFreezeError("RESULT_PATH_INVALID","result evidence link denied")
    target=raw_path.resolve(strict=True)
    if target==root or not _inside(target,root):
        raise SelfBuildFreezeError("RESULT_PATH_INVALID","result evidence escapes external state root")
    st=target.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size<=0 or st.st_size>_MAX_RESULT_BYTES:
        raise SelfBuildFreezeError("RESULT_FILE_INVALID","result evidence size/type invalid")
    raw=target.read_bytes()
    if len(raw)>_MAX_RESULT_BYTES:raise SelfBuildFreezeError("RESULT_FILE_INVALID","result evidence too large")
    try:value=json.loads(raw.decode("utf-8"),object_pairs_hook=_pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError("nonfinite")))
    except SelfBuildFreezeError:raise
    except Exception as ex:raise SelfBuildFreezeError("RESULT_JSON_INVALID","result evidence unreadable") from ex
    if not isinstance(value,dict):raise SelfBuildFreezeError("RESULT_SCHEMA_INVALID","worker result must be object")
    return value


def _run(argv,*,cwd:Path,env=None,timeout=120):
    try:
        return subprocess.run(
            list(map(str,argv)),cwd=str(cwd),env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout,check=False,
        )
    except (OSError,subprocess.TimeoutExpired) as ex:
        raise SelfBuildFreezeError("COMMAND_FAILED",str(ex)) from ex


def _git_executable()->Path:
    from forgeboss.security.executor_guard import _resolve_git_executable
    try:return Path(_resolve_git_executable()).resolve(strict=True)
    except Exception as ex:raise SelfBuildFreezeError("GIT_EXECUTABLE_INVALID","trusted git unavailable") from ex


def _git(git:Path,root:Path,*args,timeout=120)->str:
    env={k:v for k,v in os.environ.items() if not k.upper().startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":os.devnull,
        "GIT_TERMINAL_PROMPT":"0","GIT_ASKPASS":"",
        "GIT_ALLOW_PROTOCOL":"file","GIT_PROTOCOL_FROM_USER":"0",
    })
    p=_run([git,*args],cwd=root,env=env,timeout=timeout)
    if p.returncode:
        raise SelfBuildFreezeError("GIT_COMMAND_FAILED",(p.stderr or p.stdout or "git failed")[-2000:])
    return (p.stdout or "").strip()


def _rel(value)->str:
    raw=str(value or "").replace("\\","/")
    p=PurePosixPath(raw)
    if not raw or p.is_absolute() or ".." in p.parts or "." in p.parts or raw==".git" or raw.startswith(".git/"):
        raise SelfBuildFreezeError("SCOPE_INVALID","unsafe repository-relative path")
    return p.as_posix()


def _clean_test_env():
    out={}
    for k,v in os.environ.items():
        key=k.upper()
        if key in _SECRET_NAMES or any(key.startswith(prefix) for prefix in _SECRET_PREFIXES):
            continue
        out[k]=v
    out.update({
        "PYTHONUTF8":"1","PYTHONDONTWRITEBYTECODE":"1",
        "FORGEBOSS_ALLOW_PAID_EXECUTOR":"NO",
        "GIT_TERMINAL_PROMPT":"0","GIT_ASKPASS":"",
    })
    return out


def _canonical_digest(value)->str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")).hexdigest()


def validate_result(result:dict,*,item:dict,public:dict)->dict:
    if not isinstance(result,dict) or result.get("schema")!=1:
        raise SelfBuildFreezeError("RESULT_SCHEMA_INVALID","worker result schema invalid")
    packet=item.get("packet") or {};authority=item.get("authority") or {}
    exact={
        "task_id":str(item.get("task_id") or ""),
        "builder_id":str(item.get("builder_id") or ""),
        "run_id":str(packet.get("run_id") or ""),
        "expected_head_revision":str(packet.get("expected_head_revision") or "").lower(),
        "workspace":str(Path(item.get("worktree") or "").resolve()),
        "packet_sha256":str(public.get("packet_sha256") or ""),
    }
    for key,want in exact.items():
        got=str(result.get(key) or "")
        if key=="expected_head_revision":got=got.lower()
        if got!=want:raise SelfBuildFreezeError("RESULT_BINDING_MISMATCH",f"{key} mismatch")
    if result.get("executor")!="mini-swe" or result.get("completed") is not True or result.get("error") is not None:
        raise SelfBuildFreezeError("WORKER_RESULT_NOT_COMPLETE","worker did not return a clean completed result")
    calls=result.get("calls")
    if isinstance(calls,bool) or not isinstance(calls,int) or calls<1:
        raise SelfBuildFreezeError("CALL_COUNT_INVALID","completed worker must report at least one model call")
    try:
        cost=Decimal(str(result.get("cost_usd")))
        cap=Decimal(str(authority.get("budget_usd")))
    except (InvalidOperation,ValueError,TypeError) as ex:
        raise SelfBuildFreezeError("COST_INVALID","worker cost invalid") from ex
    if not cost.is_finite() or cost<0 or not cap.is_finite() or cap<=0 or cost>cap:
        raise SelfBuildFreezeError("COST_EXCEEDS_AUTHORITY","worker cost exceeds authority")
    pf=result.get("postflight")
    if not isinstance(pf,dict) or pf.get("ok") is not True or pf.get("scope_ok") is not True or pf.get("paid_consumed") is not True:
        raise SelfBuildFreezeError("POSTFLIGHT_UNPROVEN","worker postflight not proven")
    changed=tuple(_rel(x) for x in (pf.get("changed_paths") or []))
    allowed={_rel(x).casefold() for x in (packet.get("allowed_files") or [])}
    if not changed or any(x.casefold() not in allowed for x in changed):
        raise SelfBuildFreezeError("POSTFLIGHT_SCOPE_MISMATCH","postflight change set invalid")
    return {
        "measured_cost_usd":format(cost,"f"),
        "postflight_changed_paths":list(changed),
        "runner_result_digest":_canonical_digest(result),
    }


def _status_paths(git:Path,root:Path)->list[str]:
    raw=_git(git,root,"status","--porcelain=v1","-z","--untracked-files=all")
    if not raw:return []
    out=[]
    for row in raw.split("\x00"):
        if not row:continue
        if len(row)<4:raise SelfBuildFreezeError("STATUS_INVALID","malformed git status")
        status=row[:2];path=row[3:]
        if "R" in status or "C" in status:
            raise SelfBuildFreezeError("STATUS_INVALID","rename/copy changes denied in FL1 canary")
        out.append(_rel(path))
    return out


def freeze_candidate(*,item:dict,public:dict,result:dict,process_evidence:dict,
                     git_executable=None,python_executable=None)->dict:
    if (
        not isinstance(process_evidence,dict)
        or process_evidence.get("state")!="STOPPED"
        or process_evidence.get("containmentEmpty") is not True
        or process_evidence.get("exitCode")!=0
        or process_evidence.get("reason")!="verified-complete"
    ):
        raise SelfBuildFreezeError("PROCESS_COMPLETION_UNPROVEN","worker process completion not proven")

    validated=validate_result(result,item=item,public=public)
    root=Path(item["worktree"]).resolve(strict=True)
    git=Path(git_executable).resolve(strict=True) if git_executable else _git_executable()
    python=Path(python_executable or sys.executable).resolve(strict=True)
    packet=item["packet"];base=str(packet["expected_head_revision"]).lower()
    if not _SHA_RE.fullmatch(base):raise SelfBuildFreezeError("BASE_SHA_INVALID","packet base SHA invalid")
    head=_git(git,root,"rev-parse","HEAD").lower()
    if head!=base:raise SelfBuildFreezeError("BASE_HEAD_CHANGED","worker changed Git HEAD")
    if _git(git,root,"remote"):
        raise SelfBuildFreezeError("REMOTE_PRESENT","worker workspace has a Git remote")

    changed=_status_paths(git,root)
    if not changed:raise SelfBuildFreezeError("EMPTY_CANDIDATE","worker produced no candidate changes")
    allowed={_rel(x).casefold() for x in packet.get("allowed_files") or []}
    if any(p.casefold() not in allowed for p in changed):
        raise SelfBuildFreezeError("SCOPE_VIOLATION","workspace contains out-of-scope changes")
    if sorted(x.casefold() for x in changed)!=sorted(x.casefold() for x in validated["postflight_changed_paths"]):
        raise SelfBuildFreezeError("POSTFLIGHT_DIFF_MISMATCH","independent diff disagrees with worker postflight")
    if len(changed)>int(packet.get("max_changed_files") or 0):
        raise SelfBuildFreezeError("CHURN_FILES_EXCEEDED","changed-file ceiling exceeded")

    tests=[]
    commands=packet.get("required_tests") or []
    if not commands:raise SelfBuildFreezeError("FOCUSED_TEST_REQUIRED","focused test authority missing")
    for command in commands:
        m=_TEST_RE.fullmatch(str(command).strip())
        if not m:raise SelfBuildFreezeError("TEST_COMMAND_DENIED","unsupported focused test command")
        p=_run([python,"-m","unittest",m.group(1),"-v"],cwd=root,env=_clean_test_env(),timeout=180)
        output=(p.stdout or "")+"\n"+(p.stderr or "")
        tests.append({"command":str(command),"exit_code":int(p.returncode),"output_sha256":hashlib.sha256(output.encode("utf-8")).hexdigest()})
        if p.returncode:
            raise SelfBuildFreezeError("FOCUSED_TEST_FAILED",output[-4000:])

    for path in sorted(changed,key=str.casefold):
        _git(git,root,"add","--",path)
    after=_status_paths(git,root)
    if any(p.casefold() not in allowed for p in after):
        raise SelfBuildFreezeError("SCOPE_VIOLATION","out-of-scope change remained before freeze")
    numstat=_git(git,root,"diff","--cached","--numstat","--")
    line_total=0
    for line in numstat.splitlines():
        if not line.strip():continue
        parts=line.split("\t",2)
        if len(parts)!=3:raise SelfBuildFreezeError("CHURN_INVALID","malformed numstat")
        added,deleted,_=parts
        if added=="-" or deleted=="-":raise SelfBuildFreezeError("BINARY_CHANGE_DENIED","binary changes denied in FL1 canary")
        line_total+=int(added)+int(deleted)
    if line_total>int(packet.get("max_changed_lines") or 0):
        raise SelfBuildFreezeError("CHURN_LINES_EXCEEDED","changed-line ceiling exceeded")

    staged=[_rel(x) for x in _git(git,root,"diff","--cached","--name-only","--").splitlines() if x.strip()]
    if sorted(x.casefold() for x in staged)!=sorted(x.casefold() for x in changed):
        raise SelfBuildFreezeError("STAGED_SCOPE_MISMATCH","staged candidate differs from proven change set")

    message=f"self-build: {item['task_id']} by {item['builder_id']}"
    _git(
        git,root,
        "-c","user.name=ForgeBoss Self-Build",
        "-c","user.email=forgeboss@localhost",
        "commit","--no-gpg-sign","--no-verify","-m",message,"--",
    )
    candidate=_git(git,root,"rev-parse","HEAD").lower()
    if not _SHA_RE.fullmatch(candidate) or candidate==base:
        raise SelfBuildFreezeError("CANDIDATE_SHA_INVALID","candidate SHA did not freeze")
    if _git(git,root,"status","--porcelain=v1","--untracked-files=all"):
        raise SelfBuildFreezeError("CANDIDATE_NOT_PRISTINE","candidate workspace not pristine after freeze")
    diff_names=[_rel(x) for x in _git(git,root,"diff","--name-only",base,candidate,"--").splitlines() if x.strip()]
    if sorted(x.casefold() for x in diff_names)!=sorted(x.casefold() for x in changed):
        raise SelfBuildFreezeError("FROZEN_DIFF_MISMATCH","frozen candidate differs from proven change set")

    evidence={
        "schema":1,
        "task_id":item["task_id"],
        "builder_id":item["builder_id"],
        "base_sha":base,
        "candidate_sha":candidate,
        "changed_files":diff_names,
        "changed_lines":line_total,
        "focused_tests":tests,
        **validated,
    }
    evidence["evidence_digest"]=_canonical_digest(evidence)
    return evidence
