from __future__ import annotations
import argparse,hashlib,json,math,os,re,secrets,subprocess,time
from contextlib import contextmanager
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"executor-security";STATE.mkdir(parents=True,exist_ok=True)
CNW=getattr(subprocess,"CREATE_NO_WINDOW",0)
class SecurityError(RuntimeError):pass

FORBIDDEN_PREFIXES=(".git/",".github/workflows/",".github/actions/","secrets/","appdata/",".openhands/",".circleci/","ci/credentials/","build/credentials/",".vscode/","devcontainer/",".devcontainer/","state/forgebossd/","state/learning/")
FORBIDDEN_EXACT={".git",".env",".env.local",".env.production",".npmrc",".pypirc","package.json","dockerfile","docker-compose.yml","docker-compose.yaml","compose.yml","compose.yaml",".pre-commit-config.yaml",".gitlab-ci.yml","jenkinsfile","azure-pipelines.yml","bitbucket-pipelines.yml","requirements.txt","requirements-dev.txt","requirements-test.txt","pyproject.toml","setup.py","setup.cfg","tox.ini","makefile","gnumakefile","pipfile","pipfile.lock","poetry.lock","cargo.toml","cargo.lock","go.mod","go.sum"}
GIT_META_EXACT=("config","config.worktree","HEAD","packed-refs","shallow","info/attributes","info/exclude","objects/info/alternates")
GIT_META_TREES=("refs","hooks")
EXEC_CONFIG_EXACT={"core.askpass","core.editor","core.gitproxy","core.pager","core.sshcommand","diff.external","gpg.program","interactive.difffilter","sequence.editor"}
EXEC_CONFIG_PATTERNS=(re.compile(r"^filter\..+\.(?:clean|smudge|process)$",re.I),re.compile(r"^diff\..+\.(?:command|textconv)$",re.I),re.compile(r"^merge\..+\.driver$",re.I),re.compile(r"^credential(?:\..+)?\.helper$",re.I),re.compile(r"^(?:diff|merge)tool\..+\.cmd$",re.I),re.compile(r"^gpg\..+\.program$",re.I),re.compile(r"^(?:pager|browser|man)\..+\.cmd$",re.I))

def norm(p):
    if not isinstance(p,str) or not p.strip():raise SecurityError("empty path")
    x=p.replace("\\","/").strip()
    if (len(x)>=2 and x[1]==":") or x.startswith(("/","//","~")):raise SecurityError("absolute/home path denied")
    pp=PurePosixPath(x)
    if ".." in pp.parts:raise SecurityError("parent traversal denied")
    y=pp.as_posix()
    while y.startswith("./"):y=y[2:]
    if not y:raise SecurityError("empty normalized path")
    return y

def key(p):return norm(p).casefold()
def sensitive(p):
    k=key(p);return k in FORBIDDEN_EXACT or any(k.startswith(x) for x in FORBIDDEN_PREFIXES)
def phash(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def fhash(p):
    h=hashlib.sha256()
    with Path(p).open("rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""):h.update(c)
    return h.hexdigest()
def is_linklike(p:Path):
    try:
        if p.is_symlink():return True
    except OSError:return True
    try:
        if hasattr(p,"is_junction") and p.is_junction():return True
    except OSError:return True
    return False
def assert_no_link_escape(work:Path):
    work=work.resolve()
    for p in work.rglob("*"):
        if is_linklike(p):raise SecurityError("baseline symlink/junction denied: "+str(p.relative_to(work)).replace("\\","/"))
def assert_paths_contained(work:Path,paths):
    work=work.resolve()
    for rel in paths:
        p=work/norm(rel);cur=p
        while cur!=work and cur.exists():
            if is_linklike(cur):raise SecurityError("symlink/junction path denied: "+norm(rel))
            cur=cur.parent
        try:
            resolved=p.resolve(strict=False)
            if os.path.commonpath([str(work),str(resolved)])!=str(work):raise SecurityError("resolved path escapes workspace: "+norm(rel))
        except ValueError:raise SecurityError("resolved path escapes workspace: "+norm(rel))
def _metadata_entry(p:Path,label:str):
    try:
        if is_linklike(p):raise SecurityError("linklike Git metadata denied: "+label)
        if not p.is_file():raise SecurityError("Git metadata is not a regular file: "+label)
        return {"kind":"file","sha256":fhash(p),"size":p.stat().st_size}
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to read Git metadata "+label+": "+str(e)) from e
def git(work,*args):
    p=subprocess.run(["git.exe",*args],cwd=work,capture_output=True,text=True,timeout=60,creationflags=CNW)
    if p.returncode:raise SecurityError((p.stdout+p.stderr).strip() or "git failed")
    return p.stdout.strip()
def _resolve_git_dir(work:Path,flag:str):
    raw=git(work,"rev-parse",flag)
    if not raw:raise SecurityError("empty Git metadata resolution for "+flag)
    p=Path(raw)
    if not p.is_absolute():p=work/p
    try:resolved=p.resolve(strict=True)
    except Exception as e:raise SecurityError("unable to resolve Git metadata "+flag+": "+str(e)) from e
    if not resolved.is_dir():raise SecurityError("resolved Git metadata is not directory: "+flag)
    return resolved
def _snapshot_metadata_root(root:Path,prefix:str,out:dict):
    for rel in GIT_META_EXACT:
        p=root/rel
        try:exists=p.exists() or is_linklike(p)
        except OSError as e:raise SecurityError("unable to inspect Git metadata "+prefix+rel+": "+str(e)) from e
        if exists:out[prefix+rel]=_metadata_entry(p,prefix+rel)
    for tree in GIT_META_TREES:
        base=root/tree
        try:
            if not base.exists():continue
            if is_linklike(base):raise SecurityError("linklike Git metadata denied: "+prefix+tree)
            entries=list(base.rglob("*"))
        except SecurityError:raise
        except Exception as e:raise SecurityError("unable to enumerate Git metadata "+prefix+tree+": "+str(e)) from e
        for p in entries:
            rel=str(p.relative_to(root)).replace("\\","/")
            if p.is_dir() and not is_linklike(p):continue
            out[prefix+rel]=_metadata_entry(p,prefix+rel)
def _config_names(work:Path):
    raw=git(work,"config","--includes","--name-only","--list")
    return {line.strip().casefold() for line in raw.splitlines() if line.strip()}
def _config_values(work:Path,name:str):return [x.strip() for x in git(work,"config","--includes","--get-all",name).splitlines() if x.strip()]
def _resolve_effective_git_path(work:Path,*args):
    raw=git(work,*args)
    if not raw:raise SecurityError("empty Git execution target resolution")
    p=Path(raw)
    if not p.is_absolute():p=work/p
    try:return p.resolve(strict=False)
    except Exception as e:raise SecurityError("unable to resolve Git execution target: "+str(e)) from e
def _assert_effective_worktree(work:Path):
    try:
        raw=git(work,"rev-parse","--show-toplevel")
        if not raw:raise SecurityError("empty effective Git worktree identity")
        effective=Path(raw)
        if not effective.is_absolute():effective=work/effective
        effective=effective.resolve(strict=True);leased=work.resolve(strict=True)
    except SecurityError:raise
    except Exception as e:raise SecurityError("unable to resolve effective Git worktree identity: "+str(e)) from e
    if effective!=leased:raise SecurityError("effective Git worktree escapes leased workspace: "+str(effective))
def _assert_safe_execution_config(work:Path,gitdir:Path,common:Path):
    _assert_effective_worktree(work);names=_config_names(work)
    if "core.hookspath" in names:
        target=_resolve_effective_git_path(work,"rev-parse","--git-path","hooks");trusted={(gitdir/"hooks").resolve(strict=False),(common/"hooks").resolve(strict=False)}
        if target not in trusted:raise SecurityError("external Git execution target denied: core.hooksPath -> "+str(target))
    if "core.fsmonitor" in names:
        vals=[v.casefold() for v in _config_values(work,"core.fsmonitor")]
        if any(v not in ("true","false") for v in vals):raise SecurityError("external Git execution target denied: core.fsmonitor")
    if "protocol.ext.allow" in names:
        vals=[v.casefold() for v in _config_values(work,"protocol.ext.allow")]
        if not vals or any(v!="never" for v in vals):raise SecurityError("execution-capable Git transport denied: protocol.ext.allow")
    elif "protocol.allow" in names:
        vals=[v.casefold() for v in _config_values(work,"protocol.allow")]
        if not vals or any(v!="never" for v in vals):raise SecurityError("execution-capable Git transport denied: protocol.allow")
    for name in names:
        if name in EXEC_CONFIG_EXACT or any(rx.match(name) for rx in EXEC_CONFIG_PATTERNS):raise SecurityError("execution-capable Git config denied: "+name)
        if name.startswith("alias.") and any(v.lstrip().startswith("!") for v in _config_values(work,name)):raise SecurityError("execution-capable Git config denied: "+name)
        if name.startswith("submodule.") and name.endswith(".update") and any(v.lstrip().startswith("!") for v in _config_values(work,name)):raise SecurityError("execution-capable Git config denied: "+name)
def git_metadata_snapshot(work):
    work=Path(work).resolve();dotgit=work/".git";out={}
    if not dotgit.exists() and not is_linklike(dotgit):return out
    if is_linklike(dotgit):raise SecurityError("linklike workspace .git denied")
    if dotgit.is_file():out[".git"]=_metadata_entry(dotgit,".git")
    elif not dotgit.is_dir():raise SecurityError("workspace .git is not file/directory")
    gitdir=_resolve_git_dir(work,"--git-dir");common=_resolve_git_dir(work,"--git-common-dir")
    _snapshot_metadata_root(gitdir,"gitdir/",out)
    if common!=gitdir:_snapshot_metadata_root(common,"common/",out)
    _assert_safe_execution_config(work,gitdir,common)
    effective=git(work,"config","--includes","--show-origin","--show-scope","-z","--list")
    out["git:effective-config"]={"kind":"semantic","sha256":hashlib.sha256(effective.encode("utf-8")).hexdigest()}
    staged=git(work,"ls-files","--stage","-z")
    out["git:index:stage"]={"kind":"semantic","sha256":hashlib.sha256(staged.encode("utf-8")).hexdigest()}
    return out
def snapshot(work):
    work=Path(work).resolve();out={}
    for p in work.rglob("*"):
        try:r=norm(str(p.relative_to(work)))
        except Exception:continue
        rk=r.casefold()
        if rk==".git" or rk.startswith(".git/"):continue
        if is_linklike(p):out[r]={"kind":"link","target":os.readlink(p) if p.is_symlink() else "<junction>"}
        elif p.is_file():out[r]={"kind":"file","sha256":fhash(p),"size":p.stat().st_size}
    return out
def changed(a,b):return sorted(k for k in set(a)|set(b) if a.get(k)!=b.get(k))
def validate_packet(packet):
    allowed=[norm(x) for x in packet.get("allowed_files",[])];context=[norm(x) for x in packet.get("context_files",[])]
    if not allowed:raise SecurityError("packet has no allowed_files")
    if len({x.casefold() for x in allowed})!=len(allowed):raise SecurityError("duplicate allowed_files after Windows casefold")
    for p in allowed:
        if sensitive(p):raise SecurityError("sensitive/high-impact write path denied: "+p)
    for p in context:
        k=p.casefold()
        if k==".git" or k.startswith(".git/"):raise SecurityError("Git metadata read denied")
    return allowed,context
def exact_head(work,packet):
    exp=packet.get("expected_head_revision") or packet.get("exact_head")
    if exp and (Path(work)/".git").exists():
        got=git(work,"rev-parse","HEAD")
        if got!=exp:raise SecurityError(f"exact HEAD mismatch {got} != {exp}")
def no_remotes(work):
    if (Path(work)/".git").exists() and git(work,"remote").strip():raise SecurityError("Git remotes present in executor workspace")
def isolation_ok(executor):
    if executor=="mini-swe":return True
    return os.environ.get("FORGEBOSS_OS_ISOLATION_VERIFIED")=="YES"
def _positive_budget(raw):
    if isinstance(raw,bool):raise SecurityError("paid budget must be a finite positive number")
    try:v=float(raw)
    except (TypeError,ValueError,OverflowError) as e:raise SecurityError("paid budget must be a finite positive number") from e
    if not math.isfinite(v) or v<=0:raise SecurityError("paid budget must be a finite positive number")
    return v
def _atomic_write_json(path,obj):
    path=Path(path);tmp=path.with_name(path.name+f".tmp-{os.getpid()}-{secrets.token_hex(4)}")
    data=json.dumps(obj,sort_keys=True,indent=2).encode("utf-8");fd=os.open(str(tmp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as f:f.write(data);f.flush();os.fsync(f.fileno())
    finally:
        try:os.close(fd)
        except OSError:pass
    os.replace(tmp,path)
class _WorkspaceFence:
    def __init__(self,workspace):self.path=STATE/("paid-start-"+hashlib.sha256(str(Path(workspace).resolve()).encode()).hexdigest()+".lock");self.f=None
    def __enter__(self):
        self.f=self.path.open("a+b");self.f.seek(0,2)
        if self.f.tell()==0:self.f.write(b"\0");self.f.flush()
        self.f.seek(0)
        if os.name=="nt":
            import msvcrt;msvcrt.locking(self.f.fileno(),msvcrt.LK_LOCK,1)
        else:
            import fcntl;fcntl.flock(self.f.fileno(),fcntl.LOCK_EX)
        return self
    def __exit__(self,*_):
        try:
            self.f.seek(0)
            if os.name=="nt":
                import msvcrt;msvcrt.locking(self.f.fileno(),msvcrt.LK_UNLCK,1)
            else:
                import fcntl;fcntl.flock(self.f.fileno(),fcntl.LOCK_UN)
        finally:self.f.close();self.f=None
def _load_control_envelope(raw):
    if not isinstance(raw,str) or not raw.strip():raise SecurityError("signed control envelope missing")
    text=raw.strip();p=Path(text)
    if not text.startswith("{") and p.exists():text=p.read_text(encoding="utf-8")
    try:payload=json.loads(text)
    except Exception as e:raise SecurityError("signed control envelope is invalid JSON") from e
    try:
        from forgeboss.control.envelope import secret_file,verify_envelope
        _,secret=secret_file(ROOT);return verify_envelope(payload,secret)
    except Exception as e:raise SecurityError("signed control envelope verification failed: "+str(e)) from e
def _control_authority(raw,lease,workspace,executor):
    env=_load_control_envelope(raw);work=Path(workspace).resolve()
    if Path(env.get("worktreePath","")).resolve()!=work:raise SecurityError("control envelope workspace mismatch")
    task=str(env.get("taskId") or "").strip();run=str(env.get("runId") or "").strip()
    if not task or not run:raise SecurityError("control envelope task/run identity missing")
    try:epoch=int(env.get("ownerEpoch"))
    except Exception as e:raise SecurityError("control envelope ownerEpoch invalid") from e
    if epoch<=0:raise SecurityError("control envelope ownerEpoch invalid")
    runtime=env.get("runtime")
    if not isinstance(runtime,dict) or str(runtime.get("adapter") or "")!=executor:raise SecurityError("control envelope runtime differs from executor")
    budget=_positive_budget(env.get("budgetUsd"));ea=[norm(x) for x in env.get("allowedPaths",[])];la=[norm(x) for x in lease.get("allowed_files",[])]
    if [x.casefold() for x in ea]!=[x.casefold() for x in la]:raise SecurityError("control envelope allowedPaths differ from executor lease")
    unsigned=json.dumps(env,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    return {"taskId":task,"runId":run,"ownerEpoch":epoch,"budgetUsd":budget,"worktreePath":str(work),"runtime":runtime,"expiresAt":float(env["expiresAt"]),"allowedPaths":ea,"envelopeSha256":hashlib.sha256(unsigned).hexdigest()}
def issue(packet_path,workspace,executor,ttl=1200):
    pp=Path(packet_path);work=Path(workspace).resolve();packet=json.loads(pp.read_text(encoding="utf-8"));allowed,context=validate_packet(packet)
    if executor in ("openhands","opencode") and not isolation_ok(executor):raise SecurityError(f"{executor} write-capable execution is quarantined until OS/network isolation is verified")
    with _WorkspaceFence(work):
        assert_no_link_escape(work);assert_paths_contained(work,allowed+context);exact_head(work,packet);no_remotes(work);token=secrets.token_urlsafe(32)
        lease={"schema":3,"executor":executor,"workspace":str(work),"packet_sha256":phash(pp),"allowed_files":allowed,"allowed_keys":[x.casefold() for x in allowed],"issued_at":time.time(),"expires_at":time.time()+ttl,"token_sha256":hashlib.sha256(token.encode()).hexdigest(),"baseline":snapshot(work),"git_metadata":git_metadata_snapshot(work),"isolation_verified":isolation_ok(executor),"paid_consumed":False,"paid_authority":None}
        lp=STATE/f"lease-{int(time.time()*1000)}-{secrets.token_hex(4)}.json";_atomic_write_json(lp,lease)
    print(json.dumps({"ok":True,"lease":str(lp),"token":token}));return 0
def _verify_unlocked(lease_path,token,packet_path,workspace,executor):
    lease=json.loads(Path(lease_path).read_text(encoding="utf-8"));work=Path(workspace).resolve();pp=Path(packet_path)
    if time.time()>float(lease.get("expires_at",0)):raise SecurityError("executor lease expired")
    if lease.get("executor")!=executor:raise SecurityError("executor identity mismatch")
    if Path(lease.get("workspace","")).resolve()!=work:raise SecurityError("workspace mismatch")
    if lease.get("packet_sha256")!=phash(pp):raise SecurityError("packet changed after lease")
    if not secrets.compare_digest(lease.get("token_sha256",""),hashlib.sha256(token.encode()).hexdigest()):raise SecurityError("lease token mismatch")
    packet=json.loads(pp.read_text(encoding="utf-8"));allowed,context=validate_packet(packet);assert_no_link_escape(work);assert_paths_contained(work,allowed+context);exact_head(work,packet);no_remotes(work)
    if executor in ("openhands","opencode") and not isolation_ok(executor):raise SecurityError(f"{executor} isolation proof disappeared after lease")
    before=lease.get("git_metadata")
    if not isinstance(before,dict):raise SecurityError("executor lease missing Git metadata baseline")
    ch=changed(before,git_metadata_snapshot(work))
    if ch:raise SecurityError("Git metadata changed after lease before execution: "+json.dumps(ch))
    return lease
def verify(lease_path,token,packet_path,workspace,executor):
    with _WorkspaceFence(workspace):return _verify_unlocked(lease_path,token,packet_path,workspace,executor)
@contextmanager
def paid_start_authority(lease_path,token,packet_path,workspace,executor,control_envelope,cli_budget=None):
    lease_path=Path(lease_path)
    with _WorkspaceFence(workspace):
        lease=_verify_unlocked(lease_path,token,packet_path,workspace,executor)
        if lease.get("paid_consumed") is True:raise SecurityError("paid executor authority already consumed")
        authority=_control_authority(control_envelope,lease,workspace,executor);budget=authority["budgetUsd"]
        if cli_budget is not None and _positive_budget(cli_budget)!=budget:raise SecurityError("runner budget differs from signed control authority")
        ch=changed(lease.get("git_metadata"),git_metadata_snapshot(Path(workspace).resolve()))
        if ch:raise SecurityError("Git metadata changed at paid-start boundary: "+json.dumps(ch))
        lease["paid_consumed"]=True;lease["paid_consumed_at"]=time.time();lease["paid_authority"]=authority;_atomic_write_json(lease_path,lease)
        yield authority
def postflight(lease_path,token,packet_path,workspace,executor):
    lease=verify(lease_path,token,packet_path,workspace,executor)
    with _WorkspaceFence(workspace):
        before=lease.get("git_metadata")
        if not isinstance(before,dict):raise SecurityError("executor lease missing Git metadata baseline")
        gc=changed(before,git_metadata_snapshot(workspace))
        if gc:raise SecurityError("Git metadata changed during executor run: "+json.dumps(gc))
        after=snapshot(workspace);ch=changed(lease.get("baseline") or {},after);allowed={x.casefold() for x in (lease.get("allowed_files") or [])};bad=[p for p in ch if p.casefold() not in allowed];links=[p for p in ch if (after.get(p) or {}).get("kind")=="link"]
        if bad:raise SecurityError("out-of-scope changes: "+json.dumps(bad))
        if links:raise SecurityError("symlink/junction changes denied: "+json.dumps(links))
        no_remotes(Path(workspace))
    print(json.dumps({"ok":True,"changed_paths":ch,"scope_ok":True,"isolation_verified":lease.get("isolation_verified"),"paid_consumed":lease.get("paid_consumed") is True}));return 0
def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True);x=sp.add_parser("issue");x.add_argument("--packet",required=True);x.add_argument("--workspace",required=True);x.add_argument("--executor",required=True);x.add_argument("--ttl",type=int,default=1200)
    for n in ("verify","postflight"):
        x=sp.add_parser(n);x.add_argument("--lease",required=True);x.add_argument("--token",required=True);x.add_argument("--packet",required=True);x.add_argument("--workspace",required=True);x.add_argument("--executor",required=True)
    ns=ap.parse_args()
    try:
        if ns.cmd=="issue":return issue(ns.packet,ns.workspace,ns.executor,ns.ttl)
        if ns.cmd=="verify":verify(ns.lease,ns.token,ns.packet,ns.workspace,ns.executor);print(json.dumps({"ok":True}));return 0
        return postflight(ns.lease,ns.token,ns.packet,ns.workspace,ns.executor)
    except Exception as e:print(json.dumps({"ok":False,"error":f"{type(e).__name__}: {e}"}));return 13
if __name__=="__main__":raise SystemExit(main())
