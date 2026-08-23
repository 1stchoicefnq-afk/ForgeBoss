from __future__ import annotations
import argparse,hashlib,json,os,secrets,subprocess,time
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"executor-security";STATE.mkdir(parents=True,exist_ok=True)
CNW=getattr(subprocess,"CREATE_NO_WINDOW",0)
class SecurityError(RuntimeError):pass

# Windows is case-insensitive by default; all policy matching is casefolded.
FORBIDDEN_PREFIXES=(
    ".git/",".github/workflows/",".github/actions/","secrets/","appdata/",".openhands/",
    ".circleci/","ci/credentials/","build/credentials/",
    ".vscode/","devcontainer/",".devcontainer/",
    "state/forgebossd/","state/learning/"
)
FORBIDDEN_EXACT={
    ".git",".env",".env.local",".env.production",".npmrc",".pypirc",
    "package.json","dockerfile","docker-compose.yml","docker-compose.yaml",
    "compose.yml","compose.yaml",".pre-commit-config.yaml",".gitlab-ci.yml",
    "jenkinsfile","azure-pipelines.yml","bitbucket-pipelines.yml",
    "requirements.txt","requirements-dev.txt","requirements-test.txt",
    "pyproject.toml","setup.py","setup.cfg","tox.ini","makefile","gnumakefile",
    "pipfile","pipfile.lock","poetry.lock","cargo.toml","cargo.lock",
    "go.mod","go.sum"
}
# These are execution/supply-chain surfaces. Third-party writers cannot touch them.
HIGH_IMPACT_SUFFIXES=(
    ".github/workflows",".github/actions"
)
GIT_META_EXACT=(
    "config","config.worktree","HEAD","packed-refs","shallow",
    "info/attributes","info/exclude","objects/info/alternates"
)
GIT_META_TREES=("refs","hooks")

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

def key(p): return norm(p).casefold()

def sensitive(p):
    k=key(p)
    return k in FORBIDDEN_EXACT or any(k.startswith(x) for x in FORBIDDEN_PREFIXES)

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
        if is_linklike(p):
            raise SecurityError("baseline symlink/junction denied: "+str(p.relative_to(work)).replace("\\","/"))

def assert_paths_contained(work:Path,paths):
    work=work.resolve()
    for rel in paths:
        p=work/norm(rel)
        # Existing path and every existing ancestor must stay inside the workspace.
        cur=p
        while cur!=work and cur.exists():
            if is_linklike(cur):raise SecurityError("symlink/junction path denied: "+norm(rel))
            cur=cur.parent
        try:
            resolved=p.resolve(strict=False)
            if os.path.commonpath([str(work),str(resolved)])!=str(work):
                raise SecurityError("resolved path escapes workspace: "+norm(rel))
        except ValueError:
            raise SecurityError("resolved path escapes workspace: "+norm(rel))

def _metadata_entry(p:Path):
    if is_linklike(p):
        return {"kind":"link","target":os.readlink(p) if p.is_symlink() else "<junction>"}
    if p.is_file():return {"kind":"file","sha256":fhash(p),"size":p.stat().st_size}
    return None

def git_metadata_snapshot(work):
    work=Path(work).resolve();dotgit=work/".git";out={}
    if not dotgit.exists():return out
    if dotgit.is_file() or is_linklike(dotgit):
        entry=_metadata_entry(dotgit)
        if entry is not None:out[".git"]=entry
        return out
    for rel in GIT_META_EXACT:
        p=dotgit/rel
        if p.exists() or is_linklike(p):
            entry=_metadata_entry(p)
            if entry is not None:out[".git/"+rel]=entry
    for root in GIT_META_TREES:
        base=dotgit/root
        if not base.exists():continue
        for p in base.rglob("*"):
            if p.is_dir() and not is_linklike(p):continue
            entry=_metadata_entry(p)
            if entry is not None:
                rel=str(p.relative_to(work)).replace("\\","/")
                out[rel]=entry
    # Compare the semantic index rather than raw .git/index bytes so harmless
    # stat-cache refreshes from read-only Git commands do not create false positives.
    out[".git/index:stage"]={"kind":"semantic","sha256":hashlib.sha256(git(work,"ls-files","--stage","-z").encode()).hexdigest()}
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
    allowed=[norm(x) for x in packet.get("allowed_files",[])]
    context=[norm(x) for x in packet.get("context_files",[])]
    if not allowed:raise SecurityError("packet has no allowed_files")
    if len({x.casefold() for x in allowed})!=len(allowed):raise SecurityError("duplicate allowed_files after Windows casefold")
    for p in allowed:
        if sensitive(p):raise SecurityError("sensitive/high-impact write path denied: "+p)
    for p in context:
        k=p.casefold()
        if k==".git" or k.startswith(".git/"):raise SecurityError("Git metadata read denied")
    return allowed,context

def git(work,*args):
    p=subprocess.run(["git.exe",*args],cwd=work,capture_output=True,text=True,timeout=60,creationflags=CNW)
    if p.returncode:raise SecurityError((p.stdout+p.stderr).strip() or "git failed")
    return p.stdout.strip()

def exact_head(work,packet):
    exp=packet.get("expected_head_revision") or packet.get("exact_head")
    if exp and (Path(work)/".git").exists():
        got=git(work,"rev-parse","HEAD")
        if got!=exp:raise SecurityError(f"exact HEAD mismatch {got} != {exp}")

def no_remotes(work):
    if (Path(work)/".git").exists() and git(work,"remote").strip():raise SecurityError("Git remotes present in executor workspace")

def isolation_ok(executor):
    # mini-SWE executes its shell in Docker --network none. Host-model traffic is separate.
    if executor=="mini-swe":return True
    # OpenHands/OpenCode remain quarantined until an OS/network isolation adapter proves itself.
    return os.environ.get("FORGEBOSS_OS_ISOLATION_VERIFIED")=="YES"

def issue(packet_path,workspace,executor,ttl=1200):
    pp=Path(packet_path);work=Path(workspace).resolve();packet=json.loads(pp.read_text(encoding="utf-8"))
    allowed,context=validate_packet(packet)
    if executor in ("openhands","opencode") and not isolation_ok(executor):
        raise SecurityError(f"{executor} write-capable execution is quarantined until OS/network isolation is verified")
    assert_no_link_escape(work)
    assert_paths_contained(work,allowed+context)
    exact_head(work,packet);no_remotes(work)
    token=secrets.token_urlsafe(32)
    lease={"schema":2,"executor":executor,"workspace":str(work),"packet_sha256":phash(pp),
           "allowed_files":allowed,"allowed_keys":[x.casefold() for x in allowed],
           "issued_at":time.time(),"expires_at":time.time()+ttl,
           "token_sha256":hashlib.sha256(token.encode()).hexdigest(),
           "baseline":snapshot(work),"git_metadata":git_metadata_snapshot(work),
           "isolation_verified":isolation_ok(executor)}
    lp=STATE/f"lease-{int(time.time()*1000)}-{secrets.token_hex(4)}.json"
    lp.write_text(json.dumps(lease,indent=2),encoding="utf-8")
    print(json.dumps({"ok":True,"lease":str(lp),"token":token}));return 0

def verify(lease_path,token,packet_path,workspace,executor):
    lease=json.loads(Path(lease_path).read_text(encoding="utf-8"));work=Path(workspace).resolve();pp=Path(packet_path)
    if time.time()>float(lease.get("expires_at",0)):raise SecurityError("executor lease expired")
    if lease.get("executor")!=executor:raise SecurityError("executor identity mismatch")
    if Path(lease.get("workspace","")).resolve()!=work:raise SecurityError("workspace mismatch")
    if lease.get("packet_sha256")!=phash(pp):raise SecurityError("packet changed after lease")
    if not secrets.compare_digest(lease.get("token_sha256",""),hashlib.sha256(token.encode()).hexdigest()):raise SecurityError("lease token mismatch")
    packet=json.loads(pp.read_text(encoding="utf-8"));allowed,context=validate_packet(packet)
    assert_no_link_escape(work);assert_paths_contained(work,allowed+context)
    exact_head(work,packet);no_remotes(work)
    if executor in ("openhands","opencode") and not isolation_ok(executor):
        raise SecurityError(f"{executor} isolation proof disappeared after lease")
    return lease

def postflight(lease_path,token,packet_path,workspace,executor):
    lease=verify(lease_path,token,packet_path,workspace,executor)
    git_before=lease.get("git_metadata")
    if not isinstance(git_before,dict):raise SecurityError("executor lease missing Git metadata baseline")
    git_after=git_metadata_snapshot(workspace);git_ch=changed(git_before,git_after)
    if git_ch:raise SecurityError("Git metadata changed during executor run: "+json.dumps(git_ch))
    after=snapshot(workspace);ch=changed(lease.get("baseline") or {},after)
    allowed={x.casefold() for x in (lease.get("allowed_files") or [])}
    bad=[p for p in ch if p.casefold() not in allowed]
    links=[p for p in ch if (after.get(p) or {}).get("kind")=="link"]
    if bad:raise SecurityError("out-of-scope changes: "+json.dumps(bad))
    if links:raise SecurityError("symlink/junction changes denied: "+json.dumps(links))
    no_remotes(Path(workspace))
    print(json.dumps({"ok":True,"changed_paths":ch,"scope_ok":True,"isolation_verified":lease.get("isolation_verified")}));return 0

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    x=sp.add_parser("issue");x.add_argument("--packet",required=True);x.add_argument("--workspace",required=True);x.add_argument("--executor",required=True);x.add_argument("--ttl",type=int,default=1200)
    for n in ("verify","postflight"):
        x=sp.add_parser(n);x.add_argument("--lease",required=True);x.add_argument("--token",required=True);x.add_argument("--packet",required=True);x.add_argument("--workspace",required=True);x.add_argument("--executor",required=True)
    ns=ap.parse_args()
    try:
        if ns.cmd=="issue":return issue(ns.packet,ns.workspace,ns.executor,ns.ttl)
        if ns.cmd=="verify":verify(ns.lease,ns.token,ns.packet,ns.workspace,ns.executor);print(json.dumps({"ok":True}));return 0
        return postflight(ns.lease,ns.token,ns.packet,ns.workspace,ns.executor)
    except Exception as e:
        print(json.dumps({"ok":False,"error":f"{type(e).__name__}: {e}"}));return 13
if __name__=="__main__":raise SystemExit(main())
