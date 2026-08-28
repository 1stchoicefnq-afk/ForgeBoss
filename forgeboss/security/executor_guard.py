from __future__ import annotations
import argparse,hashlib,json,os,secrets,shutil,stat,subprocess,sys,time
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"executor-security"
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
# Matched as adjacent path segments at ANY depth, not only at the workspace root:
# a nested package or vendored checkout is just as executable as the top-level one.
HIGH_IMPACT_SUFFIXES=(
    ".github/workflows",".github/actions"
)
# Directory names that are execution or credential surfaces wherever they appear.
FORBIDDEN_SEGMENTS={
    ".git",".github",".openhands",".circleci",".vscode",".devcontainer","devcontainer",
    "secrets","appdata",".ssh",".aws",".gnupg",".docker","node_modules"
}
# File names that are credential material wherever they appear. Denied for BOTH
# write scope and context/read scope: a context file is pasted into a model prompt.
SECRET_BASENAMES={
    ".env",".npmrc",".pypirc",".netrc","_netrc",".git-credentials",".htpasswd",
    "credentials","credentials.json","id_rsa","id_dsa","id_ecdsa","id_ed25519",
    "secrets.json","secrets.yml","secrets.yaml","service-account.json"
}
SECRET_SUFFIXES=(".pem",".key",".p12",".pfx",".jks",".keystore",".ppk")
SECRET_PREFIXES=(".env.",)

# Windows silently strips trailing dots/spaces and resolves reserved device names,
# so "pyproject.toml." and "NUL" do not name what they appear to name.
RESERVED_DEVICES={"con","prn","aux","nul","conin$","conout$"}|{
    f"{p}{i}" for p in ("com","lpt") for i in range(1,10)}|{"com0","lpt0"}
ILLEGAL_CHARS=set('<>:"|?*')

# Executors that are permitted to run write-capable without an isolation proof.
PROVEN_ISOLATED={"mini-swe"}          # shell runs in Docker --network none
FIRST_PARTY={"repair-rat"}            # in-repo executor, not a third-party agent
# Everything else -- known or unknown -- is quarantined until isolation is proven.
KNOWN_EXECUTORS=PROVEN_ISOLATED|FIRST_PARTY|{"openhands","opencode","deepagents"}

LEASE_SCHEMA=2
MAX_TTL=86400

def _components(x:str):
    return [c for c in x.split("/") if c]

def norm(p):
    if not isinstance(p,str) or not p.strip():raise SecurityError("empty path")
    x=p.replace("\\","/").strip()
    if (len(x)>=2 and x[1]==":") or x.startswith(("/","//","~")):raise SecurityError("absolute/home path denied")
    for c in x:
        if ord(c)<32 or c=="\x7f":raise SecurityError("control character in path denied")
    pp=PurePosixPath(x)
    if ".." in pp.parts:raise SecurityError("parent traversal denied")
    y=pp.as_posix()
    while y.startswith("./"):y=y[2:]
    if not y:raise SecurityError("empty normalized path")
    for c in _components(y):
        # NTFS alternate data streams ("file.txt:evil") and drive-relative fragments
        # both hide behind a colon; the other characters are illegal on Windows and
        # are wildcard/redirection metacharacters for anything downstream.
        bad=ILLEGAL_CHARS.intersection(c)
        if bad:raise SecurityError("illegal path character "+"".join(sorted(bad))+" denied: "+y)
        if c!=c.rstrip(". "):raise SecurityError("trailing dot/space path denied: "+y)
        if c.split(".")[0].casefold() in RESERVED_DEVICES:raise SecurityError("reserved device name denied: "+y)
    return y

def key(p): return norm(p).casefold()

def _is_secret_name(base:str):
    return (base in SECRET_BASENAMES or base.endswith(SECRET_SUFFIXES)
            or base.startswith(SECRET_PREFIXES))

def secret_path(p):
    """Credential material. Denied for write scope and for context/read scope."""
    parts=key(p).split("/")
    if _is_secret_name(parts[-1]):return True
    return any(seg in ("secrets",".ssh",".aws",".gnupg") for seg in parts[:-1])

def sensitive(p):
    k=key(p)
    if k in FORBIDDEN_EXACT or any(k.startswith(x) for x in FORBIDDEN_PREFIXES):return True
    if secret_path(k):return True
    parts=k.split("/")
    # Supply-chain/CI surfaces are dangerous at every depth, not only at the root:
    # "pkg/.github/workflows/x.yml" and "sub/.git/hooks/pre-commit" are executable too.
    if any(seg in FORBIDDEN_SEGMENTS for seg in parts[:-1]):return True
    if parts[-1] in FORBIDDEN_SEGMENTS or parts[-1] in FORBIDDEN_EXACT:return True
    for hi in HIGH_IMPACT_SUFFIXES:
        h=hi.split("/")
        for i in range(len(parts)-len(h)+1):
            if parts[i:i+len(h)]==h:return True
    return False

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
        while cur!=work and cur!=cur.parent:
            if is_linklike(cur):raise SecurityError("symlink/junction path denied: "+norm(rel))
            cur=cur.parent
        try:
            resolved=p.resolve(strict=False)
            if os.path.commonpath([str(work),str(resolved)])!=str(work):
                raise SecurityError("resolved path escapes workspace: "+norm(rel))
        except ValueError:
            raise SecurityError("resolved path escapes workspace: "+norm(rel))

# .git holds volatile object/ref churn that would swamp the diff, but a handful of
# entries inside it are direct code-execution surfaces and must stay under integrity.
GIT_WATCHED=("config","config.worktree","info/exclude","packed-refs")
def _git_watched(rest:str):
    return rest in GIT_WATCHED or rest.startswith("hooks/")

def _skip_git(rk:str):
    parts=rk.split("/")
    if ".git" not in parts:return False
    i=parts.index(".git")
    return not _git_watched("/".join(parts[i+1:]))

def snapshot(work):
    work=Path(work).resolve();out={}
    for p in work.rglob("*"):
        raw=str(p.relative_to(work)).replace("\\","/")
        try:r=norm(raw)
        except Exception:
            # A path the policy refuses to name is still a path an executor can write.
            # Never drop it from the baseline -- record it under a reserved key so any
            # appearance or change shows up as an out-of-scope change in postflight.
            r="\x00unnameable/"+raw
        rk=r.casefold()
        if _skip_git(rk):continue
        if is_linklike(p):
            try:tgt=os.readlink(p) if p.is_symlink() else "<junction>"
            except OSError:tgt="<unreadable-link>"
            out[r]={"kind":"link","target":tgt}
        elif p.is_file():
            st=p.stat()
            e={"kind":"file","sha256":fhash(p),"size":st.st_size}
            # Flipping the execute bit on an existing file is a privilege change with
            # no content change; without this the diff cannot see it.
            if os.name!="nt":e["mode"]=stat.S_IMODE(st.st_mode)
            out[r]=e
    return out

def changed(a,b):return sorted(k for k in set(a)|set(b) if a.get(k)!=b.get(k))

def canonical_executor(e):
    """Fail closed on executor identity: casing/whitespace must not pick the policy."""
    if not isinstance(e,str) or not e.strip():raise SecurityError("empty executor identity")
    c=e.strip().casefold().replace("_","-")
    if c not in KNOWN_EXECUTORS:raise SecurityError("unknown executor identity denied: "+e)
    return c

def validate_packet(packet):
    allowed=[norm(x) for x in packet.get("allowed_files",[])]
    context=[norm(x) for x in packet.get("context_files",[])]
    if not allowed:raise SecurityError("packet has no allowed_files")
    if len({x.casefold() for x in allowed})!=len(allowed):raise SecurityError("duplicate allowed_files after Windows casefold")
    for p in allowed:
        if sensitive(p):raise SecurityError("sensitive/high-impact write path denied: "+p)
    for p in context:
        k=p.casefold()
        if k==".git" or k.startswith(".git/") or ".git" in k.split("/"):raise SecurityError("Git metadata read denied")
        # Read scope is exfiltration scope: context files are pasted into a prompt.
        if secret_path(k):raise SecurityError("secret material read denied: "+p)
    return allowed,context

def _git_binary():
    # subprocess on Windows resolves a bare program name against the CURRENT DIRECTORY
    # before PATH, and the current directory here is the untrusted workspace. A planted
    # git.exe would execute inside the guard. Always resolve to an absolute path first.
    exe=shutil.which("git.exe") or shutil.which("git")
    if not exe:raise SecurityError("git executable not found on PATH")
    exe=os.path.abspath(exe)
    if not os.path.isfile(exe):raise SecurityError("git executable is not a regular file")
    return exe

# The workspace's own .git/config is attacker-controlled, and git config can name
# helper binaries (fsmonitor, pager, credential helpers) that git would then execute.
GIT_SAFE_ARGS=("-c","core.fsmonitor=false","-c","core.hooksPath=","-c","core.pager=cat",
               "-c","protocol.ext.allow=never","-c","credential.helper=")
GIT_SAFE_ENV={"GIT_CONFIG_NOSYSTEM":"1","GIT_TERMINAL_PROMPT":"0","GIT_ASKPASS":"",
              "GIT_OPTIONAL_LOCKS":"0","GIT_PAGER":"cat","GIT_ATTR_NOSYSTEM":"1"}

def git(work,*args):
    env=dict(os.environ);env.update(GIT_SAFE_ENV)
    env.pop("GIT_DIR",None);env.pop("GIT_WORK_TREE",None);env.pop("GIT_CONFIG_GLOBAL",None)
    p=subprocess.run([_git_binary(),*GIT_SAFE_ARGS,*args],cwd=work,capture_output=True,
                     text=True,timeout=60,env=env,creationflags=CNW)
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
    ex=canonical_executor(executor)
    # mini-SWE executes its shell in Docker --network none. Host-model traffic is separate.
    if ex in PROVEN_ISOLATED:return True
    # OpenHands/OpenCode and anything unproven remain quarantined until an OS/network
    # isolation adapter proves itself.
    return os.environ.get("FORGEBOSS_OS_ISOLATION_VERIFIED")=="YES"

def _state_dir():
    from forgeboss.security.local_acl import harden_private_dir
    if is_linklike(STATE):raise SecurityError("executor-security state dir is a link")
    return harden_private_dir(STATE)

def issue(packet_path,workspace,executor,ttl=1200):
    executor=canonical_executor(executor)
    if not isinstance(ttl,int) or ttl<=0 or ttl>MAX_TTL:raise SecurityError(f"lease ttl out of range: {ttl}")
    pp=Path(packet_path);work=Path(workspace).resolve();packet=json.loads(pp.read_text(encoding="utf-8"))
    allowed,context=validate_packet(packet)
    if executor not in FIRST_PARTY and not isolation_ok(executor):
        raise SecurityError(f"{executor} write-capable execution is quarantined until OS/network isolation is verified")
    assert_no_link_escape(work)
    assert_paths_contained(work,allowed+context)
    exact_head(work,packet);no_remotes(work)
    token=secrets.token_urlsafe(32)
    lease={"schema":LEASE_SCHEMA,"executor":executor,"workspace":str(work),"packet_sha256":phash(pp),
           "allowed_files":allowed,"allowed_keys":[x.casefold() for x in allowed],
           "issued_at":time.time(),"expires_at":time.time()+ttl,
           "token_sha256":hashlib.sha256(token.encode()).hexdigest(),
           "baseline":snapshot(work),"isolation_verified":isolation_ok(executor)}
    sd=_state_dir()
    lp=sd/f"lease-{int(time.time()*1000)}-{secrets.token_hex(4)}.json"
    # O_EXCL so a pre-planted lease path cannot be overwritten or redirected via a link.
    fd=os.open(str(lp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:os.write(fd,json.dumps(lease,indent=2).encode("utf-8"))
    finally:os.close(fd)
    print(json.dumps({"ok":True,"lease":str(lp),"token":token}));return 0

def verify(lease_path,token,packet_path,workspace,executor):
    executor=canonical_executor(executor)
    lease=json.loads(Path(lease_path).read_text(encoding="utf-8"));work=Path(workspace).resolve();pp=Path(packet_path)
    if not isinstance(lease,dict):raise SecurityError("malformed lease")
    if lease.get("schema")!=LEASE_SCHEMA:raise SecurityError(f"unsupported lease schema: {lease.get('schema')!r}")
    try:issued=float(lease.get("issued_at"));expires=float(lease.get("expires_at"))
    except (TypeError,ValueError):raise SecurityError("malformed lease timestamps")
    now=time.time()
    if now>expires:raise SecurityError("executor lease expired")
    if expires-issued>MAX_TTL:raise SecurityError("lease ttl exceeds policy maximum")
    if issued>now+60:raise SecurityError("lease issued in the future")
    if canonical_executor(lease.get("executor") or "")!=executor:raise SecurityError("executor identity mismatch")
    lw=lease.get("workspace")
    if not isinstance(lw,str) or not lw.strip():raise SecurityError("lease has no workspace")
    if Path(lw).resolve()!=work:raise SecurityError("workspace mismatch")
    if lease.get("packet_sha256")!=phash(pp):raise SecurityError("packet changed after lease")
    if not isinstance(lease.get("baseline"),dict):raise SecurityError("lease has no baseline snapshot")
    if not secrets.compare_digest(str(lease.get("token_sha256","")),hashlib.sha256(token.encode()).hexdigest()):raise SecurityError("lease token mismatch")
    packet=json.loads(pp.read_text(encoding="utf-8"));allowed,context=validate_packet(packet)
    if {x.casefold() for x in allowed}!={str(x).casefold() for x in (lease.get("allowed_files") or [])}:
        raise SecurityError("packet scope does not match lease scope")
    assert_no_link_escape(work);assert_paths_contained(work,allowed+context)
    exact_head(work,packet);no_remotes(work)
    if executor not in FIRST_PARTY and not isolation_ok(executor):
        raise SecurityError(f"{executor} isolation proof disappeared after lease")
    return lease

def postflight(lease_path,token,packet_path,workspace,executor):
    lease=verify(lease_path,token,packet_path,workspace,executor)
    work=Path(workspace).resolve()
    baseline=lease.get("baseline") or {}
    after=snapshot(work);ch=changed(baseline,after)
    allowed={str(x).casefold() for x in (lease.get("allowed_files") or [])}
    bad=[p for p in ch if p.casefold() not in allowed]
    links=[p for p in ch if (after.get(p) or {}).get("kind")=="link" or (baseline.get(p) or {}).get("kind")=="link"]
    # Report the link violation first: it is the stronger signal and an allowed_files
    # entry replaced by a link would otherwise never reach the "bad" list.
    if links:raise SecurityError("symlink/junction changes denied: "+json.dumps(links))
    if bad:raise SecurityError("out-of-scope changes: "+json.dumps(bad))
    no_remotes(work)
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
if __name__=="__main__":
    if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
    raise SystemExit(main())
