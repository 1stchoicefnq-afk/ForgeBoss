from __future__ import annotations
import json, os, subprocess, shutil, sys, time, tempfile
from pathlib import Path
CREATE_NO_WINDOW=getattr(subprocess,"CREATE_NO_WINDOW",0)

ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"tournament"; STATE.mkdir(parents=True,exist_ok=True)
CTRL=Path.home()/".siteboss"/"autopilot"/"controller-state"
MIRROR=Path.home()/".siteboss"/"autopilot"/"mirrors"/"siteboss-monster.git"
PY=Path.home()/".forgeboss"/"runtime"/"venv"/"Scripts"/"python.exe"
CASE_ROOT=Path.home()/".siteboss"/"autopilot"/"case-sensitive-repair-workspaces"/"forgeboss-tournament"
CANONICAL_PR_TEMPLATE=".github/pull_request_template.md"
LEGACY_PR_TEMPLATE=".github/PULL_REQUEST_TEMPLATE.md"

def run(argv,cwd=None,env=None,timeout=3600):
    return subprocess.run(argv,cwd=cwd,env=env,capture_output=True,text=True,timeout=timeout)

def parse_result(text):
    for line in reversed(text.splitlines()):
        if line.startswith("FORGEBOSS_RESULT_JSON="):
            return json.loads(line.split("=",1)[1])
    return {}

def issue_executor_lease(packet_path,work,executor,env):
    guard=ROOT/"forgeboss"/"security"/"executor_guard.py"
    p=run([str(PY),str(guard),"issue","--packet",str(packet_path),"--workspace",str(work),"--executor",executor],cwd=ROOT,env=env,timeout=60)
    if p.returncode:raise RuntimeError("ForgeBoss executor policy refused lease: "+(p.stdout+p.stderr))
    j=json.loads(p.stdout.strip().splitlines()[-1]);env["FORGEBOSS_EXECUTOR_LEASE"]=j["lease"];env["FORGEBOSS_EXECUTOR_LEASE_TOKEN"]=j["token"];env["FORGEBOSS_PYTHON"]=str(PY);return env

def git(work,*args):
    r=run(["git.exe",*args],cwd=work,timeout=120)
    if r.returncode: raise RuntimeError((r.stdout+r.stderr).strip())
    return r.stdout.strip()

def status_snapshot(work):
    p=subprocess.run(["git.exe","status","--porcelain=v1","-z","--untracked-files=all"],
        cwd=work,capture_output=True,timeout=120)
    if p.returncode:
        raise RuntimeError((p.stdout+p.stderr).decode("utf-8","replace"))
    raw=p.stdout
    entries={}
    parts=raw.split(b"\0")
    i=0
    while i<len(parts):
        part=parts[i]
        if not part: i+=1;continue
        text=part.decode("utf-8","surrogateescape")
        status=text[:2]
        path=text[3:] if len(text)>=4 else ""
        # Rename/copy porcelain -z stores old and new names as consecutive NUL records.
        if status and (status[0] in "RC" or status[1] in "RC") and i+1<len(parts):
            newp=parts[i+1].decode("utf-8","surrogateescape")
            path=newp
            i+=1
        path=path.replace("\\\\","/")
        entries[path]=status
        i+=1
    return entries

def worker_attributed_paths(before,after):
    out=[]
    for path,status in after.items():
        if before.get(path)!=status:
            out.append(path)
    for path in before:
        if path not in after:
            # Worker cleaned a baseline-dirty file; that is still an attributable change.
            out.append(path)
    return sorted(set(out))

def tree_paths(work,sha):
    out=git(work,"ls-tree","-r","--name-only",sha)
    return [x.strip().replace("\\\\","/") for x in out.splitlines() if x.strip()]

def case_collisions(paths):
    buckets={}
    for p in paths:buckets.setdefault(p.lower(),[]).append(p)
    return [sorted(v) for v in buckets.values() if len(v)>1]

def template_hygiene(work,sha):
    paths=tree_paths(work,sha)
    has_canonical=CANONICAL_PR_TEMPLATE in paths
    has_legacy=LEGACY_PR_TEMPLATE in paths
    info={"canonical":CANONICAL_PR_TEMPLATE,"legacy_duplicate":LEGACY_PR_TEMPLATE,
          "canonical_present":has_canonical,"legacy_present":has_legacy,
          "collision_present":has_canonical and has_legacy,
          "recommended_action":"delete legacy uppercase duplicate; retain canonical lowercase template"}
    if has_canonical and has_legacy:
        a=git(work,"rev-parse",f"{sha}:{CANONICAL_PR_TEMPLATE}")
        b=git(work,"rev-parse",f"{sha}:{LEGACY_PR_TEMPLATE}")
        info["canonical_blob"]=a;info["legacy_blob"]=b;info["contents_identical"]=(a==b)
    return info

def ensure_case_sensitive_root():
    CASE_ROOT.mkdir(parents=True,exist_ok=True)
    # Windows per-directory case sensitivity is required because SiteBoss currently
    # contains a case-colliding PR template pair.
    q=run(["fsutil.exe","file","queryCaseSensitiveInfo",str(CASE_ROOT)],timeout=30)
    if q.returncode==0 and "enabled" in (q.stdout+q.stderr).lower():
        return
    e=run(["fsutil.exe","file","SetCaseSensitiveInfo",str(CASE_ROOT),"enable"],timeout=30)
    if e.returncode:
        raise RuntimeError("Cannot enable case-sensitive ForgeBoss tournament root. Refusing Windows checkout with known case collision.")
    q=run(["fsutil.exe","file","queryCaseSensitiveInfo",str(CASE_ROOT)],timeout=30)
    if q.returncode or "enabled" not in (q.stdout+q.stderr).lower():
        raise RuntimeError("Case-sensitive tournament root verification failed.")


def make_workspace(name,sha):
    ensure_case_sensitive_root()
    root=CASE_ROOT/f"{int(time.time())}-{name}"
    root.parent.mkdir(parents=True,exist_ok=True)
    # Create destination first so it inherits/retains the case-sensitive flag.
    root.mkdir()
    q=run(["fsutil.exe","file","queryCaseSensitiveInfo",str(root)],timeout=30)
    if q.returncode or "enabled" not in (q.stdout+q.stderr).lower():
        e=run(["fsutil.exe","file","SetCaseSensitiveInfo",str(root),"enable"],timeout=30)
        if e.returncode: raise RuntimeError("Tournament workspace is not case-sensitive.")
    r=run(["git.exe","clone","--no-checkout",str(MIRROR),str(root)],timeout=300)
    if r.returncode: raise RuntimeError("clone failed: "+(r.stdout+r.stderr))
    git(root,"config","core.autocrlf","false")
    git(root,"config","core.ignorecase","false")
    git(root,"checkout","--detach",sha)
    got=git(root,"rev-parse","HEAD")
    if got!=sha: raise RuntimeError(f"exact head mismatch {got} != {sha}")
    for remote in git(root,"remote").splitlines():
        if remote.strip():git(root,"remote","remove",remote.strip())
    baseline=status_snapshot(root)
    if baseline:
        raise RuntimeError("Tournament exact-head baseline is dirty before worker: "+json.dumps(baseline,sort_keys=True))
    return root,baseline


def validate(work,out):
    p=run(["powershell.exe","-NoProfile","-ExecutionPolicy","Bypass","-File",str(ROOT/"forgeboss"/"tournament"/"validate.ps1"),"-Repo",str(work),"-Out",str(out)],timeout=1800)
    try:j=json.loads(out.read_text(encoding="utf-8-sig"))
    except Exception:j={"passed":False,"failure_count":999,"runs":[]}
    return p.returncode,j,p.stdout+p.stderr

def main():
    if len(sys.argv)<2: print("usage: run_paid.py MAX_TOTAL_USD");return 2
    cap=max(.25,min(float(sys.argv[1]),3.0))
    if os.environ.get("FORGEBOSS_ALLOW_TOURNAMENT")!="YES":
        print("Tournament gate not enabled");return 3
    if not PY.exists(): raise RuntimeError("ForgeBoss Python runtime missing")
    if not MIRROR.exists(): raise RuntimeError("SiteBoss local mirror missing")

    # One authoritative read/plan. Both challengers receive this exact packet and exact HEAD.
    p=run(["node",str(ROOT/"controller"/"siteboss-autopilot.js"),"run"],cwd=ROOT,timeout=180)
    print(p.stdout);print(p.stderr,file=sys.stderr)
    if p.returncode:return p.returncode
    packet_path=CTRL/"packet-latest.json"
    packet=json.loads(packet_path.read_text(encoding="utf-8"))
    sha=packet["expected_head_revision"]
    allowed=set(x.replace("\\","/") for x in packet.get("allowed_files",[]))
    # Canonical GitHub default template is lowercase. Keep repository hygiene separate
    # from unrelated coding repairs; never whitelist either template into worker scope.
    hygiene_work, hygiene_baseline = make_workspace("hygiene-inspect",sha)
    hygiene=template_hygiene(hygiene_work,sha)
    shutil.rmtree(hygiene_work,ignore_errors=True)
    allowed.discard(CANONICAL_PR_TEMPLATE)
    allowed.discard(LEGACY_PR_TEMPLATE)


    # Keep first experiment cheap. Same Luna model, same frozen packet, half budget each.
    each=round(cap/2,4)
    challengers=[
      ("mini-swe",ROOT/"forgeboss"/"executors"/"mini_swe_runner.py","FORGEBOSS_MINISWE_MODEL"),
      ("openhands",ROOT/"forgeboss"/"executors"/"openhands_runner.py","FORGEBOSS_OPENHANDS_MODEL"),
    ]
    results=[]
    for name,script,model_env in challengers:
        work,baseline=make_workspace(name,sha)
        env=os.environ.copy()
        env["FORGEBOSS_ALLOW_PAID_EXECUTOR"]="YES"
        env[model_env]="openai/gpt-5.6-luna"
        # Strip GitHub publication credentials from worker host process.
        for k in ["GH_TOKEN","GITHUB_TOKEN","GITHUB_PAT"]:env.pop(k,None)
        env=issue_executor_lease(packet_path,work,name,env)
        # Both SDKs accept OpenAI via environment/provider key. Do not print it.
        start=time.time()
        proc=run([str(PY),str(script),str(packet_path),str(work),str(each)],cwd=ROOT,env=env,timeout=1800)
        elapsed=time.time()-start
        combined=(proc.stdout or "")+"\n"+(proc.stderr or "")
        meta=parse_result(combined)
        after=status_snapshot(work)
        changes=worker_attributed_paths(baseline,after)
        scope_ok=all(p in allowed for p in changes) and len(changes)>0
        val_path=STATE/f"{name}-validation-last.json"
        if scope_ok:
            vcode,v,vtxt=validate(work,val_path)
        else:
            vcode=2;v={"passed":False,"failure_count":999,"runs":[]};vtxt="scope violation or no changes"
        result={
          "executor":name,"model":"gpt-5.6-luna","assigned_budget_usd":each,
          "reported_cost_usd":round(float(meta.get("cost_usd") or 0),4),
          "elapsed_seconds":round(elapsed,1),"worker_exit_code":proc.returncode,
          "changed_paths":changes,"scope_ok":scope_ok,"acceptance_passed":bool(v.get("passed")),
          "acceptance_failure_count":v.get("failure_count"),"workspace":str(work),
          "worker_error":meta.get("error"),"validation_output_tail":vtxt[-4000:]
        }
        results.append(result)
        print(json.dumps(result,indent=2))

    successful=[r for r in results if r["scope_ok"] and r["acceptance_passed"]]
    winner=None
    if successful:
        successful.sort(key=lambda r:(r["reported_cost_usd"],r["elapsed_seconds"]))
        winner=successful[0]["executor"]

    out={
      "schema":1,"kind":"paid-same-task-tournament","exact_head":sha,"packet_id":packet.get("packet_id"),
      "max_total_usd":cap,"challengers":["mini-swe","openhands"],"same_model":"gpt-5.6-luna",
      "same_packet":True,"same_head":True,"same_validation":True,"repository_hygiene":hygiene,
      "results":results,"winner":winner,
      "promotion_status":"PROVISIONAL_ONLY" if winner else "NO_WINNER",
      "promotion_rule":"A winner is not made live default until it repeats a verified win on another frozen task or passes a full ForgeBoss review gate.",
      "github_writes":0,"merge":False,"deploy":False
    }
    (STATE/"paid-tournament-last.json").write_text(json.dumps(out,indent=2),encoding="utf-8")
    print("FORGEBOSS_TOURNAMENT_RESULT="+json.dumps(out,separators=(",",":")))
    return 0 if winner else 2

if __name__=="__main__":raise SystemExit(main())
