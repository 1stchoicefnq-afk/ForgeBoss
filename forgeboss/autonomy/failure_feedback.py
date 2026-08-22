from __future__ import annotations
import argparse, hashlib, json, re, subprocess, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"autonomy";STATE.mkdir(parents=True,exist_ok=True)
CTRL=Path.home()/".siteboss"/"autopilot"/"controller-state"

def load(p):
    try:return json.loads(Path(p).read_text(encoding="utf-8-sig"))
    except Exception:return {}

def git_head(work):
    try:
        p=subprocess.run(["git.exe","rev-parse","HEAD"],cwd=work,capture_output=True,text=True,timeout=30,
                         creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        return p.stdout.strip() if p.returncode==0 else ""
    except Exception:return ""

def strings(x,out):
    if isinstance(x,dict):
        for k,v in x.items():
            if k in ("source_files","contents","raw_source"):continue
            strings(v,out)
    elif isinstance(x,list):
        for v in x:strings(v,out)
    elif isinstance(x,str):
        if len(x)>8:out.append(x)

def category(text):
    t=text.lower()
    if any(x in t for x in ("22p05","postgres","sqlstate","unicode escape","platformstore","serializable","deadlock","database")):
        return "database"
    if any(x in t for x in ("auth","permission","oidc","membership","invitation")):
        return "auth"
    if any(x in t for x in ("http 500","500 !== 200","api","fastify","production_http")):
        return "backend"
    if any(x in t for x in ("frontend","html","css","browser","ui")):
        return "frontend"
    if any(x in t for x in ("ci","build","npm","docker")):
        return "ci"
    return "backend"

def failed_steps(obj):
    found=[]
    def walk(x):
        if isinstance(x,dict):
            name=x.get("name")
            code=x.get("exit_code")
            passed=x.get("passed")
            if name and (code not in (None,0) or passed is False):
                found.append(str(name))
            for v in x.values():walk(v)
        elif isinstance(x,list):
            for v in x:walk(v)
    walk(obj)
    return sorted(set(found))[:20]

def discover_workspace_head(repo):
    try:
        import subprocess
        p=subprocess.run(["git.exe","rev-parse","HEAD"],cwd=str(repo),capture_output=True,text=True,timeout=30)
        if p.returncode==0:return p.stdout.strip()
    except Exception:pass
    return None

def retained_authoritative_base(obj):
    p=obj.get("retained_patch_path")
    if p:
        try:
            meta=load(Path(p))
            if meta.get("authoritative_base_sha"):return str(meta["authoritative_base_sha"])
            if meta.get("exact_head"):return str(meta["exact_head"])
        except Exception:pass
    return obj.get("exact_head")

def target_sha(obj):
    for key in ("exact_head","target_sha","expected_head_revision","head_sha"):
        if obj.get(key):return str(obj[key])
    packet=load(CTRL/"packet-latest.json")
    if packet.get("expected_head_revision"):return str(packet["expected_head_revision"])
    for row in obj.get("results",[]) if isinstance(obj,dict) else []:
        w=row.get("workspace")
        if w:
            sha=git_head(Path(w))
            if sha:return sha
    return ""

def latest_attempt_view(obj):
    if isinstance(obj,dict) and isinstance(obj.get("attempts"),list) and obj["attempts"]:
        # For a Repair Rat report the newest validation result is authoritative.
        # Do not re-introduce defect signatures from an earlier attempt that a later
        # attempt already removed.
        slim=dict(obj)
        slim["attempts"]=[obj["attempts"][-1]]
        return slim
    return obj

def make(source:Path,kind:str):
    obj=load(source)
    if not obj:raise RuntimeError(f"Cannot read failure evidence: {source}")
    obj=latest_attempt_view(obj)
    ss=[];strings(obj,ss)
    text="\n".join(ss)
    cat=category(text)
    failed=failed_steps(obj)
    sha=target_sha(obj)
    # Bound feedback size: enough for exact errors/stacks without resending huge reports.
    relevant=[]
    patterns=("22P05","unsupported Unicode escape","500 !== 200","500 !== 201","HTTP_INTERNAL_ERROR","production_http",
              "travis_intake","full_postgres_suite","platformStore","postgresApplication","withSerializableRetry",
              "40001","40P01","could not serialize","finishIdempotency","getLead","saveIntakeSession","commit-window",
              "safe refusal","blocked","failure","error")
    for x in ss:
        if any(p.lower() in x.lower() for p in patterns):
            relevant.append(x[-1800:])
    if not relevant:
        relevant=[x[-1200:] for x in ss[-12:]]
    relevant=relevant[-30:]
    signature=hashlib.sha256((cat+"\n"+"\n".join(failed)+"\n"+"\n".join(relevant)).encode("utf-8","replace")).hexdigest()
    out={
      "schema":1,
      "kind":"forgeboss-autonomy-feedback",
      "generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
      "source_kind":kind,
      "source_report":str(source),
      "target_sha":sha,
      "source_repo":obj.get("local_workspace"),
      "authoritative_base_sha":retained_authoritative_base(obj),
      "retained_local_commit":obj.get("local_commit") if obj.get("partial_proven") else None,
      "workspace_head":discover_workspace_head(obj.get("local_workspace")) if obj.get("local_workspace") else None,
      "retained_patch_path":obj.get("retained_patch_path"),
      "partial_proven":bool(obj.get("partial_proven")),
      "parent_repair_pr":obj.get("root_pr") or 525,
      "passed":False,
      "category":cat,
      "signature":signature,
      "acceptance":{
        "passed":False,
        "failed_steps":failed,
        "failure_count":len(failed),
        "evidence":relevant
      },
      "instruction":"Use as fresh evidence when target_sha matches current target OR when partial_proven is true, authoritative_base_sha matches, and ForgeBoss has replayed the retained foundation. Diagnose the root cause; do not blindly repeat the previous patch.",
      "model_calls":0,
      "github_writes":0
    }
    p=STATE/"failure-feedback-last.json"
    p.write_text(json.dumps(out,indent=2),encoding="utf-8")
    print("FORGEBOSS_FAILURE_FEEDBACK="+json.dumps(out,separators=(",",":")))
    return 0

def latest_repair():
    d=ROOT/"state"/"repair-rat"
    xs=sorted(d.glob("repair-rat-*.json"),key=lambda p:p.stat().st_mtime,reverse=True) if d.exists() else []
    return xs[0] if xs else None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source")
    ap.add_argument("--bootstrap-retest",action="store_true")
    ns=ap.parse_args()
    if ns.bootstrap_retest:
        p=ROOT/"state"/"tournament"/"retest-last.json"
        if not p.exists():return 4
        return make(p,"retest")
    p=Path(ns.source) if ns.source else latest_repair()
    if not p:return 5
    return make(p,"repair-rat")
if __name__=="__main__":raise SystemExit(main())
