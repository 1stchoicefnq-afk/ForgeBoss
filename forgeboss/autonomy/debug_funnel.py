from __future__ import annotations
import argparse, json, re, subprocess, hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"autonomy";STATE.mkdir(parents=True,exist_ok=True)
CTRL=Path.home()/".siteboss"/"autopilot"/"controller-state"
CREATE_NO_WINDOW=getattr(subprocess,"CREATE_NO_WINDOW",0)

def load(p):
    try:return json.loads(Path(p).read_text(encoding="utf-8-sig"))
    except:return {}

def run(args,cwd=None,timeout=90):
    return subprocess.run(args,cwd=cwd,capture_output=True,text=True,timeout=timeout,creationflags=CREATE_NO_WINDOW)

def collect_strings(x,out):
    if isinstance(x,dict):
        for k,v in x.items():
            if k in ("source_files","contents","code_diff"):continue
            collect_strings(v,out)
    elif isinstance(x,list):
        for v in x:collect_strings(v,out)
    elif isinstance(x,str) and len(x)>5:out.append(x)

def classify(text):
    t=text.lower()
    if any(x in t for x in ("22p05","postgres","sqlstate","platformstore","unicode escape","serializable")):return "database"
    if any(x in t for x in ("production_http","http 500","500 !== 200","fastify","api")):return "backend"
    if any(x in t for x in ("auth","oidc","permission","membership","invitation")):return "auth"
    if any(x in t for x in ("frontend","css","browser","react","html")):return "frontend"
    if any(x in t for x in ("docker","ci","npm","build")):return "ci"
    return "backend"

def candidates(text,packet):
    # deterministic path ranking; no model spend
    paths=[]
    for p in packet.get("context_files",[])+packet.get("allowed_files",[]):
        if p not in paths:paths.append(p)
    tokens=set(re.findall(r'[A-Za-z][A-Za-z0-9_]{4,}',text))
    hints={
      "production_http":["tests/postgresProductionHttp.integration.test.js","src/application/production.js","src/http/fastifyServer.js","src/persistence/platformStore.js","src/persistence/postgres.js","src/travis/conversation.js"],
      "22P05":["src/travis/conversation.js","src/persistence/platformStore.js","src/persistence/postgres.js","src/intake/postgresApplication.js","tests/postgresTravisIntake.integration.test.js"],
      "receiveAnswer":["src/travis/conversation.js","src/intake/postgresApplication.js","src/persistence/platformStore.js"],
      "saveIntakeSession":["src/persistence/platformStore.js","src/intake/postgresApplication.js"],
      "NUL":["src/travis/conversation.js","src/persistence/platformStore.js"],
      "platformStore":["src/persistence/platformStore.js"],
      "invitation":["src/auth/businessInvitations.js","tests/postgresBusinessInvitations.integration.test.js"],
      "40001":["src/persistence/postgres.js","src/intake/postgresApplication.js","src/persistence/platformStore.js","src/persistence/postgresCrmStore.js"],
      "withSerializableRetry":["src/persistence/postgres.js","src/intake/postgresApplication.js","src/auth/businessInvitations.js"],
      "finishIdempotency":["src/persistence/platformStore.js","src/intake/postgresApplication.js","src/persistence/postgres.js"],
      "getLead":["src/persistence/postgresCrmStore.js","src/intake/postgresApplication.js","src/persistence/postgres.js"],
      "saveIntakeSession":["src/persistence/platformStore.js","src/intake/postgresApplication.js","src/persistence/postgres.js"],
    }
    scored={}
    for p in paths:
        score=0
        low=p.lower()
        for token in tokens:
            if token.lower() in low:score+=3
        for key,vals in hints.items():
            if key.lower() in text.lower() and p in vals:score+=20
        if p.startswith("src/"):score+=2
        if p.startswith("tests/"):score+=1
        scored[p]=score
    ordered=sorted(paths,key=lambda p:(-scored.get(p,0),p))
    return ordered[:4]

def git_show(repo,sha,path):
    if not repo or not Path(repo).exists() or not sha:return ""
    p=run(["git.exe","show",f"{sha}:{path}"],cwd=repo,timeout=30)
    return p.stdout if p.returncode==0 else ""

def resolve_repo(feedback,sha):
    src=load(feedback.get("source_report",""))
    choices=[]
    if feedback.get("source_repo"):choices.append(Path(feedback["source_repo"]))
    for x in (src.get("local_workspace"),src.get("workspace"),feedback.get("repo")):
        if x:choices.append(Path(x))
    seen=set()
    for c in choices:
        try:
            c=c.resolve()
            if c in seen or not c.exists():continue
            seen.add(c)
            p=subprocess.run(["git.exe","merge-base","--is-ancestor",sha,"HEAD"],cwd=str(c),capture_output=True,text=True,timeout=30,creationflags=CREATE_NO_WINDOW)
            if p.returncode==0:return c
            p2=subprocess.run(["git.exe","rev-parse","HEAD"],cwd=str(c),capture_output=True,text=True,timeout=30,creationflags=CREATE_NO_WINDOW)
            if p2.returncode==0 and p2.stdout.strip()==sha:return c
        except Exception:
            continue
    return None

def infer_primary_family(lines):
    text="\n".join(lines or [])
    low=text.lower()
    if low.count("40001")>=2 or "could not serialize access due to read/write dependencies among transactions" in low:
        return "postgresql-40001-serialization"
    if "22p05" in low:return "postgresql-22p05-jsonb"
    return None

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--feedback",required=True);ns=ap.parse_args()
    f=load(ns.feedback)
    packet=load(CTRL/"packet-latest.json")
    ss=[];collect_strings(f,ss);text="\n".join(ss)
    cat=classify(text)
    paths=candidates(text,packet)
    sha=f.get("target_sha") or packet.get("expected_head_revision") or ""
    repo=resolve_repo(f,sha)
    # Add files that actually contain identifiers named in the current failure.
    # This catches relevant code even when dependency-expanded packet ranking missed it.
    if repo:
        identifiers=[]
        for token in ("receiveAnswer","saveIntakeSession","production_http","22P05","NUL","conversation","withSerializableRetry","withTransaction","finishIdempotency","getLead","40001"):
            if token.lower() in text.lower():identifiers.append(token)
        discovered=[]
        for token in identifiers[:6]:
            g=run(["git.exe","grep","-l","-I","--",token,sha],cwd=repo,timeout=20)
            if g.returncode in (0,1):
                for path in g.stdout.splitlines():
                    path=path.strip().replace("\\\\","/")
                    if path and path not in discovered:discovered.append(path)
        paths=(discovered+paths)
        paths=list(dict.fromkeys(paths))[:4]
    snippets=[]
    total=0
    for p in paths:
        body=git_show(repo,sha,p)
        if not body:continue
        # hard local context budget: max ~12k chars/file, 42k total
        body=body[:8000]
        if total+len(body)>24000:body=body[:max(0,24000-total)]
        if body:
            snippets.append({"path":p,"content":body})
            total+=len(body)
        if total>=24000:break
    ev=(f.get("acceptance") or {}).get("evidence") or []
    failed=(f.get("acceptance") or {}).get("failed_steps") or []
    primary=next((x for x in failed if not str(x).startswith("full_postgres_suite_")), failed[0] if failed else None)
    obj={
      "schema":1,"kind":"forgeboss-debug-funnel","target_sha":sha,"category":cat,
      "failure_signature":f.get("signature"),"failed_steps":failed,"primary_failed_step":primary,
      "evidence":[str(x)[-1800:] for x in ev[-12:]],
      "focused_files":snippets,
      "focused_file_count":len(snippets),
      "source_repo":str(repo) if repo else None,
      "authoritative_base_sha":f.get("authoritative_base_sha"),
      "retained_local_commit":f.get("retained_local_commit"),
      "workspace_head":f.get("workspace_head"),
      "retained_patch_path":f.get("retained_patch_path"),
      "partial_foundation":bool(f.get("partial_proven")),
      "evidence_provenance":("retained-foundation-validation" if f.get("partial_proven") else "exact-target-validation"),
      "evidence_is_current_for_retained_foundation":bool(f.get("partial_proven")),
      "focused_source_chars":sum(len(x["content"]) for x in snippets),
      "packet_policy":{"max_files":4,"max_source_chars":24000,"max_chars_per_file":8000},
      "instruction":"Single-failure focused repair. Fix the best-supported PRIMARY root cause now; do not refuse merely because a separate secondary failure is not yet diagnosed. ForgeBoss will validate the whole suite after the patch.",
      "model_calls":0
    }
    raw=json.dumps(obj,indent=2)
    obj["sha256"]=hashlib.sha256(raw.encode()).hexdigest()
    p=STATE/"debug-funnel-last.json";p.write_text(json.dumps(obj,indent=2),encoding="utf-8")
    print("FORGEBOSS_DEBUG_FUNNEL="+json.dumps({"category":cat,"files":len(snippets),"chars":obj["focused_source_chars"],"path":str(p)}))
    return 0
if __name__=="__main__":raise SystemExit(main())
