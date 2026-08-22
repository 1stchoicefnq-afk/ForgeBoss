from __future__ import annotations
import argparse,json,re,subprocess,hashlib,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
STATE=ROOT/"state"/"autonomy";STATE.mkdir(parents=True,exist_ok=True)
CTRL=Path.home()/".siteboss"/"autopilot"/"controller-state"
CNW=getattr(subprocess,"CREATE_NO_WINDOW",0)

def load(p):
    try:return json.loads(Path(p).read_text(encoding="utf-8-sig"))
    except:return {}

def run(args,cwd=None,timeout=60):
    return subprocess.run(args,cwd=cwd,capture_output=True,text=True,timeout=timeout,creationflags=CNW)

def latest_attempt(report):
    xs=report.get("attempts") or []
    return xs[-1] if xs else {}

def terms(text):
    # Useful engineering identifiers only; no freeform chain-of-thought.
    out=[]
    for x in re.findall(r'\b[A-Za-z_][A-Za-z0-9_./-]{4,}\b',text or ""):
        low=x.lower()
        if low in {"would","could","should","because","therefore","repair","model","safe","insufficient","evidence","currently","failing"}:continue
        if x not in out:out.append(x)
    return out[:20]

def resolve_repo(report):
    w=report.get("local_workspace")
    return Path(w) if w and Path(w).exists() else None

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--report",required=True);ap.add_argument("--funnel");ns=ap.parse_args()
    report=load(ns.report);attempt=latest_attempt(report);funnel=load(ns.funnel) if ns.funnel else {}
    summary=str(attempt.get("model_summary") or "")
    reasoning=str(attempt.get("reasoning_summary") or "")
    query_terms=terms(summary+"\n"+reasoning)
    repo=resolve_repo(report)
    findings=[]
    if repo:
        priority=["receiveAnswer","saveIntakeSession","22P05","NUL","production_http","conversation"]
        qs=[]
        for q in priority+query_terms:
            if q and q not in qs:qs.append(q)
        for q in qs[:12]:
            p=run(["git.exe","grep","-n","-I","--",q],repo,30)
            if p.returncode in (0,1) and p.stdout.strip():
                lines=p.stdout.splitlines()[:20]
                excerpts=[]
                for line in lines[:8]:
                    try:
                        path,lineno,_=line.split(":",2); n=int(lineno)
                        body=Path(repo,path).read_text(encoding="utf-8",errors="replace").splitlines()
                        lo=max(0,n-8);hi=min(len(body),n+7)
                        excerpts.append({"path":path,"line":n,"context":"\n".join(f"{i+1}: {body[i]}" for i in range(lo,hi))})
                    except Exception:pass
                findings.append({"query":q,"matches":lines,"excerpts":excerpts})
    focused=[]
    for x in (funnel.get("focused_files") or []):
        focused.append({"path":x.get("path"),"sha256":hashlib.sha256(str(x.get("content","")).encode()).hexdigest(),
                        "excerpt":str(x.get("content",""))[:5000]})
    obj={
      "schema":1,"kind":"repair-rat-evidence-enrichment",
      "generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
            "exact_head":report.get("exact_head"),
      "workspace_available":bool(repo),
      "workspace_path":str(repo) if repo else None,
      "execution_note":"ForgeBoss owns this disposable local workspace and will apply/test any returned patch. The model does not need shell access.",
      "safe_refusal_summary":summary,
      "safe_refusal_reasoning_summary":reasoning,
      "requested_terms":query_terms,
      "local_grep_findings":findings,
      "focused_files":focused,
      "new_evidence_count":sum(len(x["matches"]) for x in findings),
      "model_calls":0
    }
    raw=json.dumps(obj,indent=2)
    obj["sha256"]=hashlib.sha256(raw.encode()).hexdigest()
    p=STATE/"evidence-enrichment-last.json";p.write_text(json.dumps(obj,indent=2),encoding="utf-8")
    print(json.dumps({"ok":True,"path":str(p),"new_evidence_count":obj["new_evidence_count"],"terms":query_terms[:8]}))
    return 0
if __name__=="__main__":raise SystemExit(main())
