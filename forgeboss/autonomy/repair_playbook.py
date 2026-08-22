from __future__ import annotations
import argparse,hashlib,json,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];STATE=ROOT/"state"/"autonomy";STATE.mkdir(parents=True,exist_ok=True);DB=STATE/"repair-playbook.json";CNW=getattr(subprocess,"CREATE_NO_WINDOW",0)
def load(p):
 try:return json.loads(Path(p).read_text(encoding="utf-8-sig"))
 except:return {}
def save(x):
 p=DB.with_suffix(".tmp");p.write_text(json.dumps(x,indent=2),encoding="utf-8");p.replace(DB)
def run(a,cwd=None,inp=None):return subprocess.run(a,cwd=cwd,input=inp,capture_output=True,text=True,timeout=90,creationflags=CNW)
def blob(repo,head,path):
 p=run(["git.exe","show",f"{head}:{path}"],repo);return hashlib.sha256(p.stdout.encode("utf-8","replace")).hexdigest() if p.returncode==0 else None
def patch_sha256(patch):return hashlib.sha256(patch.encode("utf-8","replace")).hexdigest()
def binding_sha256(base,commit,changed,patch_hash):
 payload={"base":str(base),"commit":str(commit),"changed_paths":sorted(str(x).replace("\\","/") for x in changed),"patch_sha256":str(patch_hash)}
 return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def accepted_patch(repo,base,commit,changed):
 if not repo or not base or not commit or not changed:return None
 anc=run(["git.exe","merge-base","--is-ancestor",str(base),str(commit)],repo)
 if anc.returncode!=0:return None
 names=run(["git.exe","diff","--name-only",str(base),str(commit),"--"],repo)
 if names.returncode!=0:return None
 actual=sorted(x.replace("\\","/") for x in names.stdout.splitlines() if x.strip())
 expected=sorted(str(x).replace("\\","/") for x in changed)
 if actual!=expected:return None
 p=run(["git.exe","diff","--no-ext-diff","--binary",str(base),str(commit),"--",*changed],repo)
 if p.returncode!=0 or not p.stdout.strip():return None
 ph=patch_sha256(p.stdout)
 return {"patch":p.stdout,"patch_sha256":ph,"binding_sha256":binding_sha256(base,commit,changed,ph)}
def binding_valid(e):
 patch=e.get("patch");ph=e.get("patch_sha256");base=e.get("accepted_base_sha");commit=e.get("accepted_commit");binding=e.get("binding_sha256");changed=e.get("changed_paths") or []
 if not patch or not ph or not base or not commit or not binding or not changed:return False
 if patch_sha256(patch)!=ph:return False
 return binding_sha256(base,commit,changed,ph)==binding
def record(report_path,feedback_path=None):
 r=load(report_path);f=load(feedback_path) if feedback_path else {};db=load(DB) or {"schema":1,"entries":[]};head=r.get("exact_head");repo=r.get("local_workspace");accepted_commit=r.get("local_commit")
 for a in r.get("attempts",[]) or []:
  changed=a.get("changed_paths") or []
  if not changed:continue
  passed=bool(a.get("acceptance_passed"));partial=bool(a.get("focused_resolved"));bound=accepted_patch(repo,head,accepted_commit,changed) if passed else None
  before={x:blob(repo,head,x) for x in changed} if repo and head else {}
  outcome="proven" if passed and bound else ("unbound" if passed else ("partial_proven" if partial else "failed"))
  patch=bound["patch"] if bound else None;ph=bound["patch_sha256"] if bound else None;binding=bound["binding_sha256"] if bound else None
  key=hashlib.sha256((str(f.get("signature"))+json.dumps(before,sort_keys=True)+str(accepted_commit)+str(binding)).encode()).hexdigest()
  e={"key":key,"category":f.get("category","unknown"),"failure_signature":f.get("signature"),"outcome":outcome,"changed_paths":changed,"before_sha256":before,"patch":patch if outcome=="proven" else None,"patch_sha256":ph if outcome=="proven" else None,"binding_sha256":binding if outcome=="proven" else None,"accepted_base_sha":head if outcome=="proven" else None,"accepted_commit":accepted_commit if outcome=="proven" else None,"specialists":r.get("builder_specialists") or [],"failure_fingerprint":a.get("failure_fingerprint"),"model_summary":a.get("model_summary"),"reasoning_summary":a.get("reasoning_summary"),"tests":[{"name":x.get("name"),"exit_code":x.get("exit_code")} for x in (a.get("runs") or [])],"last_seen":time.time()}
  old=next((x for x in db["entries"] if x.get("key")==key),None)
  if old:old["seen_count"]=int(old.get("seen_count",1))+1;old["last_seen"]=time.time()
  else:e["seen_count"]=1;db["entries"].append(e)
 db["entries"]=db["entries"][-1000:];save(db)
def find(funnel,repo):
 f=load(funnel);db=load(DB) or {"entries":[]};head=f.get("target_sha");sig=f.get("failure_signature");cat=f.get("category");hits=[]
 for e in db.get("entries",[]):
  if e.get("outcome")!="proven" or not binding_valid(e):continue
  if e.get("failure_signature")!=sig and e.get("category")!=cat:continue
  if all(expected and blob(repo,head,p)==expected for p,expected in (e.get("before_sha256") or {}).items()):hits.append(e)
 hits.sort(key=lambda e:(e.get("failure_signature")==sig,int(e.get("seen_count",1))),reverse=True);return hits[0] if hits else None
def apply(funnel,repo):
 hit=find(funnel,repo)
 if not hit:print(json.dumps({"ok":False,"hit":False}));return 4
 p=run(["git.exe","apply","--check","--whitespace=nowarn","-"],repo,hit["patch"])
 if p.returncode:print(json.dumps({"ok":False,"hit":True,"reason":"patch check failed"}));return 5
 p=run(["git.exe","apply","--whitespace=nowarn","-"],repo,hit["patch"])
 if p.returncode:return 6
 print(json.dumps({"ok":True,"hit":True,"key":hit["key"],"outcome":hit.get("outcome"),"changed_paths":hit["changed_paths"]}));return 0
def main():
 ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True);r=sp.add_parser("record");r.add_argument("--report",required=True);r.add_argument("--feedback");a=sp.add_parser("apply");a.add_argument("--funnel",required=True);a.add_argument("--repo",required=True);q=sp.add_parser("query");q.add_argument("--funnel",required=True);q.add_argument("--repo",required=True);ns=ap.parse_args()
 if ns.cmd=="record":record(ns.report,ns.feedback);return 0
 if ns.cmd=="query":print(json.dumps(find(ns.funnel,Path(ns.repo)) or {"hit":False}));return 0
 return apply(ns.funnel,Path(ns.repo))
if __name__=="__main__":raise SystemExit(main())
