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
def record(report_path,feedback_path=None):
 r=load(report_path);f=load(feedback_path) if feedback_path else {};db=load(DB) or {"schema":1,"entries":[]};head=r.get("exact_head");repo=r.get("local_workspace")
 for a in r.get("attempts",[]) or []:
  changed=a.get("changed_paths") or []
  if not changed:continue
  passed=bool(a.get("acceptance_passed"));partial=bool(a.get("focused_resolved"));patch=None
  if (passed or partial) and repo and head:
   p=run(["git.exe","diff","--no-ext-diff","--binary",head,"--",*changed],repo);patch=p.stdout if p.returncode==0 and p.stdout.strip() else None
  before={x:blob(repo,head,x) for x in changed} if repo and head else {}
  key=hashlib.sha256((str(f.get("signature"))+json.dumps(before,sort_keys=True)+str(patch)).encode()).hexdigest()
  e={"key":key,"category":f.get("category","unknown"),"failure_signature":f.get("signature"),"outcome":"proven" if passed else ("partial_proven" if partial else "failed"),"changed_paths":changed,"before_sha256":before,"patch":patch if passed else None,"specialists":r.get("builder_specialists") or [],"failure_fingerprint":a.get("failure_fingerprint"),"model_summary":a.get("model_summary"),"reasoning_summary":a.get("reasoning_summary"),"tests":[{"name":x.get("name"),"exit_code":x.get("exit_code")} for x in (a.get("runs") or [])],"last_seen":time.time()}
  old=next((x for x in db["entries"] if x.get("key")==key),None)
  if old:old["seen_count"]=int(old.get("seen_count",1))+1;old["last_seen"]=time.time()
  else:e["seen_count"]=1;db["entries"].append(e)
 db["entries"]=db["entries"][-1000:];save(db)
def find(funnel,repo):
 f=load(funnel);db=load(DB) or {"entries":[]};head=f.get("target_sha");sig=f.get("failure_signature");cat=f.get("category");hits=[]
 for e in db.get("entries",[]):
  if e.get("outcome") not in ("proven","partial_proven") or not e.get("patch"):continue
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
