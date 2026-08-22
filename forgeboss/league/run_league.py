import json,os,subprocess,sys,time
from pathlib import Path
CREATE_NO_WINDOW=getattr(subprocess,"CREATE_NO_WINDOW",0)
from fixtures import make
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent;STATE=ROOT/"state"/"league";STATE.mkdir(parents=True,exist_ok=True);PY=Path.home()/".forgeboss"/"runtime"/"venv"/"Scripts"/"python.exe"
def run(a,cwd=None,env=None,t=700):return subprocess.run(a,cwd=cwd,env=env,capture_output=True,text=True,timeout=t,creationflags=CREATE_NO_WINDOW)
def meta(x):
 for l in reversed(x.splitlines()):
  if l.startswith("FORGEBOSS_RESULT_JSON="):
   try:return json.loads(l.split("=",1)[1])
   except:pass
 return {}
def changes(w):return sorted(set(l[3:].strip().replace("\\\\","/") for l in run(["git","status","--porcelain=v1"],w).stdout.splitlines() if l.strip()))
def main():
 target=max(.5,min(float(sys.argv[1] if len(sys.argv)>1 else 1),2));cats=json.loads((HERE/"categories.json").read_text())["categories"];alloc=round(target/20,4);spent=0.;res=[];wins={};env=os.environ.copy();env["FORGEBOSS_ALLOW_PAID_EXECUTOR"]="YES";env["FORGEBOSS_MINISWE_MODEL"]=env["FORGEBOSS_OPENHANDS_MODEL"]=env["FORGEBOSS_OPENCODE_MODEL"]="openai/gpt-5.6-luna"
 for k in ["GH_TOKEN","GITHUB_TOKEN","GITHUB_PAT"]:env.pop(k,None)
 for cat,candidates in cats.items():
  rows=[]
  for ex in candidates:
   if spent>=target*.9:rows.append({"executor":ex,"skipped":"budget reserve"});continue
   w=Path.home()/".forgeboss"/"league-workspaces"/f"{int(time.time()*1000)}-{cat}-{ex}";packet=make(w,cat);st=time.time()
   guard=ROOT/"forgeboss"/"security"/"executor_guard.py";q=run([str(PY),str(guard),"issue","--packet",str(w/"packet.json"),"--workspace",str(w),"--executor",ex],ROOT,env,t=60)
   if q.returncode:rows.append({"executor":ex,"skipped":"ForgeBoss policy lease denied"});continue
   lj=json.loads(q.stdout.strip().splitlines()[-1]);runenv=dict(env);runenv["FORGEBOSS_EXECUTOR_LEASE"]=lj["lease"];runenv["FORGEBOSS_EXECUTOR_LEASE_TOKEN"]=lj["token"];runenv["FORGEBOSS_PYTHON"]=str(PY)
   if ex in ("mini-swe","openhands"):
    script=ROOT/"forgeboss"/"executors"/("mini_swe_runner.py" if ex=="mini-swe" else "openhands_runner.py");p=run([str(PY),str(script),str(w/"packet.json"),str(w),str(alloc)],ROOT,runenv);m=meta(p.stdout+"\n"+p.stderr);cost=m.get("cost_usd")
   else:
    script=ROOT/"forgeboss"/"executors"/"opencode_runner.js";p=run(["node",str(script),str(w/"packet.json"),str(w)],ROOT,runenv);m=meta(p.stdout+"\n"+p.stderr);cost=m.get("cost_usd")
   if cost is not None:spent+=float(cost or 0)
   ch=changes(w);scope=bool(ch) and all(x in packet["allowed_files"] for x in ch);t=run(["node","test.js"],w,t=60) if scope else None;passed=bool(scope and t and t.returncode==0);row={"category":cat,"executor":ex,"passed":passed,"scope_ok":scope,"changed_paths":ch,"reported_cost_usd":cost,"elapsed_seconds":round(time.time()-st,1),"worker_exit_code":p.returncode};rows.append(row);res.append(row);print(json.dumps(row),flush=True)
  good=[x for x in rows if x.get("passed")];good.sort(key=lambda x:(x.get("reported_cost_usd") is None,x.get("reported_cost_usd") if x.get("reported_cost_usd") is not None else 999,x.get("elapsed_seconds",9999)));wins[cat]=good[0]["executor"] if good else None
 out={"schema":1,"kind":"category-league","target_budget_usd":target,"reported_measured_spend_usd":round(spent,4),"results":res,"winners":wins,"designation_status":"BENCHMARK_DESIGNATIONS","cost_note":"$1 is a target experiment budget, not an absolute billing guarantee: mini-SWE has a hard framework limit; OpenHands can only be rejected after an SDK call; OpenCode is quarantined by default until an OS-isolated adapter exists.","github_writes":0,"merge":False,"deploy":False};(STATE/"league-last.json").write_text(json.dumps(out,indent=2));print("FORGEBOSS_LEAGUE_RESULT="+json.dumps(out,separators=(",",":")));return 0
if __name__=="__main__":raise SystemExit(main())
