"""ForgeBoss category league: runs executor candidates against controlled
benchmarks and designates a per-category winner.

Correctness invariants this module is responsible for:
 * Agent-reported cost is untrusted input. NaN/Inf/negative/non-numeric values
   never reach the budget accumulator and never influence winner selection.
 * An unreported or unusable cost is charged at the full per-candidate
   allocation, so silence can never buy unlimited paid execution.
 * Every candidate appears in ``results`` -- including skipped, denied,
   timed-out and errored ones. Missing rows are not silently dropped.
 * One candidate crashing never aborts the tournament, and state is persisted
   after every row so a crash mid-round leaves an attributable partial record.
 * Persisted output is always strict JSON (no NaN/Infinity literals) and is
   written atomically under an exclusive lock.
 * Winner selection is a total order with a name tiebreak: identical inputs
   always designate the same executor.
"""
import json,math,os,shutil,subprocess,sys,time,uuid
from pathlib import Path
CREATE_NO_WINDOW=getattr(subprocess,"CREATE_NO_WINDOW",0)
try:from .fixtures import make,digest,FixtureError
except ImportError:from fixtures import make,digest,FixtureError

ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
STATE=ROOT/"state"/"league"
PY=Path.home()/".forgeboss"/"runtime"/"venv"/"Scripts"/"python.exe"
RESULT_PREFIX="FORGEBOSS_RESULT_JSON="
MIN_TARGET,MAX_TARGET=.5,2.
ALLOC_DIVISOR=20;BUDGET_RESERVE=.9
WORKER_TIMEOUT=700;LEASE_TIMEOUT=60;TEST_TIMEOUT=60;GIT_TIMEOUT=60
LOCK_STALE_SECONDS=4*3600
SECRETISH=("KEY","TOKEN","SECRET","PASSWORD","PASSWD","CREDENTIAL")
RUNNERS={"mini-swe":("python","mini_swe_runner.py"),"openhands":("python","openhands_runner.py"),"opencode":("node","opencode_runner.js")}

class LeagueError(RuntimeError):pass
class LeaseError(LeagueError):pass

def run(a,cwd=None,env=None,t=WORKER_TIMEOUT):
 return subprocess.run(a,cwd=None if cwd is None else str(cwd),env=env,capture_output=True,text=True,timeout=t,creationflags=CREATE_NO_WINDOW)

# ---------------------------------------------------------------- pure helpers

def parse_target(argv):
 """Clamp the requested target budget. Rejects NaN/Inf and junk explicitly."""
 raw=argv[1] if len(argv)>1 else "1"
 try:v=float(raw)
 except (TypeError,ValueError):raise LeagueError(f"LEAGUE_BAD_TARGET_BUDGET:{raw!r}")
 if not math.isfinite(v):raise LeagueError(f"LEAGUE_BAD_TARGET_BUDGET:{raw!r}")
 return max(MIN_TARGET,min(v,MAX_TARGET))

def coerce_cost(value):
 """Validate an agent-reported cost.

 Returns ``(cost,reason)``: a finite non-negative float and ``"ok"``, or
 ``(None,reason)``. Never weakens to 0.0 -- callers must charge the fallback
 allocation instead, otherwise unreported cost would be free budget.
 """
 if value is None:return None,"missing"
 if isinstance(value,bool):return None,"non_numeric"
 if isinstance(value,(int,float)):n=float(value)
 elif isinstance(value,str):
  s=value.strip()
  if not s:return None,"missing"
  try:n=float(s)
  except ValueError:return None,"non_numeric"
 else:return None,"non_numeric"
 if not math.isfinite(n):return None,"non_finite"
 if n<0:return None,"negative"
 return n,"ok"

def charge_for(cost,alloc):
 """Budget charge for one candidate: reported cost, or the full allocation."""
 if cost is None or not math.isfinite(cost) or cost<0:return max(float(alloc),0.)
 return cost

def meta(text):
 """Last well-formed ``FORGEBOSS_RESULT_JSON=`` object in agent output.

 Non-object payloads (lists, scalars) are ignored rather than crashing the
 tournament on ``.get``.
 """
 for line in reversed((text or "").splitlines()):
  if not line.startswith(RESULT_PREFIX):continue
  try:obj=json.loads(line.split("=",1)[1])
  except (ValueError,TypeError):continue
  if isinstance(obj,dict):return obj
 return {}

def parse_lease(text):
 """Extract (lease,token) from executor_guard stdout, or raise LeaseError."""
 lines=[l for l in (text or "").splitlines() if l.strip()]
 if not lines:raise LeaseError("lease output was empty")
 try:obj=json.loads(lines[-1])
 except ValueError:raise LeaseError("lease output was not JSON")
 if not isinstance(obj,dict):raise LeaseError("lease payload was not an object")
 lease,token=obj.get("lease"),obj.get("token")
 if not isinstance(lease,str) or not lease.strip():raise LeaseError("lease payload missing 'lease'")
 if not isinstance(token,str) or not token.strip():raise LeaseError("lease payload missing 'token'")
 return lease,token

def dedupe(candidates):
 """Order-preserving dedupe. Returns (unique,dropped)."""
 seen=set();out=[];dropped=[]
 for x in candidates:
  if not isinstance(x,str) or not x.strip():dropped.append(repr(x));continue
  k=x.strip()
  if k in seen:dropped.append(k);continue
  seen.add(k);out.append(k)
 return out,dropped

def load_categories(path):
 """Read categories.json with schema validation; category order is sorted so
 the tournament does not depend on file formatting."""
 try:doc=json.loads(Path(path).read_text(encoding="utf-8"))
 except (OSError,ValueError) as e:raise LeagueError(f"LEAGUE_BAD_CATEGORIES:{e}")
 if not isinstance(doc,dict):raise LeagueError("LEAGUE_BAD_CATEGORIES:root is not an object")
 cats=doc.get("categories")
 if not isinstance(cats,dict) or not cats:raise LeagueError("LEAGUE_BAD_CATEGORIES:missing categories map")
 out={}
 for k in sorted(cats):
  v=cats[k]
  if not isinstance(v,list):raise LeagueError(f"LEAGUE_BAD_CATEGORIES:{k} is not a list")
  out[str(k)]=v
 return out

def sanitize(obj):
 """Make a value strict-JSON safe: non-finite floats become None."""
 if obj is None or isinstance(obj,(bool,str)):return obj
 if isinstance(obj,dict):return {str(k):sanitize(v) for k,v in obj.items()}
 if isinstance(obj,(list,tuple,set)):return [sanitize(v) for v in obj]
 if isinstance(obj,(int,float)):return obj if math.isfinite(obj) else None
 return str(obj)

def dumps(obj,**kw):
 """Strict JSON. allow_nan=False can no longer raise because we sanitize."""
 return json.dumps(sanitize(obj),allow_nan=False,**kw)

def select_winner(rows):
 """Deterministic designation among passing rows.

 Ranked by charged cost, then elapsed time, then executor name. All keys are
 forced finite so a poisoned float can never scramble the ordering, and the
 name tiebreak makes ties reproducible.
 """
 good=[r for r in rows if isinstance(r,dict) and r.get("passed") is True]
 if not good:return None
 def num(v):
  return float(v) if isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v) else None
 def key(r):
  c=num(r.get("budget_charged_usd"));e=num(r.get("elapsed_seconds"))
  return (c is None,c if c is not None else 0.,e is None,e if e is not None else 0.,str(r.get("executor","")),int(r.get("candidate_index",0) or 0))
 return sorted(good,key=key)[0]

def scrub_env(env):
 """Environment for the acceptance test: no provider credentials leak into a
 candidate-influenced process."""
 return {k:v for k,v in env.items() if not any(s in k.upper() for s in SECRETISH)}

# --------------------------------------------------------------- persistence

def write_json_atomic(path,obj):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 tmp=path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
 try:
  tmp.write_text(dumps(obj,indent=2),encoding="utf-8");os.replace(str(tmp),str(path))
 finally:
  try:tmp.unlink()
  except OSError:pass

def acquire_lock(path,stale=LOCK_STALE_SECONDS):
 """Exclusive league lock. Two concurrent leagues would interleave writes into
 league-last.json and cross-attribute spend."""
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 payload=dumps({"pid":os.getpid(),"started":time.time()}).encode("utf-8")
 for _ in range(2):
  try:
   fd=os.open(str(path),os.O_CREAT|os.O_EXCL|os.O_WRONLY)
   try:os.write(fd,payload)
   finally:os.close(fd)
   return True
  except FileExistsError:
   try:age=time.time()-path.stat().st_mtime
   except OSError:return False
   if age<stale:return False
   try:path.unlink()
   except OSError:return False
 return False

def release_lock(path):
 try:Path(path).unlink()
 except OSError:pass

# ------------------------------------------------------------ workspace state

def _git_paths(workspace,args,timeout=GIT_TIMEOUT):
 q=run(["git",*args],workspace,t=timeout)
 if q.returncode!=0:raise LeagueError(f"git_failed:{' '.join(args[:2])}:rc={q.returncode}")
 return [r for r in (q.stdout or "").split("\0") if r]

def changed_paths(workspace,base):
 """Every path the candidate touched, relative to the fixture base commit.

 ``git diff <base>`` covers tracked edits whether or not the candidate
 committed them -- committing work used to read as "no changes" and silently
 scored a correct fix as a failure. ``git status`` adds untracked files.
 ``-z`` is used so paths are never quoted or octal-escaped.
 """
 out=set(_git_paths(workspace,["diff","--name-only","--no-renames","-z",base,"--"]))
 recs=_git_paths(workspace,["status","--porcelain=v1","-z","--untracked-files=all"])
 i=0
 while i<len(recs):
  r=recs[i];i+=1
  if len(r)<4:raise LeagueError("git_failed:status:unparsable_record")
  status,path=r[:2],r[3:]
  if status[0] in ("R","C") and i<len(recs):
   src=recs[i];i+=1
   if src:out.add(src)
  if path:out.add(path)
 return sorted(out)

def check_scope(paths,allowed):
 return bool(paths) and all(p in allowed for p in paths)

# ------------------------------------------------------------------ execution

def _executor_env(base,lease,token):
 e=dict(base);e["FORGEBOSS_EXECUTOR_LEASE"]=lease;e["FORGEBOSS_EXECUTOR_LEASE_TOKEN"]=token;e["FORGEBOSS_PYTHON"]=str(PY);return e

def run_candidate(cat,ex,alloc,env,seq):
 """Execute one candidate. Returns a partial row dict. Raises only for
 conditions the caller records as an error row."""
 out={}
 if ex not in RUNNERS:return {"status":"skipped","skipped":f"unknown executor {ex!r}"}
 ws=Path.home()/".forgeboss"/"league-workspaces"/f"{int(time.time()*1000)}-{seq:03d}-{uuid.uuid4().hex[:8]}-{cat}-{ex}"
 fx=make(ws,cat);allowed=fx["allowed_files"];out["workspace"]=str(ws)
 guard=ROOT/"forgeboss"/"security"/"executor_guard.py"
 q=run([str(PY),str(guard),"issue","--packet",str(ws/"packet.json"),"--workspace",str(ws),"--executor",ex],ROOT,env,t=LEASE_TIMEOUT)
 if q.returncode:return {**out,"status":"skipped","skipped":"ForgeBoss policy lease denied","lease_exit_code":q.returncode}
 lease,token=parse_lease(q.stdout)
 runenv=_executor_env(env,lease,token)
 kind,script=RUNNERS[ex];path=ROOT/"forgeboss"/"executors"/script
 cmd=[str(PY),str(path),str(ws/"packet.json"),str(ws),str(alloc)] if kind=="python" else ["node",str(path),str(ws/"packet.json"),str(ws)]
 p=run(cmd,ROOT,runenv,t=WORKER_TIMEOUT)
 out["worker_exit_code"]=p.returncode
 m=meta((p.stdout or "")+"\n"+(p.stderr or ""))
 raw=m.get("cost_usd");cost,reason=coerce_cost(raw)
 out["reported_cost_usd"]=cost;out["cost_status"]=reason
 if reason!="ok":out["reported_cost_raw"]=repr(raw)[:120]
 out["budget_charged_usd"]=round(charge_for(cost,alloc),6)
 try:paths=changed_paths(ws,fx["base_commit"])
 except LeagueError as e:
  return {**out,"status":"scored","passed":False,"scope_ok":False,"changed_paths":[],"scope_error":str(e)}
 out["changed_paths"]=paths
 scope=check_scope(paths,allowed)
 # The acceptance oracle must be byte-identical: a rewritten test.js is a void
 # run, not a pass. Restore the pristine copy before scoring regardless.
 try:tampered=digest(ws/"test.js")!=fx["test_sha256"]
 except OSError:tampered=True
 if tampered:scope=False;out["test_tampered"]=True
 out["scope_ok"]=scope
 if not scope:return {**out,"status":"scored","passed":False}
 shutil.copy2(fx["pristine_test"],ws/"test.js")
 t=run(["node","test.js"],ws,scrub_env(env),t=TEST_TIMEOUT)
 out["test_exit_code"]=t.returncode
 return {**out,"status":"scored","passed":t.returncode==0}

# ----------------------------------------------------------------------- main

def _blank_row(run_id,cat,ex,idx):
 return {"run_id":run_id,"category":cat,"executor":ex,"candidate_index":idx,"status":"pending","passed":False,"scope_ok":False,"changed_paths":[],"reported_cost_usd":None,"cost_status":"missing","budget_charged_usd":0.,"elapsed_seconds":None,"worker_exit_code":None}

def _snapshot(run_id,target,started,spent,charged,res,wins,details,notes,complete):
 return {"schema":1,"kind":"category-league","run_id":run_id,"complete":complete,"started_at":round(started,3),"updated_at":round(time.time(),3),"target_budget_usd":target,"reported_measured_spend_usd":round(spent,4),"budget_charged_usd":round(charged,4),"results":res,"winners":wins,"winner_details":details,"notes":notes,"designation_status":"BENCHMARK_DESIGNATIONS","cost_note":"$1 is a target experiment budget, not an absolute billing guarantee: mini-SWE has a hard framework limit; OpenHands can only be rejected after an SDK call; OpenCode is quarantined by default until an OS-isolated adapter exists. reported_measured_spend_usd sums only self-reported costs that validated; budget_charged_usd is the conservative figure enforced against the cap.","github_writes":0,"merge":False,"deploy":False}

def _run(target,run_id):
 started=time.time();cats=load_categories(HERE/"categories.json")
 clean={};notes={"duplicate_candidates_ignored":{}}
 total=0
 for cat,raw in cats.items():
  uniq,dropped=dedupe(raw);clean[cat]=uniq;total+=len(uniq)
  if dropped:notes["duplicate_candidates_ignored"][cat]=dropped
 # Per-candidate allocation never exceeds the historical target/20 and shrinks
 # if the field grows, so the field size cannot outrun the target budget.
 alloc=round(target/max(ALLOC_DIVISOR,total or 1),4)
 notes["per_candidate_allocation_usd"]=alloc;notes["candidate_count"]=total
 spent=0.;charged=0.;res=[];wins={};details={}
 env=os.environ.copy();env["FORGEBOSS_ALLOW_PAID_EXECUTOR"]="YES"
 env["FORGEBOSS_MINISWE_MODEL"]=env["FORGEBOSS_OPENHANDS_MODEL"]=env["FORGEBOSS_OPENCODE_MODEL"]="openai/gpt-5.6-luna"
 for k in ["GH_TOKEN","GITHUB_TOKEN","GITHUB_PAT"]:env.pop(k,None)
 last=STATE/"league-last.json";archive=STATE/"runs"/f"league-{run_id}.json"
 def persist(complete):
  snap=_snapshot(run_id,target,started,spent,charged,res,wins,details,notes,complete)
  write_json_atomic(last,snap);write_json_atomic(archive,snap);return snap
 persist(False)
 seq=0
 for cat in clean:
  rows=[]
  for idx,ex in enumerate(clean[cat]):
   seq+=1;row=_blank_row(run_id,cat,ex,idx);st=time.time()
   if charged>=target*BUDGET_RESERVE:
    row.update(status="skipped",skipped="budget reserve")
   else:
    try:row.update(run_candidate(cat,ex,alloc,env,seq))
    except subprocess.TimeoutExpired as e:
     # A hung candidate used to abort the whole league and discard every row.
     row.update(status="timeout",timed_out=True,error=f"timeout after {e.timeout}s",budget_charged_usd=round(alloc,6))
    # Lease/fixture failures happen strictly before any paid call, so they are
    # not charged. Anything else is charged the allocation: under-charging a
    # spend control is worse than stopping the league early.
    except LeaseError as e:row.update(status="skipped",skipped=f"lease unusable: {e}")
    except FixtureError as e:row.update(status="error",error=f"fixture: {e}")
    except Exception as e:row.update(status="error",error=f"{type(e).__name__}: {e}",budget_charged_usd=round(alloc,6))
   row["elapsed_seconds"]=round(time.time()-st,1)
   c,_=coerce_cost(row.get("reported_cost_usd"))
   if c is not None:spent+=c
   rc=row.get("budget_charged_usd");charged+=rc if isinstance(rc,(int,float)) and not isinstance(rc,bool) and math.isfinite(rc) and rc>0 else 0.
   rows.append(row);res.append(row)
   print(dumps(row),flush=True)
   persist(False)
  win=select_winner(rows)
  # winners[cat] stays a plain executor name for the dashboard; winner_details
  # carries the identity needed to attribute a designation to a specific run.
  wins[cat]=win["executor"] if win else None
  details[cat]={"executor":win["executor"],"run_id":win.get("run_id"),"candidate_index":win.get("candidate_index"),"reported_cost_usd":win.get("reported_cost_usd"),"budget_charged_usd":win.get("budget_charged_usd"),"elapsed_seconds":win.get("elapsed_seconds"),"workspace":win.get("workspace")} if win else {"reason":"no passing candidate","candidates_run":len(rows)}
  persist(False)
 out=persist(True)
 print("FORGEBOSS_LEAGUE_RESULT="+dumps(out,separators=(",",":")))
 return 0

def main(argv=None):
 argv=list(sys.argv if argv is None else argv)
 try:target=parse_target(argv)
 except LeagueError as e:print(f"FORGEBOSS_LEAGUE_ERROR={e}",file=sys.stderr);return 2
 STATE.mkdir(parents=True,exist_ok=True);lock=STATE/"league.lock"
 if not acquire_lock(lock):
  print("FORGEBOSS_LEAGUE_ERROR=LEAGUE_ALREADY_RUNNING",file=sys.stderr);return 3
 run_id=uuid.uuid4().hex
 try:return _run(target,run_id)
 except LeagueError as e:print(f"FORGEBOSS_LEAGUE_ERROR={e}",file=sys.stderr);return 4
 finally:release_lock(lock)

if __name__=="__main__":raise SystemExit(main())
