from __future__ import annotations
import json, os, re, math, subprocess, sys, threading, time, webbrowser, shutil, secrets

# Windows-safe logging/output: avoid locale charmap crashes on Unicode text.
def _force_utf8_stdio():
    import sys
    for stream_name in ("stdout","stderr"):
        stream=getattr(sys,stream_name,None)
        if stream is not None and hasattr(stream,"reconfigure"):
            try: stream.reconfigure(encoding="utf-8",errors="replace")
            except Exception: pass
_force_utf8_stdio()

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
from datetime import datetime, timezone, timedelta
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DASH = Path(__file__).resolve().parent
STATE = ROOT / "state" / "dashboard"
STATE.mkdir(parents=True, exist_ok=True)
STATUS = STATE / "status.json"
LOG = STATE / "dashboard.log"
SESSION = STATE / "session.json"
MAX_SESSION_BUDGET_USD=10.0
LOCAL_HOSTS={"127.0.0.1:8765","localhost:8765"}
LOCAL_ORIGINS={"http://127.0.0.1:8765","http://localhost:8765"}
RPC_TOKEN=secrets.token_urlsafe(32)
_engine_cache_lock=threading.Lock()
_engine_cache_value=None
_engine_cache_at=0.0

lock = threading.RLock()
stop_requested = threading.Event()
worker_thread = None

def now():
    return datetime.now(timezone.utc).isoformat()

def write_json(path: Path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    tmp.replace(path)

def log(msg):
    line = f"{datetime.now().strftime('%H:%M:%S')}  {msg}"
    with lock:
        with LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line, flush=True)

def default_status():
    return {
        "schema":1,"app":"ForgeBoss","product":"SiteBoss","version":"0.2-dashboard",
        "running":False,"stage":"IDLE","message":"Ready","started_at":None,"ends_at":None,"finished_at":None,"duration_mode":"timed",
        "duration_minutes":120,"budget_usd":3.0,"spent_usd":0.0,"workers":1,
        "mode":"cost-optimized","current_cycle":0,"draft_prs":[],"stop_requested":False,
        "last_exit_code":None,"executor":"repair-rat",
        "executor_policy":"AUTO candidates are benchmarked; proven Repair Rat stays default until a candidate wins.",
        "engines":{}
    }

def load_status():
    if STATUS.exists():
        try: return json.loads(STATUS.read_text(encoding="utf-8"))
        except Exception: pass
    s=default_status(); write_json(STATUS,s); return s

def normalize_fatal_failure(report):
    fatal=(report or {}).get("fatal_failure") or {}
    reason=str(fatal.get("reason") or "")
    if not reason:
        return None
    reason=re.sub(r"expected=[0-9a-fA-F]+ actual=[0-9a-fA-F]+ line=\d+","",reason)
    reason=re.sub(r"L\d+#[0-9a-fA-F]{8}","L#HASH",reason)
    return reason.strip()

def ops_phrase(stage,message="",target=None):
    stage=str(stage or "").upper()
    msg=str(message or "")
    t=(target or "").strip()
    if stage in ("SAFETY_GATES","PLANNING"):
        return ("SCANNING TARGET", msg or "ForgeBoss is narrowing the next bounded problem.")
    if stage in ("LIVE_WORKLOAD","BUILDING"):
        return ("TARGET ACQUIRED", (f"ForgeBoss locked onto: {t}" if t else msg or "ForgeBoss locked onto the current defect."))
    if stage in ("DIAGNOSED","ROOT_CAUSE"):
        return ("ROOT CAUSE FOUND", msg or "ForgeBoss nailed the likely problem.")
    if stage in ("REPAIRING","EDITING"):
        return ("REPAIR IN PROGRESS", msg or "Repair Rat is building a bounded patch transaction.")
    if stage in ("VALIDATING","TESTING"):
        return ("VALIDATING HIT", msg or "ForgeBoss is proving the repair.")
    if stage=="VALIDATION_FAILED":
        return ("VALIDATION HIT BACK", msg or "A SiteBoss validation check still fails.")
    if stage=="NEXT_TARGET_FOUND":
        return ("NEXT TARGET FOUND", msg or "Validation exposed the next SiteBoss defect family.")
    if stage=="PARTIAL_WIN":
        return ("PARTIAL WIN", msg or "Target eliminated locally; other defects remain.")
    if stage in ("DRAFT_READY","COMPLETED"):
        return ("FULL HIT", msg or "Target eliminated and validation is green.")
    if stage in ("BUDGET_BLOCKED","BUDGET_REACHED"):
        return ("BUDGET BLOCKED - $0 SPENT" if "preflight" in msg.lower() else "BUDGET BLOCKED", msg)
    if stage=="AI_SAFE_REFUSAL":
        return ("TARGET LOST", msg or "Evidence is not strong enough for a safe change.")
    if stage in ("PATCH_REJECTED","STALE_FILE","PATCH_PRECONDITION_FAILED"):
        return ("PATCH REJECTED", msg)
    if stage in ("INFRA_ERROR","FORGEBOSS_FAULT"):
        return ("FORGEBOSS FAULT", msg or "Internal controller/workspace problem.")
    if stage in ("NEEDS_OWNER","BLOCKED"):
        return ("MISSION BLOCKED", msg)
    return (stage.replace("_"," ") if stage else "IDLE", msg)

def save_status(**changes):
    with lock:
        current=load_status()
        stage=changes.get("stage",current.get("stage"))
        message=changes.get("message",current.get("message",""))
        label,detail=ops_phrase(stage,message)
        changes.setdefault("ops_label",label)
        changes.setdefault("ops_detail",detail)
        current.update(changes)
        write_json(STATUS,current)
        return current

def runtime_python():
    v=Path.home()/".forgeboss"/"runtime"/"venv"/"Scripts"/"python.exe"
    return str(v if v.exists() else Path(sys.executable))

def check_engines(force=False):
    global _engine_cache_value,_engine_cache_at
    with _engine_cache_lock:
        if (not force) and _engine_cache_value is not None and time.time()-_engine_cache_at<30:
            return _engine_cache_value
        engines={};py=runtime_python()
        for label,pkg in {"OpenHands":"openhands-sdk","mini-SWE":"mini-swe-agent","Deep Agents":"deepagents"}.items():
            try:
                r=subprocess.run([py,"-c",f"import importlib.metadata as m;print(m.version({pkg!r}))"],capture_output=True,text=True,timeout=20,creationflags=CREATE_NO_WINDOW)
                txt=(r.stdout or r.stderr).strip()
                engines[label]={"ready":r.returncode==0,"version":txt.splitlines()[-1] if txt else ""}
            except Exception as e:
                engines[label]={"ready":False,"version":type(e).__name__}
        exe=shutil.which("opencode")
        if exe:
            try:
                r=subprocess.run([exe,"--version"],capture_output=True,text=True,timeout=20,creationflags=CREATE_NO_WINDOW)
                txt=(r.stdout or r.stderr).strip()
                engines["OpenCode"]={"ready":r.returncode==0,"version":txt.splitlines()[-1] if txt else "","policy":"QUARANTINED"}
            except Exception as e:
                engines["OpenCode"]={"ready":False,"version":type(e).__name__,"policy":"QUARANTINED"}
        else:
            engines["OpenCode"]={"ready":False,"version":"","policy":"QUARANTINED"}
        engines["Repair Rat"]={"ready":(ROOT/"SiteBoss-Repair-Rat.ps1").exists(),"version":"proven fallback"}
        if "OpenHands" in engines: engines["OpenHands"]["policy"]="QUARANTINED_WRITE_UNTIL_OS_ISOLATION"
        if "OpenCode" in engines: engines["OpenCode"]["policy"]="QUARANTINED_WRITE_UNTIL_OS_ISOLATION"
        _engine_cache_value=engines
        _engine_cache_at=time.time()
        save_status(engines=engines)
        return engines

def latest_repair_report_after(start_ts):
    d=ROOT/"state"/"repair-rat"
    if not d.exists(): return None
    for p in sorted(d.glob("repair-rat-*.json"),key=lambda p:p.stat().st_mtime,reverse=True):
        if p.stat().st_mtime>=start_ts-2:
            try:return json.loads(p.read_text(encoding="utf-8"))
            except Exception:pass
    return None

def run_command_live(argv,env=None):
    log("COMMAND: "+" ".join(argv))
    flags=getattr(subprocess,"CREATE_NO_WINDOW",0)
    p=subprocess.Popen(argv,cwd=str(ROOT),env=env or os.environ.copy(),
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,
        universal_newlines=True,creationflags=flags)
    assert p.stdout
    for line in p.stdout: log(line.rstrip())
    return p.wait()

def local_gates():
    """Run only self-tests that actually ship in this ForgeBoss package."""
    gates=[
      ("HYBRID SELFTEST",["node",str(ROOT/"controller"/"hybrid"/"selftest.js")]),
      ("AGENCY CORE TEAM",["node",str(ROOT/"controller"/"selftest-agency-core-team.js")]),
      ("DEEP AGENTS SECURITY",[runtime_python(),str(ROOT/"controller"/"deepagents"/"tests"/"test_policy.py")]),
      ("CONTROLLER SELFTEST",["node",str(ROOT/"controller"/"siteboss-autopilot.js"),"selftest"]),
      ("COST FUNNEL SELFTEST",[runtime_python(),str(ROOT/"forgeboss"/"autonomy"/"selftest-cost-funnel.py")]),
    ]
    for name,cmd in gates:
        script=None
        for part in cmd:
            if isinstance(part,str) and part.lower().endswith((".js",".py")):
                script=Path(part);break
        if script is not None and not script.exists():
            log(f"[FAIL] {name}: shipped selftest is missing: {script}")
            return 2
        log(f"=== {name} ===")
        code=run_command_live(cmd)
        if code:
            log(f"[FAIL] {name} exit={code}")
            return code
        log(f"[PASS] {name}")
    return 0

def run_bakeoff():
    save_status(stage="BAKEOFF",message="Running zero-cost executor readiness bake-off")
    log("=== ZERO-COST EXECUTOR BAKE-OFF ===")
    engines=check_engines(); results={}
    for name,info in engines.items():
        results[name]={"ready":bool(info.get("ready")),"version":info.get("version",""),
            "coding_quality":"NOT_MEASURED_NO_MODEL_CALL","cost_usd":0.0,
            "scope_safety":"ForgeBoss wrapper required"}
        log(f"{name}: {'READY' if info.get('ready') else 'NOT READY'} {info.get('version','')}")
    write_json(STATE/"bakeoff-last.json",{
      "schema":1,"generated_at":now(),"model_calls":0,"github_writes":0,
      "note":"Readiness only; no claim that an upstream executor beats Repair Rat until a same-task paid benchmark is run.",
      "results":results,"default_executor":"repair-rat"})
    save_status(stage="IDLE",message="Zero-cost bake-off complete",executor="repair-rat")
    log("Bake-off complete: $0 API spend. Repair Rat remains default until a paid same-task comparison proves a winner.")


def run_paid_tournament(cap):
    save_status(stage="TOURNAMENT",message=f"Running same-task mini-SWE vs OpenHands tournament; hard cap ${cap:.2f}")
    log(f"=== PAID EXECUTOR TOURNAMENT: total cap ${cap:.2f} ===")
    env=os.environ.copy()
    env["FORGEBOSS_ALLOW_TOURNAMENT"]="YES"
    p=subprocess.Popen([runtime_python(),str(ROOT/"forgeboss"/"tournament"/"run_paid.py"),str(cap)],
        cwd=str(ROOT),env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,
        creationflags=CREATE_NO_WINDOW)
    assert p.stdout
    for line in p.stdout: log(line.rstrip())
    code=p.wait()
    result_path=ROOT/"state"/"tournament"/"paid-tournament-last.json"
    if result_path.exists():
        try:
            result=json.loads(result_path.read_text(encoding="utf-8"))
            winner=result.get("winner")
            total=sum(float(x.get("reported_cost_usd") or 0) for x in result.get("results",[]))
            save_status(spent_usd=round(total,4),executor=(winner or "repair-rat"),
                stage=("TOURNAMENT_COMPLETE" if winner else "NEEDS_OWNER"),
                message=(f"Provisional tournament winner: {winner}. Not promoted live yet." if winner else "Tournament found no verified winner."))
            return
        except Exception as e: log("Tournament result read failed: "+str(e))
    save_status(stage="SAFE_STOP",message=f"Tournament stopped with exit code {code}; nothing published.")


def prepare_template_cleanup():
    save_status(stage="REPO_HYGIENE",message="Inspecting PR template case collision; no GitHub writes")
    log("=== REPOSITORY HYGIENE: PR TEMPLATE CASE COLLISION ===")
    p=subprocess.run([runtime_python(),str(ROOT/"forgeboss"/"tournament"/"prepare_template_cleanup.py")],
        cwd=str(ROOT),capture_output=True,text=True,timeout=300)
    for line in (p.stdout+p.stderr).splitlines(): log(line)
    if p.returncode:
        save_status(stage="SAFE_STOP",message="PR template hygiene inspection failed; nothing changed remotely")
    else:
        save_status(stage="IDLE",message="PR template cleanup patch prepared locally; canonical lowercase template retained")

def run_category_league(cap):
    save_status(stage="CATEGORY_LEAGUE",message=f"Running executor league across 8 categories; target spend ${cap:.2f}")
    log(f"=== FORGEBOSS CATEGORY LEAGUE: target ${cap:.2f} ===")
    env=os.environ.copy();env["FORGEBOSS_ALLOW_PAID_EXECUTOR"]="YES"
    p=subprocess.Popen([runtime_python(),str(ROOT/"forgeboss"/"league"/"run_league.py"),str(cap)],cwd=str(ROOT),env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,creationflags=CREATE_NO_WINDOW)
    assert p.stdout
    for line in p.stdout:log(line.rstrip())
    code=p.wait();path=ROOT/"state"/"league"/"league-last.json"
    if code==0 and path.exists():
        j=json.loads(path.read_text());w=", ".join(f"{k}={v or 'none'}" for k,v in j["winners"].items());save_status(stage="LEAGUE_COMPLETE",spent_usd=j.get("reported_measured_spend_usd",0),message="Category designations: "+w)
    else:save_status(stage="SAFE_STOP",message=f"Category league stopped exit={code}; nothing published.")


def retest_last_candidates():
    save_status(stage="RETEST",message="Re-testing the already-paid mini-SWE and OpenHands candidates; $0 model spend")
    log("=== RETESTING LAST PAID CANDIDATES - $0 ===")
    p=subprocess.Popen([runtime_python(),str(ROOT/"forgeboss"/"tournament"/"retest_latest.py")],
        cwd=str(ROOT),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1,
        creationflags=CREATE_NO_WINDOW)
    assert p.stdout
    for line in p.stdout: log(line.rstrip())
    code=p.wait()
    rp=ROOT/"state"/"tournament"/"retest-last.json"
    if rp.exists():
        try:
            j=json.loads(rp.read_text(encoding="utf-8"));winner=j.get("winner")
            if winner:
                msg=("Both existing candidates passed; compare cost/review next." if winner=="both-pass-needs-cost-tiebreak" else f"{winner} passed the repaired validator.")
                save_status(stage="RETEST_COMPLETE",message=msg)
                return
        except Exception: pass
    save_status(stage="NEEDS_OWNER",message=f"Existing candidates did not pass validation (exit {code}). No model calls were made.")


def make_failure_feedback(source=None,bootstrap=False):
    args=[runtime_python(),str(ROOT/"forgeboss"/"autonomy"/"failure_feedback.py")]
    if bootstrap: args.append("--bootstrap-retest")
    elif source: args += ["--source",str(source)]
    p=subprocess.run(args,cwd=str(ROOT),capture_output=True,text=True,timeout=90,creationflags=CREATE_NO_WINDOW)
    path=ROOT/"state"/"autonomy"/"failure-feedback-last.json"
    if p.returncode==0 and path.exists():
        try:return path,json.loads(path.read_text(encoding="utf-8"))
        except Exception:return None,None
    return None,None

def latest_repair_report_path_after(epoch):
    d=ROOT/"state"/"repair-rat"
    if not d.exists():return None
    files=[p for p in d.glob("repair-rat-*.json") if p.stat().st_mtime>=epoch-2]
    return max(files,key=lambda p:p.stat().st_mtime) if files else None


def build_overall_run_report(run_id,session,cycles):
    d=ROOT/"state"/"run-reports";d.mkdir(parents=True,exist_ok=True)
    inp=d/f"{run_id}-input.json"
    write_json(inp,{"run_id":run_id,"session":session,"cycles":cycles})
    p=subprocess.run([runtime_python(),str(ROOT/"forgeboss"/"reports"/"build_run_report.py"),"--input",str(inp)],
                     cwd=str(ROOT),capture_output=True,text=True,timeout=120,creationflags=CREATE_NO_WINDOW)
    if p.returncode!=0:
        log("RUN REPORT generation failed: "+(p.stderr or p.stdout)[-1200:])
        return None
    try:return json.loads((p.stdout or "").strip().splitlines()[-1])
    except Exception:return None

def publish_live_run_report(run_id,started,duration_label,budget,cumulative,cycles,stage,message):
    session={"started_at":started.isoformat(),"finished_at":datetime.now(timezone.utc).isoformat(),
             "duration_label":duration_label,"budget_usd":budget,"spent_usd":round(cumulative,4),
             "final_stage":stage,"stop_reason":message,"draft_pr":None}
    meta=build_overall_run_report(run_id,session,cycles)
    if meta:
        save_status(last_run_report=meta,last_cycle_report=meta)
        log("LIVE DIAGNOSIS ready: "+str(meta.get("text") or "report generated"))
    return meta

def normalize_session_budget(value):
    try:
        budget=float(value)
    except Exception:
        raise ValueError("budget_usd must be a finite number")
    if not math.isfinite(budget):
        raise ValueError("budget_usd must be a finite number")
    if budget<0.10:
        raise ValueError("budget_usd must be at least $0.10")
    if budget>MAX_SESSION_BUDGET_USD:
        raise ValueError(f"budget_usd cannot exceed ${MAX_SESSION_BUDGET_USD:.2f}")
    return round(budget,4)

def resolve_report_root_pr(report_meta):
    try:
        jp=report_meta.get("json")
        if jp and Path(jp).exists():
            j=json.loads(Path(jp).read_text(encoding="utf-8-sig"))
            for c in j.get("cycles",[]) or []:
                pr=c.get("root_pr")
                if isinstance(pr,int) and pr>0: return pr
    except Exception:
        pass
    try:
        p=Path.home()/".siteboss"/"autopilot"/"controller-state"/"packet-latest.json"
        if p.exists():
            pr=json.loads(p.read_text(encoding="utf-8-sig")).get("root_pr")
            if isinstance(pr,int) and pr>0: return pr
    except Exception:
        pass
    return None

def publish_run_report_to_github(report_meta,owner_confirmed=False,automated=False):
    if not report_meta:return {"ok":False,"message":"no report"}
    if os.environ.get("SITEBOSS_ALLOW_DRAFT_PUBLISH")!="YES":
        return {"ok":False,"non_fatal":True,"message":"GitHub findings publication gate is OFF"}
    if automated:
        if os.environ.get("SITEBOSS_ALLOW_AUTO_DRAFT_PUBLISH")!="YES":
            return {"ok":False,"non_fatal":True,"message":"Automatic GitHub findings publication is OFF"}
    elif not owner_confirmed:
        return {"ok":False,"non_fatal":True,"message":"Native owner confirmation is required for manual GitHub publication"}
    md=report_meta.get("github_markdown")
    if not md: return {"ok":False,"message":"no github markdown"}
    root_pr=resolve_report_root_pr(report_meta)
    if not root_pr:
        return {"ok":False,"non_fatal":True,"message":"Could not resolve authoritative root PR; refusing GitHub write"}
    p=subprocess.run(["node",str(ROOT/"forgeboss"/"github"/"publish-run-report.js"),"--markdown",str(md),"--pr",str(root_pr)],
                     cwd=str(ROOT),capture_output=True,text=True,timeout=120,creationflags=CREATE_NO_WINDOW)
    if p.returncode:
        detail=(p.stderr or p.stdout)[-1200:]
        log("GITHUB REPORT publication failed; local report retained. "+detail)
        return {"ok":False,"non_fatal":True,"message":detail}
    try:
        result=json.loads((p.stdout or "").strip().splitlines()[-1])
        log(f"GITHUB REPORT published to root PR #{root_pr}: {result.get('html_url','comment created')}")
        return result
    except Exception:
        return {"ok":True,"message":"published","pull_request":root_pr}

def build_remaining_failure_packet(report,retained_foundation_path=None):
    if not report:return None
    runs=[]
    for a in report.get("attempts") or []:runs.extend(a.get("runs") or [])
    failing=[r for r in runs if int(r.get("exit_code") or 0)!=0]
    if not failing:return None
    evidence=[{"name":r.get("name"),"exit_code":r.get("exit_code"),"failure_lines":r.get("failure_lines") or [],"output_tail":r.get("output_tail") or ""} for r in failing]
    text=json.dumps(evidence,ensure_ascii=False).lower()
    family="postgresql-40001-serialization" if ("40001" in text or "could not serialize access" in text) else "remaining-validation-failure"
    files=["src/persistence/postgres.js","src/intake/postgresApplication.js","src/persistence/platformStore.js","src/persistence/postgresCrmStore.js","src/persistence/postgresLeadConversion.js","src/auth/businessInvitations.js"] if family=="postgresql-40001-serialization" else []
    packet={"schema":1,"objective":"Repair remaining "+family+" defect family after a verified partial win.","primary_failure_family":family,
            "allowed_files":files,"context_files":files+["tests/postgresTravisIntake.integration.test.js"],
            "acceptance_criteria":["Preserve the retained partial-win foundation.","Eliminate repeated PostgreSQL 40001/40P01 failures without weakening tests.","Keep exact-once/idempotency and transaction invariants intact."],
            "retained_foundation":retained_foundation_path,"evidence":evidence[:12]}
    out=ROOT/"state"/"autonomy"/"debug-funnel-last.json";out.parent.mkdir(parents=True,exist_ok=True);write_json(out,packet)
    log("NEXT TARGET PACKET: built directly from remaining validation evidence; family="+family)
    return str(out)

def promote_verified_learning(report,project_id="siteboss"):
    """Promote only validated engineering artefacts; never model chain-of-thought."""
    if not report:return None
    try:
        from forgeboss.learning.store import LearningStore
        from forgeboss.learning.policy import can_promote
        validation={
            "all_required_passed":bool(report.get("passed")),
            "focused_target_passed":bool(report.get("partial_proven")),
            "introduced_regression":bool(report.get("introduced_regression"))
        }
        if not can_promote(validation,partial_proven=bool(report.get("partial_proven"))):return None
        attempts=report.get("attempts") or []
        latest=attempts[-1] if attempts else {}
        failures=[]
        for a in attempts:
            for run in a.get("runs") or []:
                if int(run.get("exit_code") or 0)!=0:
                    failures.extend(run.get("failure_lines") or [])
        family=str(report.get("resolved_focused_step") or report.get("failure_family") or "validated-repair")
        summary=str(latest.get("repair_summary") or latest.get("summary") or report.get("repair_summary") or family)
        pattern={
            "files_changed":report.get("files_changed") or latest.get("files_changed") or [],
            "code_diff":report.get("code_diff") or "",
            "retained_patch_path":report.get("retained_patch_path"),
            "transaction_kind":"validated-partial" if report.get("partial_proven") else "validated-full"
        }
        evidence={"failure_lines":failures[:80],"fingerprint":latest.get("failure_fingerprint") or report.get("failure_fingerprint")}
        db=ROOT/"state"/"learning"/"forgeboss-learning.db"
        st=LearningStore(db)
        lid=st.record_verified_lesson(project_id,family,summary,pattern,evidence,validation,confidence=1.0,reusable=True)
        log("REPAIR RAT LEARNED: verified lesson "+lid[:12]+" stored for "+family)
        return lid
    except Exception as e:
        log("LEARNING STORE NON-FATAL: "+str(e)[:500])
        return None

def prepare_cost_optimized_retry(feedback_path):
    if not feedback_path:return None,None
    # Record failure memory.
    subprocess.run([runtime_python(),str(ROOT/"forgeboss"/"autonomy"/"repair_memory.py"),"--feedback",str(feedback_path)],
                   cwd=str(ROOT),capture_output=True,text=True,timeout=30,creationflags=CREATE_NO_WINDOW)
    # Build compact $0 debug packet.
    p=subprocess.run([runtime_python(),str(ROOT/"forgeboss"/"autonomy"/"debug_funnel.py"),"--feedback",str(feedback_path)],
                     cwd=str(ROOT),capture_output=True,text=True,timeout=90,creationflags=CREATE_NO_WINDOW)
    funnel=ROOT/"state"/"autonomy"/"debug-funnel-last.json"
    if p.returncode or not funnel.exists():
        log("COST FUNNEL failed; refusing another large blind model call.")
        return None,None
    try:
        j=json.loads(funnel.read_text(encoding="utf-8"))
        if int(j.get("focused_file_count") or 0)<1:
            log("COST FUNNEL produced zero source files; refusing a full-context paid fallback.")
            return None,None
    except Exception:
        return None,None
    # Query memory for matching failed/proven history.
    memout=ROOT/"state"/"autonomy"/"repair-memory-context-last.json"
    q=subprocess.run([runtime_python(),str(ROOT/"forgeboss"/"autonomy"/"repair_memory.py"),"--query",str(funnel)],
                     cwd=str(ROOT),capture_output=True,text=True,timeout=30,creationflags=CREATE_NO_WINDOW)
    try:memout.write_text(q.stdout.strip() or "{}",encoding="utf-8")
    except Exception:pass
    try:
        j=json.loads(funnel.read_text(encoding="utf-8"))
        log(f"COST FUNNEL: next AI packet narrowed to {j.get('focused_file_count',0)} files / {j.get('focused_source_chars',0)} source chars.")
    except Exception:pass
    return funnel,memout

def choose_openai_lane(mode,cycle,same_signature_count):
    mode=str(mode or "cost-optimized").strip().lower()
    if mode=="cost-optimized":return {"requested_mode":mode,"model":"gpt-5.6-luna","reasoning":"low","max_output":3000,"lane":"CHEAP"}
    if mode=="balanced":return {"requested_mode":mode,"model":"gpt-5.6-terra","reasoning":"medium","max_output":4000,"lane":"BALANCED"}
    if mode=="strong":return {"requested_mode":mode,"model":"gpt-5.6-sol","reasoning":"medium","max_output":5000,"lane":"STRONG"}
    raise ValueError(f"Unknown AI mode: {mode}")

def teach_repair_rat(report_path,feedback_path=None):
    if not report_path:return
    cmd=[runtime_python(),str(ROOT/"forgeboss"/"autonomy"/"repair_playbook.py"),"record","--report",str(report_path)]
    if feedback_path:cmd += ["--feedback",str(feedback_path)]
    p=subprocess.run(cmd,cwd=str(ROOT),capture_output=True,text=True,timeout=90,creationflags=CREATE_NO_WINDOW)
    log("REPAIR RAT MEMORY: "+("attempt outcome stored." if p.returncode==0 else "record failed; continuing safely."))

def classify_failure_code(text):
    t=str(text or "")
    known=("CONTEXT_INSUFFICIENT","MODEL_REFUSED_UNBOUNDED_OUTPUT","MODEL_POLICY_REFUSAL",
           "PATCH_CONTRACT_INVALID","PATCH_ANCHOR_ROLE_MISMATCH","PATCH_SEMANTIC_SCOPE_INVALID","AMBIGUOUS_SYMBOL_ANCHOR","PATCH_ANCHOR_INTENT_MISMATCH","PATCH_LINE_RANGE_TOO_WIDE","PATCH_CANDIDATE_INVALID","PATCH_CONTEXT_MISMATCH","PATCH_PRECONDITION_FAILED","AMBIGUOUS_EDIT_ANCHOR","STALE_FILE","PATH_OUTSIDE_SCOPE",
           "VALIDATION_FAILED","NEW_DIAGNOSTICS_INTRODUCED","PROVIDER_RATE_LIMITED",
           "PROVIDER_OVERLOADED","TOOL_PERMISSION_DENIED","WORKTREE_CONFLICT",
           "BUDGET_EXHAUSTED","TASK_CANCELLED")
    for code in known:
        if code in t:return code
    return "UNCLASSIFIED_FAILURE"

def classify_repair_outcome(report):
    if not report:return {"kind":"unknown"}
    attempts=report.get("attempts") or []
    a=attempts[-1] if attempts else {}
    changed=a.get("changed_paths") or []
    failures=a.get("failure_count")
    summary=str(a.get("model_summary") or "")
    reasoning=str(a.get("reasoning_summary") or "")
    if report.get("fatal_failure"):return {"kind":"fatal","reason":str((report.get("fatal_failure") or {}).get("reason") or "")}
    if not changed and failures in (0,None) and (summary or reasoning):
        return {"kind":"safe_refusal","reason":summary or reasoning,"summary":summary,"reasoning":reasoning}
    if changed and a.get("acceptance_passed") is False:
        return {"kind":"patch_failed_tests","reason":"Candidate code changed but acceptance failed"}
    if a.get("acceptance_passed") is True:return {"kind":"passed","reason":"Acceptance passed"}
    return {"kind":"failed","reason":summary or "Repair did not pass"}

def collect_missing_evidence(report_path,funnel_path):
    if not report_path:return None,0
    cmd=[runtime_python(),str(ROOT/"forgeboss"/"autonomy"/"evidence_collector.py"),"--report",str(report_path)]
    if funnel_path:cmd += ["--funnel",str(funnel_path)]
    p=subprocess.run(cmd,cwd=str(ROOT),capture_output=True,text=True,timeout=90,creationflags=CREATE_NO_WINDOW)
    if p.returncode:return None,0
    try:
        j=json.loads((p.stdout or "").strip().splitlines()[-1])
        return Path(j["path"]),int(j.get("new_evidence_count") or 0)
    except Exception:return None,0

def _run_session_impl(settings):
    budget=normalize_session_budget(settings.get("budget_usd",3.0))
    mode=str(settings.get("mode","cost-optimized"))
    duration_mode=str(settings.get("duration_mode","timed"))
    until_stopped=(duration_mode=="until-stopped")
    if until_stopped:
        duration=None
    else:
        duration=max(1,min(int(settings.get("duration_minutes",120)),1440))

    started=datetime.now(timezone.utc)
    run_id="FB-"+started.strftime("%Y%m%d-%H%M%S")
    cycle_records=[]
    ends=None if until_stopped else started+timedelta(minutes=duration)
    stop_requested.clear()

    save_status(running=True,stage="SAFETY_GATES",message="Running local safety gates",
        started_at=started.isoformat(),ends_at=(ends.isoformat() if ends else None),
        duration_minutes=(duration if duration is not None else "until-stopped"),
        duration_mode=duration_mode,budget_usd=budget,spent_usd=0.0,workers=1,mode=mode,current_cycle=0,
        draft_prs=[],stop_requested=False,last_exit_code=None)

    write_json(SESSION,settings)
    pretty_duration="UNTIL STOP SAFELY" if until_stopped else f"{duration} min"
    log(f"=== SESSION START: {pretty_duration}, ${budget:.2f} max, workers=1, mode={mode} ===")
    log("Draft PR publication may occur only after green validation/review. Merge/deploy execution remains disabled in this build.")

    code=local_gates()
    if code:
        save_status(running=False,stage="SAFE_STOP",message="Local safety gate failed",last_exit_code=code); return
    log("STARTUP: safety gates passed. Checking executor readiness...")
    try:
        check_engines()
        log("STARTUP: executor readiness check complete.")
    except Exception as e:
        log("STARTUP WARNING: executor readiness check failed; Repair Rat can still continue. "+repr(e))

    cumulative=0.0
    cycle=0
    last_signature=None
    same_signature_count=0
    feedback_path=None
    debug_funnel_path=None
    memory_context_path=None
    evidence_enrichment_path=None
    retained_foundation_path=None
    last_refusal_reason=None

    # Bootstrap with the real $0 candidate re-test evidence when it is exact-head
    # compatible. Repair Rat itself performs the exact SHA gate before using it.
    log("STARTUP: checking for reusable $0 failure evidence...")
    try:
        bp,bj=make_failure_feedback(bootstrap=True)
    except subprocess.TimeoutExpired as e:
        bp,bj=None,None
        log(f"STARTUP WARNING: saved-evidence bootstrap timed out after {e.timeout}s; continuing without it.")
    except Exception as e:
        bp,bj=None,None
        log("STARTUP WARNING: saved-evidence bootstrap failed; continuing without it. "+repr(e))
    if bp:
        feedback_path=bp
        log(f"AUTONOMY: loaded saved acceptance evidence; category={bj.get('category','unknown')} (exact-head gate enforced downstream).")
        try:
            debug_funnel_path,memory_context_path=prepare_cost_optimized_retry(feedback_path)
        except subprocess.TimeoutExpired as e:
            debug_funnel_path,memory_context_path=None,None
            log(f"STARTUP WARNING: focused-packet preparation timed out after {e.timeout}s.")
        except Exception as e:
            debug_funnel_path,memory_context_path=None,None
            log("STARTUP WARNING: focused-packet preparation failed. "+repr(e))
        if mode=="cost-optimized" and not debug_funnel_path:
            save_status(running=False,stage="NEEDS_OWNER",message="Could not build a focused $0 debug packet; stopped before paid AI.",spent_usd=0.0)
            log("COST OPTIMIZER STOP: no focused packet; $0 model spend.")
            return
    else:
        log("STARTUP: no reusable saved evidence found; starting a fresh bounded build cycle.")

    log("STARTUP: entering autonomous work loop.")
    while not stop_requested.is_set():
        if ends and datetime.now(timezone.utc)>=ends:
            log("SESSION TIME LIMIT reached. No new build cycle will start."); break
        remaining=budget-cumulative
        if remaining<=.01:
            log("SESSION BUDGET reached. No new paid call will start."); break
        # The Repair Rat already has a hard per-run preflight budget gate using the
        # selected model and remaining session budget. Do not duplicate that with a
        # blunt $0.20 controller reserve: normal Luna repair cycles are ~2-3 cents and
        # the old reserve prevented a $0.20 session from ever entering cycle 2.
        #
        # Keep only a tiny controller floor for bookkeeping/process overhead. The paid
        # model call itself remains fail-closed under Assert-EstimatedCallFitsBudget.
        min_cycle_reserve=0.03
        if cycle>0 and remaining<min_cycle_reserve:
            reason=f"Only ${remaining:.4f} remains; below ${min_cycle_reserve:.2f} controller reserve."
            log("BUDGET RESERVE: "+reason)
            save_status(stage="BUDGET_REACHED",message=reason,spent_usd=round(cumulative,4))
            break
        if cycle>=12:
            log("AUTONOMY SAFETY LIMIT: 12 build cycles reached. Stop/restart to continue."); break

        cycle+=1
        save_status(stage="LIVE_WORKLOAD",message=f"Preparing SiteBoss build cycle {cycle}",
                    current_cycle=cycle,spent_usd=round(cumulative,4))
        env=os.environ.copy()
        env["PYTHONUTF8"]="1"
        env["PYTHONIOENCODING"]="utf-8"
        env["SITEBOSS_ALLOW_PAID_REPAIR"]="YES"
        env["SITEBOSS_ALLOW_DRAFT_PUBLISH"]="YES"
        env["SITEBOSS_RUN_BUDGET_USD"]=f"{remaining:.4f}"
        env.setdefault("SITEBOSS_DAILY_BUDGET_USD",f"{max(budget,10.0):.4f}")
        lane=choose_openai_lane(mode,cycle,same_signature_count)
        env["SITEBOSS_OPENAI_MODEL"]=lane["model"]
        env["SITEBOSS_OPENAI_REASONING_EFFORT"]=lane["reasoning"]
        env["SITEBOSS_OPENAI_MAX_OUTPUT_TOKENS"]=str(lane["max_output"])
        log(f"AI ROUTING: requested={mode.upper()} -> lane={lane['lane']} -> selected={lane['model']} - reasoning={lane['reasoning']} - max_output={lane['max_output']}")
        save_status(requested_ai_mode=mode,selected_ai_lane=lane["lane"],selected_ai_model=lane["model"])
        if feedback_path:
            env["SITEBOSS_FORGEBOSS_FAILURE_FEEDBACK"]=str(feedback_path)
        if debug_funnel_path:
            env["SITEBOSS_FORGEBOSS_DEBUG_FUNNEL"]=str(debug_funnel_path)
        if memory_context_path:
            env["SITEBOSS_FORGEBOSS_REPAIR_MEMORY"]=str(memory_context_path)
        if evidence_enrichment_path:
            env["SITEBOSS_FORGEBOSS_EVIDENCE_ENRICHMENT"]=str(evidence_enrichment_path)
        if retained_foundation_path:
            env["SITEBOSS_FORGEBOSS_RETAINED_FOUNDATION"]=str(retained_foundation_path)

        before=time.time()
        save_status(stage="BUILDING",message=f"Cycle {cycle}: diagnose -> repair -> test -> review")
        if debug_funnel_path:
            try:
                _fp=json.loads(Path(debug_funnel_path).read_text(encoding="utf-8"))
                _fam=_fp.get("primary_failure_family") or _fp.get("objective") or "remaining defect"
                log(f"TARGET ACQUIRED: ForgeBoss locked onto {_fam}; ${remaining:.2f} budget remains.")
            except Exception:
                log(f"TARGET ACQUIRED: ForgeBoss locked onto build cycle {cycle}; ${remaining:.2f} budget remains.")
        else:
            log(f"TARGET ACQUIRED: ForgeBoss locked onto build cycle {cycle}; ${remaining:.2f} budget remains.")
        log("REPAIR IN PROGRESS: Repair Rat is building one bounded patch transaction.")
        code=run_command_live(["node",str(ROOT/"controller"/"siteboss-autopilot.js"),"autobuild"],env=env)

        report=latest_repair_report_after(before)
        report_path=latest_repair_report_path_after(before)
        call_cost=0.0
        if report:
            call_cost=float(report.get("usage_estimated_usd") or 0.0)
            cumulative+=call_cost
            save_status(spent_usd=round(cumulative,4))
            log(f"CYCLE COST: ~${call_cost:.4f} USD | SESSION TOTAL: ~${cumulative:.4f} / ${budget:.2f}")
        cycle_records.append({"cycle":cycle,"exit_code":code,"cost_usd":round(call_cost,4),
                              "report_path":str(report_path) if report_path else None,
                              "routed_model":lane.get("model"),"lane":lane.get("lane"),"requested_mode":mode,
                              "fatal_failure":(report or {}).get("fatal_failure"),
                              "fatal_fingerprint":normalize_fatal_failure(report)})
        publish_live_run_report(run_id,started,("RUN UNTIL STOPPED" if until_stopped else f"{duration} minutes"),budget,cumulative,cycle_records,
                                ("CYCLE_COMPLETE" if code==0 else "CYCLE_FAILED"),
                                (f"Cycle {cycle} completed" if code==0 else f"Cycle {cycle} failed; diagnosis captured"))

        # A fatal before any model call is ForgeBoss plumbing/budget control, not a
        # SiteBoss code failure. Retrying it cannot learn anything and previously
        # caused the zero-spend loop seen in v0.7.2.
        if code!=0 and report and int(report.get("api_calls") or 0)==0 and report.get("fatal_failure"):
            fatal=report.get("fatal_failure") or {}
            reason=str(fatal.get("reason") or "pre-model infrastructure failure")
            if reason.startswith("BUDGET PREFLIGHT STOP"):
                log("BUDGET BLOCKED - $0 SPENT: next model call cannot fit inside the owner cap.")
                save_status(stage="BUDGET_BLOCKED",message=("Budget blocked before spend. "+reason),last_exit_code=code)
            else:
                log("FORGEBOSS FAULT: internal controller/workspace failure before model spend.")
                save_status(stage="INFRA_ERROR",message=reason,last_exit_code=code)
            break

        if report and int(report.get("api_calls") or 0)>1:
            log("SECURITY/COST CONTRACT VIOLATION: Repair Rat reported more than one paid model call in one invocation.")
            save_status(stage="INFRA_ERROR",message="Repair Rat violated the hard one-call contract; stopped before further work.",last_exit_code=code)
            break
        outcome=classify_repair_outcome(report)

        # Invalid structured-output schema is a deterministic ForgeBoss fault.
        if code!=0 and report and report.get("fatal_failure"):
            _sr=str((report.get("fatal_failure") or {}).get("reason") or "")
            if "invalid_json_schema" in _sr or "FORGEBOSS_SCHEMA_INVALID" in _sr or "FORGEBOSS_SCHEMA_PREFLIGHT_FAILED" in _sr or "FORGEBOSS_CONTEXT_PACKET_TOO_LARGE" in _sr:
                log("FORGEBOSS FAULT: structured-output schema invalid; stopping immediately.")
                save_status(stage="INFRA_ERROR",message=_sr[:1800],last_exit_code=code)
                break

        # Runtime/controller exceptions after a paid call are still ForgeBoss faults.
        # Never turn them into SiteBoss evidence or a second paid context-shrink retry.
        if code!=0 and report and report.get("fatal_failure"):
            _fr=str((report.get("fatal_failure") or {}).get("reason") or "")
            _ft=str((report.get("fatal_failure") or {}).get("type") or "")
            if "PropertyNotFoundException" in _ft or "property 'Count' cannot be found" in _fr:
                log("FORGEBOSS FAULT: "+_fr[:900])
                save_status(stage="INFRA_ERROR",message=_fr[:1800],last_exit_code=code)
                break

        # Unknown paid ForgeBoss fatal: fail closed before another paid cycle.
        if code!=0 and report and int(report.get("api_calls") or 0)>0 and report.get("fatal_failure"):
            _fr=str((report.get("fatal_failure") or {}).get("reason") or "")
            if not any(x in _fr for x in ("PROVIDER_RATE_LIMIT_TRANSIENT","PROVIDER_5XX_TRANSIENT")):
                log("FORGEBOSS FAULT: unknown paid fatal; fail closed.")
                save_status(stage="INFRA_ERROR",message=_fr[:1800],last_exit_code=code)
                break

        # A paid model response that violates the patch transaction contract is not a SiteBoss
        # failure and must not trigger another paid model cycle. Deterministic normalization
        # already repairs safe metadata/path/hash omissions; anything left is genuinely ambiguous.
        if code!=0 and report and int(report.get("api_calls") or 0)>0 and report.get("fatal_failure"):
            _fatal_reason=str((report.get("fatal_failure") or {}).get("reason") or "")
            _fatal_code=classify_failure_code(_fatal_reason)
            if _fatal_code in ("PATCH_CONTRACT_INVALID","PATCH_ANCHOR_LOCATOR_INVALID","PATCH_ANCHOR_LOCATOR_MISMATCH","PATCH_ANCHOR_ROLE_MISMATCH","PATCH_SEMANTIC_SCOPE_INVALID","AMBIGUOUS_SYMBOL_ANCHOR","PATCH_ANCHOR_INTENT_MISMATCH","PATCH_LINE_RANGE_TOO_WIDE","PATCH_CANDIDATE_INVALID","PATCH_CONTEXT_MISMATCH","PATCH_PRECONDITION_FAILED","AMBIGUOUS_EDIT_ANCHOR","STALE_FILE","PATH_OUTSIDE_SCOPE"):
                teach_repair_rat(report_path,feedback_path)
                log("PATCH REJECTED: "+_fatal_reason[:900])
                log("SPEND GUARD: transaction-format/scope ambiguity is terminal for this paid response; no second paid format retry.")
                save_status(stage="PATCH_REJECTED",message=_fatal_reason[:1800],last_exit_code=code)
                break

        if code!=0 and report and int(report.get("api_calls") or 0)>0 and report.get("fatal_failure"):
            _repeat_reason=str((report.get("fatal_failure") or {}).get("reason") or "")
            _repeat_fp=normalize_fatal_failure(report)
            _prior_same=sum(
                1 for _cr in cycle_records[:-1]
                if _repeat_fp and _cr.get("fatal_fingerprint")==_repeat_fp
            )
            if _prior_same>=1:
                log("SPEND GUARD: repeated deterministic ForgeBoss failure fingerprint; stopping before another paid cycle.")
                save_status(stage="INFRA_ERROR",message=_repeat_reason[:1800],last_exit_code=code)
                break

        if code!=0 and report and report.get("partial_proven"):
            promote_verified_learning(report,"siteboss")
            step=str(report.get("resolved_focused_step") or "focused defect")
            log(f"PARTIAL WIN: ForgeBoss eliminated {step} locally and retained the verified sub-fix.")
            log("NEXT TARGET: ForgeBoss is isolating the remaining failure family.")
            retained_foundation_path=report.get("retained_patch_path")
            if retained_foundation_path:
                log("FOUNDATION CHAIN: newest verified sub-fix has been folded into one cumulative retained foundation.")
            if not retained_foundation_path:
                save_status(stage="NEEDS_OWNER",message="Partial win had no retained foundation metadata.",last_exit_code=code);break
            save_status(stage="PARTIAL_WIN",message=f"Verified sub-fix retained: {step}. Preparing next failure family.",last_exit_code=code)
            fp,fj=make_failure_feedback(source=report_path) if report_path else (None,None)
            if not fp or not fj:
                save_status(stage="NEEDS_OWNER",message="Sub-fix retained, but remaining failure evidence could not be prepared.",last_exit_code=code);break
            feedback_path=fp;teach_repair_rat(report_path,feedback_path)
            debug_funnel_path,memory_context_path=prepare_cost_optimized_retry(feedback_path)
            if not debug_funnel_path:
                debug_funnel_path=build_remaining_failure_packet(report,retained_foundation_path)
                memory_context_path=None
            if not debug_funnel_path:
                save_status(stage="NEEDS_OWNER",message="Verified sub-fix retained, but no next-target packet could be derived from remaining failures.",last_exit_code=code);break
            log("ACCUMULATING PIPELINE: retained foundation + next remaining-failure packet ready.")
            save_status(stage="NEXT_TARGET_FOUND",message="Remaining failure family isolated; starting the next bounded cycle.")
            continue

        if code!=0 and outcome.get("kind")=="safe_refusal":
            reason=outcome.get("reason","Safe refusal")
            log("AI SAFE REFUSAL: "+reason[:900])
            save_status(stage="AI_SAFE_REFUSAL",message=("AI refused patch: "+reason)[:1800],last_exit_code=code,last_refusal_reason=reason[:4000])
            publish_live_run_report(run_id,started,("RUN UNTIL STOPPED" if until_stopped else f"{duration} minutes"),budget,cumulative,cycle_records,
                                    "AI_SAFE_REFUSAL",("AI refused patch: "+reason)[:2000])
            # Store the refusal as negative Repair Rat memory.
            teach_repair_rat(report_path,feedback_path)
            ep,new_count=collect_missing_evidence(report_path,debug_funnel_path)
            normalized_reason=re.sub(r"\s+"," ",reason.strip().lower())
            if ep and new_count>0 and normalized_reason!=last_refusal_reason:
                evidence_enrichment_path=ep
                last_refusal_reason=normalized_reason
                save_status(stage="GATHERING_EVIDENCE",message=f"AI requested more evidence; Repair Rat gathered {new_count} local matches at $0. One focused retry allowed.",last_exit_code=code)
                log(f"REPAIR RAT EVIDENCE: gathered {new_count} new local matches at $0. One focused retry allowed.")
                continue
            save_status(stage="NEEDS_OWNER",message=("AI refused patch: "+reason)[:1800],last_exit_code=code,last_refusal_reason=reason[:4000])
            publish_live_run_report(run_id,started,("RUN UNTIL STOPPED" if until_stopped else f"{duration} minutes"),budget,cumulative,cycle_records,
                                    "NEEDS_OWNER",("AI refused patch: "+reason)[:2000])
            log("SAFE REFUSAL STOP: no genuinely new local evidence; no repeated paid retry.")
            break

        if code==0:
            promote_verified_learning(report,"siteboss")
            teach_repair_rat(report_path,feedback_path)
            log(f"Cycle {cycle} completed green. Reviewed candidate/draft publication stage completed according to controller policy.")
            save_status(stage="DRAFT_READY",message=f"Cycle {cycle} passed. Waiting for a new authoritative workload before doing more.",
                        last_exit_code=0)
            # With merge disabled, immediately rerunning the same authoritative root
            # can create duplicate work. End cleanly after one green publication.
            break

        # Failed cycle: extract deterministic evidence rather than blindly retry.
        fp,fj=make_failure_feedback(source=report_path) if report_path else (None,None)
        if not fp or not fj:
            log(f"Cycle {cycle} failed but ForgeBoss could not produce bounded failure evidence. Stopping instead of blind retry.")
            save_status(stage="NEEDS_OWNER",message=f"Cycle {cycle} failed without usable diagnosis evidence",last_exit_code=code)
            break

        feedback_path=fp
        teach_repair_rat(report_path,feedback_path)
        debug_funnel_path,memory_context_path=prepare_cost_optimized_retry(feedback_path)
        if not debug_funnel_path:
            save_status(stage="NEEDS_OWNER",message="Could not safely shrink failure context; stopped before another paid call.",last_exit_code=code)
            break
        sig=fj.get("signature")
        cat=fj.get("category","unknown")
        failed=(fj.get("acceptance") or {}).get("failed_steps") or []
        log(f"DIAGNOSIS: category={cat}; failed={', '.join(failed[:8]) if failed else 'see evidence'}")
        save_status(stage="DIAGNOSED",message=f"Cycle {cycle} failed; {cat} evidence captured. Preparing a focused repair retry.",
                    last_exit_code=code)

        if sig and sig==last_signature:
            same_signature_count+=1
        else:
            same_signature_count=0
            last_signature=sig

        # Two consecutive repeats of the same bounded failure signature means the
        # automation is not learning. Stop before wasting more credit.
        if same_signature_count>=2:
            log("STAGNATION GUARD: same failure signature repeated 3 times. Stopping to avoid wasting API credit.")
            save_status(stage="NEEDS_OWNER",message="Same failure repeated 3 times; stopped before more API spend.",last_exit_code=code)
            break

        if stop_requested.is_set():break
        if budget-cumulative<=.01:break
        log("AUTONOMY: fresh failure evidence will be supplied to the next repair cycle.")

    current=load_status()
    final=current.get("stage")
    if stop_requested.is_set():
        final="SAFE_STOP";stop_reason="Owner requested safe stop"
    elif cumulative>=budget and final!="DRAFT_READY":
        final="BUDGET_REACHED";stop_reason="Session budget reached with work unresolved"
    elif final=="BUDGET_REACHED":
        stop_reason=current.get("message") or "Remaining session budget is below the safe controller reserve"
    elif final=="DRAFT_READY":
        stop_reason="Green reviewed candidate reached draft-ready/publication gate"
    elif final in ("NEEDS_OWNER","BUDGET_BLOCKED","INFRA_ERROR","PATCH_REJECTED","AI_SAFE_REFUSAL"):
        stop_reason=current.get("message",final)
    else:
        stop_reason=current.get("message","Session ended")

    session_summary={
      "started_at":started.isoformat(),
      "finished_at":datetime.now(timezone.utc).isoformat(),
      "duration_label":("RUN UNTIL STOPPED" if until_stopped else f"{duration} minutes"),
      "budget_usd":budget,
      "spent_usd":round(cumulative,4),
      "final_stage":final,
      "stop_reason":stop_reason,
      "draft_pr":None
    }
    report_meta=build_overall_run_report(run_id,session_summary,cycle_records)
    github_report=publish_run_report_to_github(report_meta,automated=True)
    save_status(running=False,stage=final,
                message=stop_reason,stop_requested=stop_requested.is_set(),
                spent_usd=round(cumulative,4),finished_at=datetime.now(timezone.utc).isoformat(),
                last_run_report=report_meta,github_run_report=github_report)
    log(f"=== SESSION END: spent ~${cumulative:.4f} USD | report={report_meta.get('text') if report_meta else 'FAILED'} ===")


def run_session(settings):
    """Guard the worker thread so a crash/timeout cannot leave LIVE_WORKLOAD stuck forever."""
    try:
        return _run_session_impl(settings)
    except subprocess.TimeoutExpired as e:
        msg=f"ForgeBoss phase timed out after {e.timeout}s"
        log("WATCHDOG STOP: "+msg)
        save_status(running=False,stage="INFRA_ERROR",message=msg,last_exit_code=124)
    except Exception as e:
        msg=f"{type(e).__name__}: {e}"
        log("WORKER CRASH: "+msg)
        try:
            import traceback as _tb
            log(_tb.format_exc()[-5000:])
        except Exception:
            pass
        save_status(running=False,stage="INFRA_ERROR",message=msg,last_exit_code=2)

def start_session(settings):
    global worker_thread
    try:
        clean=dict(settings or {})
        clean["budget_usd"]=normalize_session_budget(clean.get("budget_usd",3.0))
    except (TypeError,ValueError) as e:
        return False,str(e)
    with lock:
        if worker_thread and worker_thread.is_alive(): return False,"ForgeBoss is already running."
        worker_thread=threading.Thread(target=run_session,args=(clean,),daemon=True)
        worker_thread.start()
        return True,"Started"

class Handler(BaseHTTPRequestHandler):
    server_version="ForgeBossLocal/1.3"
    def send_json(self,obj,code=200):
        data=json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def local_host_ok(self):
        return self.headers.get("Host","") in LOCAL_HOSTS
    def post_authorized(self):
        if not self.local_host_ok(): return False,"invalid Host"
        origin=self.headers.get("Origin")
        if origin and origin not in LOCAL_ORIGINS: return False,"invalid Origin"
        ctype=self.headers.get("Content-Type","").split(";",1)[0].strip().lower()
        if ctype!="application/json": return False,"Content-Type must be application/json"
        if not secrets.compare_digest(self.headers.get("X-ForgeBoss-Token",""),RPC_TOKEN):
            return False,"invalid local RPC token"
        return True,""
    def do_GET(self):
        if not self.local_host_ok():
            self.send_json({"error":"invalid Host"},403); return
        p=urlparse(self.path).path
        if p=="/api/session-token":
            self.send_json({"token":RPC_TOKEN}); return
        if p=="/api/status":
            st=load_status(); st["engines"]=check_engines(); self.send_json(st); return
        if p=="/api/log":
            txt=LOG.read_text(encoding="utf-8",errors="replace")[-30000:] if LOG.exists() else ""
            self.send_json({"text":txt}); return
        if p=="/":
            data=(DASH/"index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Cache-Control","no-store")
            self.send_header("X-Frame-Options","DENY")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Content-Length",str(len(data)))
            self.end_headers(); self.wfile.write(data); return
        self.send_response(404); self.end_headers()
    def do_POST(self):
        ok,why=self.post_authorized()
        if not ok:
            self.send_json({"ok":False,"error":why},403); return
        try:
            n=int(self.headers.get("Content-Length","0") or 0)
            if n<0 or n>65536: raise ValueError("request body too large")
            raw=self.rfile.read(n)
            body=json.loads(raw.decode("utf-8") if raw else "{}")
            if not isinstance(body,dict): raise ValueError("JSON body must be an object")
        except (ValueError,UnicodeDecodeError,json.JSONDecodeError) as e:
            self.send_json({"ok":False,"error":str(e)},400); return
        p=urlparse(self.path).path
        try:
            if p=="/api/start":
                ok,msg=start_session(body); self.send_json({"ok":ok,"message":msg},200 if ok else 409); return
            if p=="/api/stop":
                stop_requested.set(); save_status(stop_requested=True,message="Stop requested; current atomic operation will finish and no new work will start.")
                log("OWNER requested safe stop."); self.send_json({"ok":True}); return
            if p=="/api/bakeoff":
                threading.Thread(target=run_bakeoff,daemon=True).start(); self.send_json({"ok":True}); return
            if p=="/api/tournament/run":
                cap=max(.25,min(float(body.get("max_usd",1.0)),3.0))
                threading.Thread(target=run_paid_tournament,args=(cap,),daemon=True).start()
                self.send_json({"ok":True,"max_usd":cap}); return
            if p=="/api/hygiene/pr-template":
                threading.Thread(target=prepare_template_cleanup,daemon=True).start(); self.send_json({"ok":True}); return
            if p=="/api/league/run":
                cap=max(.5,min(float(body.get("max_usd",1.0)),2.0))
                threading.Thread(target=run_category_league,args=(cap,),daemon=True).start()
                self.send_json({"ok":True}); return
            if p=="/api/tournament/retest":
                threading.Thread(target=retest_last_candidates,daemon=True).start(); self.send_json({"ok":True}); return
            self.send_response(404); self.end_headers()
        except (TypeError,ValueError) as e:
            self.send_json({"ok":False,"error":str(e)},400)
    def log_message(self,fmt,*args):
        pass

def main():
    check_engines()
    server=ThreadingHTTPServer(("127.0.0.1",8765),Handler)
    url="http://127.0.0.1:8765/"
    log(f"ForgeBoss dashboard listening at {url}")
    threading.Timer(.8,lambda:webbrowser.open(url)).start()
    try: server.serve_forever()
    except KeyboardInterrupt: pass

if __name__=="__main__": main()
