from __future__ import annotations
import json, os, sys, threading, time, subprocess, traceback, ctypes, uuid
from pathlib import Path


# Windows-safe logging/output: avoid locale charmap crashes on Unicode text.
def owner_status(st):
    if not isinstance(st,dict): return owner_status(st)
    out=dict(st)
    out["stage"]=st.get("ops_label") or st.get("stage","IDLE")
    out["message"]=st.get("ops_detail") or st.get("message","")
    return out

def _force_utf8_stdio():
    import sys
    for stream_name in ("stdout","stderr"):
        stream=getattr(sys,stream_name,None)
        if stream is not None and hasattr(stream,"reconfigure"):
            try: stream.reconfigure(encoding="utf-8",errors="replace")
            except Exception: pass
_force_utf8_stdio()

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
CREATE_NO_WINDOW=getattr(subprocess,"CREATE_NO_WINDOW",0)

def msgbox(text,title="ForgeBoss",flags=0x40):
    try: ctypes.windll.user32.MessageBoxW(None,text,title,flags)
    except Exception: pass

def confirmbox(text,title="ForgeBoss"):
    """Native OS confirmation. Returns True only when the human presses Yes."""
    try:
        # MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2
        return ctypes.windll.user32.MessageBoxW(None,text,title,0x04|0x20|0x100)==6
    except Exception:
        return False

def ensure_webview():
    try:
        import webview
        return webview
    except Exception:
        py=Path.home()/".forgeboss"/"runtime"/"venv"/"Scripts"/"python.exe"
        if not py.exists(): py=Path(sys.executable)
        msgbox("ForgeBoss is completing a one-time desktop UI setup.\n\nNo AI calls. No GitHub writes.\n\nForgeBoss will open automatically when setup finishes.","ForgeBoss setup")
        p=subprocess.run([str(py),"-m","pip","install","--disable-pip-version-check","--quiet","pywebview>=5.4,<7"],
                         capture_output=True,text=True,creationflags=CREATE_NO_WINDOW,timeout=600)
        if p.returncode:
            msgbox("ForgeBoss desktop UI setup failed.\n\n"+(p.stderr[-1200:] or "pip install failed"),"ForgeBoss",0x10)
            raise SystemExit(3)
        import webview
        return webview

sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(HERE))
import server as fb
from forgeboss.control.self_build_preflight import self_build_preflight,concise_blockers,self_build_session_plan
from forgeboss.control.self_build_session_evidence import canonical_digest,evaluate_p0_session
from forgeboss.protected_authority.client import ProtectedAuthorityClient
from forgeboss.control.self_build_launcher import SelfBuildLauncher,SelfBuildLaunchError
from forgeboss.control.process_supervisor import ProcessSupervisor

def safe_json(path:Path):
    try:return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:return {}

def dedupe_events(events):
    out=[]
    for e in events:
        if out and out[-1].get("msg")==e.get("msg") and out[-1].get("detail")==e.get("detail"):
            continue
        out.append(e)
    return out

def canonical_activity_label(text):
    low=str(text or "").lower()
    if "budget preflight stop" in low or "budget blocked" in low:return "BUDGET BLOCKED - $0 SPENT"
    if "next packet could not be built" in low or "retained local commit" in low:return "MISSION BLOCKED"
    if "patch_contract_invalid" in low or "patch_candidate_invalid" in low or "patch_anchor_intent_mismatch" in low or "patch_line_range_too_wide" in low or "patch_context_mismatch" in low or "patch_contract_invalid" in low or "patch_precondition_failed" in low or "ambiguous_edit_anchor" in low or "stale_file" in low:return "PATCH REJECTED"
    if "partial win" in low:return "PARTIAL WIN"
    if "next target" in low:return "NEXT TARGET"
    if "target acquired" in low:return "TARGET ACQUIRED"
    if "root cause found" in low:return "ROOT CAUSE FOUND"
    if "repair in progress" in low:return "REPAIR IN PROGRESS"
    if "[fail]" in low:
        if "full_postgres_suite" in low or "40001" in low or "40p01" in low or "production_http" in low or "travis_intake" in low or "business_invitations" in low:
            return "NEXT TARGET FOUND"
        return "VALIDATION HIT BACK"
    if "worker crash" in low or "infra_error" in low or "infrastructure" in low:return "FORGEBOSS FAULT"
    return None

def friendly_activity(text):
    """Compact owner timeline. Raw attempt/round/test lines stay available in technical drill-down."""
    lines=[x.strip() for x in str(text or "").splitlines() if x.strip()]
    raw=[]
    for line in lines[-500:]:
        m=re.match(r'(?:(\d\d:\d\d:\d\d)\s+)?(.*)',line)
        ts=(m.group(1) or "") if m else ""
        x=(m.group(2) if m else line).strip()
        raw.append((ts,x,x.lower()))

    events=[]
    # Collapse startup/selftest flood into one card.
    startup_markers=("selftest","compiles passed","focused env passed","memory env passed",
                     "focused output cap passed","full historical payload omitted focused passed",
                     "reference pack omitted focused passed","funnel hard char cap passed",
                     "no blind retry passed","agency core team passed","deep agents security passed",
                     "controller selftest passed")
    startup=[(ts,x) for ts,x,low in raw if any(k in low for k in startup_markers)]
    startup_fail=[x for _,x,low in raw if any(k in low for k in startup_markers) and ("[fail]" in low or " failed" in low)]
    if startup:
        if startup_fail:
            events.append({"time":startup[-1][0],"message":"PRE-FLIGHT BLOCKED","detail":f"{len(startup)-len(startup_fail)}/{len(startup)} checks passed. Click for technical details.","kind":"warn","key":"preflight"})
        else:
            events.append({"time":startup[-1][0],"message":"LOCKED AND LOADED","detail":f"{len(startup)}/{len(startup)} ForgeBoss systems passed. Click for technical details.","kind":"ok","key":"preflight"})

    # Collapse internal attempt/round checks into validation batches.
    batch_pass=[]; batch_fail=[]
    for ts,x,low in raw:
        internal=("attempt " in low and " round " in low)
        if internal and ("[pass]" in low or " passed" in low):
            batch_pass.append((ts,x))
            continue
        if internal and ("[fail]" in low or " failed" in low):
            batch_fail.append((ts,x))
            continue

        msg=detail=kind=key=None
        if "repair rat learned hit" in low:
            msg="REPAIR RAT KNEW THIS";detail="A validated local lesson matched current evidence and source; trying the repair for $0 API cost.";kind="active";key="memory"
        elif "target acquired" in low:
            msg="TARGET ACQUIRED"; detail=x.split(":",1)[1].strip()[:260] if ":" in x else x[:260];kind="active";key="target"
        elif "repair in progress" in low:
            msg="REPAIR IN PROGRESS";detail=x.split(":",1)[1].strip()[:260] if ":" in x else x[:260];kind="active";key="repair"
        elif "validating hit" in low or "running acceptance" in low:
            msg="VALIDATING";detail="ForgeBoss is proving the candidate against focused and broad checks.";kind="active";key="validation"
        elif "partial win" in low:
            msg="PARTIAL WIN";detail=x.split(":",1)[1].strip()[:260] if ":" in x else x[:260];kind="ok";key="partial"
        elif "next target" in low:
            msg="NEXT TARGET";detail=x.split(":",1)[1].strip()[:260] if ":" in x else x[:260];kind="active";key="next"
        elif "budget preflight stop" in low or "budget blocked" in low:
            msg="BUDGET BLOCKED - $0 SPENT";detail=x[:260];kind="warn";key="budget"
        elif "patch_precondition_failed" in low or "ambiguous_edit_anchor" in low or "stale_file" in low:
            msg="PATCH REJECTED";detail=x[:260];kind="warn";key="patch"
        elif "worker crash" in low or "infra_error" in low or "forgeboss fault" in low:
            msg="FORGEBOSS FAULT";detail=x[:260];kind="warn";key="infra"
        elif "owner requested safe stop" in low:
            msg="SAFE STOP REQUESTED";detail="ForgeBoss will finish the current atomic operation and start no new work.";kind="warn";key="stop"
        elif "cycle cost" in low:
            mm=re.search(r'\$[0-9.]+',x);msg="AI COST UPDATED";detail=(mm.group(0)+" this cycle" if mm else "Usage recorded.");kind="money";key="cost"
        if msg:
            item={"time":ts,"message":msg,"detail":detail,"kind":kind,"key":key or "activity"}
            if not events or events[-1]["message"]!=msg:events.append(item)

    if batch_pass:
        # Show one useful aggregate rather than attempt/round spam.
        events.append({"time":batch_pass[-1][0],"message":"VALIDATION SWEEP","detail":f"{len(batch_pass)} internal checks passed. Raw attempt/round results are in technical details.","kind":"ok","key":"validation"})
    if batch_fail:
        broad=sum(1 for _,x in batch_fail if "full_postgres_suite" in x.lower() or "40001" in x.lower() or "40p01" in x.lower())
        if broad:
            events.append({"time":batch_fail[-1][0],"message":"NEXT TARGET FOUND","detail":f"{broad} broad PostgreSQL validation runs exposed remaining SiteBoss behavior.","kind":"warn","key":"validation"})
        else:
            events.append({"time":batch_fail[-1][0],"message":"VALIDATION HIT BACK","detail":f"{len(batch_fail)} validation checks still fail.","kind":"warn","key":"validation"})

    # Active heartbeat if run is live and latest owner event is stale.
    try:
        st=fb.load_status()
        if st.get("running"):
            stage=str(st.get("ops_label") or st.get("stage") or "").upper()
            if stage in ("TARGET ACQUIRED","REPAIR IN PROGRESS","VALIDATING","VALIDATING HIT","NEXT TARGET","SCANNING TARGET","LIVE_WORKLOAD"):
                events.append({"time":"","message":"WORKING NOW","detail":st.get("ops_detail") or st.get("message") or "ForgeBoss is actively working; waiting for the next bounded result.","kind":"active","key":"heartbeat"})
    except Exception:
        pass
    return events[-12:]

import re

DASH_STATE_ROOT=Path(os.environ.get("FORGEBOSS_STATE_ROOT") or (ROOT/"state")).expanduser().resolve()
SETTINGS_PATH=DASH_STATE_ROOT/"dashboard"/"owner-settings.json"
def load_settings():
 d={"merge_enabled":False,"deploy_enabled":False,"daily_budget_usd":10.0,"risk_mode":"conservative","require_review":True}
 try:
  if SETTINGS_PATH.exists():d.update(json.loads(SETTINGS_PATH.read_text()))
 except:pass
 return d
def save_settings_file(x):
 d=load_settings();d.update({k:v for k,v in x.items() if k in d});SETTINGS_PATH.parent.mkdir(parents=True,exist_ok=True);SETTINGS_PATH.write_text(json.dumps(d,indent=2));return d
def tasks():
 out=[];p=Path.home()/".siteboss"/"autopilot"/"controller-state"/"packet-latest.json"
 if p.exists():
  j=safe_json(p);out.append({"id":j.get("packet_id","CURRENT"),"title":j.get("objective","Current SiteBoss task"),"status":"READY","scope":len(j.get("allowed_files",[])),"head":j.get("expected_head_revision","")[:12]})
 return out
def costs():
 items=[];total=0.0
 p=ROOT/"state"/"tournament"/"paid-tournament-last.json"
 if p.exists():
  for x in safe_json(p).get("results",[]):
   c=x.get("reported_cost_usd")
   if c is not None:c=float(c);total+=c;items.append({"source":x.get("executor"),"cost":c})
 p=ROOT/"state"/"league"/"league-last.json"
 if p.exists():
  c=safe_json(p).get("reported_measured_spend_usd")
  if c is not None:c=float(c);total+=c;items.append({"source":"Category league","cost":c})
 return {"known_total":round(total,4),"items":items}
def project_profiles_snapshot():
    try:
        from forgeboss.control.projects import list_profiles
        return list_profiles()
    except Exception:
        return []

def forgebossd_health():
    try:
        from forgeboss.control.client import Client
        c=Client(timeout=0.5)
        try:
            h=c.call("health")
            return {"ready":True,"status":h.get("status"),"schemaVersion":h.get("state",{}).get("schemaVersion",1)}
        finally:c.close()
    except Exception as e:
        return {"ready":False,"status":"OFFLINE","detail":str(e)[:160]}

SELECTED_PROJECT_PATH=DASH_STATE_ROOT/"dashboard"/"selected-project.json"
SELF_BUILD_EVIDENCE_ROOT=DASH_STATE_ROOT/"dashboard"/"self-build-sessions"
from forgeboss.control.project_intake import detect_project_source,load_selected_project as _load_selected_project,save_selected_project as _save_selected_project

def load_selected_project():
    return _load_selected_project(SELECTED_PROJECT_PATH)

def save_selected_project(data):
    return _save_selected_project(SELECTED_PROJECT_PATH,data)

class Api:
    def __init__(self):
        self._probe_lock=threading.Lock()
        self._engine_cache={}
        self._last_probe=0.0
        self._self_build_lock=threading.RLock()
        self._self_build_launcher=None
        self._self_build_runs={}
        self._self_build_sessions={}

    def _session_public_record_locked(self,session_id):
        session=self._self_build_sessions.get(session_id)
        if not session:return None
        rows=[]
        for run_id in list(session.get("runs") or []):
            state=self._self_build_runs.get(run_id) or {}
            prepared=state.get("prepared") or {}
            finish=state.get("finish") or {}
            successor=finish.get("successor") or {}
            activation_raw=state.get("activation") or {}
            activation=activation_raw.get("result") if isinstance(activation_raw,dict) else {}
            if not isinstance(activation,dict):activation={}
            activation_authority={k:v for k,v in activation_raw.items() if k!="result"} if isinstance(activation_raw,dict) and activation else None
            proof_raw=state.get("rollback_proof") or {}
            proof=proof_raw.get("result") if isinstance(proof_raw,dict) else {}
            if not isinstance(proof,dict):proof={}
            proof_authority={k:v for k,v in proof_raw.items() if k!="result"} if isinstance(proof_raw,dict) and proof else None
            rows.append({
                "cycle_index":int(state.get("cycle_index") or 0),
                "run_id":run_id,
                "base_revision":str(prepared.get("base_sha") or "").lower(),
                "source_root":str(prepared.get("source_root") or ""),
                "successor_sha":str(successor.get("successor_sha") or "").lower(),
                "successor_manifest_sha256":str(successor.get("manifest_sha256") or "").lower(),
                "phase":state.get("phase"),"error":state.get("error"),
                "activation":activation or None,
                "activation_authority":activation_authority,
                "rollback_proof":proof or None,
                "rollback_proof_authority":proof_authority,
            })
        proof=None;proof_authority=None
        proof_run=session.get("rollback_proof_run_id")
        if proof_run:
            for row in rows:
                if row.get("run_id")==proof_run and isinstance(row.get("rollback_proof"),dict):
                    proof=row["rollback_proof"];proof_authority=row.get("rollback_proof_authority");break
        record={
            "schema":1,"session_id":session_id,"proof_mode":bool(session.get("proof_mode")),
            "phase":session.get("phase"),"cycle_target":int(session.get("cycle_target") or 0),
            "current_cycle":int(session.get("current_cycle") or 0),
            "completed_cycles":int(session.get("completed_cycles") or 0),
            "session_budget_usd":f"{float(session.get('session_budget_usd') or 0):.2f}",
            "reserved_cap_usd":f"{float(session.get('reserved_cap_usd') or 0):.2f}",
            "stop_requested":bool(session.get("stop_requested")),"error":session.get("error"),
            "runs":rows,"rollback_proof":proof,"rollback_proof_authority":proof_authority,
            "final_known_good":session.get("final_known_good"),
            "final_known_good_authority":session.get("final_known_good_authority"),
        }
        core=dict(record);record["session_record_digest"]=canonical_digest(core)
        return record

    def _persist_self_build_session(self,session_id,*,evaluate=False):
        with self._self_build_lock:
            record=self._session_public_record_locked(session_id)
            if record is None:return None
            if evaluate:
                record["p0_evaluation"]=evaluate_p0_session(record)
            root=SELF_BUILD_EVIDENCE_ROOT
            root.mkdir(parents=True,exist_ok=True)
            target=root/f"{session_id}.json";tmp=root/f".{session_id}.{uuid.uuid4().hex}.tmp"
            raw=json.dumps(record,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n"
            with tmp.open("w",encoding="utf-8",newline="\n") as fh:
                fh.write(raw);fh.flush();os.fsync(fh.fileno())
            os.replace(tmp,target)
            if os.name!="nt":
                try:
                    fd=os.open(str(root),os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
                    try:os.fsync(fd)
                    finally:os.close(fd)
                except OSError:pass
            return {"path":str(target.resolve()),"record":record}

    def _get_self_build_launcher(self,client):
        with self._self_build_lock:
            terminal={"COMPLETE","FAILED","SAFE_STOPPED","PREFLIGHT_BLOCKED"}
            active=any(str(x.get("phase") or "") not in terminal for x in self._self_build_sessions.values())
            if self._self_build_launcher is None or not active:
                self._self_build_launcher=SelfBuildLauncher(
                    client=client,
                    supervisor=ProcessSupervisor(),
                    state_root=DASH_STATE_ROOT,
                )
            return self._self_build_launcher

    def _session_stop_requested(self,session_id):
        with self._self_build_lock:
            session=self._self_build_sessions.get(session_id)
            return session is None or bool(session.get("stop_requested"))

    def _revoke_prepared_unlaunched(self,client,prepared,reason):
        for item in list(prepared.get("builders") or []):
            try:
                client.revoke_self_build_worker(
                    run_id=prepared["run_id"],task_id=item["task_id"],
                    worker_run_id=item["authority"]["run_id"],owner_epoch=item["owner_epoch"],
                    reason=reason,
                )
            except Exception as e:
                fb.log(f"SELF-BUILD PRELAUNCH REVOKE FAILED {item.get('builder_id')}: {e}")

    def _launch_self_build_cycle(self,session_id,cycle_index):
        with self._self_build_lock:
            session=self._self_build_sessions.get(session_id)
            if not session or session.get("stop_requested"):
                return None
            client=session["client"];launcher=session["launcher"];plan=dict(session["plan"])
            target=int(plan["cycle_target"]);budget=float(plan["session_budget_usd"])
        if not 1<=int(cycle_index)<=target:
            raise RuntimeError("self-build cycle index exceeds owner-authorized session target")
        reserved_before=(int(cycle_index)-1)*float(plan["per_cycle_cap_usd"])
        remaining=budget-reserved_before
        if remaining+1e-9<float(plan["per_cycle_cap_usd"]):
            raise RuntimeError("self-build session budget exhausted before next protected cycle")

        known_good_response=client.self_build_current_known_good()
        known_good=known_good_response.get("result") or {}
        source_root=known_good.get("code_root")
        if not source_root:
            raise RuntimeError("protected current known-good source is unavailable")
        preflight=self_build_preflight(
            source_root,running_root=ROOT,requested_budget_usd=remaining,
            env=os.environ,authoritative_known_good=known_good,
        )
        if not preflight.get("ready"):
            message="ForgeBoss self-build preflight blocked: "+concise_blockers(preflight)
            with self._self_build_lock:
                session=self._self_build_sessions.get(session_id)
                if session:
                    session["phase"]="PREFLIGHT_BLOCKED"
                    session["error"]=message
                    session["stop_requested"]=True
            self._persist_self_build_session(session_id)
            raise RuntimeError(message)
        if self._session_stop_requested(session_id):
            return None

        run_id=f"fl1-{session_id[-8:]}-c{int(cycle_index)}-{uuid.uuid4().hex[:6]}"
        response=client.prepare_self_build(
            source_root=source_root,base_sha=preflight["known_good_sha"],run_id=run_id,
        )
        prepared=response.get("result") or {}
        if self._session_stop_requested(session_id):
            self._revoke_prepared_unlaunched(client,prepared,"owner safe stop before paid cycle launch")
            return None

        with self._self_build_lock:
            session=self._self_build_sessions.get(session_id)
            if not session or session.get("stop_requested"):
                self._revoke_prepared_unlaunched(client,prepared,"owner safe stop before paid cycle launch")
                return None
            launched=launcher.launch_initial(prepared)
            self._self_build_runs[run_id]={
                "client":client,"launcher":launcher,"prepared":prepared,
                "launched":launched,"phase":"TWO_BUILDERS_RUNNING",
                "stop_requested":False,"error":None,"session_id":session_id,
                "cycle_index":int(cycle_index),"cycle_target":target,
                "session_budget_usd":budget,
            }
            session.setdefault("runs",[]).append(run_id)
            session["current_run_id"]=run_id
            session["current_cycle"]=int(cycle_index)
            session["reserved_cap_usd"]=int(cycle_index)*float(plan["per_cycle_cap_usd"])
            session["phase"]="TWO_BUILDERS_RUNNING"
        self._persist_self_build_session(session_id)
        fb.log(f"SELF-BUILD CYCLE {cycle_index}/{target} TWO BUILDERS RUNNING run={run_id} base={preflight['known_good_sha']} session={session_id}")
        threading.Thread(target=self._mandatory_b2,args=(run_id,),daemon=True).start()
        return {"run_id":run_id,"preflight":preflight,"launched":launched,"known_good":known_good}

    def _mandatory_b2(self,run_id):
        # First-run proof only: after durable simultaneous RUNNING evidence,
        # deliberately stop B, revoke its authority, prepare a fresh B2 task,
        # and launch B2 from the exact known-good base.
        try:
            time.sleep(2.0)
            with self._self_build_lock:
                state=self._self_build_runs.get(run_id)
                if not state or state.get("stop_requested"):return
                launcher=state["launcher"];prepared=state["prepared"];launched=state["launched"];client=state["client"]
                session_id=state.get("session_id");cycle_index=int(state.get("cycle_index") or 1);cycle_target=int(state.get("cycle_target") or 1)
            launcher.stop_worker(
                prepared_run=prepared,launched_run=launched,builder_id="builder-b",
                reason="mandatory Finish Line 1 stop/reassign proof",
            )
            response=client.prepare_self_build_replacement(run_id=run_id)
            replacement=response.get("result") or {}
            with self._self_build_lock:
                state=self._self_build_runs.get(run_id)
                if not state or state.get("stop_requested"):return
                prepared["replacement"]=replacement
                state["phase"]="B_REVOKED_B2_PREPARED"
            launched2=launcher.launch_replacement(prepared,replacement,launched)
            with self._self_build_lock:
                state=self._self_build_runs.get(run_id)
                if state:
                    state["launched"]=launched2
                    state["phase"]="B2_RUNNING"
            fb.log(f"SELF-BUILD B2 RUNNING run={run_id} task={replacement.get('task_id')}")

            def stop_requested():
                with self._self_build_lock:
                    current=self._self_build_runs.get(run_id)
                    run_stop=current is None or bool(current.get("stop_requested"))
                    session=self._self_build_sessions.get(session_id) if session_id else None
                    session_stop=bool(session_id and (session is None or session.get("stop_requested")))
                    return run_stop or session_stop
            finished=launcher.finish_review_accept_compose(
                prepared_run=prepared,launched_run=launched2,
                builder_ids=("builder-a","builder-b2"),stop_requested=stop_requested,
                timeout=1200.0,poll_seconds=0.5,
            )
            successor=finished.get("successor") or {}
            with self._self_build_lock:
                state=self._self_build_runs.get(run_id)
                if state:
                    state["finish"]=finished
                    state["phase"]="SUCCESSOR_COMPOSED"
                    state["next_cycle_source"]=successor.get("workspace")
                    state["error"]=None
            fb.log(f"SELF-BUILD SUCCESSOR COMPOSED run={run_id} sha={successor.get('successor_sha')} awaiting activation")
            if stop_requested():
                with self._self_build_lock:
                    state=self._self_build_runs.get(run_id)
                    if state:state["phase"]="SUCCESSOR_COMPOSED_STOPPED_BEFORE_ACTIVATION"
                fb.log(f"SELF-BUILD STOPPED BEFORE ACTIVATION run={run_id}")
                return
            activation=launcher.activate_composed_successor(run_id=run_id)
            activated=activation.get("result") or {}
            with self._self_build_lock:
                state=self._self_build_runs.get(run_id)
                if state:
                    state["activation"]=activation
                    state["phase"]="SUCCESSOR_ACTIVATED"
                    state["error"]=None
            fb.log(f"SELF-BUILD SUCCESSOR ACTIVATED run={run_id} sha={activated.get('successor_sha')} status={activated.get('status')}")
            with self._self_build_lock:
                session=self._self_build_sessions.get(session_id) if session_id else None
                proof_due=bool(session and session.get("proof_mode") and cycle_index==1 and not session.get("rollback_proven"))
            if proof_due and not stop_requested():
                fb.log(f"SELF-BUILD P0 ROLLBACK DRILL START session={session_id} run={run_id} new_ai_spend=$0")
                proof_response=client.prove_self_build_activation_rollback(run_id=run_id)
                proof=proof_response.get("result") or {}
                if proof.get("status")!="ROLLBACK_PROVEN":
                    raise RuntimeError("protected rollback drill did not return ROLLBACK_PROVEN")
                with self._self_build_lock:
                    state=self._self_build_runs.get(run_id)
                    if state:state["rollback_proof"]=proof_response
                    session=self._self_build_sessions.get(session_id) if session_id else None
                    if session:
                        session["rollback_proven"]=True
                        session["rollback_proof_run_id"]=run_id
                        session["phase"]="ROLLBACK_PROVEN"
                self._persist_self_build_session(session_id)
                fb.log(f"SELF-BUILD P0 ROLLBACK PROVEN session={session_id} broken={proof.get('broken_candidate_sha')} restored={proof.get('pointer_revision')}")
            next_cycle=None
            with self._self_build_lock:
                session=self._self_build_sessions.get(session_id) if session_id else None
                if session:
                    session["completed_cycles"]=max(int(session.get("completed_cycles") or 0),cycle_index)
                    session["phase"]="CYCLE_ACTIVATED"
                    session["last_activation"]=activated
                    should_continue=(not session.get("stop_requested")) and cycle_index<cycle_target
                else:
                    should_continue=False
            if should_continue:
                next_cycle=self._launch_self_build_cycle(session_id,cycle_index+1)
                if next_cycle is None:
                    fb.log(f"SELF-BUILD SESSION STOPPED BEFORE CYCLE {cycle_index+1} session={session_id}")
                else:
                    fb.log(f"SELF-BUILD NEXT CYCLE STARTED session={session_id} cycle={cycle_index+1}/{cycle_target} run={next_cycle['run_id']}")
            else:
                final_known_good=None
                with self._self_build_lock:
                    session=self._self_build_sessions.get(session_id) if session_id else None
                    complete=bool(session and not session.get("stop_requested"))
                if complete:
                    final_response=client.self_build_current_known_good()
                    final_known_good=final_response.get("result") or {}
                    final_authority={k:v for k,v in final_response.items() if k!="result"} if isinstance(final_response,dict) else None
                    with self._self_build_lock:
                        session=self._self_build_sessions.get(session_id)
                        if session:
                            session["final_known_good"]=final_known_good
                            session["final_known_good_authority"]=final_authority
                            session["phase"]="COMPLETE"
                    saved=self._persist_self_build_session(session_id,evaluate=bool(session and session.get("proof_mode")))
                    evaluation=((saved or {}).get("record") or {}).get("p0_evaluation") if saved else None
                    if evaluation is not None:
                        with self._self_build_lock:
                            session=self._self_build_sessions.get(session_id)
                            if session:
                                session["p0_evaluation"]=evaluation
                                session["evidence_path"]=(saved or {}).get("path")
                                if evaluation.get("status")=="PASS":
                                    session["phase"]="P0_PROOF_PASS"
                                else:
                                    session["phase"]="P0_PROOF_FAILED"
                                    session["error"]="P0 proof evidence failed closed"
                                    session["stop_requested"]=True
                        self._persist_self_build_session(session_id,evaluate=True)
                        fb.log(f"SELF-BUILD P0 PROOF {evaluation.get('status')} session={session_id} evidence={evaluation.get('evidence_digest')}")
                    if session_id:
                        fb.log(f"SELF-BUILD SESSION COMPLETE session={session_id} cycles={cycle_index}/{cycle_target} final={final_known_good.get('revision')}")
        except Exception as e:
            with self._self_build_lock:
                state=self._self_build_runs.get(run_id)
                if state:
                    state["phase"]="SELF_BUILD_FAILED"
                    state["error"]=str(e)
                    sid=state.get("session_id")
                    session=self._self_build_sessions.get(sid) if sid else None
                    if session:
                        session["phase"]="FAILED"
                        session["error"]=str(e)
                        session["stop_requested"]=True
            if state and state.get("session_id"):
                try:self._persist_self_build_session(state.get("session_id"))
                except Exception as persist_error:fb.log(f"SELF-BUILD EVIDENCE PERSIST FAILED run={run_id}: {persist_error}")
            fb.log(f"SELF-BUILD FAILED run={run_id}: {e}")

    def _probe(self):
        if time.time()-self._last_probe < 25:return
        if not self._probe_lock.acquire(blocking=False):return
        def run():
            try:self._engine_cache=fb.check_engines()
            except Exception:pass
            finally:
                self._last_probe=time.time()
                self._probe_lock.release()
        threading.Thread(target=run,daemon=True).start()

    def get_snapshot(self):
        self._probe()
        s=fb.load_status()
        s["engines"]=self._engine_cache
        log=fb.LOG.read_text(encoding="utf-8",errors="replace")[-50000:] if fb.LOG.exists() else ""
        s["activity"]=friendly_activity(log)

        rp=ROOT/"state"/"tournament"/"retest-last.json"
        r=safe_json(rp) if rp.exists() else {}
        rows={x.get("executor"):x for x in r.get("results",[])}
        def rr(name):
            x=rows.get(name,{})
            if not x:return {"status":"NO RESULT","failures":None}
            if x.get("missing"):return {"status":"MISSING","failures":None}
            failures=x.get("failure_count")
            validation=x.get("validation") or {}
            runs=validation.get("runs") or []
            if failures==999 and not runs:
                return {"status":"VALIDATOR ERROR","failures":999}
            return {"status":"PASS" if x.get("acceptance_passed") else "FAIL","failures":failures}
        s["retest"]={"mini-swe":rr("mini-swe"),"openhands":rr("openhands"),"winner":r.get("winner"),"new_spend":0.0}

        lp=ROOT/"state"/"league"/"league-last.json"
        league=safe_json(lp) if lp.exists() else {}
        s["league"]={"winners":league.get("winners",{}),"spend":league.get("reported_measured_spend_usd")}
        s["owner_settings"]=load_settings();s["tasks"]=tasks();s["costs"]=costs()
        s["forgebossd"]=forgebossd_health()
        s["project_profiles"]=project_profiles_snapshot()
        s["selected_project"]=load_selected_project()
        with self._self_build_lock:
            sessions=list(self._self_build_sessions.values())
            if sessions:
                latest=sessions[-1]
                s["self_build_session"]={k:latest.get(k) for k in (
                    "session_id","phase","cycle_target","current_cycle","completed_cycles",
                    "session_budget_usd","reserved_cap_usd","current_run_id","stop_requested","error",
                    "proof_mode","rollback_proven","rollback_proof_run_id","evidence_path","p0_evaluation"
                )}
        return s

    def set_safety_toggle(self,name,value):
        if name not in ("merge_enabled","deploy_enabled"):return {"ok":False}
        st=save_settings_file({name:bool(value)});fb.log(f"OWNER setting: {name}={'ON' if value else 'OFF'}")
        return {"ok":True,"settings":st}
    def save_settings(self,x):
        return {"ok":True,"settings":save_settings_file(x)}
    def get_event_details(self,key):
        """Read-only technical drill-down for a friendly activity event."""
        chunks=[]
        if key=="retest":
            rp=ROOT/"state"/"tournament"/"retest-last.json"
            if rp.exists():
                try:
                    j=json.loads(rp.read_text(encoding="utf-8-sig"))
                    chunks.append("=== CANDIDATE RE-TEST RESULT ===\n"+json.dumps(j,indent=2))
                    for row in j.get("results",[]):
                        w=row.get("workspace")
                        if not w: continue
                        wp=Path(w)
                        if not wp.exists(): continue
                        try:
                            p=subprocess.run(["git.exe","diff","--no-ext-diff","--unified=80"],
                                cwd=wp,capture_output=True,text=True,timeout=60,creationflags=CREATE_NO_WINDOW)
                            diff=(p.stdout or "").strip()
                            if diff:
                                chunks.append(f"\n\n=== {row.get('executor','worker').upper()} CODE DIFF ===\n{diff}")
                        except Exception as e:
                            chunks.append(f"\n\n=== {row.get('executor','worker').upper()} CODE DIFF ===\nCould not read diff: {e}")
                        try:
                            val=row.get("validation") or {}
                            if val:
                                chunks.append(f"\n\n=== {row.get('executor','worker').upper()} VALIDATION ===\n"+json.dumps(val,indent=2))
                        except Exception:
                            pass
                except Exception as e:
                    chunks.append("Could not read re-test evidence: "+str(e))
            else:
                chunks.append("No saved re-test evidence exists yet.")
        else:
            try:
                raw=fb.LOG.read_text(encoding="utf-8",errors="replace")[-30000:] if fb.LOG.exists() else ""
                chunks.append("=== RECENT FORGEBOSS TECHNICAL LOG ===\n"+raw)
            except Exception as e:
                chunks.append("Could not read activity log: "+str(e))
        return {"ok":True,"text":"".join(chunks)}

    def get_last_run_report(self):
        st=fb.load_status()
        meta=st.get("last_run_report") or st.get("last_cycle_report") or {}
        p=meta.get("text")
        if not p:
            reason=st.get("last_refusal_reason") or st.get("message")
            if reason:return {"ok":True,"text":"FORGEBOSS LIVE DIAGNOSIS\n"+"="*72+"\n\n"+str(reason)}
            return {"ok":False,"text":"No run diagnosis exists yet."}
        try:return {"ok":True,"text":Path(p).read_text(encoding="utf-8")}
        except Exception as e:return {"ok":False,"text":"Could not read run report: "+str(e)}

    def publish_last_run_report(self):
        meta=fb.load_status().get("last_run_report") or {}
        if not meta:return {"ok":False,"message":"No completed run report exists yet."}
        if not confirmbox(
            "Publish the SANITISED findings summary to the authoritative GitHub root PR?\n\n"
            "This does NOT push failed candidate code, merge, deploy, or force-push.\n\n"
            "Choose Yes to authorize this one publication.",
            "ForgeBoss - Publish Findings"
        ):
            return {"ok":False,"cancelled":True,"message":"Owner cancelled GitHub publication."}
        return fb.publish_run_report_to_github(meta,owner_confirmed=True,automated=False)

    def attach_project(self,source_path):
        try:
            selected=detect_project_source(source_path)
            selected["selected_at"]=time.time()
            save_selected_project(selected)
            fb.log("OWNER selected self-build project: "+selected["source_path"])
            return {"ok":True,"project":selected}
        except Exception as e:
            return {"ok":False,"message":str(e)}

    def clear_project(self):
        try: SELECTED_PROJECT_PATH.unlink(missing_ok=True)
        except Exception: pass
        return {"ok":True}

    def start_build(self,settings):
        session_id=None
        try:
            selected=load_selected_project()
            budget=float(settings.get("budget_usd",3.0))
            if selected and selected.get("project_id")=="forgeboss":
                plan=self_build_session_plan(budget)
                proof_mode=bool(settings.get("p0_three_cycle_proof",False))
                if proof_mode and int(plan["cycle_target"])!=3:
                    return {"ok":False,"blocked":True,"phase":"PROOF_BUDGET_BLOCKED","message":"P0 three-cycle proof mode requires at least $6.00 owner budget so all three $2.00 protected cycle caps are reserved."}
                with self._self_build_lock:
                    terminal={"COMPLETE","FAILED","SAFE_STOPPED"}
                    active=[x for x in self._self_build_sessions.values() if str(x.get("phase") or "") not in terminal]
                    if active:
                        return {"ok":False,"blocked":True,"phase":"SELF_BUILD_SESSION_ACTIVE","message":"A ForgeBoss self-build session is already active. Stop it safely or let it finish before starting another."}
                client=ProtectedAuthorityClient.from_environment(os.environ,timeout=180.0)
                launcher=self._get_self_build_launcher(client)
                session_id="fl1s-"+uuid.uuid4().hex[:12]
                with self._self_build_lock:
                    self._self_build_sessions[session_id]={
                        "session_id":session_id,"client":client,"launcher":launcher,"plan":plan,
                        "cycle_target":int(plan["cycle_target"]),"current_cycle":0,"completed_cycles":0,
                        "session_budget_usd":float(plan["session_budget_usd"]),"reserved_cap_usd":0.0,
                        "current_run_id":None,"runs":[],"phase":"STARTING","stop_requested":False,"error":None,
                        "proof_mode":proof_mode,"rollback_proven":False,"rollback_proof_run_id":None,
                        "final_known_good":None,"final_known_good_authority":None,"evidence_path":None,"p0_evaluation":None,
                    }
                self._persist_self_build_session(session_id)
                first=self._launch_self_build_cycle(session_id,1)
                if first is None:
                    return {"ok":False,"cancelled":True,"phase":"SAFE_STOPPED","message":"Self-build stopped before paid launch."}
                return {
                    "ok":True,"launched":True,"phase":"TWO_BUILDERS_RUNNING",
                    "run_id":first["run_id"],"session_id":session_id,
                    "cycle_target":int(plan["cycle_target"]),
                    "message":f"ForgeBoss self-build session started. Up to {plan['cycle_target']} cycle(s) authorized by the owner budget; each cycle is capped at $2.00."+(" P0 proof mode will run one $0 deliberate activation rollback drill after cycle 1." if proof_mode else ""),
                    "preflight":first["preflight"],
                    "concurrent_proof":first["launched"].get("concurrent_proof"),
                    "session_plan":plan,
                }
            duration_mode=str(settings.get("duration_mode","timed"))
            duration=int(settings.get("duration_minutes",120)) if duration_mode!="until-stopped" else 120
            ok,msg=fb.start_session({"duration_minutes":duration,"duration_mode":duration_mode,"budget_usd":budget,"workers":1,"mode":settings.get("mode","cost-optimized")})
            return {"ok":ok,"message":msg}
        except Exception as e:
            if session_id:
                with self._self_build_lock:
                    session=self._self_build_sessions.get(session_id)
                    if session:
                        session["phase"]="FAILED";session["error"]=str(e);session["stop_requested"]=True
                try:self._persist_self_build_session(session_id)
                except Exception as persist_error:fb.log(f"SELF-BUILD EVIDENCE PERSIST FAILED session={session_id}: {persist_error}")
            return {"ok":False,"message":str(e)}

    def safe_stop(self):
        stopped=[]
        with self._self_build_lock:
            runs=list(self._self_build_runs.items())
            for _,state in runs:state["stop_requested"]=True
            for session in self._self_build_sessions.values():
                session["stop_requested"]=True
                session["phase"]="SAFE_STOP_REQUESTED"
        for run_id,state in runs:
            launcher=state["launcher"];prepared=state["prepared"];launched=state["launched"]
            try:status=launcher.status(launched)
            except Exception:status=launched
            for worker in status.get("workers") or []:
                if worker.get("state")!="RUNNING":continue
                try:
                    launcher.stop_worker(
                        prepared_run=prepared,launched_run=launched,
                        builder_id=worker["builder_id"],reason="owner safe stop",
                    )
                    stopped.append(worker["builder_id"])
                except Exception as e:
                    fb.log(f"SELF-BUILD SAFE STOP FAILED {worker.get('builder_id')}: {e}")
            with self._self_build_lock:
                if run_id in self._self_build_runs:self._self_build_runs[run_id]["phase"]="SAFE_STOPPED"
        with self._self_build_lock:
            for session in self._self_build_sessions.values():
                if session.get("stop_requested"):session["phase"]="SAFE_STOPPED"
        with self._self_build_lock:
            stopped_sessions=[sid for sid,session in self._self_build_sessions.items() if session.get("stop_requested")]
        for sid in stopped_sessions:
            try:self._persist_self_build_session(sid)
            except Exception as persist_error:fb.log(f"SELF-BUILD EVIDENCE PERSIST FAILED session={sid}: {persist_error}")
        fb.stop_requested.set()
        fb.save_status(stop_requested=True,message="Safe stop requested; no new work will start.")
        fb.log("OWNER requested safe stop.")
        return {"ok":True,"self_build_workers_stopped":stopped}

    def run_retest(self):
        threading.Thread(target=fb.retest_last_candidates,daemon=True).start()
        return {"ok":True}

    def run_league(self):
        threading.Thread(target=fb.run_category_league,args=(1.0,),daemon=True).start()
        return {"ok":True}

def shell_preflight():
    page=HERE/"pro.html"
    if not page.exists():
        raise RuntimeError("ForgeBoss UI file is missing: "+str(page))
    if page.stat().st_size<5000:
        raise RuntimeError("ForgeBoss UI file appears incomplete. Extract the full ZIP before launching.")
    profile=ROOT/"projects"/"forgeboss"/"project.json"
    if not profile.exists():
        raise RuntimeError("ForgeBoss self-build project profile is missing: "+str(profile))
    return {"ok":True,"page":str(page),"project_profile":str(profile)}

def main():
    preflight=shell_preflight()
    if "--smoke" in sys.argv:
        print(json.dumps(preflight,sort_keys=True))
        return
    webview=ensure_webview()
    page=Path(preflight["page"])

    api=Api()

    # Load the dashboard as a LOCAL FILE. Do not inject a giant HTML string.
    # pywebview exposes absolute Explorer drop paths on the Python DOM event
    # as dataTransfer.files[*].pywebviewFullPath. Browser File objects alone
    # do not provide an authoritative local path.
    window=webview.create_window(
        "ForgeBoss - Self Build",
        url=page.as_uri(),
        js_api=api,
        width=1380,
        height=860,
        min_size=(1080,700),
        resizable=True,
        background_color="#07120f",
    )

    def bind_project_drop(win):
        from webview.dom import DOMEventHandler
        def on_drop(event):
            result={"ok":False,"message":"Drop the ForgeBoss folder or ZIP."}
            try:
                files=((event or {}).get("dataTransfer") or {}).get("files") or []
                full=files[0].get("pywebviewFullPath") if files else None
                result=api.attach_project(full)
            except Exception as e:
                result={"ok":False,"message":str(e)}
            try:
                win.evaluate_js("window.forgeBossDropResult("+json.dumps(result)+")")
            except Exception:
                pass
        win.dom.document.events.dragover += DOMEventHandler(lambda _e: None, prevent_default=True, stop_propagation=True, debounce=250)
        win.dom.document.events.drop += DOMEventHandler(on_drop, prevent_default=True, stop_propagation=True)

    webview.start(bind_project_drop, window, debug=False)

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        try:
            logdir=DASH_STATE_ROOT/"dashboard";logdir.mkdir(parents=True,exist_ok=True)
            (logdir/"desktop-startup-error.txt").write_text(traceback.format_exc(),encoding="utf-8")
        except Exception:
            pass
        msgbox("ForgeBoss desktop failed to start.\n\n"+str(e),"ForgeBoss",0x10)
