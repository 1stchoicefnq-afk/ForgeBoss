from __future__ import annotations
import json, os, sys, threading, time, subprocess, traceback, ctypes
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

sys.path.insert(0,str(HERE))
import server as fb

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

SETTINGS_PATH=ROOT/"state"/"dashboard"/"owner-settings.json"
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

SELECTED_PROJECT_PATH=ROOT/"state"/"dashboard"/"selected-project.json"
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
        try:
            selected=load_selected_project()
            if selected and selected.get("project_id")=="forgeboss":
                return {
                    "ok":False,
                    "blocked":True,
                    "message":"ForgeBoss self-build target is selected, but the self-build execution bridge is not wired yet. START refused safely instead of running the old SiteBoss controller."
                }
            budget=float(settings.get("budget_usd",3.0))
            duration_mode=str(settings.get("duration_mode","timed"))
            duration=int(settings.get("duration_minutes",120)) if duration_mode!="until-stopped" else 120
            ok,msg=fb.start_session({"duration_minutes":duration,"duration_mode":duration_mode,"budget_usd":budget,"workers":1,"mode":settings.get("mode","cost-optimized")})
            return {"ok":ok,"message":msg}
        except Exception as e:return {"ok":False,"message":str(e)}

    def safe_stop(self):
        fb.stop_requested.set()
        fb.save_status(stop_requested=True,message="Safe stop requested; current atomic operation may finish, but no new work will start.")
        fb.log("OWNER requested safe stop.")
        return {"ok":True}

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
            logdir=ROOT/"state"/"dashboard";logdir.mkdir(parents=True,exist_ok=True)
            (logdir/"desktop-startup-error.txt").write_text(traceback.format_exc(),encoding="utf-8")
        except Exception:
            pass
        msgbox("ForgeBoss desktop failed to start.\n\n"+str(e),"ForgeBoss",0x10)
