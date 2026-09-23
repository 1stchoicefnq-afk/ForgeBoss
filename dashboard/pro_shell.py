    def save_settings(self,x):
        return {"ok":True,"settings":save_settings_file(x)}
    def get_event_details(self,key):
        """Read-only technical drill-down for a friendly activity event."""
        chunks=[]
        if key=="retest":
            rp=DASH_STATE_ROOT/"tournament"/"retest-last.json"
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
        if p:
            try:return {"ok":True,"text":Path(p).read_text(encoding="utf-8")}
            except Exception as e:return {"ok":False,"text":"Could not read run report: "+str(e)}

        # P0 self-build has its own durable evidence stream. Surface the newest
        # session and any initial-launch diagnostic instead of falling back to
        # the legacy report fields.
        try:
            sessions=sorted(
                SELF_BUILD_EVIDENCE_ROOT.glob("*.json"),
                key=lambda x:x.stat().st_mtime,
                reverse=True,
            )
            if sessions:
                session=json.loads(sessions[0].read_text(encoding="utf-8"))
                chunks=[
                    "FORGEBOSS P0 SELF-BUILD REPORT\n",
                    "="*72+"\n\n",
                    "Session evidence: "+str(sessions[0])+"\n\n",
                    json.dumps(session,indent=2,sort_keys=True,ensure_ascii=False),
                ]
                failures=sorted(
                    (DASH_STATE_ROOT/"self-build-launch").glob("**/initial-launch-failure.json"),
                    key=lambda x:x.stat().st_mtime,
                    reverse=True,
                )
                if failures:
                    chunks.extend([
                        "\n\nINITIAL LAUNCH DIAGNOSTIC\n",
                        "="*72+"\n",
                        "Diagnostic: "+str(failures[0])+"\n\n",
                        failures[0].read_text(encoding="utf-8"),
                    ])
                return {"ok":True,"text":"".join(chunks)}
        except Exception as e:
            return {"ok":False,"text":"Could not read P0 self-build report: "+str(e)}

        reason=st.get("last_refusal_reason") or st.get("message")
        if reason:return {"ok":True,"text":"FORGEBOSS LIVE DIAGNOSIS\n"+"="*72+"\n\n"+str(reason)}
        return {"ok":False,"text":"No run diagnosis exists yet."}

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
                    terminal={"COMPLETE","FAILED","SAFE_STOPPED","P0_PROOF_PASS","P0_PROOF_FAILED"}
                    active=[x for x in self._self_build_sessions.values() if str(x.get("phase") or "") not in terminal]
                    if active:
                        return {"ok":False,"blocked":True,"phase":"SELF_BUILD_SESSION_ACTIVE","message":"A ForgeBoss self-build session is already active. Stop it safely or let it finish before starting another."}
                client=ProtectedAuthorityClient.from_environment(os.environ,timeout=300.0)
                launcher=self._get_self_build_launcher(client)
                session_id="fl1s-"+uuid.uuid4().hex[:12]
                with self._self_build_lock:
                    self._self_build_sessions[session_id]={
                        "session_id":session_id,"client":client,"launcher":launcher,"plan":plan,