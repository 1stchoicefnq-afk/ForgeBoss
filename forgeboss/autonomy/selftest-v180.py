from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
ff=(ROOT/"forgeboss"/"autonomy"/"failure_feedback.py").read_text();df=(ROOT/"forgeboss"/"autonomy"/"debug_funnel.py").read_text();sv=(ROOT/"dashboard"/"server.py").read_text();rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig");rep=(ROOT/"forgeboss"/"reports"/"build_run_report.py").read_text()
checks={
"partial local commit":'obj.get("partial_proven") and obj.get("local_commit")' in ff,
"source repo":'"source_repo":obj.get("local_workspace")' in ff,
"40001 hints":'"40001":["src/persistence/postgres.js"' in df,
"retained env":"SITEBOSS_FORGEBOSS_RETAINED_FOUNDATION" in rr and "SITEBOSS_FORGEBOSS_RETAINED_FOUNDATION" in sv,
"exact base":"Retained foundation base mismatch" in rr,
"accumulating":"ACCUMULATING PIPELINE" in sv,
"strong sol":'if mode=="strong":return' in sv and '"gpt-5.6-sol"' in sv,
"balanced terra":'if mode=="balanced":return' in sv and '"gpt-5.6-terra"' in sv,
"actual model":"$obj.model" in rr and "actual_models" in rr,
"report routing":'"requested_mode":c.get("requested_mode")' in rep,
}
for p in [ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py",ROOT/"forgeboss"/"autonomy"/"failure_feedback.py",ROOT/"forgeboss"/"autonomy"/"debug_funnel.py",ROOT/"forgeboss"/"reports"/"build_run_report.py"]:
 try:compile(p.read_text(),str(p),"exec");checks[p.name+" compiles"]=True
 except Exception:checks[p.name+" compiles"]=False
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v1.8 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
