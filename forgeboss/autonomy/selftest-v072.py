from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
checks={}
for p in [ROOT/"forgeboss"/"autonomy"/"debug_funnel.py",ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py",ROOT/"forgeboss"/"reports"/"build_run_report.py"]:
 q=subprocess.run([sys.executable,"-m","py_compile",str(p)],capture_output=True,text=True);checks[p.name+" compiles"]=q.returncode==0
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig");sv=(ROOT/"dashboard"/"server.py").read_text();df=(ROOT/"forgeboss"/"autonomy"/"debug_funnel.py").read_text();rb=(ROOT/"forgeboss"/"reports"/"build_run_report.py").read_text()
checks["process budget"]="SITEBOSS_RUN_BUDGET_USD" in rr and "$env:SITEBOSS_RUN_BUDGET_USD" in rr
checks["call preflight"]="BUDGET PREFLIGHT STOP" in rr
checks["focused first call"]="Could not build a focused $0 debug packet" in sv
checks["real packet key"]="context_files" in df
checks["workspace resolver"]="resolve_repo" in df
checks["zero file blocks"]="zero source files" in sv
checks["node github"]="publish-run-report.js" in sv
checks["actual report schema"]="changed_paths" in rb and "failure_fingerprint" in rb
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v0.7.2 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
