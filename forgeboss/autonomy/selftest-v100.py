from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2];checks={}
for p in [ROOT/"forgeboss"/"autonomy"/"evidence_collector.py",ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py",ROOT/"forgeboss"/"reports"/"build_run_report.py"]:
 q=subprocess.run([sys.executable,"-m","py_compile",str(p)],capture_output=True,text=True);checks[p.name+" compiles"]=q.returncode==0
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig");sv=(ROOT/"dashboard"/"server.py").read_text();rep=(ROOT/"forgeboss"/"reports"/"build_run_report.py").read_text();ui=(ROOT/"dashboard"/"pro.html").read_text()
checks["enrichment into prompt"]="SITEBOSS_FORGEBOSS_EVIDENCE_ENRICHMENT" in rr
checks["safe refusal classifier"]="safe_refusal" in sv
checks["zero dollar collector"]="evidence_collector.py" in sv
checks["no repeated refusal"]="no genuinely new local evidence" in sv.lower()
checks["report why"]="WHY IT STOPPED/FAILED" in rep
checks["report next action"]="RECOMMENDED NEXT ACTION" in rep
checks["report rationale"]="Engineering rationale" in rep
checks["report exact tests"]="Failure lines" in rep and "Output tail" in rep
checks["dashboard blocker"]="Current blocker" in ui
checks["dashboard next action"]="Next best action" in ui
checks["dashboard diagnosis button"]="OPEN FULL DIAGNOSIS" in ui
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v1.0 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
