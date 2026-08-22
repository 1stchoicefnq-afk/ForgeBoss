from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2];checks={}
for p in [ROOT/"forgeboss"/"autonomy"/"debug_funnel.py",ROOT/"forgeboss"/"autonomy"/"evidence_collector.py",ROOT/"dashboard"/"server.py",ROOT/"forgeboss"/"reports"/"build_run_report.py"]:
 q=subprocess.run([sys.executable,"-m","py_compile",str(p)],capture_output=True,text=True);checks[p.name+" compiles"]=q.returncode==0
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig");df=(ROOT/"forgeboss"/"autonomy"/"debug_funnel.py").read_text();ec=(ROOT/"forgeboss"/"autonomy"/"evidence_collector.py").read_text();ui=(ROOT/"dashboard"/"pro.html").read_text();rep=(ROOT/"forgeboss"/"reports"/"build_run_report.py").read_text()
checks["workspace execution contract"]="model_has_no_tool_execution_requirement" in rr
checks["no tool-refusal instruction"]="Lack of direct tool access is NOT a reason" in rr
checks["exact missing fact required"]="name the exact missing fact/file/error" in rr
checks["travis file hint"]="src/travis/conversation.js" in df
checks["dynamic grep discovery"]="git.exe\",\"grep\",\"-l" in df
checks["packet max 4"]="max_files\":4" in df
checks["packet max 24k"]="max_source_chars\":24000" in df
checks["collector proves workspace"]="workspace_available" in ec
checks["collector excerpts"]="excerpts" in ec
checks["report tooling misunderstanding"]="TOOLING MISUNDERSTANDING" in rep
checks["dashboard learning engine"]="LEARNING ENGINE ACTIVE" in ui
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v1.1 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
