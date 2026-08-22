from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
checks={}
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
ad=(ROOT/"controller"/"lib"/"repair-adapter.js").read_text()
builder=(ROOT/"SiteBoss-Builder.ps1").read_text(encoding="utf-8-sig")
checks["targeted proof"]="function Test-TargetedRegressionGatesGreen" in rr
checks["broad failures required"]="full_postgres_suite_*" in rr
checks["attempt records targeted green"]="targeted_gates_green=(Test-TargetedRegressionGatesGreen $accept)" in rr
checks["partial works initial cycle"]="if($focusedResolved){" in rr and "and$null-ne$focusedPacket" not in rr[rr.find("$focusedResolved="):rr.find("$focusedResolved=")+500]
checks["one call rule"]="ONE-CALL RULE: one paid code-producing attempt completed" in rr
checks["adapter hard cap"]="'-MaxAttempts','1'" in ad
checks["builder hard cap"]="-MaxAttempts 1" in builder
for p in [ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py",ROOT/"forgeboss"/"reports"/"build_run_report.py"]:
 try:compile(p.read_text(encoding="utf-8"),str(p),"exec");checks[p.name+" compiles"]=True
 except Exception:checks[p.name+" compiles"]=False
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v1.7.2 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
