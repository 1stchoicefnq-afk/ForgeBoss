from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
checks={}
for p in [ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py"]:
 q=subprocess.run([sys.executable,"-m","py_compile",str(p)],capture_output=True,text=True);checks[p.name+" compiles"]=q.returncode==0
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
ui=(ROOT/"dashboard"/"pro_shell.py").read_text()
checks["separate controller boundary"]="controllerWriteAllowlist" in rr
checks["specialist compares controller scope"]="controllerAllowed" in rr
checks["focused edit boundary retained"]="$writeAllowlist=[string[]]@($writeAllowlist|Where-Object{$sourcePaths-contains$_})" in rr
checks["budget message numeric"]="estimated call floor USD {0:N3}" in rr
checks["focused output 3000"]="$fallback=$(if($null-ne$focusedPacket){3000}else{8000})" in rr and "max_output_tokens=(Get-OpenAIOutputLimit)" in rr
checks["zero-spend fatal stops"]="int(report.get(\"api_calls\") or 0)==0" in sv
checks["budget blocked"]="BUDGET_BLOCKED" in sv
checks["infra error"]="INFRA_ERROR" in sv
checks["no owner wording for worker stop"]='"owner requested safe stop" in low' in ui and 'msg="SAFE STOP REQUESTED"' in ui
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v0.7.3 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
