from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
checks={}
for p in [ROOT/"forgeboss"/"autonomy"/"debug_funnel.py",ROOT/"forgeboss"/"autonomy"/"repair_memory.py",ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py"]:
 q=subprocess.run([sys.executable,"-m","py_compile",str(p)],capture_output=True,text=True)
 checks[p.name+" compiles"]=q.returncode==0
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
checks["focused env"]= "SITEBOSS_FORGEBOSS_DEBUG_FUNNEL" in rr and "SITEBOSS_FORGEBOSS_DEBUG_FUNNEL" in sv
checks["memory env"]= "SITEBOSS_FORGEBOSS_REPAIR_MEMORY" in rr and "repair_memory.py" in sv
checks["focused output cap"]="max_output_tokens=(Get-OpenAIOutputLimit)" in rr and "SITEBOSS_OPENAI_MAX_OUTPUT_TOKENS" in rr
checks["full historical payload omitted focused"]="repair_lab_evidence=$(if($null-ne$focusedPacket){$null}" in rr
checks["reference pack omitted focused"]="open_source_reference_pack=$(if($null-ne$focusedPacket){$null}" in rr
checks["funnel hard char cap"]="24000" in (ROOT/"forgeboss"/"autonomy"/"debug_funnel.py").read_text() and "42000" not in (ROOT/"forgeboss"/"autonomy"/"debug_funnel.py").read_text()
checks["no blind retry"]="refusing another large blind model call" in sv
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"COST FUNNEL SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
