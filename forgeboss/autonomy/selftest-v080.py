from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
checks={}
for p in [ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py"]:
 q=subprocess.run([sys.executable,"-m","py_compile",str(p)],capture_output=True,text=True)
 checks[p.name+" compiles"]=q.returncode==0
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
ui=(ROOT/"dashboard"/"pro.html").read_text()
checks["luna pricing"]="gpt-5.6-luna" in rr and "$inputRate=0.20" in rr and "$outputRate=1.20" in rr
checks["terra pricing"]="gpt-5.6-terra" in rr and "$inputRate=2.00" in rr and "$outputRate=12.00" in rr
checks["sol pricing"]="gpt-5.6-sol" in rr and "$inputRate=5.00" in rr and "$outputRate=30.00" in rr
checks["reasoning low control"]="SITEBOSS_OPENAI_REASONING_EFFORT" in rr
checks["output control"]="SITEBOSS_OPENAI_MAX_OUTPUT_TOKENS" in rr
checks["cheap mode luna"]='mode=="cost-optimized"' in sv and '"gpt-5.6-luna"' in sv
checks["balanced escalation"]='"gpt-5.6-terra"' in sv
checks["strong escalation"]='"gpt-5.6-sol"' in sv
checks["route passed by process env"]="SITEBOSS_OPENAI_MODEL" in sv
checks["ui lanes"]="Luna cheap-first" in ui and "Luna -> Terra" in ui
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v0.8 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
