from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2];checks={}
for p in [ROOT/"forgeboss"/"autonomy"/"repair_playbook.py",ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py"]:
 q=subprocess.run([sys.executable,"-m","py_compile",str(p)],capture_output=True,text=True);checks[p.name+" compiles"]=q.returncode==0
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig");sv=(ROOT/"dashboard"/"server.py").read_text();pb=(ROOT/"forgeboss"/"autonomy"/"repair_playbook.py").read_text()
checks["playbook before model"]=rr.find("REPAIR RAT MEMORY HIT")<rr.find("$patch=Get-OrCreatePatch") and rr.find("REPAIR RAT MEMORY HIT")>0
checks["only proven replay"]='e.get("outcome")!="proven"' in pb
checks["exact hashes"]="before_sha256" in pb and "blob(repo,head,p)" in pb
checks["patch check"]='"apply","--check"' in pb
checks["full acceptance"]="Run-Acceptance $work 0" in rr
checks["memory hit zero api"]="AI spend=$0" in rr
checks["green teaching"]="teach_repair_rat(report_path,feedback_path)" in sv
checks["failed strategy recorded"]='"outcome":"proven" if passed else "failed"' in pb
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v0.9 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}");raise SystemExit(2 if not all(checks.values()) else 0)
