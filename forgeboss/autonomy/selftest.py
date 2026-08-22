from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2];p=f=0
def ok(n,v):
 global p,f;print(f"[{'PASS' if v else 'FAIL'}] {n}");p+=int(v);f+=int(not v)
files=[ROOT/"forgeboss"/"autonomy"/"failure_feedback.py",ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py"]
for x in files:
 q=subprocess.run([sys.executable,"-m","py_compile",str(x)],capture_output=True,text=True);ok(x.name+" compiles",q.returncode==0)
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
ui=(ROOT/"dashboard"/"pro.html").read_text()
ok("feedback exact SHA gate",'$fbJson.target_sha' in rr and '-eq"$head"' in rr)
ok("feedback env gate","SITEBOSS_FORGEBOSS_FAILURE_FEEDBACK" in rr)
ok("until stopped loop",'duration_mode=="until-stopped"' in sv)
ok("session budget enforced","remaining=budget-cumulative" in sv)
ok("stagnation guard","same failure signature repeated 3 times" in sv)
ok("max cycle guard","cycle>=12" in sv)
ok("failure evidence fed next cycle","SITEBOSS_FORGEBOSS_FAILURE_FEEDBACK" in sv)
ok("draft success stops duplicate work","DRAFT_READY" in sv)
ok("UI until stop option","UNTIL I PRESS STOP SAFELY" in ui)
ok("merge deploy execution disabled","Merge/deploy execution remains disabled" in sv)
print(f"AUTONOMY SELFTEST PASS={p} FAIL={f}");raise SystemExit(2 if f else 0)
