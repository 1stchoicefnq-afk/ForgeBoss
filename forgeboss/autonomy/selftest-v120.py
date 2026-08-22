from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
checks={}
for p in [ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py"]:
 q=subprocess.run([sys.executable,"-m","py_compile",str(p)],capture_output=True,text=True);checks[p.name+" compiles"]=q.returncode==0
ui=(ROOT/"dashboard"/"pro.html").read_text(encoding="utf-8")
for name,needle in {
 "premium theme":"radial-gradient(circle at 15% -10%",
 "hero metrics":"heroRat",
 "tasks":"Authoritative Work Queue",
 "workers":"REPAIR RAT FIRST",
 "costs":"Overspend Guard",
 "activity":"Engineering Timeline",
 "settings":"Review Gate",
 "learning chip":"REPAIR RAT LEARNING",
 "version":"v1.2"
}.items():checks[name]=needle in ui
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v1.2 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
