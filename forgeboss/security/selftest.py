from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2];checks={}
for p in [ROOT/"forgeboss"/"security"/"executor_guard.py",ROOT/"forgeboss"/"executors"/"openhands_runner.py",ROOT/"forgeboss"/"executors"/"mini_swe_runner.py",ROOT/"forgeboss"/"league"/"run_league.py",ROOT/"forgeboss"/"tournament"/"run_paid.py"]:
 try:compile(p.read_text(encoding="utf-8"),str(p),"exec");checks[p.name+" compiles"]=True
 except Exception:checks[p.name+" compiles"]=False
oh=(ROOT/"forgeboss"/"executors"/"openhands_runner.py").read_text();ms=(ROOT/"forgeboss"/"executors"/"mini_swe_runner.py").read_text();oc=(ROOT/"forgeboss"/"executors"/"opencode_runner.js").read_text();lg=(ROOT/"forgeboss"/"league"/"run_league.py").read_text();tr=(ROOT/"forgeboss"/"tournament"/"run_paid.py").read_text();gd=(ROOT/"forgeboss"/"security"/"executor_guard.py").read_text()
checks["openhands no terminal"]="TerminalTool" not in oh
checks["openhands lease"]="executor_guard.py" in oh and "postflight" in oh
checks["mini docker no network"]='"--network","none"' in ms
checks["mini lease"]="executor_guard.py" in ms and "postflight" in ms
checks["opencode quarantine"]="QUARANTINED" in oc
checks["league wrapper"]="opencode_runner.js" in lg and 'run(["opencode","run"' not in lg
checks["league leases"]="executor_guard.py" in lg
checks["tournament leases"]="issue_executor_lease" in tr
checks["guard sensitive paths"]="FORBIDDEN_PREFIXES" in gd and '".git/"' in gd
checks["guard symlinks"]="symlink changes denied" in gd
checks["guard exact head"]="exact HEAD mismatch" in gd
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"UNIFIED SECURITY SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
