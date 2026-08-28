from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parents[2];checks={}
for p in [ROOT/"forgeboss"/"security"/"executor_guard.py",ROOT/"forgeboss"/"executors"/"openhands_runner.py",ROOT/"forgeboss"/"executors"/"mini_swe_runner.py",ROOT/"forgeboss"/"league"/"run_league.py",ROOT/"forgeboss"/"tournament"/"run_paid.py"]:
 try:compile(p.read_text(encoding="utf-8"),str(p),"exec");checks[p.name+" compiles"]=True
 except Exception:checks[p.name+" compiles"]=False
def read(*parts):
    # A missing or non-UTF-8 file must fail the check, not crash the selftest with a
    # traceback that hides every check after it.
    try:return (ROOT.joinpath(*parts)).read_text(encoding="utf-8")
    except Exception:return ""
oh=read("forgeboss","executors","openhands_runner.py");ms=read("forgeboss","executors","mini_swe_runner.py");oc=read("forgeboss","executors","opencode_runner.js");lg=read("forgeboss","league","run_league.py");tr=read("forgeboss","tournament","run_paid.py");gd=read("forgeboss","security","executor_guard.py");ac=read("forgeboss","security","local_acl.py")
checks["executor sources readable"]=all([oh,ms,oc,lg,tr,gd,ac])
checks["openhands no terminal"]=bool(oh) and "TerminalTool" not in oh
checks["openhands lease"]="executor_guard.py" in oh and "postflight" in oh
checks["mini docker no network"]='"--network","none"' in ms
checks["mini lease"]="executor_guard.py" in ms and "postflight" in ms
checks["opencode quarantine"]="QUARANTINED" in oc
checks["league wrapper"]="opencode_runner.js" in lg and 'run(["opencode","run"' not in lg
checks["league leases"]="executor_guard.py" in lg
checks["tournament leases"]="issue_executor_lease" in tr
checks["guard sensitive paths"]="FORBIDDEN_PREFIXES" in gd and '".git/"' in gd
# The guard has always raised "symlink/junction changes denied"; this check greppped
# for "symlink changes denied", so it was red on every run and its signal was dead.
checks["guard symlinks"]="symlink/junction changes denied" in gd and "assert_no_link_escape" in gd
checks["guard exact head"]="exact HEAD mismatch" in gd
checks["guard nested ci surfaces"]="FORBIDDEN_SEGMENTS" in gd and "HIGH_IMPACT_SUFFIXES" in gd
checks["guard secret read scope"]="secret material read denied" in gd
checks["guard absolute git binary"]="_git_binary" in gd and "shutil.which" in gd and 'subprocess.run(["git.exe"' not in gd
checks["guard executor identity"]="canonical_executor" in gd
checks["acl pinned icacls"]="System32" in ac and "icacls.exe" in ac and "/inheritance:r" in ac
checks["acl wellknown sids"]="S-1-5-18" in ac and "S-1-5-32-544" in ac
checks["acl rejects broad principal"]="BROAD_PRINCIPALS" in ac
checks["acl link safety"]="_assert_not_link" in ac
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"UNIFIED SECURITY SELFTEST PASS={sum(bool(v) for v in checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
