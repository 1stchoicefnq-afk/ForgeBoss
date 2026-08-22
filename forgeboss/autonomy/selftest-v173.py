from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
rb=(ROOT/"forgeboss"/"reports"/"build_run_report.py").read_text()
checks={
 "internal hard cap":"$MaxAttempts=1" in rr,
 "runtime marker":"SITEBOSS REPAIR RAT v1.7.3-one-paid-call" in rr,
 "loop guard":"HARD ONE-CALL GUARD: a second paid model attempt was requested." in rr,
 "model guard":"model invocation refused because one paid call already occurred" in rr,
 "report contract":"repair_contract='one-paid-call-v1.7.3'" in rr,
 "server violation stop":"SECURITY/COST CONTRACT VIOLATION" in sv,
 "report carries contract":'"repair_contract":report.get("repair_contract")' in rb,
}
for p in [ROOT/"dashboard"/"server.py",ROOT/"dashboard"/"pro_shell.py",ROOT/"forgeboss"/"reports"/"build_run_report.py"]:
 try:compile(p.read_text(encoding="utf-8"),str(p),"exec");checks[p.name+" compiles"]=True
 except Exception:checks[p.name+" compiles"]=False
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v1.7.3 SELFTEST PASS={sum(checks.values())} FAIL={sum(not x for x in checks.values())}")
raise SystemExit(2 if not all(checks.values()) else 0)
