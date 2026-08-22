from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
paths=[
 ROOT/"controller"/"hybrid"/"selftest.js",
 ROOT/"controller"/"selftest-agency-core-team.js",
 ROOT/"controller"/"deepagents"/"tests"/"test_policy.py",
 ROOT/"controller"/"siteboss-autopilot.js",
 ROOT/"forgeboss"/"autonomy"/"selftest-cost-funnel.py",
]
bad=[]
for p in paths:
 ok=p.exists()
 print(f"[{'PASS' if ok else 'FAIL'}] {p.relative_to(ROOT)}")
 if not ok:bad.append(p)
print(f"PACKAGE PATH SELFTEST PASS={len(paths)-len(bad)} FAIL={len(bad)}")
raise SystemExit(2 if bad else 0)
