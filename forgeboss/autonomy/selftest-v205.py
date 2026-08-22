from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sv=(ROOT/"dashboard"/"server.py").read_text(encoding="utf-8")
checks={
"old 20c reserve removed":"remaining<0.20" not in sv,
"new 3c floor":"min_cycle_reserve=0.03" in sv,
"preflight authority documented":"Assert-EstimatedCallFitsBudget" in sv,
"reserve has explicit stage":'stage="BUDGET_REACHED"' in sv,
"reserve has explicit stop reason":'elif final=="BUDGET_REACHED"' in sv,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.0.5 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
