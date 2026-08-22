from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
checks={
"scalar count fixed":"if(@($changed).Count-gt0)" in rr,
"regression classifier":"function Test-IntroducedRegression" in rr,
"npm failure blocks retention":"$npm[0].exit_code-ne0" in rr,
"reference error blocks retention":"ReferenceError" in rr and "is not defined" in rr,
"partial win gated":"if($focusedResolved-and-not$introducedRegression)" in rr,
"prompt preserves declarations":"NEVER delete or replace a variable declaration" in rr,
"cache schema 6":"schema=6" in rr,
"server infra stop":"PropertyNotFoundException" in sv and 'stage="INFRA_ERROR"' in sv,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.0.6 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
