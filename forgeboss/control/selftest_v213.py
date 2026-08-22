from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
checks={
"dynamic anchor catalog":"function Get-CurrentAnchorHints" in rr,
"schema anchor enum":"enum=@($script:CurrentAnchorHints)" in rr,
"catalog before call":"$script:CurrentAnchorHints=@(Get-CurrentAnchorHints $Repo $WriteAllowlist)" in rr,
"local lesson":"function Try-ValidatedLocalLesson" in rr,
"22p05 evidence gate":"22P05" in rr and "unsupported Unicode escape" in rr,
"exact source precondition":"siteboss.travis-jsonb-nul-identity.v1" in rr and "$old='const identity =" in rr and "$count=([regex]::Matches" in rr,
"zero cost log":"AI spend=$0" in rr,
"normal validation":"Run-Acceptance $work 0 $validationRound" in rr,
"partial retain":"REPAIR RAT LOCAL LESSON PARTIAL WIN" in rr,
"cache11":"schema=11" in rr,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.1.3 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
