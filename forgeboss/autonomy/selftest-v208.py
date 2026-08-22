from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
ff=(ROOT/"forgeboss"/"autonomy"/"failure_feedback.py").read_text()
sv=(ROOT/"dashboard"/"server.py").read_text()
checks={
"cumulative diff":"@('diff','--binary',$base,$Commit,'--')" in rr,
"prior root carried":"$prior.authoritative_base_sha" in rr,
"ancestry checked":"merge-base','--is-ancestor" in rr,
"schema2 foundation":"schema=2" in rr and "cumulative=$true" in rr,
"replay root base":"$foundationBase" in rr,
"save uses expected head":"Save-RetainedPartialPatch $work $expectedHead" in rr,
"feedback root helper":"def retained_authoritative_base" in ff,
"feedback uses root":'"authoritative_base_sha":retained_authoritative_base(obj)' in ff,
"activity chain":"FOUNDATION CHAIN:" in sv,
"cache schema8":"schema=8" in rr,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.0.8 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
