from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
checks={
"edit schema nonempty old_text":"old_text=@{type='string';minLength=1}" in rr,
"create schema empty old_text":"old_text=@{type='string';maxLength=0}" in rr,
"delete still supported":"enum=@('replace','insert_before','insert_after','delete')" in rr,
"local empty-anchor guard":"PATCH_CONTRACT_INVALID: $mode requires non-empty old_text" in rr,
"insert replaceall guard":"does not allow replace_all" in rr,
"cache schema 4":"schema=4" in rr,
"schema accepts union":"items=@{anyOf=@($editOp,$createOp)}" in rr,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.0.3 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
