from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
rep=(ROOT/"forgeboss"/"reports"/"build_run_report.py").read_text()
checks={
"dynamic path enum":"$script:CurrentWriteAllowlist" in rr and "enum=@($script:CurrentWriteAllowlist)" in rr,
"model hash removed":"required=@('path','mode','old_text','new_text','replace_all')" in rr,
"normalizer":"function Normalize-PatchTransaction" in rr,
"authoritative hash":"expected_file_hash -NotePropertyValue (Sha256File $full)" in rr,
"local base sha":"base_sha -NotePropertyValue $Head" in rr,
"cache schema 3":"schema=3" in rr,
"call passes scope":"-Repo $work -WriteAllowlist $writeAllowlist" in rr,
"terminal paid guard":"transaction-format/scope ambiguity is terminal" in sv,
"patch rejected stage":'stage="PATCH_REJECTED"' in sv,
"report patch rejected":'status":"PATCH REJECTED"' in rep,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.0.1 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
