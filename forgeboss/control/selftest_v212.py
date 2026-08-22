from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
checks={
"anchor hint schema":"'anchor_hint'" in rr and "maxLength=160" in rr,
"intent mismatch guard":"PATCH_ANCHOR_INTENT_MISMATCH" in rr,
"range bounded":"PATCH_LINE_RANGE_TOO_WIDE" in rr,
"single source payload":"source_files=@($sources|ForEach-Object" in rr,
"fast syntax helper":"function Test-FastCandidateSyntax" in rr,
"node check":"@('--check',$rel)" in rr,
"candidate invalid":"PATCH_CANDIDATE_INVALID" in rr,
"server terminal":"PATCH_CANDIDATE_INVALID" in sv,
"cache10":"schema=10" in rr,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.1.2 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
