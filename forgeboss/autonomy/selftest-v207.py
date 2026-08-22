from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
df=(ROOT/"forgeboss"/"autonomy"/"debug_funnel.py").read_text()
ff=(ROOT/"forgeboss"/"autonomy"/"failure_feedback.py").read_text()
checks={
"focused packet retained acceptance":"$packetOnRetainedFoundation" in rr,
"base sha verified":"$($fp.authoritative_base_sha)" in rr and "$expectedHead" in rr,
"feedback retained acceptance":"$feedbackOnRetainedFoundation" in rr,
"retained evidence in payload":"retained_foundation_evidence=" in rr,
"stochastic 40001 rule":"single clean rerun does NOT erase repeated nondeterministic 40001" in rr,
"current sources outrank snippets":"Current `source_files` were read from the replayed current workspace" in rr,
"debug provenance":"retained-foundation-validation" in df,
"feedback instruction updated":"partial_proven is true" in ff,
"cache schema 7":"schema=7" in rr,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.0.7 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
