from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
checks={
"context fields required":"required=@('path','mode','old_text','new_text','replace_all','context_before','context_after')" in rr,
"context locator":"function Find-ContextualAnchor" in rr,
"zero match rejection":"PATCH_CONTEXT_MISMATCH" in rr,
"multi match rejection":"supplied context still matches" in rr,
"deterministic resolver":"PATCH ANCHOR RESOLVED" in rr,
"prompt exact adjacency":"Context strings are exact adjacent text" in rr,
"cache schema 5":"schema=5" in rr,
"server classifies mismatch":"PATCH_CONTEXT_MISMATCH" in sv,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.0.4 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
