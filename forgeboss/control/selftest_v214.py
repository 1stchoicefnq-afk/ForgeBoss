from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text()
checks={
"resolver":"function Resolve-CurrentSymbolRange" in rr,
"unique symbol":"resolved_by='unique-symbol'" in rr,
"tie break":"resolved_by='symbol-plus-line-hint'" in rr,
"ambiguity":"AMBIGUOUS_SYMBOL_ANCHOR" in rr,
"line optional":"required=@('path','mode','anchor_hint','new_text','replace_all')" in rr,
"materialized line":"NotePropertyName line_start -NotePropertyValue $lineStart" in rr,
"prompt":"ForgeBoss resolves that symbol to its actual current line" in rr,
"server":"AMBIGUOUS_SYMBOL_ANCHOR" in sv,
"cache12":"schema=12" in rr,
"local learned":"REPAIR RAT LEARNED HIT" in rr,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.1.4 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
