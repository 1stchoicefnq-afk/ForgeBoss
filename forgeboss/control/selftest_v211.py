from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
sv=(ROOT/"dashboard"/"server.py").read_text(encoding="utf-8")
checks={
"line schema":"required=@('path','mode','line_start','line_end','new_text','replace_all')" in rr,
"materializer":"function Get-LineMaterialization" in rr,
"local old text":"NotePropertyName old_text -NotePropertyValue $mat.old_text" in rr,
"local file hash":"NotePropertyName expected_file_hash -NotePropertyValue (Sha256File $full)" in rr,
"numbered current source":"current_numbered_source_files=$numberedSources" in rr,
"prompt bans stale anchors":"Never copy an old_text anchor from debug-funnel/history" in rr,
"cache schema9":"schema=9" in rr,
"learning promotion":"def promote_verified_learning" in sv,
"partial promotion":'promote_verified_learning(report,"siteboss")' in sv,
"validated only":"can_promote(validation" in sv,
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"v2.1.1 SELFTEST PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
