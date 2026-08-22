from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SV=(ROOT/"dashboard"/"server.py").read_text(encoding="utf-8")
RR=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
c={
"re imported":"import json, os, re, subprocess" in SV,
"fatal stored":"\"fatal_failure\":(report or {}).get(\"fatal_failure\")" in SV,
"fingerprint stored":"\"fatal_fingerprint\":normalize_fatal_failure(report)" in SV,
"normalizer":"def normalize_fatal_failure(report):" in SV,
"breaker uses prior records":"cycle_records[:-1]" in SV and '_cr.get("fatal_fingerprint")==_repeat_fp' in SV,
"structured travis id":"JSON.stringify([providerKey, String(messageId)])" in RR,
"colon learned repair removed":"$new='const identity = `${providerKey}:${messageId}`;'" not in RR,
"lesson v2":"siteboss.travis-jsonb-structured-identity.v2" in RR,
"cache23":"schema=23" in RR,
}
for k,v in c.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"FORGEBOSS v2.2.6 FATAL/TRAVIS MATRIX PASS={sum(c.values())} FAIL={sum(not v for v in c.values())}")
raise SystemExit(0 if all(c.values()) else 2)
