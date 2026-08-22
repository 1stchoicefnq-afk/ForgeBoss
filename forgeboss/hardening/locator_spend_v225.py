from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
RR=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig");SV=(ROOT/"dashboard"/"server.py").read_text()
c={"canonical source lines":"function Get-CanonicalSourceLines" in RR,"canonical verifier":"$lines=@(Get-CanonicalFileLines $Full)" in RR,
"canonical generator":"$lines=@(Get-CanonicalSourceLines ([string]$sf.content))" in RR,"old split removed":'$lines=[string]$sf.content -split "`r?`n",-1' not in RR,
"diagnostic hash":"expected={1} actual={2} line={3}" in RR,"locator invalid terminal":"PATCH_ANCHOR_LOCATOR_INVALID" in SV,
"locator mismatch terminal":"PATCH_ANCHOR_LOCATOR_MISMATCH" in SV,"repeat spend guard":"repeated deterministic ForgeBoss failure fingerprint" in SV,"cache22_or_newer":("schema=22" in RR or "schema=23" in RR)}
for k,v in c.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"FORGEBOSS v2.2.5 LOCATOR/SPEND MATRIX PASS={sum(c.values())} FAIL={sum(not v for v in c.values())}")
raise SystemExit(0 if all(c.values()) else 2)
