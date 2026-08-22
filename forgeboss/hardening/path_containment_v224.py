from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
RR=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
checks={
 "repo prefix has separator":"$repoPrefix=$repoFull+[IO.Path]::DirectorySeparatorChar" in RR,
 "candidate component-aware check":"$candidate.StartsWith($repoPrefix" in RR,
 "sibling-prefix bug removed":"$candidate.StartsWith($repoFull,[StringComparison]::OrdinalIgnoreCase)" not in RR,
 "expanded file candidates rechecked":"$fullP.StartsWith($repoPrefix" in RR,
 "relative path still src bounded":"if($rel.StartsWith('src/')){return $rel}" in RR,
 "cache21_or_newer":("schema=21" in RR or "schema=22" in RR or "schema=23" in RR),
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"FORGEBOSS v2.2.4 PATH-CONTAINMENT MATRIX PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
