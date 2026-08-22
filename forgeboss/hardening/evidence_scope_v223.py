from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
rr=(ROOT/"SiteBoss-Repair-Rat.ps1").read_text(encoding="utf-8-sig")
checks={
 "dependency helper":"function Get-EvidenceDependencyExpansion" in rr,
 "stack src extraction":"/workspace/(src/" in rr,
 "failing test imports":"failed_test_files" in rr and "Resolve-RepoModulePath" in rr,
 "bounded files":"Get-EvidenceDependencyExpansion $work $freshEvidence $sourcePaths 8 140000" in rr,
 "controller write subset":"$controllerWriteAllowlist-contains$rel" in rr,
 "context can grow":"EVIDENCE CONTEXT EXPANDED" in rr,
 "write restoration audited":"CONTROLLER-APPROVED WRITE RESTORED" in rr,
 "prompt uses expanded source":"evidence-expanded dependency/call-site files" in rr,
 "no write widening":"writes remain a subset of controller-approved write scope" in rr,
 "cache20_or_newer":("schema=20" in rr or "schema=21" in rr or "schema=22" in rr or "schema=23" in rr),
}
for k,v in checks.items():print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"FORGEBOSS v2.2.3 EVIDENCE-SCOPE MATRIX PASS={sum(checks.values())} FAIL={sum(not v for v in checks.values())}")
raise SystemExit(0 if all(checks.values()) else 2)
