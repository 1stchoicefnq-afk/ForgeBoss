from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
p=ROOT/"forgeboss"/"tournament"/"validate.ps1"
t=p.read_text(encoding="utf-8-sig")

checks={
 "DockerArgs parameter": "function D([Parameter(Mandatory=$true)][string[]]$DockerArgs)" in t,
 "native stderr guard": "$PSNativeCommandUseErrorActionPreference=$false" in t,
 "temporary EAP Continue": "$ErrorActionPreference='Continue'" in t,
 "exit code authoritative": "$c=$LASTEXITCODE" in t,
 "restores EAP": "$ErrorActionPreference=$oldEap" in t,
 "restores native preference": "$PSNativeCommandUseErrorActionPreference=$oldNative" in t,
 "stdout captured": "1>$o 2>$e" in t,
}
bad=[k for k,v in checks.items() if not v]
for k,v in checks.items():
    print(f"[{'PASS' if v else 'FAIL'}] {k}")
print(f"VALIDATOR HOTFIX SELFTEST PASS={sum(checks.values())} FAIL={len(bad)}")
raise SystemExit(2 if bad else 0)
