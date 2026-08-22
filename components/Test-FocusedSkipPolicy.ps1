$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$sample=@"
TAP version 13
# Subtest: a
ok 1 - a # SKIP
# Subtest: b
ok 2 - b # SKIP
1..2
# tests 2
# suites 0
# pass 0
# fail 0
# cancelled 0
# skipped 2
# todo 0
"@

$tests=[regex]::Match($sample,'(?m)^# tests\s+(\d+)\s*$')
$pass=[regex]::Match($sample,'(?m)^# pass\s+(\d+)\s*$')
$fail=[regex]::Match($sample,'(?m)^# fail\s+(\d+)\s*$')
$skip=[regex]::Match($sample,'(?m)^# skipped\s+(\d+)\s*$')
if(-not($tests.Success-and$pass.Success-and$fail.Success-and$skip.Success)){throw 'TAP summary parsing failed'}
$total=[int]$tests.Groups[1].Value
$passed=[int]$pass.Groups[1].Value
$failed=[int]$fail.Groups[1].Value
$skipped=[int]$skip.Groups[1].Value
if(-not($total-gt0-and$skipped-eq$total-and$passed-eq0-and$failed-eq0)){throw 'All-skipped classification failed'}
Write-Host 'FOCUSED TEST SKIPPED-EVIDENCE SELFTEST: PASS'
