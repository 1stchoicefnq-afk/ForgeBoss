$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

# Regression test for two budget-gating bugs in engines/Cost-Ledger.ps1 and its caller
# in SiteBoss-Builder.ps1's PaidCallsToday:
#  1. Cost-Ledger.ps1 used to emit a raw PowerShell object as its final expression.
#     Callers invoke it as a separate `pwsh -File` child process and capture stdout,
#     so across that process boundary the object was only ever visible as its
#     formatted-for-display text table -- `$result.today_paid_calls` silently
#     evaluated to $null (-> 0), making the daily paid-call cap check a permanent
#     no-op regardless of actual ledger content.
#  2. A ledger file that exists but fails to parse (corrupt/partial write) was
#     treated the same as a missing file -- an empty ledger -- which silently
#     reset the daily cap to zero and let unlimited further paid calls through.

$root=$PSScriptRoot
$ledgerScript=Join-Path $root 'Cost-Ledger.ps1'
$tmp=Join-Path ([IO.Path]::GetTempPath()) ('cost-ledger-test-'+[Guid]::NewGuid().ToString('N')+'.json')

function Read-Ledger([string]$Path){
  $raw=& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $ledgerScript -Mode read -LedgerPath $Path
  if($LASTEXITCODE -ne 0){ throw "Cost-Ledger.ps1 -Mode read exited $LASTEXITCODE" }
  return ($raw -join "`n") | ConvertFrom-Json
}

try{
  # 1. A fresh ledger must parse as a real object, not a formatted text table.
  $r1=Read-Ledger $tmp
  if($r1.PSObject.Properties.Name -notcontains 'today_paid_calls'){ throw "REGRESSION: today_paid_calls did not deserialize as a real property (child-process output is not being parsed as JSON)" }
  if([int]$r1.today_paid_calls -ne 0 -or $r1.ledger_status -ne 'ok'){ throw "Expected a clean empty ledger, got $($r1 | ConvertTo-Json -Compress)" }

  # 2. Recording a call must be reflected on the next read.
  & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $ledgerScript -Mode record -Provider test -Purpose unit -PaidCalls 3 -Artifact x -LedgerPath $tmp | Out-Null
  if($LASTEXITCODE -ne 0){ throw "Cost-Ledger.ps1 -Mode record exited $LASTEXITCODE" }
  $r2=Read-Ledger $tmp
  if([int]$r2.today_paid_calls -ne 3){ throw "Expected today_paid_calls=3 after recording, got $($r2.today_paid_calls)" }

  # 3. A corrupt ledger file must fail closed on read (sentinel value that always
  #    compares as "cap exceeded"), never silently degrade to an empty/zero ledger.
  Set-Content -LiteralPath $tmp -Value '{not valid json'
  $r3=Read-Ledger $tmp
  if($r3.ledger_status -ne 'corrupt' -or [int64]$r3.today_paid_calls -ne [int]::MaxValue){
    throw "REGRESSION: corrupt ledger did not fail closed, got $($r3 | ConvertTo-Json -Compress)"
  }

  # 4. A corrupt ledger must also refuse to record over itself (would silently
  #    discard whatever real spend history existed before the corruption).
  $before=Get-Content -LiteralPath $tmp -Raw
  & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $ledgerScript -Mode record -Provider test -Purpose unit -PaidCalls 1 -Artifact x -LedgerPath $tmp 2>$null | Out-Null
  if($LASTEXITCODE -eq 0){ throw 'REGRESSION: record mode succeeded against a corrupt ledger' }
  $after=Get-Content -LiteralPath $tmp -Raw
  if($after -ne $before){ throw 'REGRESSION: a failed record attempt modified the corrupt ledger file' }
  if(Test-Path -LiteralPath "$tmp.lock"){ throw 'Lock file was not cleaned up after a failed record attempt' }
}finally{
  Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath "$tmp.lock" -Force -ErrorAction SilentlyContinue
}

Write-Host 'COST LEDGER FAIL-CLOSED SELFTEST: PASS' -ForegroundColor Green
