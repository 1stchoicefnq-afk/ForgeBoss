param([int]$RepairPullRequest=525)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=$PSScriptRoot
$State=Join-Path $Root 'state\builder'
New-Item -ItemType Directory -Force -Path $State|Out-Null
$Stamp=[DateTimeOffset]::Now.ToString('yyyyMMdd-HHmmss')
$Report=Join-Path $State "oneclick-$Stamp.json"
$Results=[System.Collections.Generic.List[object]]::new()

function Save-Report([string]$Status,[string]$FailedStage='',[string]$Reason=''){
  $tmp="$Report.tmp-$([Guid]::NewGuid().ToString('N'))"
  $obj=[ordered]@{
    schema=1
    generated_at=[DateTimeOffset]::Now.ToString('o')
    status=$Status
    failed_stage=$FailedStage
    reason=$Reason
    repair_pr=$RepairPullRequest
    stages=@($Results)
  }
  try{
    $obj|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $Report -Force
  }finally{
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

function Run-Stage([string]$Name,[scriptblock]$Body){
  Write-Host "`n============================================================" -ForegroundColor DarkCyan
  Write-Host "SITEBOSS ONE-CLICK :: $Name" -ForegroundColor Cyan
  Write-Host "============================================================" -ForegroundColor DarkCyan
  $started=[DateTimeOffset]::Now
  try{
    & $Body
    $code=$LASTEXITCODE
    if($null-eq$code){$code=0}
    if($code-ne0){throw "$Name exited with code $code"}
    [void]$Results.Add([pscustomobject]@{
      stage=$Name
      status='PASS'
      exit_code=0
      started_at=$started.ToString('o')
      finished_at=[DateTimeOffset]::Now.ToString('o')
    })
    Write-Host "[PASS] $Name" -ForegroundColor Green
  }catch{
    [void]$Results.Add([pscustomobject]@{
      stage=$Name
      status='FAIL'
      exit_code=$(if($LASTEXITCODE){$LASTEXITCODE}else{1})
      reason=$_.Exception.Message
      started_at=$started.ToString('o')
      finished_at=[DateTimeOffset]::Now.ToString('o')
    })
    Save-Report 'FAILED' $Name $_.Exception.Message
    Write-Host "`n[FAIL] $Name" -ForegroundColor Red
    Write-Host "WHY: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Report: $Report" -ForegroundColor Yellow
    exit 2
  }
}

Write-Host "`nSITEBOSS BUILDER v0.4.7-oneclick-hotfix" -ForegroundColor Cyan
Write-Host 'ONE DOUBLE-CLICK: CHECK -> BREAKER -> DIAGNOSE -> FULL BUILDER' -ForegroundColor Green
Write-Host 'CHECK/BREAKER/DIAGNOSE are local. FULL BUILDER may make paid API calls.' -ForegroundColor Yellow

Run-Stage 'CHECK' {
  & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'CHECK-SITEBOSS.ps1')
}
Run-Stage 'BREAKER' {
  & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'BREAK-REPAIR-RAT.ps1')
}
Run-Stage 'DIAGNOSE' {
  & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'SiteBoss-Builder.ps1') -Mode diagnose -RepairPullRequest $RepairPullRequest -SkipPreflight
}
Run-Stage 'FULL BUILDER' {
  & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'SiteBoss-Builder.ps1') -Mode cycle -RepairPullRequest $RepairPullRequest -SkipPreflight
}

Save-Report 'COMPLETE'
Write-Host "`nSITEBOSS ONE-CLICK COMPLETE" -ForegroundColor Green
Write-Host "Report: $Report" -ForegroundColor Cyan
Write-Host 'Automatic merge=OFF | deployment=OFF' -ForegroundColor Green
exit 0
