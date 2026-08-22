param([int]$RepairPullRequest=525)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Root=$PSScriptRoot
$BuilderState=Join-Path $Root 'state\builder'
$Next=Join-Path $Root 'state\nextgen'
New-Item -ItemType Directory -Force -Path $Next|Out-Null

Write-Host "`nSITEBOSS NEXTGEN DEV DIAGNOSTICS v0.6" -ForegroundColor Cyan
Write-Host 'LOCAL ONLY - zero model calls, zero GitHub reads/writes.' -ForegroundColor Green

Write-Host '[0/10] NextGen self-test...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\SELFTEST-NEXTGEN.ps1') -Output (Join-Path $Next 'selftest.json')
if($LASTEXITCODE-ne0){throw 'NextGen selftest failed'}

$reports=@(Get-ChildItem -LiteralPath (Join-Path $env:USERPROFILE 'Downloads') -Recurse -File -Filter 'repair-rat-*.json' -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending)
$Repo=$null
foreach($report in $reports){
  try{
    $j=Get-Content -LiteralPath $report.FullName -Raw|ConvertFrom-Json
    if("$($j.repair_pr)"-eq"$RepairPullRequest"-and(Test-Path -LiteralPath "$($j.local_workspace)")){
      $Repo="$($j.local_workspace)"
      break
    }
  }catch{}
}
if(-not$Repo){throw 'No local Repair Rat workspace found for NextGen diagnostics.'}

Write-Host '[1/10] Provenance...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Provenance.ps1') -Repo $Repo -Output (Join-Path $Next 'provenance.json')|Out-Null
if($LASTEXITCODE-ne0){throw 'Provenance failed'}

Write-Host '[2/10] Product planning...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Product-Planner.ps1') -Repo $Repo -BacklogPath (Join-Path $BuilderState 'backlog.json') -Output (Join-Path $Next 'product-plan.json')|Out-Null
if($LASTEXITCODE-ne0){throw 'Product planner failed'}

Write-Host '[3/10] Issue graph...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Issue-Graph.ps1') -WorkGraphPath (Join-Path $BuilderState 'work-graph.json') -ProductPlanPath (Join-Path $Next 'product-plan.json') -Output (Join-Path $Next 'issue-graph.json')|Out-Null
if($LASTEXITCODE-ne0){throw 'Issue graph failed'}

Write-Host '[4/10] Impact analysis...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Impact-Analysis.ps1') -Repo $Repo -IssueGraphPath (Join-Path $Next 'issue-graph.json') -Output (Join-Path $Next 'impact.json')|Out-Null
if($LASTEXITCODE-ne0){throw 'Impact analysis failed'}

Write-Host '[5/10] Acceptance contracts...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Acceptance-Contracts.ps1') -IssueGraphPath (Join-Path $Next 'issue-graph.json') -Output (Join-Path $Next 'acceptance-contracts.json')|Out-Null
if($LASTEXITCODE-ne0){throw 'Acceptance contracts failed'}

Write-Host '[6/10] Static security scan...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Security-Scan.ps1') -Repo $Repo -Output (Join-Path $Next 'security.json')|Out-Null
if($LASTEXITCODE-ne0){throw 'Security scan failed'}

Write-Host '[7/10] Job queue...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Job-Queue.ps1') -Mode init -IssueGraphPath (Join-Path $Next 'issue-graph.json') -QueuePath (Join-Path $Next 'job-queue.json')|Out-Null
if($LASTEXITCODE-ne0){throw 'Job queue failed'}

Write-Host '[8/10] Readiness score...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Readiness-Score.ps1') `
  -PolicyPath (Join-Path $Root 'NEXTGEN-POLICY.json') `
  -ProductPlanPath (Join-Path $Next 'product-plan.json') `
  -IssueGraphPath (Join-Path $Next 'issue-graph.json') `
  -AcceptancePath (Join-Path $Next 'acceptance-contracts.json') `
  -SecurityPath (Join-Path $Next 'security.json') `
  -ProvenancePath (Join-Path $Next 'provenance.json') `
  -SelfTestPath (Join-Path $Next 'selftest.json') `
  -Output (Join-Path $Next 'readiness.json')|Out-Null
if($LASTEXITCODE-ne0){throw 'Readiness scoring failed'}

Write-Host '[9/10] Merge readiness report...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Merge-Readiness.ps1') `
  -PolicyPath (Join-Path $Root 'NEXTGEN-POLICY.json') `
  -ReadinessPath (Join-Path $Next 'readiness.json') `
  -Output (Join-Path $Next 'merge-readiness.json')|Out-Null
if($LASTEXITCODE-ne0){throw 'Merge readiness failed'}

Write-Host '[10/10] Dashboard export...'
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Dashboard-Export.ps1') -BuilderState $BuilderState -NextGenState $Next -Output (Join-Path $Next 'dashboard.html')
if($LASTEXITCODE-ne0){throw 'Dashboard export failed'}

$ready=Get-Content -LiteralPath (Join-Path $Next 'readiness.json') -Raw|ConvertFrom-Json
$merge=Get-Content -LiteralPath (Join-Path $Next 'merge-readiness.json') -Raw|ConvertFrom-Json

Write-Host "`nNEXTGEN DEV DIAGNOSTICS: PASS" -ForegroundColor Green
Write-Host "Readiness score: $($ready.score)/100"
Write-Host "Merge candidate: $($merge.merge_candidate)"
Write-Host "State: $Next"
Write-Host 'OpenAI calls=0 | Anthropic calls=0 | GitHub reads=0 | GitHub writes=0' -ForegroundColor Green
