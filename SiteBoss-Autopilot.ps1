param(
  [int]$TargetPullRequest = 168
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Root=$PSScriptRoot
$State=Join-Path $Root 'state'
New-Item -ItemType Directory -Force -Path $State|Out-Null
$ReviewPath=Join-Path $State ("review-pr{0}.json" -f $TargetPullRequest)
$Reviewer=Join-Path $Root 'components\Review-PR.ps1'
$Repair=Join-Path $Root 'components\Repair-PR.ps1'
$ChildCycle=Join-Path $Root 'components\Child-Cycle.ps1'

Write-Host "`nSITEBOSS AUTOPILOT Repair Rat v0.5-smokescreen" -ForegroundColor Cyan
Write-Host 'single launcher - parent review -> follow repair chain -> independent child review -> bounded parent-branch integration/repair' -ForegroundColor DarkGray
Write-Host "Target integration PR: #$TargetPullRequest" -ForegroundColor DarkGray

if(-not(Test-Path -LiteralPath $Reviewer)){throw "Reviewer missing: $Reviewer"}
if(-not(Test-Path -LiteralPath $Repair)){throw "Repair worker missing: $Repair"}
if(-not(Test-Path -LiteralPath $ChildCycle)){throw "Child-cycle manager missing: $ChildCycle"}

# Cost guard: this alpha is a review->repair cycle, so Docker must be ready before any paid review.
if(-not(Get-Command docker -ErrorAction SilentlyContinue)){
  throw 'Docker Desktop is required before starting this repair cycle. No OpenAI call was made.'
}
& docker info *> $null
if($LASTEXITCODE -ne 0){
  throw 'Docker Desktop is not running. Start Docker Desktop and rerun; no OpenAI call was made.'
}
Write-Host 'Cost preflight: Docker engine is running.' -ForegroundColor DarkGray

$SandboxPreflight=Join-Path $Root 'components\Test-Sandbox.ps1'
if(-not(Test-Path -LiteralPath $SandboxPreflight)){throw "Sandbox preflight missing: $SandboxPreflight"}
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $SandboxPreflight
if($LASTEXITCODE -ne 0){throw "Docker sandbox preflight failed with exit code $LASTEXITCODE. No reviewer API call was made."}

Write-Host "`n[1/2] Independent review / cache validation..." -ForegroundColor Yellow
& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $Reviewer -PullRequest $TargetPullRequest -ResultPath $ReviewPath -ReviewOnly -UseCache
if($LASTEXITCODE-ne0){throw "Reviewer failed closed with exit code $LASTEXITCODE"}
if(-not(Test-Path -LiteralPath $ReviewPath)){throw 'Reviewer produced no machine-readable result'}
$review=Get-Content -LiteralPath $ReviewPath -Raw|ConvertFrom-Json

switch("$($review.verdict)"){
  'PASS' {
    Write-Host "`nAUTOPILOT STATE: REVIEW PASS" -ForegroundColor Green
    Write-Host 'The reviewed exact head needs explicit integration authority. Autopilot alpha will not self-authorise or merge it.'
    exit 0
  }
  'NEEDS_EVIDENCE' {
    Write-Host "`nAUTOPILOT STATE: OWNER/CONTROLLER EVIDENCE REQUIRED" -ForegroundColor Yellow
    Write-Host "$($review.summary)"
    exit 0
  }
  'FAIL' {
    Write-Host "`n[2/2] Following bounded repair chain..." -ForegroundColor Yellow
    & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $ChildCycle `
      -RootPullRequest $TargetPullRequest `
      -RootReviewPath $ReviewPath `
      -StateDir $State `
      -ReviewerPath $Reviewer `
      -RepairPath $Repair
    if($LASTEXITCODE-ne0){throw "Repair-chain manager failed closed with exit code $LASTEXITCODE"}
    Write-Host "`nAUTOPILOT CYCLE COMPLETE" -ForegroundColor Green
    Write-Host 'At most one reviewed repair integration or one new bounded repair was performed. main was not merged/deployed.'
    exit 0
  }
  default {throw "Unknown reviewer verdict: $($review.verdict)"}
}
