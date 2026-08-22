$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=$PSScriptRoot
$files=@(Get-ChildItem -LiteralPath $root -Recurse -File|Where-Object{$_.Extension-in@('.ps1','.psm1')})
foreach($file in $files){
  $tokens=$null;$errors=$null
  [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
  if($errors.Count-gt0){
    foreach($e in $errors){Write-Host "$($file.FullName) line $($e.Extent.StartLineNumber): $($e.Message)" -ForegroundColor Red}
    throw "$($file.Name) has $($errors.Count) parser error(s)"
  }
}
if(-not(Get-Command git.exe -ErrorAction SilentlyContinue)){throw 'git.exe missing'}
if(-not(Get-Command docker.exe -ErrorAction SilentlyContinue)){throw 'docker.exe missing'}
& docker.exe info *> $null
if($LASTEXITCODE-ne0){throw 'Docker engine is not running'}
foreach($img in @('node:22-bookworm','postgres:17-alpine')){
  & docker.exe image inspect $img *> $null
  if($LASTEXITCODE-ne0){throw "Required Docker image missing: $img"}
}
$rat=Join-Path $root 'SiteBoss-Repair-Rat.ps1'
if(-not(Test-Path -LiteralPath $rat)){throw 'SiteBoss-Repair-Rat.ps1 missing'}
$text=Get-Content -LiteralPath $rat -Raw
foreach($forbidden in @('git push','GHPatch','GHPost','/git/refs/','/pulls/525/merge')){
  if($text-match[regex]::Escape($forbidden)){throw "Repair Rat contains forbidden publication primitive: $forbidden"}
}
foreach($required in @(
  'MaxAttempts = 3',
  'Failure fingerprint repeated unchanged',
  'tests/postgres*.integration.test.js',
  'postgresBusinessInvitations.integration.test.js',
  'postgresProductionHttp.integration.test.js',
  'postgresTravisIntake.integration.test.js',
  'npm run db:rollback',
  'SKIPPED_EVIDENCE',
  'github_repo_writes=0'
)){
  if($required-eq'SKIPPED_EVIDENCE'){
    $repair=Get-Content -LiteralPath (Join-Path $root 'components\Repair-PR.ps1') -Raw
    if($repair-notmatch'SKIPPED_EVIDENCE'){throw 'Focused skip-evidence guard missing from preserved repair worker'}
  }elseif($text-notmatch[regex]::Escape($required)){
    throw "Repair Rat contract missing: $required"
  }
}
$lab=Get-ChildItem -LiteralPath (Join-Path $root 'state\repair-lab') -Filter 'repair-lab-*.json' -File|Select-Object -First 1
if($null-eq$lab){throw 'Bundled repair-lab evidence missing'}
$j=Get-Content -LiteralPath $lab.FullName -Raw|ConvertFrom-Json
if("$($j.exact_head)"-ne'd40a5d97211c1c826fcdcd3dfde5e8fc0ef919f9'){throw 'Bundled repair-lab exact head mismatch'}

$ratText=Get-Content -LiteralPath $rat -Raw
foreach($required in @(
  'case-sensitive-repair-workspaces\repair-rat',
  'Assert-CaseSensitiveRoot',
  "Assert-Pristine `$work 'pre-model baseline'",
  'PATCH CACHE HIT',
  'Patch cached before application',
  'Get-CaseCollisionGroups',
  'evidence_sha256'
)){
  if($ratText-notmatch[regex]::Escape($required)){throw "Repair Rat v0.5-smokescreen hardening missing: $required"}
}
$caseRoot=Join-Path $env:USERPROFILE '.siteboss\autopilot\case-sensitive-repair-workspaces'
if(-not(Test-Path -LiteralPath $caseRoot)){throw "Case-sensitive base root missing: $caseRoot"}
$case=& fsutil.exe file queryCaseSensitiveInfo $caseRoot 2>&1
if($LASTEXITCODE-ne0-or"$case"-notmatch'(?i)enabled'){throw 'Case-sensitive base root is not enabled'}
Write-Host 'Repair Rat case-sensitive/pristine/cache contract: PASS'


if($ratText.Contains("WorkspaceRoot=(Join-Path `$env:USERPROFILE '.siteboss\repair-rat')")){
  throw 'Repair Rat must not use the old case-insensitive workspace root'
}
foreach($required in @(
  'Discover-RepairScope',
  'MaxSourceFiles=42',
  'source_scope_sha256',
  'MODEL SAFE REFUSAL',
  'git.exe'
)){
  if($ratText-notmatch[regex]::Escape($required)){throw "Repair Rat v0.5-smokescreen discovery contract missing: $required"}
}
Write-Host 'Repair Rat bounded dependency-discovery contract: PASS'


$referencePack=Join-Path $root 'references\postgres-transaction-reference-pack.json'
if(-not(Test-Path -LiteralPath $referencePack)){throw 'PostgreSQL transaction reference pack missing'}
$ref=Get-Content -LiteralPath $referencePack -Raw|ConvertFrom-Json
if(@($ref.sources).Count-lt4){throw 'Reference pack is incomplete'}
foreach($required in @(
  'Find-LatestRatReviewFailure',
  'Load-ReferencePack',
  'FullSuiteRepeats = 5',
  'ValidationRounds = 2',
  'open_source_reference_pack',
  'clean_rat_review_failure',
  'repairContextHash',
  'full_postgres_suite_round'
)){
  if($ratText-notmatch[regex]::Escape($required)){throw "Repair Rat v0.5-smokescreen contract missing: $required"}
}
Write-Host 'Reference-guided clean-feedback contract: PASS'
Write-Host 'Full PostgreSQL suite repeats per round: 5'
Write-Host 'Independent PostgreSQL validation rounds: 2'


$breaker=Join-Path $root 'BREAK-REPAIR-RAT.ps1'
if(-not(Test-Path -LiteralPath $breaker)){throw 'Repair Rat breaker harness missing'}
$breakerText=Get-Content -LiteralPath $breaker -Raw
foreach($required in @(
  'temporary_git_dirty_detection_fixture',
  'malformed_json_fixture_rejected',
  'stale_head_fixture_changes_cache_key',
  'checker.does_not_expand_env_inside_regex',
  'docker.no_network_smoke',
  'OpenAI calls=0 | Anthropic calls=0 | GitHub API calls=0'
)){
  if($breakerText-notmatch[regex]::Escape($required)){throw "Breaker contract missing: $required"}
}
Write-Host 'Adversarial breaker harness: PRESENT'


foreach($f in @('SiteBoss-Builder.ps1','SiteBoss-Rat-Review.ps1','BUILDER-MANIFEST.json','BUILDER-POLICY.json','engines\Repo-Mirror.ps1','engines\Backlog-Scanner.ps1','engines\Test-Selector.ps1','engines\Model-Router.ps1','engines\Architecture-Map.ps1','engines\Cluster-Evidence.ps1','engines\Work-Graph.ps1','engines\Cost-Ledger.ps1')){
 if(-not(Test-Path -LiteralPath (Join-Path $root $f))){throw "Builder platform file missing: $f"}
}
Write-Host 'Builder v0.3 platform inventory: PASS'


foreach($f in @('START-SITEBOSS.cmd','ONE-CLICK-SITEBOSS.cmd','SiteBoss-OneClick.ps1')){
  if(-not(Test-Path -LiteralPath (Join-Path $root $f))){throw "One-click launcher missing: $f"}
}
$builderText=Get-Content -LiteralPath (Join-Path $root 'SiteBoss-Builder.ps1') -Raw
if($builderText-notmatch[regex]::Escape('[switch]$SkipPreflight')){throw 'SkipPreflight contract missing'}
Write-Host 'One-click orchestration: PRESENT'

Write-Host 'SITEBOSS BUILDER v0.4.7-oneclick-hotfix CHECK: PASS' -ForegroundColor Green
Write-Host ("PowerShell/module files parsed: {0}"-f$files.Count)
Write-Host 'Docker engine: RUNNING'
Write-Host 'node:22-bookworm: READY'
Write-Host 'postgres:17-alpine: READY'
Write-Host 'Repair-lab evidence: BOUND'
Write-Host 'GitHub publication primitives: ABSENT'
Write-Host 'No GitHub/OpenAI/Anthropic call was made.'
