$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$root=$PSScriptRoot
$active=@(
  (Join-Path $root 'SiteBoss-Autopilot.ps1'),
  (Join-Path $root 'components\Review-PR.ps1'),
  (Join-Path $root 'components\Repair-PR.ps1')
)

foreach($p in $active){
  if(-not(Test-Path -LiteralPath $p)){throw "Missing active script: $p"}
  $text=Get-Content -LiteralPath $p -Raw

  $tokens=$null;$errors=$null
  [void][Management.Automation.Language.Parser]::ParseFile($p,[ref]$tokens,[ref]$errors)
  if($errors.Count -gt 0){
    foreach($e in $errors){Write-Host "$p line $($e.Extent.StartLineNumber): $($e.Message)" -ForegroundColor Red}
    throw "Parser errors in $p"
  }

  if($text -match 'foreach\(\$[A-Za-z_][A-Za-z0-9_]*\s+in@\('){
    throw "Compact foreach/in@ syntax found in $p"
  }
  if($text -match '(?m)^\s*(?:\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*)?(?:Git|Invoke-Git)\s+-CommandArgs\s+@\('){
    throw "Inline array passed directly to Git helper in $p; bind through a typed variable first"
  }
  if($text -match '2>&1'){
    throw "Merged stdout/stderr capture remains in active script $p"
  }
}

# Repair-specific external invocation contract.
$repair=Get-Content -LiteralPath (Join-Path $root 'components\Repair-PR.ps1') -Raw

if($repair -match '(?im)^\s*function\s+git\b'){
  throw 'Repair worker defines a function named Git, which collides case-insensitively with git.exe'
}
if($repair -match '(?im)&\s+git(?:\s|@)'){
  throw 'Repair worker contains a bare `& git` invocation; use explicit git.exe in the process runner'
}
if($repair -match '(?m)(?<![A-Za-z0-9_-])Git\s+-CommandArgs'){
  throw 'Old Git helper call remains in Repair-PR.ps1'
}

if($repair -match '\$pr\.head|\$pr\.base|\$pr2\.head|\$pr2\.base'){
  throw 'Direct StrictMode-sensitive PR head/base dereference remains in Repair-PR.ps1'
}

# Reviewer-specific direct PR head/base dereference contract.
$review=Get-Content -LiteralPath (Join-Path $root 'components\Review-PR.ps1') -Raw
if($review -match '\$pr\.head|\$pr\.base|\$pr2\.head|\$pr2\.base'){
  throw 'Direct StrictMode-sensitive PR head/base dereference remains in Review-PR.ps1'
}

# Harmless local Git helper semantic self-test, independent of GitHub/OpenAI.
$temp=Join-Path ([IO.Path]::GetTempPath()) ("siteboss-alpha11-check-"+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temp|Out-Null
try{
  & git.exe init --quiet $temp
  if($LASTEXITCODE-ne0){throw 'git init self-test failed'}
  Push-Location $temp
  try{
    $v=& git.exe rev-parse --is-inside-work-tree
    if($LASTEXITCODE-ne0-or"$v"-ne'true'){throw 'git rev-parse self-test failed'}
  }finally{Pop-Location}
}finally{Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}


# Alpha15 stabilization invariants.
if($repair -match 'dst=/workspace,readonly.*dst=/workspace/node_modules'){
  throw 'Forbidden Docker topology: nested node_modules volume beneath read-only /workspace bind'
}
if($repair -match 'dst=/workspace/node_modules'){
  throw 'Repair worker must not mount node_modules as a nested volume'
}
if($repair -notmatch 'dst=/source,readonly'){
  throw 'Repair sandbox must stage from a read-only /source bind'
}
if($repair -notmatch 'type=volume,src=\$vol,dst=/workspace'){
  throw 'Repair sandbox must use a Docker-managed /workspace volume'
}
if($repair -notmatch '(?m)^function\s+Assert-DockerSandboxTopology'){
  throw 'Repair worker must preflight its exact Docker sandbox topology before model calls'
}
if($repair -notmatch "GitUserName='SiteBoss Autopilot'"){
  throw 'Repair worker must set explicit local Git commit identity'
}


# Reject assignments/parameters that collide with PowerShell automatic variables.
$reservedAutomatic=@(
  'args','input','error','home','host','pid','profile','pwd','shellid','stacktrace',
  'this','foreach','switch','matches','lastexitcode','psitem','_','null','true','false',
  'ofs','nestedpromptlevel','event','eventargs','eventsubscriber','sender',
  'psboundparameters','myinvocation','executioncontext'
)

foreach($scriptFile in $allScripts){
  $tokens2=$null
  $parseErrors2=$null
  $ast2=[Management.Automation.Language.Parser]::ParseFile($scriptFile.FullName,[ref]$tokens2,[ref]$parseErrors2)
  if($parseErrors2.Count -gt 0){ continue }

  $assignments=$ast2.FindAll({
    param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst]
  },$true)

  foreach($assignment in $assignments){
    if($assignment.Left -is [Management.Automation.Language.VariableExpressionAst]){
      $name=$assignment.Left.VariablePath.UserPath.ToLowerInvariant()
      if($reservedAutomatic -contains $name){
        throw "Reserved automatic variable assignment in $($scriptFile.FullName): `$$name"
      }
    }
  }

  $parameters=$ast2.FindAll({
    param($node)
    $node -is [Management.Automation.Language.ParameterAst]
  },$true)

  foreach($parameter in $parameters){
    $name=$parameter.Name.VariablePath.UserPath.ToLowerInvariant()
    if($reservedAutomatic -contains $name){
      throw "Reserved automatic variable used as parameter in $($scriptFile.FullName): `$$name"
    }
  }
}


# Alpha18 repair-chain invariants.
$childCyclePath=Join-Path $root 'components\Child-Cycle.ps1'
if(-not(Test-Path -LiteralPath $childCyclePath)){throw 'Missing components\Child-Cycle.ps1'}
$childCycle=Get-Content -LiteralPath $childCyclePath -Raw

if($childCycle -notmatch 'MaxRepairDepth=4'){throw 'Repair-chain manager must have a bounded maximum depth'}
if($childCycle -notmatch "if\(\$parentHead\.ref-eq'main'\)"){throw 'Repair-chain integration must explicitly refuse main'}
if($childCycle -notmatch "force=\$false"){throw 'Repair-chain ref update must be non-forced'}
if($childCycle -notmatch 'Child head moved after review'){throw 'Repair-chain manager must revalidate exact child head after review'}
if($childCycle -notmatch 'Parent branch moved after child review'){throw 'Repair-chain manager must revalidate parent branch after review'}
if($childCycle -notmatch 'compare/\$\(\$parentHead\.sha\)\.\.\.\$\(\$childHead\.sha\)'){throw 'Repair-chain manager must verify fast-forward ancestry'}
if($childCycle -notmatch 'One reviewed integration'){ } # documentation-only; no-op
if($review -notmatch "ValidateSet\('main','child'\)"){throw 'Reviewer must support explicit child review mode'}
if($review -notmatch 'Child review requires ExpectedBaseRef and ExpectedBaseSha'){throw 'Child reviewer must bind expected parent base'}

Write-Host 'SITEBOSS ALPHA18 REPAIR-LOOP REGRESSION AUDIT: PASS' -ForegroundColor Green
Write-Host 'Checked parser, Git-helper binding pattern, StrictMode PR shape access, and local Git semantics.'
Write-Host 'No GitHub/OpenAI call was made.'


# Cross-provider scaffold contract (inert by default).
$repair=Get-Content -LiteralPath (Join-Path $root 'components\Repair-PR.ps1') -Raw
$review=Get-Content -LiteralPath (Join-Path $root 'components\Review-PR.ps1') -Raw

if($repair -notmatch "SITEBOSS_REPAIR_PROVIDER"){ throw 'Repair provider env switch missing' }
if($review -notmatch "SITEBOSS_REVIEW_PROVIDER"){ throw 'Review provider env switch missing' }
if($repair -notmatch "function\s+Invoke-Claude"){ throw 'Repair Anthropic adapter missing' }
if($review -notmatch "function\s+Invoke-ClaudeStructured"){ throw 'Reviewer Anthropic adapter missing' }
if($repair -notmatch "claude-sonnet-5"){ throw 'Repair Anthropic default model not pinned' }
if($review -notmatch "claude-sonnet-5"){ throw 'Reviewer Anthropic default model not pinned' }

if($repair -notmatch "@\('reset','--hard','HEAD'\)"){ throw 'Pristine baseline reset missing' }
if($repair -notmatch "@\('clean','-ffd'\)"){ throw 'Pristine baseline clean missing' }
if($repair -notmatch "@\('status','--porcelain=v1','-z','--untracked-files=all'\)"){ throw 'NUL-safe pristine status check missing' }
if($repair -notmatch "@\('diff','--name-only','-z'"){ throw 'NUL-safe post-write diff path check missing' }

$policyPath=Join-Path $root 'PROVIDER-POLICY.json'
if(-not(Test-Path -LiteralPath $policyPath)){ throw 'PROVIDER-POLICY.json missing' }
$policy=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
if("$($policy.active_mode)" -ne 'single-provider'){ throw 'Provider policy must remain single-provider in alpha12' }
if([bool]$policy.future_dual_review.enabled){ throw 'Dual review must remain disabled in alpha12' }

Write-Host 'Cross-provider scaffold contract: PASS' -ForegroundColor Green
