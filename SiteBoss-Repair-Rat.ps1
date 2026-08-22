param(
  [int]$RepairPullRequest = 525,
  [int]$MaxAttempts = 3,
  [int]$RepeatCount = 3,
  [int]$FullSuiteRepeats = 5,
  [int]$ValidationRounds = 2,
  [string]$ScopeManifest = '',
  [int]$RootPullRequest = 0,
  [string]$TargetSha = '',
  [string]$SpecialistPlan = ''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Root=$PSScriptRoot
$State=Join-Path $Root 'state\repair-rat'
New-Item -ItemType Directory -Force -Path $State|Out-Null
$Stamp=[DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')
$ReportPath=Join-Path $State "repair-rat-$Stamp.json"
$LogPath=Join-Path $State "repair-rat-$Stamp.log"

$Config=@{
  RepoUrl='https://github.com/1stchoicefnq-afk/siteboss-monster.git'
  NodeImage=$(if($env:SITEBOSS_TEST_IMAGE){$env:SITEBOSS_TEST_IMAGE}else{'node:22-bookworm'})
  PostgresImage='postgres:17-alpine'
  Provider=$(if($env:SITEBOSS_REPAIR_PROVIDER){$env:SITEBOSS_REPAIR_PROVIDER.ToLowerInvariant()}else{'openai'})
  OpenAIModel=$(if($env:SITEBOSS_OPENAI_MODEL){$env:SITEBOSS_OPENAI_MODEL}else{'gpt-5.6'})
  AnthropicModel=$(if($env:SITEBOSS_ANTHROPIC_MODEL){$env:SITEBOSS_ANTHROPIC_MODEL}else{'claude-sonnet-5'})
  WorkspaceRoot=(Join-Path $env:USERPROFILE '.siteboss\autopilot\case-sensitive-repair-workspaces\repair-rat')
  CacheRoot=(Join-Path $Root 'state\repair-rat\patch-cache')
  ReferencePack=(Join-Path $Root 'references\postgres-transaction-reference-pack.json')
  MaxFiles=16
  MaxSourceChars=520000
  MaxSourceFiles=42
  FocusedPacket=$(if($env:SITEBOSS_FORGEBOSS_DEBUG_FUNNEL){$env:SITEBOSS_FORGEBOSS_DEBUG_FUNNEL}else{''})
  RetainedFoundation=$(if($env:SITEBOSS_FORGEBOSS_RETAINED_FOUNDATION){$env:SITEBOSS_FORGEBOSS_RETAINED_FOUNDATION}else{''})
  PlaybookScript=(Join-Path $Root 'forgeboss\autonomy\repair_playbook.py')
}
if($MaxAttempts-lt1-or$MaxAttempts-gt5){throw 'MaxAttempts must be between 1 and 5'}
# HARD COST CONTRACT: Repair Rat itself enforces one paid model call per invocation.
$MaxAttempts=1
if($RepeatCount-lt1-or$RepeatCount-gt5){throw 'RepeatCount must be between 1 and 5'}
if($FullSuiteRepeats-lt2-or$FullSuiteRepeats-gt8){throw 'FullSuiteRepeats must be between 2 and 8'}
if($ValidationRounds-lt1-or$ValidationRounds-gt3){throw 'ValidationRounds must be between 1 and 3'}
if($Config.Provider-notin@('openai','anthropic')){throw "Unsupported repair provider: $($Config.Provider)"}

$SeedAllowedPaths=@(
  'src/persistence/transactionalPlatformStore.js',
  'src/persistence/postgres.js',
  'src/persistence/platformStore.js',
  'src/persistence/postgresCrmStore.js',
  'src/persistence/postgresApplicationServices.js',
  'src/persistence/postgresLeadConversion.js',
  'src/intake/postgresApplication.js',
  'tests/postgresTravisIntake.integration.test.js',
  'tests/postgresBusinessInvitations.integration.test.js',
  'tests/postgresProductionHttp.integration.test.js'
)

$script:ApiCalls=0
$script:Usage=[ordered]@{input_tokens=0;cached_input_tokens=0;output_tokens=0;estimated_usd=0.0}
$script:CallUsage=[System.Collections.Generic.List[object]]::new()
$script:ActualModels=[System.Collections.Generic.List[string]]::new()
$script:CurrentWriteAllowlist=@()
$script:CurrentAnchorHints=@()
$script:FreshTargetEvidence=$null

$script:Attempts=[System.Collections.Generic.List[object]]::new()
$script:BuilderSpecialists=@()
$script:Workspace=$null
$script:ExactHead=$null
$script:FinalCommit=$null
$script:Fatal=$null
$script:PartialProven=$false
$script:ResolvedFocusedStep=$null
$script:RetainedPatchPath=$null

function Log([string]$Message,[string]$Color='Gray'){
  Add-Content -LiteralPath $LogPath -Value $Message
  Write-Host $Message -ForegroundColor $Color
}
function Run([string]$Exe,[string[]]$CommandArgs,[string]$Cwd=''){
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName=$Exe
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true
  if($Cwd){$psi.WorkingDirectory=$Cwd}
  foreach($a in $CommandArgs){[void]$psi.ArgumentList.Add([string]$a)}
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi
  try{
    if(-not$p.Start()){throw "Failed to start $Exe"}
    $o=$p.StandardOutput.ReadToEnd()
    $e=$p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return [pscustomobject]@{exit_code=$p.ExitCode;stdout=$o;stderr=$e}
  }finally{$p.Dispose()}
}
function Sha256Text([string]$Text){
  $sha=[Security.Cryptography.SHA256]::Create()
  try{
    $b=[Text.Encoding]::UTF8.GetBytes($Text)
    (($sha.ComputeHash($b)|ForEach-Object{$_.ToString('x2')})-join'')
  }finally{$sha.Dispose()}
}


function Get-CanonicalSourceLines([string]$Text){
  $norm=$Text.Replace("`r`n","`n").Replace("`r","`n")
  $lines=[System.Collections.Generic.List[string]]::new()
  foreach($line in @($norm.Split([char]"`n"))){[void]$lines.Add([string]$line)}
  if($lines.Count-gt0-and$lines[$lines.Count-1]-eq''-and$norm.EndsWith("`n")){$lines.RemoveAt($lines.Count-1)}
  return @($lines)
}
function Get-CanonicalFileLines([string]$Path){return @(Get-CanonicalSourceLines ([IO.File]::ReadAllText($Path)))}

function Sha256File([string]$Path){
  $sha=[Security.Cryptography.SHA256]::Create()
  try{
    $stream=[IO.File]::OpenRead($Path)
    try{
      (($sha.ComputeHash($stream)|ForEach-Object{$_.ToString('x2')})-join'')
    }finally{$stream.Dispose()}
  }finally{$sha.Dispose()}
}

function Get-OpenAIPricing {
  # ForgeBoss v0.8 rate card, refreshed 2026-08-19 from OpenAI's official API docs.
  # Process environment overrides are supported so rates can be changed without code edits.
  $model="$($Config.OpenAIModel)".ToLowerInvariant()
  switch($model){
    'gpt-5.6-luna' {$inputRate=0.20;$cachedRate=0.02;$outputRate=1.20}
    'gpt-5.6-terra' {$inputRate=2.00;$cachedRate=0.20;$outputRate=12.00}
    'gpt-5.6-sol' {$inputRate=5.00;$cachedRate=0.50;$outputRate=30.00}
    'gpt-5.6' {$inputRate=5.00;$cachedRate=0.50;$outputRate=30.00}
    default {$inputRate=5.00;$cachedRate=0.50;$outputRate=30.00}
  }
  $v=$env:SITEBOSS_OPENAI_INPUT_USD_PER_M;if(-not$v){$v=[Environment]::GetEnvironmentVariable('SITEBOSS_OPENAI_INPUT_USD_PER_M','User')};if($v){$inputRate=[double]$v}
  $v=$env:SITEBOSS_OPENAI_CACHED_INPUT_USD_PER_M;if(-not$v){$v=[Environment]::GetEnvironmentVariable('SITEBOSS_OPENAI_CACHED_INPUT_USD_PER_M','User')};if($v){$cachedRate=[double]$v}
  $v=$env:SITEBOSS_OPENAI_OUTPUT_USD_PER_M;if(-not$v){$v=[Environment]::GetEnvironmentVariable('SITEBOSS_OPENAI_OUTPUT_USD_PER_M','User')};if($v){$outputRate=[double]$v}
  [pscustomobject]@{model=$model;input=$inputRate;cached=$cachedRate;output=$outputRate}
}
function Get-OpenAIReasoningEffort {
  $v=$env:SITEBOSS_OPENAI_REASONING_EFFORT
  if([string]::IsNullOrWhiteSpace($v)){$v='low'}
  if($v-notin@('none','low','medium','high','xhigh','max')){$v='low'}
  return $v
}
function Get-OpenAIOutputLimit {
  $fallback=$(if($null-ne$focusedPacket){3000}else{8000})
  $v=$env:SITEBOSS_OPENAI_MAX_OUTPUT_TOKENS
  if($v){
    $n=[int]$v
    if($n-ge800-and$n-le12000){return $n}
  }
  return $fallback
}
function Record-OpenAIUsage([object]$Obj,[string]$Model){
  if($null-eq$Obj.usage){return}
  $in=[long]$(if($null-ne$Obj.usage.input_tokens){$Obj.usage.input_tokens}else{0})
  $out=[long]$(if($null-ne$Obj.usage.output_tokens){$Obj.usage.output_tokens}else{0})
  $cached=0
  if($null-ne$Obj.usage.input_tokens_details-and$null-ne$Obj.usage.input_tokens_details.cached_tokens){$cached=[long]$Obj.usage.input_tokens_details.cached_tokens}
  if($cached-gt$in){$cached=$in}
  $uncached=$in-$cached
  $price=Get-OpenAIPricing
  $usd=($uncached/1000000.0*$price.input)+($cached/1000000.0*$price.cached)+($out/1000000.0*$price.output)
  $script:Usage.input_tokens+=$in;$script:Usage.cached_input_tokens+=$cached;$script:Usage.output_tokens+=$out;$script:Usage.estimated_usd+=$usd
  [void]$script:CallUsage.Add([pscustomobject]@{model=$Model;input_tokens=$in;cached_input_tokens=$cached;output_tokens=$out;estimated_usd=[Math]::Round($usd,4)})
  Log ("[COST] This AI call: ~${0:N4} USD | input={1:N0} cached={2:N0} output={3:N0}"-f$usd,$in,$cached,$out) 'Yellow'
  Log ("[COST] This Repair Rat run so far: ~${0:N4} USD" -f $script:Usage.estimated_usd) 'Yellow'
}
function Get-TodayCost {
  $today=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-dd')
  $total=0.0
  $roots=@((Join-Path $Root 'state\repair-rat'),(Join-Path $Root 'state\rat-review'))
  foreach($dir in $roots){
    if(-not(Test-Path -LiteralPath $dir)){continue}
    foreach($f in @(Get-ChildItem -LiteralPath $dir -File -Filter '*.json' -ErrorAction SilentlyContinue)){
      try{
        $j=Get-Content -LiteralPath $f.FullName -Raw|ConvertFrom-Json
        $stamp="$($j.generated_at)"
        if($stamp.StartsWith($today)-and$null-ne$j.usage_estimated_usd){$total+=[double]$j.usage_estimated_usd}
      }catch{}
    }
  }
  return $total
}
function Assert-CostBudget {
  $runLimit=3.0;$dailyLimit=10.0
  $v=$env:SITEBOSS_RUN_BUDGET_USD;if(-not$v){$v=[Environment]::GetEnvironmentVariable('SITEBOSS_RUN_BUDGET_USD','User')};if($v){$runLimit=[double]$v}
  $v=$env:SITEBOSS_DAILY_BUDGET_USD;if(-not$v){$v=[Environment]::GetEnvironmentVariable('SITEBOSS_DAILY_BUDGET_USD','User')};if($v){$dailyLimit=[double]$v}
  $today=Get-TodayCost
  if($script:Usage.estimated_usd-ge$runLimit){throw ("BUDGET STOP: repair run estimate ${0:N2} reached run limit ${1:N2}"-f$script:Usage.estimated_usd,$runLimit)}
  if($today-ge$dailyLimit){throw ("BUDGET STOP: today estimate ${0:N2} reached daily limit ${1:N2}"-f$today,$dailyLimit)}
  Log ("[BUDGET] Run limit=${0:N2} USD | daily limit=${1:N2} USD | recorded today~${2:N2} USD"-f$runLimit,$dailyLimit,$today) 'DarkGray'
}
function Get-RunBudgetLimit {
  $runLimit=3.0
  $v=$env:SITEBOSS_RUN_BUDGET_USD
  if(-not$v){$v=[Environment]::GetEnvironmentVariable('SITEBOSS_RUN_BUDGET_USD','User')}
  if($v){$runLimit=[double]$v}
  return $runLimit
}
function Assert-EstimatedCallFitsBudget([string]$Body,[int]$RequestedOutputTokens){
  $price=Get-OpenAIPricing
  $remaining=(Get-RunBudgetLimit)-[double]$script:Usage.estimated_usd
  $bytes=[Text.Encoding]::UTF8.GetByteCount($Body)
  $maxBodyBytes=6MB
  if($bytes-gt$maxBodyBytes){
    throw ("FORGEBOSS_CONTEXT_PACKET_TOO_LARGE: body_bytes={0:N0} exceeds hard ceiling {1:N0}. Compact evidence/source context before another paid call." -f $bytes,$maxBodyBytes)
  }
  $inputTokens=[Math]::Ceiling($bytes/3.2)
  $inputUsd=($inputTokens/1000000.0)*$price.input
  $reserveOut=$RequestedOutputTokens
  $outputUsd=($reserveOut/1000000.0)*$price.output
  $estimate=$inputUsd+$outputUsd
  if($estimate-gt$remaining){
    throw ("BUDGET PREFLIGHT STOP: estimated call floor USD {0:N3} exceeds remaining run budget USD {1:N3}; body_bytes={2:N0}, input_tokens~{3:N0}. If estimate is abnormal, treat this as context-packet inflation rather than raising the budget." -f $estimate,$remaining,$bytes,$inputTokens)
  }
  Log ("[BUDGET PREFLIGHT] body_bytes={0:N0}; input_tokens~{1:N0}; output_reserve={2:N0}; estimated_floor~USD {3:N3}; remaining=USD {4:N3}" -f $bytes,$inputTokens,$reserveOut,$estimate,$remaining) 'DarkGray'
}
function Resolve-RepoModulePath([string]$Repo,[string]$FromFile,[string]$Spec){
  if([string]::IsNullOrWhiteSpace($Spec)-or-not$Spec.StartsWith('.')){return $null}
  $base=Split-Path -Parent (Join-Path $Repo $FromFile)
  $candidate=[IO.Path]::GetFullPath((Join-Path $base $Spec))
  $repoFull=[IO.Path]::GetFullPath($Repo).TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
  $repoPrefix=$repoFull+[IO.Path]::DirectorySeparatorChar
  if(
    -not$candidate.Equals($repoFull,[StringComparison]::OrdinalIgnoreCase) -and
    -not$candidate.StartsWith($repoPrefix,[StringComparison]::OrdinalIgnoreCase)
  ){return $null}
  foreach($p in @($candidate,$candidate+'.js',$candidate+'.cjs',$candidate+'.mjs',(Join-Path $candidate 'index.js'))){
    if(Test-Path -LiteralPath $p -PathType Leaf){
      $fullP=[IO.Path]::GetFullPath($p)
      if(
        -not$fullP.Equals($repoFull,[StringComparison]::OrdinalIgnoreCase) -and
        -not$fullP.StartsWith($repoPrefix,[StringComparison]::OrdinalIgnoreCase)
      ){continue}
      $rel=[IO.Path]::GetRelativePath($repoFull,$fullP).Replace('\','/')
      if($rel.StartsWith('src/')){return $rel}
    }
  }
  return $null
}

function Get-EvidenceDependencyExpansion([string]$Repo,[object]$Evidence,[string[]]$Existing,[int]$MaxFiles=8,[int]$MaxChars=140000){
  $ordered=[System.Collections.Generic.List[string]]::new()
  $seen=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($x in @($Existing)){if(-not[string]::IsNullOrWhiteSpace("$x")){[void]$seen.Add("$x")}}

  function Add-Candidate([string]$Rel){
    if([string]::IsNullOrWhiteSpace($Rel)){return}
    $rel=$Rel.Replace('\','/')
    if(-not$rel.StartsWith('src/')){return}
    if($rel-match'(^|/)\.\.(/|$)'){return}
    if($seen.Contains($rel)){return}
    $full=Join-Path $Repo $rel
    if(-not(Test-Path -LiteralPath $full -PathType Leaf)){return}
    [void]$seen.Add($rel);[void]$ordered.Add($rel)
  }

  $failed=@()
  foreach($run in @($Evidence.runs)){
    if([int]$run.exit_code-ne0){$failed+=$run}
  }

  # 1) Exact source/test paths from authoritative failing stack traces.
  $testFiles=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($run in $failed){
    $blob=((@($run.failure_lines)+@($run.output_tail))-join"`n")
    foreach($m in [regex]::Matches($blob,'/workspace/(src/[A-Za-z0-9_./-]+\.(?:js|cjs|mjs|ts))(?::[0-9]+(?::[0-9]+)?)?')){
      Add-Candidate $m.Groups[1].Value
    }
    foreach($m in [regex]::Matches($blob,'/workspace/(tests/[A-Za-z0-9_./-]+\.(?:js|cjs|mjs|ts))(?::[0-9]+(?::[0-9]+)?)?')){
      [void]$testFiles.Add($m.Groups[1].Value)
    }
  }

  # 2) Imports from the exact failing test files. This often exposes the business
  #    service/call-site omitted by a narrow focused packet.
  foreach($tf in $testFiles){
    $full=Join-Path $Repo $tf
    if(-not(Test-Path -LiteralPath $full)){continue}
    $txt=[IO.File]::ReadAllText($full)
    foreach($m in [regex]::Matches($txt,'(?:require\(|from\s+)["'']([^"'']+)["'']')){
      $rel=Resolve-RepoModulePath $Repo $tf $m.Groups[1].Value
      Add-Candidate $rel
    }
  }

  # 3) One dependency hop from stack/import-discovered source files.
  foreach($rel in @($ordered.ToArray())){
    $full=Join-Path $Repo $rel
    if(-not(Test-Path -LiteralPath $full)){continue}
    $txt=[IO.File]::ReadAllText($full)
    foreach($m in [regex]::Matches($txt,'(?:require\(|from\s+)["'']([^"'']+)["'']')){
      $dep=Resolve-RepoModulePath $Repo $rel $m.Groups[1].Value
      Add-Candidate $dep
      if($ordered.Count-ge$MaxFiles){break}
    }
    if($ordered.Count-ge$MaxFiles){break}
  }

  # 4) Bounded semantic grep from failing test names. This is context discovery,
  #    never independent authority to widen writes.
  $terms=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $stop=@('postgresql','serializable','transaction','failure','failed','preserves','prevents','among','exact','current','production','integration','tests','retry','retries','error')
  foreach($run in $failed){
    foreach($line in @($run.failure_lines)){
      if("$line"-match'not ok [0-9]+ - (.+)$'){
        foreach($m in [regex]::Matches($Matches[1],'[A-Za-z][A-Za-z0-9_-]{4,}')){
          $w=$m.Value.ToLowerInvariant()
          if($stop-notcontains$w){[void]$terms.Add($w)}
        }
      }
    }
  }
  foreach($term in @($terms|Select-Object -First 6)){
    $gr=Run 'git.exe' @('grep','-l','-i','--',$term,'--','src') $Repo
    if($gr.exit_code-eq0){
      foreach($line in @($gr.stdout -split"`r?`n")){
        Add-Candidate $line.Trim()
        if($ordered.Count-ge$MaxFiles){break}
      }
    }
    if($ordered.Count-ge$MaxFiles){break}
  }

  $selected=[System.Collections.Generic.List[string]]::new();$chars=0
  foreach($rel in $ordered){
    if($selected.Count-ge$MaxFiles){break}
    $full=Join-Path $Repo $rel
    $n=[IO.File]::ReadAllText($full).Length
    if(($chars+$n)-gt$MaxChars){continue}
    [void]$selected.Add($rel);$chars+=$n
  }
  return [pscustomobject]@{paths=@($selected);chars=$chars;failed_test_files=@($testFiles)}
}

function Get-ModelEvidenceView([object]$Evidence){
  if($null-eq$Evidence){return $null}
  $failed=@()
  foreach($run in @($Evidence.runs)){
    if([int]$run.exit_code-ne0){
      $failed+=[ordered]@{
        name=$run.name
        exit_code=$run.exit_code
        failure_lines=@($run.failure_lines|Select-Object -First 40)
        output_tail=@($run.output_tail|Select-Object -Last 24)
      }
    }
  }
  $diags=@()
  foreach($d in @($Evidence.diagnostics)){
    $diags+=[ordered]@{
      name=$d.name
      executable=$d.executable
      exit_code=$d.exit_code
      trace_lines=@($d.trace_lines|Select-Object -First 120)
      error_lines=@($d.error_lines|Select-Object -First 80)
      interpretation=$d.interpretation
    }
  }
  return [ordered]@{
    schema=$Evidence.schema
    exact_head=$Evidence.exact_head
    generated_at=$Evidence.generated_at
    executable=$Evidence.executable
    passed=$Evidence.passed
    failure_count=$Evidence.failure_count
    failed_runs=$failed
    diagnostics=$diags
  }
}

function Get-FreshTargetEvidence([string]$Repo,[string]$Head){
  Log "`n[FRESH EVIDENCE] Running exact-head PostgreSQL baseline before any paid call..." 'Cyan'
  $savedRepeat=$RepeatCount;$savedFull=$FullSuiteRepeats
  try{
    $script:RepeatCount=$RepeatCount
    $script:FullSuiteRepeats=$FullSuiteRepeats
    Set-Variable -Name RepeatCount -Value 1 -Scope Script
    Set-Variable -Name FullSuiteRepeats -Value 1 -Scope Script
    $a=Run-Acceptance $Repo 0 0
    $obj=[ordered]@{
      schema=1
      exact_head=$Head
      generated_at=[DateTimeOffset]::UtcNow.ToString('o')
      executable=$true
      passed=$a.passed
      failure_count=$a.failure_count
      runs=@($a.runs)
      diagnostics=@($a.diagnostics)
    }
    Log ("[FRESH EVIDENCE] exact_head=$Head passed=$($a.passed) failures=$($a.failure_count)") $(if($a.passed){'Green'}else{'Yellow'})
    return [pscustomobject]$obj
  }finally{
    Set-Variable -Name RepeatCount -Value $savedRepeat -Scope Script
    Set-Variable -Name FullSuiteRepeats -Value $savedFull -Scope Script
  }
}

function Assert-CaseSensitiveRoot([string]$Path){
  $probe=$Path
  while(-not(Test-Path -LiteralPath $probe)){
    $parent=Split-Path -Parent $probe
    if([string]::IsNullOrWhiteSpace($parent)-or$parent-eq$probe){break}
    $probe=$parent
  }
  if(-not(Test-Path -LiteralPath $probe)){throw "Case-sensitive workspace ancestor does not exist: $Path"}
  $r=Run 'fsutil.exe' @('file','queryCaseSensitiveInfo',$probe)
  if($r.exit_code-ne0-or"$($r.stdout)"-notmatch'(?i)enabled'){
    throw "Repair Rat requires a case-sensitive workspace before any model call. Checked: $probe"
  }
  return $probe
}
function Assert-Pristine([string]$Repo,[string]$Stage){
  $r=Run 'git.exe' @('status','--porcelain=v1','-z','--untracked-files=all') $Repo
  if($r.exit_code-ne0){throw "git status failed during $Stage`: $($r.stderr)"}
  if(-not[string]::IsNullOrEmpty($r.stdout)){
    $printable=($r.stdout -replace "`0",' | ')
    throw "Repair Rat workspace is not pristine during $Stage`: $printable"
  }
}
function Get-CaseCollisionGroups([string]$Repo){
  $r=Run 'git.exe' @('ls-tree','-r','--name-only','HEAD') $Repo
  if($r.exit_code-ne0){throw "git ls-tree failed: $($r.stderr)"}
  $map=@{}
  foreach($path in @($r.stdout -split "`r?`n"|Where-Object{$_})){
    $key=$path.ToLowerInvariant()
    if(-not$map.ContainsKey($key)){$map[$key]=@()}
    $map[$key]+=$path
  }
  $groups=@()
  foreach($key in $map.Keys){
    $u=@($map[$key]|Select-Object -Unique)
    if($u.Count-gt1){$groups+=,@($u)}
  }
  return $groups
}
function Get-PatchCachePath([string]$Head,[string]$EvidenceHash,[string]$ScopeHash,[int]$Attempt){
  New-Item -ItemType Directory -Force -Path $Config.CacheRoot|Out-Null
  $provider=$Config.Provider
  Join-Path $Config.CacheRoot ("pr{0}-{1}-{2}-{3}-{4}-attempt{5}.json"-f$RepairPullRequest,$Head.Substring(0,12),$provider,$EvidenceHash.Substring(0,12),$ScopeHash.Substring(0,12),$Attempt)
}
function Get-OrCreatePatch(
  [int]$Attempt,
  [string]$Head,
  [string]$EvidenceHash,
  [string]$ScopeHash,
  [string]$Instructions,
  [object]$Payload,
  [string]$Repo,
  [string[]]$WriteAllowlist
){
  $cachePath=Get-PatchCachePath $Head $EvidenceHash $ScopeHash $Attempt
  if(Test-Path -LiteralPath $cachePath){
    try{
      $cached=Get-Content -LiteralPath $cachePath -Raw|ConvertFrom-Json
      if("$($cached.schema)"-eq'24'-and"$($cached.head)"-eq$Head-and"$($cached.provider)"-eq$Config.Provider-and"$($cached.evidence_sha256)"-eq$EvidenceHash-and"$($cached.source_scope_sha256)"-eq$ScopeHash){
        Log "PATCH CACHE HIT: attempt $Attempt - no paid model call" 'Green'
        return $cached.patch
      }
    }catch{
      Log "PATCH CACHE INVALID: deleting malformed cache $cachePath" 'Yellow'
      Remove-Item -LiteralPath $cachePath -Force -ErrorAction SilentlyContinue
    }
  }

  if($script:ApiCalls-ge1){throw 'HARD ONE-CALL GUARD: model invocation refused because one paid call already occurred.'}
  $script:CurrentWriteAllowlist=@($WriteAllowlist)
  $script:CurrentAnchorHints=@(Get-CurrentAnchorHints $Repo $WriteAllowlist)
  $patch=Invoke-Model $Instructions $Payload
  foreach($candidateOp in @($patch.operations)){
    if("$($candidateOp.mode)"-ne'create'-and"$($candidateOp.anchor_hint)"-notmatch'^[A-Za-z_$][A-Za-z0-9_$]{3,79}$'){
      throw "PATCH_CONTRACT_INVALID: anchor_hint must be one identifier token copied from the located current line; prose hints are forbidden"
    }
  }
  $patch=Normalize-PatchTransaction $patch $Repo $Head $WriteAllowlist

  # Persist normalized model intent BEFORE touching the working tree so a plumbing/test-runner
  # failure never forces payment for the same exact patch again.
  $cache=[ordered]@{
    schema=24
    created_at=[DateTimeOffset]::UtcNow.ToString('o')
    repair_pr=$RepairPullRequest
    head=$Head
    provider=$Config.Provider
    evidence_sha256=$EvidenceHash
    source_scope_sha256=$ScopeHash
    attempt=$Attempt
    patch=$patch
  }
  Write-JsonAtomic $cachePath $cache 100
  Log "Patch cached before application: $cachePath" 'DarkGray'
  return $patch
}

function Write-JsonAtomic([string]$Path,[object]$Object,[int]$Depth=100){
  $dir=Split-Path -Parent $Path
  if($dir){New-Item -ItemType Directory -Force -Path $dir|Out-Null}
  $tmp="$Path.tmp-$([Guid]::NewGuid().ToString('N'))"
  try{$Object|ConvertTo-Json -Depth $Depth|Set-Content -LiteralPath $tmp -Encoding UTF8;Move-Item -LiteralPath $tmp -Destination $Path -Force}
  finally{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}
}
function Latest-LabEvidence {
  $dir=Join-Path $Root 'state\repair-lab'
  $files=@(Get-ChildItem -LiteralPath $dir -File -Filter 'repair-lab-*.json' -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending)
  foreach($f in $files){
    try{
      $j=Get-Content -LiteralPath $f.FullName -Raw|ConvertFrom-Json
      if("$($j.completed)"-ne'True'){continue}
      if([string]::IsNullOrWhiteSpace($TargetSha)-and"$($j.repair_pr)"-ne"$RepairPullRequest"){continue}
      return [pscustomobject]@{
        path=$f.FullName
        json=$j
        raw=(Get-Content -LiteralPath $f.FullName -Raw)
        historical=([bool](-not[string]::IsNullOrWhiteSpace($TargetSha)))
      }
    }catch{}
  }
  throw 'No completed repair-lab JSON found under state\repair-lab'
}
function Get-SpecialistRouting([string]$Mode,[object]$Packet,[string[]]$BuilderSpecialists=@()){
  if($Mode-eq'builder'-and-not[string]::IsNullOrWhiteSpace($SpecialistPlan)){
    if(-not(Test-Path -LiteralPath $SpecialistPlan)){throw "Controller specialist plan missing: $SpecialistPlan"}
    $plan=Get-Content -LiteralPath $SpecialistPlan -Raw|ConvertFrom-Json
    if("$($plan.routing.mode)"-ne'builder'){throw 'Controller specialist plan mode mismatch'}
    if(@($plan.routing.specialists).Count-gt2){throw 'Controller specialist plan exceeds max builder profiles'}
    $plannedAllowed=@($plan.composition.boundaries.allowed_files|ForEach-Object{"$_"}|Sort-Object)
    $controllerAllowed=@($controllerWriteAllowlist|ForEach-Object{"$_"}|Sort-Object)
    if(($plannedAllowed-join"`n")-ne($controllerAllowed-join"`n")){throw 'Controller specialist plan write boundary does not match controller-approved Repair Rat scope'}
    return $plan
  }
  $dir=Join-Path $Root 'state\specialists'
  New-Item -ItemType Directory -Force -Path $dir|Out-Null
  $id=[Guid]::NewGuid().ToString('N')
  $inputPath=Join-Path $dir "route-input-$id.json"
  $output=Join-Path $dir "route-output-$id.json"
  try{
    $Packet|ConvertTo-Json -Depth 80|Set-Content -LiteralPath $inputPath -Encoding UTF8
    $nodeArgs=@((Join-Path $Root 'controller\specialists-cli.js'),'route','--input',$inputPath,'--mode',$Mode,'--output',$output)
    if($BuilderSpecialists.Count-gt0){$nodeArgs+=@('--builder-specialists',($BuilderSpecialists-join','))}
    $r=Run 'node.exe' $nodeArgs $Root
    if($r.exit_code-ne0){throw "Specialist router failed: $($r.stderr) $($r.stdout)"}
    if(-not(Test-Path -LiteralPath $output)){throw 'Specialist router produced no output'}
    Get-Content -LiteralPath $output -Raw|ConvertFrom-Json
  }finally{
    Remove-Item -LiteralPath $inputPath,$output -Force -ErrorAction SilentlyContinue
  }
}

function Get-CurrentAnchorHints([string]$Repo,[string[]]$WriteAllowlist){
  $set=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $stop=@('const','let','var','function','return','if','else','for','while','true','false','null','undefined','async','await','throw','new','this','class','module','exports','require')
  foreach($rel in @($WriteAllowlist)){
    $full=Join-Path $Repo $rel
    if(-not(Test-Path -LiteralPath $full)){continue}
    $text=[IO.File]::ReadAllText($full)
    foreach($m in [regex]::Matches($text,'[A-Za-z_$][A-Za-z0-9_$]{3,}')){
      $v=$m.Value
      if($stop-notcontains$v){[void]$set.Add($v)}
    }
  }
  return @($set|Sort-Object)
}

function Get-PatchSchema {
  $pathSchema=@{type='string';minLength=1}
  if(@($script:CurrentWriteAllowlist).Count-gt0){
    $pathSchema=@{type='string';enum=@($script:CurrentWriteAllowlist)}
  }

  $editOp=@{
    type='object';additionalProperties=$false
    required=@('path','mode','line_start','line_end','anchor_hint','anchor_role','anchor_locator','new_text','replace_all')
    properties=@{
      path=$pathSchema
      mode=@{type='string';enum=@('replace','insert_before','insert_after','delete')}
      line_start=@{type='integer';minimum=0}
      line_end=@{type='integer';minimum=0}
      anchor_hint=@{type='string';pattern='^[A-Za-z_$][A-Za-z0-9_$]{3,79}$'}
      anchor_role=@{type='string';enum=@('definition','reference','any')}
      anchor_locator=@{type='string';pattern='^L[0-9]+#[0-9a-fA-F]{8}$'}
      new_text=@{type='string'}
      replace_all=@{type='boolean';enum=@($false)}
    }
  }
  $createOp=@{
    type='object';additionalProperties=$false
    required=@('path','mode','line_start','line_end','anchor_hint','anchor_role','anchor_locator','new_text','replace_all')
    properties=@{
      path=$pathSchema
      mode=@{type='string';enum=@('create')}
      line_start=@{type='integer';enum=@(1)}
      line_end=@{type='integer';enum=@(1)}
      anchor_hint=@{type='string';maxLength=0}
      anchor_role=@{type='string';enum=@('any')}
      anchor_locator=@{type='string';maxLength=0}
      new_text=@{type='string';minLength=1}
      replace_all=@{type='boolean';enum=@($false)}
    }
  }

  @{
    type='object';additionalProperties=$false
    required=@('safe','summary','reasoning_summary','operations','validation_plan')
    properties=@{
      safe=@{type='boolean'}
      summary=@{type='string'}
      reasoning_summary=@{type='string'}
      operations=@{type='array';minItems=1;maxItems=16;items=@{anyOf=@($editOp,$createOp)}}
      validation_plan=@{type='array';maxItems=12;items=@{type='string'}}
    }
  }
}

function Get-LineMaterialization([string]$Full,[int]$LineStart,[int]$LineEnd){
  if($LineStart-lt1-or$LineEnd-lt$LineStart){throw "PATCH_LINE_RANGE_INVALID: $LineStart..$LineEnd"}
  $text=[IO.File]::ReadAllText($Full)
  $matches=[regex]::Matches($text,'(?m)^.*(?:\r?\n|$)')
  $lines=@()
  foreach($m in $matches){if($m.Length-gt0){$lines+=$m.Value}}
  if($LineEnd-gt$lines.Count){throw "PATCH_LINE_RANGE_INVALID: requested $LineStart..$LineEnd but file has $($lines.Count) lines"}
  $old=($lines[($LineStart-1)..($LineEnd-1)]-join'')
  if([string]::IsNullOrEmpty($old)){throw "PATCH_LINE_RANGE_INVALID: materialized range is empty"}
  $before=''
  if($LineStart-gt1){$before=$lines[$LineStart-2]}
  $after=''
  if($LineEnd-lt$lines.Count){$after=$lines[$LineEnd]}
  return [pscustomobject]@{old_text=$old;context_before=$before;context_after=$after;line_count=$lines.Count}
}

function Find-ContextualAnchor([string]$Text,[string]$Old,[string]$Before,[string]$After,[bool]$ReplaceAll){
  if([string]::IsNullOrEmpty($Old)){throw 'PATCH_CONTRACT_INVALID: empty edit anchor'}
  $hits=[System.Collections.Generic.List[int]]::new()
  $at=0
  while($at-le$Text.Length-$Old.Length){
    $i=$Text.IndexOf($Old,$at,[StringComparison]::Ordinal)
    if($i-lt0){break}
    [void]$hits.Add($i)
    $at=$i+[Math]::Max(1,$Old.Length)
  }
  if($hits.Count-eq0){throw 'PATCH_PRECONDITION_FAILED: edit anchor not found'}

  if($ReplaceAll){return [pscustomobject]@{all=$true;indexes=@($hits)}}
  if($hits.Count-eq1){return [pscustomobject]@{all=$false;index=$hits[0];contextual=$false}}

  $matches=[System.Collections.Generic.List[int]]::new()
  foreach($i in $hits){
    $leftOk=$true;$rightOk=$true
    if(-not[string]::IsNullOrEmpty($Before)){
      if($i-lt$Before.Length){$leftOk=$false}
      else{
        $left=$Text.Substring($i-$Before.Length,$Before.Length)
        $leftOk=($left-eq$Before)
      }
    }
    if(-not[string]::IsNullOrEmpty($After)){
      $rightStart=$i+$Old.Length
      if($rightStart+$After.Length-gt$Text.Length){$rightOk=$false}
      else{
        $right=$Text.Substring($rightStart,$After.Length)
        $rightOk=($right-eq$After)
      }
    }
    if($leftOk-and$rightOk){[void]$matches.Add($i)}
  }

  if($matches.Count-eq1){
    return [pscustomobject]@{all=$false;index=$matches[0];contextual=$true}
  }
  if($matches.Count-eq0){
    throw "PATCH_CONTEXT_MISMATCH: old_text occurs $($hits.Count) times but supplied context identifies none"
  }
  throw "AMBIGUOUS_EDIT_ANCHOR: old_text occurs $($hits.Count) times and supplied context still matches $($matches.Count) locations"
}

function Resolve-CurrentSymbolRange([string]$Full,[string]$Hint,[object]$LineHint,[string]$Role='any',[string]$Locator=''){
  if([string]::IsNullOrWhiteSpace($Hint)){throw 'PATCH_ANCHOR_INTENT_MISMATCH: anchor_hint is empty'}
  if($Hint-notmatch'^[A-Za-z_$][A-Za-z0-9_$]{3,79}$'){
    throw "PATCH_ANCHOR_INTENT_MISMATCH: anchor_hint must be one exact current-source identifier token, not prose"
  }
  $lines=@(Get-CanonicalFileLines $Full)
  $pat='(?<![A-Za-z0-9_$])'+[regex]::Escape($Hint)+'(?![A-Za-z0-9_$])'
  $defPat='^\s*(?:async\s+)?(?:function|class)\s+'+[regex]::Escape($Hint)+'\b|^\s*(?:const|let|var)\s+'+[regex]::Escape($Hint)+'\b|^\s*(?:async\s+)?(?:static\s+)?'+[regex]::Escape($Hint)+'\s*\('

  # Exact current-line locator is authoritative. Resolve it FIRST, then validate
  # anchor_hint and semantic role against that exact line. This eliminates global
  # symbol ambiguity and prevents stale/prose intent from overriding exact source.
  if(-not[string]::IsNullOrWhiteSpace($Locator)){
    $lm=[regex]::Match($Locator,'^L([0-9]+)#([0-9a-fA-F]{8})$')
    if(-not$lm.Success){throw "PATCH_ANCHOR_LOCATOR_INVALID: expected L<line>#<8hex>"}
    $ln=[int]$lm.Groups[1].Value
    if($ln-lt1-or$ln-gt$lines.Count){throw "PATCH_ANCHOR_LOCATOR_MISMATCH: locator line is outside current file"}
    $line=$lines[$ln-1]
    $actual=(Sha256Text $line.Trim()).Substring(0,8).ToLowerInvariant()
    if($actual-ne$lm.Groups[2].Value.ToLowerInvariant()){
      throw ("PATCH_ANCHOR_LOCATOR_MISMATCH: {0} expected={1} actual={2} line={3}" -f $Locator,$lm.Groups[2].Value.ToLowerInvariant(),$actual,$ln)
    }
    if(-not[regex]::IsMatch($line,$pat)){
      throw "PATCH_ANCHOR_INTENT_MISMATCH: exact located current line does not contain identifier '$Hint'"
    }
    $isDef=[regex]::IsMatch($line,$defPat)
    if($Role-eq'definition'-and-not$isDef){
      throw "PATCH_ANCHOR_ROLE_MISMATCH: located '$Hint' occurrence is not a definition"
    }
    if($Role-eq'reference'-and$isDef){
      throw "PATCH_ANCHOR_ROLE_MISMATCH: located '$Hint' occurrence is a definition, not a reference"
    }
    if($Role-notin@('definition','reference','any')){
      throw "PATCH_CONTRACT_INVALID: unsupported anchor_role '$Role'"
    }
    return [pscustomobject]@{line_start=$ln;line_end=$ln;resolved_by=("exact-locator-"+$Role);line_text=$line;definition=$isDef}
  }

  # Defensive fallback for old/internal transactions. Paid v2.2.1 responses always
  # require anchor_locator, so this path should only serve compatible cached/internal data.
  $all=[System.Collections.Generic.List[object]]::new()
  for($i=0;$i-lt$lines.Count;$i++){
    if([regex]::IsMatch($lines[$i],$pat)){
      $isDef=[regex]::IsMatch($lines[$i],$defPat)
      [void]$all.Add([pscustomobject]@{line=$i+1;definition=$isDef;text=$lines[$i]})
    }
  }
  if($all.Count-eq0){throw "PATCH_ANCHOR_INTENT_MISMATCH: current source contains no exact token '$Hint'"}
  $candidates=@($all)
  if($Role-eq'definition'){$candidates=@($all|Where-Object{$_.definition})}
  elseif($Role-eq'reference'){$candidates=@($all|Where-Object{-not$_.definition})}
  elseif($Role-ne'any'){throw "PATCH_CONTRACT_INVALID: unsupported anchor_role '$Role'"}
  if($candidates.Count-eq1){
    return [pscustomobject]@{line_start=$candidates[0].line;line_end=$candidates[0].line;resolved_by=("fallback-unique-"+$Role);line_text=$candidates[0].text;definition=[bool]$candidates[0].definition}
  }
  throw "AMBIGUOUS_SYMBOL_ANCHOR: exact anchor_locator required when '$Hint' is not unique"
}

function Normalize-PatchTransaction([object]$Patch,[string]$Repo,[string]$Head,[string[]]$WriteAllowlist){
  if($null-eq$Patch){throw 'PATCH_CONTRACT_INVALID: model returned no patch object'}
  $ops=@($Patch.operations)
  if($ops.Count-lt1-or$ops.Count-gt16){throw 'PATCH_CONTRACT_INVALID: operation count outside 1..16'}

  $Patch|Add-Member -NotePropertyName transaction_id -NotePropertyValue ("tx-"+[Guid]::NewGuid().ToString('N')) -Force
  $Patch|Add-Member -NotePropertyName base_sha -NotePropertyValue $Head -Force

  foreach($op in $ops){
    $rel="$($op.path)".Replace('\','/')
    if([string]::IsNullOrWhiteSpace($rel)){
      if(@($WriteAllowlist).Count-eq1){$rel=$WriteAllowlist[0];$op.path=$rel}
      else{throw 'PATCH_CONTRACT_INVALID: operation path missing and scope contains multiple writable files'}
    }
    if($WriteAllowlist-notcontains$rel){throw "PATH_OUTSIDE_SCOPE: $rel"}

    $mode="$($op.mode)"
    $new=[string]$op.new_text
    $hint=[string]$op.anchor_hint
    $role=[string]$op.anchor_role
    $locator=[string]$op.anchor_locator
    $lineStart=0;$lineEnd=0
    try{$lineStart=[int]$op.line_start}catch{}
    try{$lineEnd=[int]$op.line_end}catch{}

    if($mode-eq'create'){
      if([string]::IsNullOrEmpty($new)){throw "PATCH_CONTRACT_INVALID: create new_text must be non-empty for $rel"}
      $op|Add-Member -NotePropertyName old_text -NotePropertyValue '' -Force
      $op|Add-Member -NotePropertyName context_before -NotePropertyValue '' -Force
      $op|Add-Member -NotePropertyName context_after -NotePropertyValue '' -Force
      $op|Add-Member -NotePropertyName expected_file_hash -NotePropertyValue '' -Force
      continue
    }

    if($mode-notin@('replace','insert_before','insert_after','delete')){
      throw "PATCH_CONTRACT_INVALID: unsupported operation mode $mode for $rel"
    }
    $full=Join-Path $Repo $rel
    if(-not(Test-Path -LiteralPath $full)){throw "STALE_FILE: target file missing: $rel"}

    $resolved=Resolve-CurrentSymbolRange $full $hint $lineStart $role $locator
    $lineStart=[int]$resolved.line_start;$lineEnd=[int]$resolved.line_end
    if($mode-eq'insert_before'-and$resolved.definition-and$resolved.line_text-match'^\s*async\s+function\b'-and$new-match'(?m)\bawait\b'){
      throw "PATCH_SEMANTIC_SCOPE_INVALID: await-bearing code cannot be inserted before async function definition '$hint'; use insert_after to place it inside the function body"
    }
    $op|Add-Member -NotePropertyName line_start -NotePropertyValue $lineStart -Force
    $op|Add-Member -NotePropertyName line_end -NotePropertyValue $lineEnd -Force
    $mat=Get-LineMaterialization $full $lineStart $lineEnd
    Log ("PATCH SYMBOL RESOLVED: {0} -> {1}:{2} ({3})" -f $hint,$rel,$lineStart,$resolved.resolved_by) 'DarkGray'
    # ForgeBoss resolves the current symbol and copies the exact
    # current source bytes into the transaction anchor immediately before application.
    $op|Add-Member -NotePropertyName old_text -NotePropertyValue $mat.old_text -Force
    $op|Add-Member -NotePropertyName context_before -NotePropertyValue $mat.context_before -Force
    $op|Add-Member -NotePropertyName context_after -NotePropertyValue $mat.context_after -Force
    $op|Add-Member -NotePropertyName expected_file_hash -NotePropertyValue (Sha256File $full) -Force
    Log ("PATCH ANCHOR MATERIALIZED: {0}:{1}-{2} from exact current workspace" -f $rel,$lineStart,$lineEnd) 'DarkGray'
  }
  return $Patch
}

function Assert-StrictSchemaRequiredCoverage([object]$Node,[string]$Path='$'){
  if($null-eq$Node){return}
  if($Node-is[System.Collections.IDictionary]){
    $hasType=$Node.Contains('type')
    $hasProperties=$Node.Contains('properties')
    if($hasType-and"$($Node['type'])"-eq'object'-and$hasProperties-and$null-ne$Node['properties']){
      $propsNode=$Node['properties']
      if(-not($propsNode-is[System.Collections.IDictionary])){
        throw "FORGEBOSS_SCHEMA_INVALID: $Path.properties is not a dictionary"
      }
      $props=@($propsNode.Keys|ForEach-Object{"$_"})
      $req=@()
      if($Node.Contains('required')-and$null-ne$Node['required']){$req=@($Node['required']|ForEach-Object{"$_"})}
      $missing=@($props|Where-Object{$req-notcontains$_})
      if($missing.Count-gt0){throw "FORGEBOSS_SCHEMA_INVALID: $Path required[] missing: $($missing-join', ')"}
      $unknown=@($req|Where-Object{$props-notcontains$_})
      if($unknown.Count-gt0){throw "FORGEBOSS_SCHEMA_INVALID: $Path required[] contains unknown properties: $($unknown-join', ')"}
    }
    foreach($k in @($Node.Keys)){Assert-StrictSchemaRequiredCoverage $Node[$k] ($Path+'.'+$k)}
    return
  }
  if($Node-is[System.Collections.IEnumerable]-and-not($Node-is[string])){
    $i=0;foreach($v in $Node){Assert-StrictSchemaRequiredCoverage $v ($Path+"[$i]");$i++}
  }
}

function Invoke-OpenAI([string]$Instructions,[object]$Payload){
  $key=[Environment]::GetEnvironmentVariable('OPENAI_API_KEY','User')
  if(-not$key){$key=$env:OPENAI_API_KEY}
  if(-not$key){throw 'OPENAI_API_KEY missing'}
  $payloadJson=ConvertTo-Json -InputObject $Payload -Depth 80 -Compress
  $strictPatchSchema=Get-PatchSchema
  try{Assert-StrictSchemaRequiredCoverage $strictPatchSchema}catch{throw ('FORGEBOSS_SCHEMA_PREFLIGHT_FAILED: '+$_.Exception.Message)}
  $body=ConvertTo-Json -InputObject @{
    model=$Config.OpenAIModel
    instructions=$Instructions
    input=$payloadJson
    reasoning=@{effort=(Get-OpenAIReasoningEffort)}
    max_output_tokens=(Get-OpenAIOutputLimit)
    text=@{format=@{type='json_schema';name='siteboss_repair_rat_patch';strict=$true;schema=$strictPatchSchema}}
  } -Depth 100 -Compress
  Assert-CostBudget
  $requestedOutput=Get-OpenAIOutputLimit
  Assert-EstimatedCallFitsBudget $body $requestedOutput
  $script:ApiCalls++
  Log ("AI repair call {0}/{1}: provider=openai model={2} reasoning={3} max_output={4} body_bytes={5}"-f$script:ApiCalls,$MaxAttempts,$Config.OpenAIModel,(Get-OpenAIReasoningEffort),(Get-OpenAIOutputLimit),[Text.Encoding]::UTF8.GetByteCount($body)) 'DarkGray'
  $resp=Invoke-WebRequest -Method Post -Uri 'https://api.openai.com/v1/responses' -Headers @{Authorization="Bearer $key";'Content-Type'='application/json'} -Body $body -SkipHttpErrorCheck
  if([int]$resp.StatusCode-lt200-or[int]$resp.StatusCode-ge300){throw "OpenAI HTTP $([int]$resp.StatusCode): $($resp.Content)"}
  $obj=$resp.Content|ConvertFrom-Json
  $actualModel=$(if($null-ne$obj.model-and-not[string]::IsNullOrWhiteSpace("$($obj.model)")){"$($obj.model)"}else{$Config.OpenAIModel})
  [void]$script:ActualModels.Add($actualModel)
  Record-OpenAIUsage $obj $actualModel
  $texts=@()
  foreach($i in @($obj.output)){foreach($c in @($i.content)){if($c.type-eq'output_text'){$texts+=$c.text}}}
  if($texts.Count-eq0){throw 'OpenAI returned no output_text'}
  return ($texts-join"`n")|ConvertFrom-Json
}
function Invoke-Claude([string]$Instructions,[object]$Payload){
  throw "PROVIDER_BUDGET_UNSUPPORTED: Anthropic Repair Rat disabled until authoritative reservation ledger integration."

  $key=[Environment]::GetEnvironmentVariable('ANTHROPIC_API_KEY','User')
  if(-not$key){$key=$env:ANTHROPIC_API_KEY}
  if(-not$key){throw 'ANTHROPIC_API_KEY missing'}
  $tool=@{
    name='siteboss_repair_rat_patch'
    description='Return one bounded SiteBoss patch transaction with hashed preconditions and typed edit operations'
    input_schema=(Get-PatchSchema)
  }
  $body=ConvertTo-Json -InputObject @{
    model=$Config.AnthropicModel
    max_tokens=20000
    system=$Instructions
    messages=@(@{role='user';content=(ConvertTo-Json -InputObject $Payload -Depth 80 -Compress)})
    tools=@($tool)
    tool_choice=@{type='tool';name='siteboss_repair_rat_patch'}
  } -Depth 100 -Compress
  $script:ApiCalls++
  Log ("AI repair call {0}/{1}: provider=anthropic model={2} body_bytes={3}"-f$script:ApiCalls,$MaxAttempts,$Config.AnthropicModel,[Text.Encoding]::UTF8.GetByteCount($body)) 'DarkGray'
  $resp=Invoke-WebRequest -Method Post -Uri 'https://api.anthropic.com/v1/messages' -Headers @{
    'x-api-key'=$key;'anthropic-version'='2023-06-01';'content-type'='application/json'
  } -Body $body -SkipHttpErrorCheck
  if([int]$resp.StatusCode-lt200-or[int]$resp.StatusCode-ge300){throw "Anthropic HTTP $([int]$resp.StatusCode): $($resp.Content)"}
  $obj=$resp.Content|ConvertFrom-Json
  foreach($c in @($obj.content)){if($c.type-eq'tool_use'-and$c.name-eq'siteboss_repair_rat_patch'){return $c.input}}
  throw 'Anthropic returned no forced repair tool result'
}
function Invoke-Model([string]$Instructions,[object]$Payload){
  if($Config.Provider-eq'openai'){return Invoke-OpenAI $Instructions $Payload}
  return Invoke-Claude $Instructions $Payload
}


function Load-ReferencePack {
  if(-not(Test-Path -LiteralPath $Config.ReferencePack)){throw "Reference pack missing: $($Config.ReferencePack)"}
  $raw=Get-Content -LiteralPath $Config.ReferencePack -Raw
  [pscustomobject]@{raw=$raw;sha256=(Sha256Text $raw);json=($raw|ConvertFrom-Json)}
}

function Find-LatestRatReviewFailure {
  $candidates=@()
  $local=Join-Path $Root 'state\rat-review'
  if(Test-Path -LiteralPath $local){
    $candidates+=@(Get-ChildItem -LiteralPath $local -File -Filter 'rat-review-*.json' -ErrorAction SilentlyContinue)
  }
  $downloads=Join-Path $env:USERPROFILE 'Downloads'
  if(Test-Path -LiteralPath $downloads){
    foreach($outer in @(Get-ChildItem -LiteralPath $downloads -Directory -Filter 'SiteBoss-Repair-Rat-Review-v0.*' -ErrorAction SilentlyContinue)){
      foreach($dir in @((Join-Path $outer.FullName 'state\rat-review'),(Join-Path $outer.FullName ($outer.Name+'\state\rat-review')))){
        if(Test-Path -LiteralPath $dir){
          $candidates+=@(Get-ChildItem -LiteralPath $dir -File -Filter 'rat-review-*.json' -ErrorAction SilentlyContinue)
        }
      }
    }
  }
  foreach($file in @($candidates|Sort-Object LastWriteTimeUtc -Descending)){
    try{
      $j=Get-Content -LiteralPath $file.FullName -Raw|ConvertFrom-Json
      if("$($j.parent_repair_pr)"-ne"$RepairPullRequest"){continue}
      if("$($j.passed)"-eq'True'){continue}
      if($null-eq$j.acceptance){continue}
      return [pscustomobject]@{path=$file.FullName;raw=(Get-Content -LiteralPath $file.FullName -Raw);json=$j}
    }catch{}
  }
  return $null
}

function Discover-RepairScope([string]$Repo){
  $patterns=@(
    'withTransaction',
    '40001',
    '40P01',
    'acceptInvitation',
    'invitation',
    'recordQualification',
    'INTAKE_CONVERSION_CONFLICT',
    'Trade pack fencing',
    'SERIALIZABLE'
  )

  $found=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach($seed in $SeedAllowedPaths){
    if(Test-Path -LiteralPath (Join-Path $Repo $seed)){[void]$found.Add($seed)}
  }

  foreach($pattern in $patterns){
    $r=Run 'git.exe' @('grep','-l','-I','-E',$pattern,'HEAD','--','src','tests') $Repo
    if($r.exit_code-notin@(0,1)){throw "git grep failed for '$pattern': $($r.stderr)"}
    foreach($line in @($r.stdout -split "`r?`n"|Where-Object{$_})){
      $rel=$line.Trim().Replace('\','/')
      if($rel.StartsWith('src/')-or$rel.StartsWith('tests/')){[void]$found.Add($rel)}
    }
  }

  $ordered=@($found|Sort-Object)
  if($ordered.Count-gt$Config.MaxSourceFiles){
    $seedExisting=@($SeedAllowedPaths|Where-Object{Test-Path -LiteralPath (Join-Path $Repo $_)})
    $rest=@($ordered|Where-Object{$seedExisting-notcontains$_})
    $ordered=@($seedExisting+($rest|Select-Object -First ([Math]::Max(0,$Config.MaxSourceFiles-$seedExisting.Count)))|Select-Object -Unique)
  }

  $write=@()
  foreach($rel in $ordered){
    if($rel.StartsWith('src/')-and$rel.EndsWith('.js')){$write+=$rel}
    elseif($rel-match'^tests/postgres.*\.integration\.test\.js$'){$write+=$rel}
  }
  $write=@($write|Select-Object -Unique|Sort-Object)

  [pscustomobject]@{
    source_paths=$ordered
    write_allowlist=$write
  }
}

function Resolve-RepairScope([string]$Repo,[string]$ManifestPath){
 if([string]::IsNullOrWhiteSpace($ManifestPath)){return Discover-RepairScope $Repo}
 if(-not(Test-Path -LiteralPath $ManifestPath)){throw "Controller scope manifest missing: $ManifestPath"}
 try{$m=Get-Content -LiteralPath $ManifestPath -Raw|ConvertFrom-Json}catch{throw "Controller scope manifest invalid JSON: $ManifestPath :: $($_.Exception.Message)"}
 if([string]::IsNullOrWhiteSpace($TargetSha)){
  if([int]$m.repair_pr-ne$RepairPullRequest){throw "Controller scope repair PR mismatch: manifest=$($m.repair_pr) requested=$RepairPullRequest"}
 }else{
  if([int]$m.root_pr-ne$RootPullRequest){throw "Controller scope root PR mismatch: manifest=$($m.root_pr) requested=$RootPullRequest"}
  if($null-ne$m.repair_pr-and"$($m.repair_pr)"-ne''){throw "Parent-head-local scope must not bind a repair PR: $($m.repair_pr)"}
 }
 if("$($m.exact_head)"-ne"$script:ExactHead"){throw "Controller scope exact head mismatch: manifest=$($m.exact_head) checkout=$script:ExactHead"}
 $source=@($m.source_paths|ForEach-Object{"$_".Replace('\','/')}|Where-Object{$_}|Select-Object -Unique)
 $write=@($m.write_allowlist|ForEach-Object{"$_".Replace('\','/')}|Where-Object{$_}|Select-Object -Unique)
 if($source.Count-lt1){throw 'Controller scope source_paths is empty'};if($write.Count-lt1){throw 'Controller scope write_allowlist is empty'}

 $manifestLimits=$m.PSObject.Properties['limits']
 if($null-eq$manifestLimits){throw 'Controller scope manifest is missing limits'}
 $limits=$manifestLimits.Value

 $sourceLimitProp=$limits.PSObject.Properties['max_source_files']
 $writeLimitProp=$limits.PSObject.Properties['max_write_files']
 if($null-eq$sourceLimitProp-or$null-eq$writeLimitProp){throw 'Controller scope manifest limits are incomplete'}

 $manifestMaxSource=[int]$sourceLimitProp.Value
 $manifestMaxWrite=[int]$writeLimitProp.Value
 if($manifestMaxSource-lt1-or$manifestMaxSource-gt64){throw "Controller scope max_source_files is outside absolute safety ceiling: $manifestMaxSource"}
 if($manifestMaxWrite-lt1-or$manifestMaxWrite-gt32){throw "Controller scope max_write_files is outside absolute safety ceiling: $manifestMaxWrite"}

 if($source.Count-gt$manifestMaxSource){throw "Controller scope source count exceeds manifest limit $manifestMaxSource"}
 if($write.Count-gt$manifestMaxWrite){throw "Controller scope write count exceeds manifest limit $manifestMaxWrite"}
 foreach($rel in $source){if(-not($rel.StartsWith('src/')-or$rel.StartsWith('tests/'))){throw "Unsafe controller source path: $rel"};if(-not(Test-Path -LiteralPath (Join-Path $Repo $rel))){throw "Controller source path missing at exact head: $rel"}}
 foreach($rel in $write){if($source-notcontains$rel){throw "Controller write path is not included in source_paths: $rel"};if(-not($rel.StartsWith('src/')-or$rel.StartsWith('tests/'))){throw "Unsafe controller write path: $rel"}}
 [pscustomobject]@{source_paths=$source;write_allowlist=$write}
}

function Collect-Sources([string]$Repo,[string[]]$SourcePaths){
  $files=@()
  $chars=0
  foreach($rel in $SourcePaths){
    $p=Join-Path $Repo $rel
    if(-not(Test-Path -LiteralPath $p)){continue}
    $content=Get-Content -LiteralPath $p -Raw
    $chars+=$content.Length
    if($chars-gt$Config.MaxSourceChars){
      throw "Bounded source packet exceeded $($Config.MaxSourceChars) chars at '$rel'"
    }
    $files+=@{
      path=$rel
      content=$content
      sha256=(Sha256File $p)
      fully_read=$true
      bytes=([IO.FileInfo]$p).Length
    }
  }
  $files
}

function Apply-Patch([string]$Repo,$Patch,[string[]]$WriteAllowlist){
  Assert-Pristine $Repo 'before patch transaction'
  if("$($Patch.safe)"-ne'True'){throw "MODEL_POLICY_REFUSAL: $($Patch.summary)"}

  $headRun=Run 'git.exe' @('rev-parse','HEAD') $Repo
  if($headRun.exit_code-ne0){throw "PATCH_PRECONDITION_FAILED: cannot resolve repository HEAD"}
  $currentHead=$headRun.stdout.Trim()
  if("$($Patch.base_sha)"-ne$currentHead){
    throw "PATCH_PRECONDITION_FAILED: base SHA mismatch; expected $($Patch.base_sha), current $currentHead"
  }

  $ops=@($Patch.operations)
  if($ops.Count-lt1-or$ops.Count-gt16){throw "PATCH_PRECONDITION_FAILED: operation count outside 1..16"}

  $sources=@{}
  foreach($src in @(Collect-Sources $Repo $WriteAllowlist)){
    $sources["$($src.path)"]=$src
  }

  $byFile=[ordered]@{}
  foreach($op in $ops){
    $rel="$($op.path)".Replace('\','/')
    if([string]::IsNullOrWhiteSpace($rel)-or$rel.StartsWith('/')-or$rel.Contains('..')){
      throw "PATH_OUTSIDE_SCOPE: unsafe operation path $rel"
    }
    if($WriteAllowlist-notcontains$rel){throw "PATH_OUTSIDE_SCOPE: $rel"}
    if(-not$byFile.Contains($rel)){$byFile[$rel]=[System.Collections.Generic.List[object]]::new()}
    [void]$byFile[$rel].Add($op)
  }

  $backupRoot=Join-Path $Root ("state\repair-rat\transactions\"+$Patch.transaction_id)
  New-Item -ItemType Directory -Force -Path $backupRoot|Out-Null
  $touched=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

  foreach($rel in $byFile.Keys){
    $fileOps=@($byFile[$rel])
    $full=Join-Path $Repo $rel
    $createOnly=@($fileOps|Where-Object{"$($_.mode)"-eq'create'}).Count-gt0

    if($createOnly){
      if($fileOps.Count-ne1){throw "PATCH_PRECONDITION_FAILED: create must be the only operation for $rel"}
      if(Test-Path -LiteralPath $full){throw "STALE_FILE: create target already exists: $rel"}
      $op=$fileOps[0]
      if(-not[string]::IsNullOrEmpty("$($op.expected_file_hash)")){throw "PATCH_PRECONDITION_FAILED: create expected_file_hash must be empty"}
      $parent=Split-Path -Parent $full
      New-Item -ItemType Directory -Force -Path $parent|Out-Null
      $final=[string]$op.new_text
    }else{
      if(-not(Test-Path -LiteralPath $full)){throw "STALE_FILE: file no longer exists: $rel"}
      if(-not$sources.ContainsKey($rel)){throw "PATCH_PRECONDITION_FAILED: file was not fully read by this task: $rel"}
      if("$($sources[$rel].fully_read)"-ne'True'){throw "PATCH_PRECONDITION_FAILED: partial read cannot authorize edit: $rel"}

      $before=[IO.File]::ReadAllText($full)
      $actualHash=Sha256File $full
      $expectedHashes=@($fileOps|ForEach-Object{"$($_.expected_file_hash)"}|Select-Object -Unique)
      if($expectedHashes.Count-ne1-or[string]::IsNullOrWhiteSpace($expectedHashes[0])){
        throw "PATCH_PRECONDITION_FAILED: every operation for $rel must carry the same expected_file_hash"
      }
      if($actualHash-ne$expectedHashes[0]){
        throw "STALE_FILE: hash mismatch for $rel; expected $($expectedHashes[0]), current $actualHash"
      }
      if("$($sources[$rel].sha256)"-ne$actualHash){
        throw "STALE_FILE: file changed since task context was assembled: $rel"
      }

      $final=$before
      foreach($op in $fileOps){
        $mode="$($op.mode)"
        $old=[string]$op.old_text
        $new=[string]$op.new_text
        $replaceAll=("$($op.replace_all)"-eq'True')

        if($mode-ne'create'-and[string]::IsNullOrEmpty($old)){
          throw "PATCH_CONTRACT_INVALID: $mode requires non-empty old_text for $rel"
        }

        $ctxBefore=[string]$op.context_before
        $ctxAfter=[string]$op.context_after
        try{$anchor=Find-ContextualAnchor $final $old $ctxBefore $ctxAfter $replaceAll}
        catch{throw ($_.Exception.Message+" in "+$rel)}
        $first=$(if($replaceAll){-1}else{[int]$anchor.index})
        if((-not$replaceAll)-and$anchor.contextual){
          Log ("PATCH ANCHOR RESOLVED: contextual match selected uniquely in "+$rel) 'DarkGray'
        }

        switch($mode){
          'replace' {
            if($replaceAll){$updated=$final.Replace($old,$new)}
            else{$updated=$final.Substring(0,$first)+$new+$final.Substring($first+$old.Length)}
          }
          'delete' {
            if($replaceAll){$updated=$final.Replace($old,'')}
            else{$updated=$final.Substring(0,$first)+$final.Substring($first+$old.Length)}
          }
          'insert_before' {
            if($replaceAll){throw "PATCH_PRECONDITION_FAILED: replace_all is not supported for insert_before"}
            $updated=$final.Substring(0,$first)+$new+$final.Substring($first)
          }
          'insert_after' {
            if($replaceAll){throw "PATCH_PRECONDITION_FAILED: replace_all is not supported for insert_after"}
            $at=$first+$old.Length
            $updated=$final.Substring(0,$at)+$new+$final.Substring($at)
          }
          default {throw "PATCH_PRECONDITION_FAILED: unsupported operation mode $mode"}
        }

        if($updated-eq$final){throw "PATCH_PRECONDITION_FAILED: no-op operation rejected for $rel"}
        $final=$updated
      }

      if($final-eq$before){throw "PATCH_PRECONDITION_FAILED: transaction produced no change for $rel"}

      $backup=Join-Path $backupRoot ($rel.Replace('/','__').Replace('\','__')+'.before')
      [IO.File]::WriteAllText($backup,$before,[Text.UTF8Encoding]::new($false))
    }

    if($final.Length-gt2000000){throw "PATCH_PRECONDITION_FAILED: resulting file exceeds 2,000,000 characters: $rel"}

    $tmp=$full+".forgeboss-"+[Guid]::NewGuid().ToString('N')+".tmp"
    try{
      [IO.File]::WriteAllText($tmp,$final,[Text.UTF8Encoding]::new($false))
      Move-Item -LiteralPath $tmp -Destination $full -Force
    }finally{
      Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    [void]$touched.Add($rel)
  }

  $changed=Run 'git.exe' @('diff','--name-only') $Repo
  if($changed.exit_code-ne0){throw "PATCH_PRECONDITION_FAILED: git diff failed: $($changed.stderr)"}
  $paths=@($changed.stdout -split "`r?`n"|Where-Object{$_})
  if($paths.Count-eq0){throw 'PATCH_PRECONDITION_FAILED: transaction produced no working-tree changes'}
  foreach($p in $paths){
    $n=$p.Replace('\','/')
    if($WriteAllowlist-notcontains$n){throw "PATH_OUTSIDE_SCOPE: unexpected changed path $n"}
    if(-not$touched.Contains($n)){throw "PATCH_PRECONDITION_FAILED: changed file not represented by transaction operation: $n"}
  }

  $diff=Run 'git.exe' @('diff','--no-ext-diff','--') $Repo
  if($diff.exit_code-ne0){throw "PATCH_PRECONDITION_FAILED: structured diff generation failed"}
  $receipt=[ordered]@{
    schema=1
    transaction_id="$($Patch.transaction_id)"
    base_sha=$currentHead
    changed_paths=$paths
    diff_sha256=(Sha256Text $diff.stdout)
    backup_root=$backupRoot
    validation_plan=@($Patch.validation_plan)
    generated_at=[DateTimeOffset]::UtcNow.ToString('o')
  }
  $receiptPath=Join-Path $backupRoot 'transaction-receipt.json'
  Write-JsonAtomic $receiptPath $receipt 30
  Log ("PATCH TRANSACTION APPLIED: {0} files={1} diff={2}"-f$Patch.transaction_id,$paths.Count,$receipt.diff_sha256.Substring(0,12)) 'Green'
  return $paths
}

function Run-Acceptance([string]$Repo,[int]$Attempt,[int]$ValidationRound){
  $net=("rat_net_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  $pg=("rat_pg_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  $ws=("rat_ws_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  $u='siteboss';$db='siteboss_test';$pw='siteboss_test_password'
  $url="postgresql://${u}:${pw}@postgres:5432/$db"
  $runs=[System.Collections.Generic.List[object]]::new()
  $diagnostics=[System.Collections.Generic.List[object]]::new()
  function Step([string]$Name,[string]$Cmd,[bool]$DbAware=$true){
    $dockerArgs=@('run','--rm','--network',$net,'--mount',"type=volume,src=$ws,dst=/workspace",
      '-e','NODE_ENV=test','-w','/workspace',$Config.NodeImage,'sh','-lc',$Cmd)
    if($DbAware){
      $dockerArgs=@('run','--rm','--network',$net,'--mount',"type=volume,src=$ws,dst=/workspace",
        '-e',"DATABASE_URL=$url",'-e','NODE_ENV=test','-e','RUN_POSTGRES_INTEGRATION=1',
        '-w','/workspace',$Config.NodeImage,'sh','-lc',$Cmd)
    }
    $r=Run 'docker.exe' $dockerArgs
    $combined="$($r.stdout)`n$($r.stderr)"
    $lines=@($combined -split "`r?`n")
    [void]$runs.Add([pscustomobject]@{
      name=$Name;exit_code=$r.exit_code
      failure_lines=@($lines|Where-Object{$_-match'(?i)not ok|error:|40001|500 !== 201|Trade pack fencing|AssertionError'}|Select-Object -First 120)
      output_tail=@($lines|Select-Object -Last ([Math]::Min(100,$lines.Count)))
    })
    $status=$(if($r.exit_code-eq0){'PASS'}else{'FAIL'})
    Log ("[$status] attempt $Attempt round $ValidationRound :: $Name") $(if($r.exit_code-eq0){'Green'}else{'Red'})
    return $r.exit_code
  }

  function Run-RetryTraceDiagnostic {
    $source='/workspace/src/persistence/postgres.js'
    $instrument=@'
const fs=require("fs");
const p="/workspace/src/persistence/postgres.js";
let s=fs.readFileSync(p,"utf8");
const loop="for (let attempt = 1; attempt <= attempts; attempt += 1) {";
const decision='if (!retryable) throw error;';
if ((s.split(loop).length-1)!==1 || (s.split(decision).length-1)!==1) {
  console.error("FORGEBOSS_TRACE_INSTRUMENTATION_UNSUPPORTED");
  process.exit(42);
}
s=s.replace(loop, loop + `
    if (process.env.FORGEBOSS_RETRY_TRACE === "1") console.error("[FB_RETRY_TRACE] "+JSON.stringify({phase:"start",attempt,at:Date.now()}));`);
s=s.replace(decision, `
      if (process.env.FORGEBOSS_RETRY_TRACE === "1") console.error("[FB_RETRY_TRACE] "+JSON.stringify({
        phase:"decision",attempt,at:Date.now(),code:String(error&&error.code||""),
        outcome:attemptContext.outcome,sameError:(attemptContext.error===error),retryable,
        aborted:Boolean(signal&&signal.aborted)
      }));
      `+decision);
fs.writeFileSync(p,s);
'@
    $b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($instrument))
    $injectCmd="node -e `"eval(Buffer.from('$b64','base64').toString())`""
    $injectArgs=@('run','--rm','--network',$net,'--mount',"type=volume,src=$ws,dst=/workspace",
      '-e',"DATABASE_URL=$url",'-e','NODE_ENV=test','-e','RUN_POSTGRES_INTEGRATION=1',
      '-w','/workspace',$Config.NodeImage,'sh','-lc',$injectCmd)
    $inj=Run 'docker.exe' $injectArgs
    if($inj.exit_code-ne0){
      [void]$diagnostics.Add([pscustomobject]@{
        name='serializable_retry_trace';executable=$false;reason=(($inj.stderr+" "+$inj.stdout)-replace'\s+',' ').Trim()
        trace_lines=@();error_lines=@()
      })
      return
    }

    $traceCmd='FORGEBOSS_RETRY_TRACE=1 node --test tests/postgres*.integration.test.js'
    $traceArgs=@('run','--rm','--network',$net,'--mount',"type=volume,src=$ws,dst=/workspace",
      '-e',"DATABASE_URL=$url",'-e','NODE_ENV=test','-e','RUN_POSTGRES_INTEGRATION=1',
      '-e','FORGEBOSS_RETRY_TRACE=1','-w','/workspace',$Config.NodeImage,'sh','-lc',$traceCmd)
    $tr=Run 'docker.exe' $traceArgs
    $combined="$($tr.stdout)`n$($tr.stderr)"
    $lines=@($combined -split "`r?`n")
    $traceLines=@($lines|Where-Object{$_-match'\[FB_RETRY_TRACE\]'}|Select-Object -First 240)
    $errorLines=@($lines|Where-Object{$_-match'(?i)40001|could not serialize|withSerializableRetry|ERR_REQUIRE_'}|Select-Object -First 160)
    [void]$diagnostics.Add([pscustomobject]@{
      name='serializable_retry_trace'
      executable=$true
      exit_code=$tr.exit_code
      trace_lines=$traceLines
      error_lines=$errorLines
      interpretation='Trace is from an instrumented disposable Docker workspace only. SiteBoss source in the repair worktree is unchanged. decision rows expose attempt number, PostgreSQL code, rollback outcome, error identity, retry eligibility and timing.'
    })
  }

  try{
    foreach($img in @($Config.NodeImage,$Config.PostgresImage)){
      $q=Run 'docker.exe' @('image','inspect',$img)
      if($q.exit_code-ne0){throw "Missing Docker image $img"}
    }
    $q=Run 'docker.exe' @('network','create',$net);if($q.exit_code-ne0){throw "network create failed: $($q.stderr)"}
    $q=Run 'docker.exe' @('volume','create',$ws);if($q.exit_code-ne0){throw "volume create failed: $($q.stderr)"}
    $q=Run 'docker.exe' @('run','-d','--rm','--name',$pg,'--network',$net,'--network-alias','postgres',
      '-e',"POSTGRES_DB=$db",'-e',"POSTGRES_USER=$u",'-e',"POSTGRES_PASSWORD=$pw",$Config.PostgresImage)
    if($q.exit_code-ne0){throw "postgres start failed: $($q.stderr)"}
    $ready=$false
    for($i=1;$i-le30;$i++){
      $q=Run 'docker.exe' @('exec',$pg,'pg_isready','-U',$u,'-d',$db)
      if($q.exit_code-eq0){$ready=$true;break};Start-Sleep 1
    }
    if(-not$ready){throw 'postgres readiness timeout'}

    $q=Run 'docker.exe' @('run','--rm','--network',$net,
      '--mount',"type=bind,src=$Repo,dst=/source,readonly",'--mount',"type=volume,src=$ws,dst=/workspace",
      '-e','npm_config_cache=/tmp/npm-cache','--tmpfs','/tmp','-w','/workspace',$Config.NodeImage,
      'sh','-lc','cp -a /source/. /workspace/ && npm ci --ignore-scripts --no-audit --no-fund')
    if($q.exit_code-ne0){throw "npm ci failed: $($q.stdout) $($q.stderr)"}

    [void](Step 'npm_test' 'npm test' $false)
    [void](Step 'initial_migrate' 'npm run db:migrate' $true)

    foreach($i in 1..$RepeatCount){
      [void](Step "business_invitations_$i" 'node --test tests/postgresBusinessInvitations.integration.test.js' $true)
      [void](Step "production_http_$i" 'node --test tests/postgresProductionHttp.integration.test.js' $true)
      [void](Step "travis_intake_$i" 'node --test tests/postgresTravisIntake.integration.test.js' $true)
    }
    foreach($i in 1..$FullSuiteRepeats){
      [void](Step "full_postgres_suite_round${ValidationRound}_$i" 'node --test tests/postgres*.integration.test.js' $true)
    }

    $saw40001=@($runs|Where-Object{(@($_.failure_lines)-join"`n")-match'40001'}).Count-gt0
    if($saw40001){
      Log '[DIAGNOSTIC] 40001 observed; collecting disposable retry-attempt trace before teardown.' 'Cyan'
      Run-RetryTraceDiagnostic
    }

    [void](Step 'rollback' 'npm run db:rollback' $true)
    [void](Step 'migrate_again' 'npm run db:migrate' $true)

    $fails=@($runs|Where-Object{$_.exit_code-ne0})
    return [pscustomobject]@{
      passed=($fails.Count-eq0)
      validation_round=$ValidationRound
      runs=@($runs)
      diagnostics=@($diagnostics)
      failure_count=$fails.Count
    }
  }finally{
    try{[void](Run 'docker.exe' @('rm','-f',$pg))}catch{}
    try{[void](Run 'docker.exe' @('volume','rm','-f',$ws))}catch{}
    try{[void](Run 'docker.exe' @('network','rm',$net))}catch{}
  }
}
function Failure-Fingerprint($Acceptance){
  $parts=@()
  foreach($r in @($Acceptance.runs|Where-Object{$_.exit_code-ne0})){
    $parts+=("$($r.name):"+(($r.failure_lines|Select-Object -First 8)-join'|'))
  }
  return Sha256Text ($parts-join"`n")
}
function Get-FocusedTargetSteps($FocusedPacket){
  if($null-eq$FocusedPacket){return @()}
  $primary="$($FocusedPacket.primary_failed_step)"
  if(-not[string]::IsNullOrWhiteSpace($primary)){return @($primary)}
  # Backward compatibility: focused packets created before v1.7 did not carry
  # primary_failed_step. Derive the focused target from their failed_steps.
  $steps=@($FocusedPacket.failed_steps|ForEach-Object{"$_"}|Where-Object{$_})
  $isolated=@($steps|Where-Object{-not$_.StartsWith('full_postgres_suite_')})
  if($isolated.Count-gt0){return @($isolated)}
  return @($steps|Select-Object -First 1)
}
function Try-ValidatedLocalLesson([string]$Repo,[string[]]$WriteAllowlist,[object]$Evidence){
  $evidenceText=''
  try{$evidenceText=$Evidence|ConvertTo-Json -Depth 80 -Compress}catch{$evidenceText="$Evidence"}

  if($WriteAllowlist-contains'src/travis/conversation.js'){
    $full=Join-Path $Repo 'src/travis/conversation.js'
    if(Test-Path -LiteralPath $full){
      $text=[IO.File]::ReadAllText($full)
      $old='const identity = `${providerKey}\u0000${messageId}`;'
      $new='const identity = JSON.stringify([providerKey, String(messageId)]);`n  session.messageIdentityVersion = 2;'
      $evidenceMatch=($evidenceText-match'(?i)22P05|unsupported Unicode escape|unsupported.*unicode.*escape|\\u0000|NUL')
      $count=([regex]::Matches($text,[regex]::Escape($old))).Count
      if($evidenceMatch-and$count-eq1){
        [IO.File]::WriteAllText($full,$text.Replace($old,$new),[Text.UTF8Encoding]::new($false))
        $syntax=Run 'node.exe' @('--check','src/travis/conversation.js') $Repo
        if($syntax.exit_code-ne0){
          [IO.File]::WriteAllText($full,$text,[Text.UTF8Encoding]::new($false))
          return [pscustomobject]@{applied=$false;reason='local lesson syntax validation failed'}
        }
        Log 'REPAIR RAT LEARNED HIT: applied verified Travis 22P05/NUL repair locally; AI spend=$0.' 'Green'
        return [pscustomobject]@{applied=$true;lesson_id='siteboss.travis-jsonb-structured-identity.v2';family='postgresql-22p05-jsonb';changed_paths=@('src/travis/conversation.js');summary='Replace Travis provider/message identity with collision-safe structured JSON encoding'}
      }
    }
  }
  return [pscustomobject]@{applied=$false;reason='no exact validated local lesson matched current evidence/source'}
}

function Test-FastCandidateSyntax([string]$Repo,[string[]]$ChangedPaths){
  foreach($rel in @($ChangedPaths)){
    if($rel-match'\.(js|cjs|mjs)$'){
      $check=Run 'node.exe' @('--check',$rel) $Repo
      if($check.exit_code-ne0){
        $msg=(($check.stderr+" "+$check.stdout)-replace'\s+',' ').Trim()
        return [pscustomobject]@{passed=$false;reason=("FAST_SYNTAX_GUARD: node --check failed for "+$rel+" :: "+$msg)}
      }
      $full=Join-Path $Repo $rel
      $src=[IO.File]::ReadAllText($full)
      if($src.Contains('module.exports')-or$src.Contains('exports.')){
        $loader='const p=require("path").resolve(process.argv[1]); require(p);'
        $load=Run 'node.exe' @('-e',$loader,$rel) $Repo
        if($load.exit_code-ne0){
          $msg=(($load.stderr+" "+$load.stdout)-replace'\s+',' ').Trim()
          return [pscustomobject]@{passed=$false;reason=("FAST_MODULE_LOAD_GUARD: CommonJS load failed for "+$rel+" :: "+$msg)}
        }
      }
    }
  }
  return [pscustomobject]@{passed=$true;reason=$null}
}

function Test-IntroducedRegression([object]$Acceptance,[object]$FocusedPacket){
  $runs=@($Acceptance.runs)
  $npm=@($runs|Where-Object{$_.name-eq'npm_test'}|Select-Object -First 1)
  if($npm.Count-gt0-and[int]$npm[0].exit_code-ne0){return $true}
  $allText=($runs|ForEach-Object{(@($_.failure_lines)-join"`n")+"`n"+(@($_.output_tail)-join"`n")})-join"`n"
  if($allText-match'(?i)\bReferenceError\b|\bSyntaxError\b|\bTypeError\b|is not defined|Cannot find module|Unexpected token|ERR_REQUIRE_ASYNC_MODULE|ERR_REQUIRE_'){return $true}
  return $false
}

function Test-FocusedTargetResolved($Acceptance,$FocusedPacket){
  $targets=@(Get-FocusedTargetSteps $FocusedPacket)
  if($targets.Count-lt1){return $false}
  $seen=0
  foreach($target in $targets){
    $matches=@($Acceptance.runs|Where-Object{"$($_.name)"-eq"$target"})
    if($matches.Count-lt1){continue}
    $seen++
    if(@($matches|Where-Object{$_.exit_code-ne0}).Count-gt0){return $false}
  }
  return ($seen-gt0)
}
function Test-FocusedFailureFamilyCleared($Acceptance,$FocusedPacket){
  if($null-eq$FocusedPacket){return $false}
  $evidenceText=((@($FocusedPacket.evidence)+@($FocusedPacket.failed_steps)) -join "`n").ToLowerInvariant()
  if([string]::IsNullOrWhiteSpace($evidenceText)){return $false}
  $failureText=''
  foreach($run in @($Acceptance.runs|Where-Object{$_.exit_code-ne0})){
    $failureText+=("`n"+(@($run.failure_lines)-join"`n")+"`n"+(@($run.output_tail)-join"`n"))
  }
  $failureText=$failureText.ToLowerInvariant()

  # Treat the focused family as cleared when the packet explicitly contained one
  # of these high-confidence signatures and that signature disappeared after patch.
  $signatures=@(
    @('22p05','22p05'),
    @('unsupported unicode escape','unsupported unicode escape'),
    @('500 !== 200','500 !== 200'),
    @('500 !== 201','500 !== 201'),
    @('serializable transaction retry exhausted','serializable transaction retry exhausted'),
    @('40001','40001')
  )
  $had=$false
  foreach($pair in $signatures){
    if($evidenceText.Contains($pair[0])){
      $had=$true
      if($failureText.Contains($pair[1])){return $false}
    }
  }
  return $had
}

function Test-TargetedRegressionGatesGreen($Acceptance){
  $runs=@($Acceptance.runs)
  if($runs.Count-lt1){return $false}
  $targeted=@($runs|Where-Object{
    "$($_.name)"-eq'npm_test' -or
    "$($_.name)"-eq'initial_migrate' -or
    "$($_.name)"-eq'rollback' -or
    "$($_.name)"-eq'migrate_again' -or
    "$($_.name)"-like'business_invitations_*' -or
    "$($_.name)"-like'production_http_*' -or
    "$($_.name)"-like'travis_intake_*'
  })
  if($targeted.Count-lt1){return $false}
  if(@($targeted|Where-Object{$_.exit_code-ne0}).Count-gt0){return $false}
  $broadFails=@($runs|Where-Object{"$($_.name)"-like'full_postgres_suite_*' -and $_.exit_code-ne0})
  return ($broadFails.Count-gt0)
}

function Save-RetainedPartialPatch([string]$Repo,[string]$AuthoritativeHead,[string]$Commit,[string]$ResolvedStep){
  $dir=Join-Path $Root 'state\repair-rat'
  New-Item -ItemType Directory -Force -Path $dir|Out-Null

  # A retained foundation is always a cumulative patch from the ORIGINAL authoritative
  # base to the newest verified local commit. Never chain a patch whose exact_head is
  # the previous local commit: the next Repair Rat invocation always checks out the
  # frozen authoritative base first.
  $base="$AuthoritativeHead"
  if(-not[string]::IsNullOrWhiteSpace("$($Config.RetainedFoundation)")-and(Test-Path -LiteralPath $Config.RetainedFoundation)){
    try{
      $prior=Get-Content -LiteralPath $Config.RetainedFoundation -Raw|ConvertFrom-Json
      if(-not[string]::IsNullOrWhiteSpace("$($prior.authoritative_base_sha)")){$base="$($prior.authoritative_base_sha)"}
      elseif(-not[string]::IsNullOrWhiteSpace("$($prior.exact_head)")){$base="$($prior.exact_head)"}
    }catch{throw "Retained foundation metadata unreadable while composing cumulative foundation: $($_.Exception.Message)"}
  }

  $ancestor=Run 'git.exe' @('merge-base','--is-ancestor',$base,$Commit) $Repo
  if($ancestor.exit_code-ne0){throw "Retained foundation ancestry mismatch: authoritative base $base is not an ancestor of verified commit $Commit"}

  $pr=Run 'git.exe' @('diff','--binary',$base,$Commit,'--') $Repo
  if($pr.exit_code-ne0){throw "retained cumulative patch generation failed: $($pr.stderr)"}
  if([string]::IsNullOrWhiteSpace($pr.stdout)){throw 'retained cumulative patch is empty'}

  $pp=Join-Path $dir 'retained-foundation-last.patch'
  [IO.File]::WriteAllText($pp,$pr.stdout,[Text.UTF8Encoding]::new($false))
  $mp=Join-Path $dir 'retained-foundation-last.json'
  Write-JsonAtomic $mp ([ordered]@{
    schema=2
    exact_head=$base
    authoritative_base_sha=$base
    local_commit=$Commit
    resolved_step=$ResolvedStep
    cumulative=$true
    patch_path=$pp
    created_at=[DateTimeOffset]::UtcNow.ToString('o')
  }) 20
  $script:RetainedPatchPath=$mp
  Log ("REPAIR RAT FOUNDATION CHAIN: cumulative verified foundation now spans "+$base.Substring(0,12)+" -> "+$Commit.Substring(0,12)) 'Green'
  return $mp
}

function Write-Report([bool]$Passed){
  $obj=[ordered]@{
    schema=1
    name='SiteBoss Repair Rat'
    generated_at=[DateTimeOffset]::UtcNow.ToString('o')
    repair_pr=$RepairPullRequest
    root_pr=$RootPullRequest
    target_mode=$(if([string]::IsNullOrWhiteSpace($TargetSha)){'existing-child'}else{'parent-head-local'})
    exact_head=$script:ExactHead
    provider=$Config.Provider
    requested_model=$(if($Config.Provider-eq'openai'){$Config.OpenAIModel}else{$Config.AnthropicModel})
    actual_models=@($script:ActualModels)
    api_calls=$script:ApiCalls
    usage_estimated_usd=[Math]::Round([double]$script:Usage.estimated_usd,4)
    usage_input_tokens=$script:Usage.input_tokens
    usage_cached_input_tokens=$script:Usage.cached_input_tokens
    usage_output_tokens=$script:Usage.output_tokens
    usage_calls=@($script:CallUsage)

    max_attempts=$MaxAttempts
    repair_contract='one-paid-call-v1.7.3'
    effective_paid_attempt_cap=1
    repeat_count=$RepeatCount
    full_suite_repeats=$FullSuiteRepeats
    validation_rounds=$ValidationRounds
    reference_pack_sha256=$(if(Get-Variable referencePack -ErrorAction SilentlyContinue){$referencePack.sha256}else{$null})
    clean_feedback_sha256=$(if(Get-Variable feedbackHash -ErrorAction SilentlyContinue){$feedbackHash}else{$null})
    passed=$Passed
    local_workspace=$script:Workspace
    local_commit=$script:FinalCommit
    partial_proven=$script:PartialProven
    resolved_focused_step=$script:ResolvedFocusedStep
    retained_patch_path=$script:RetainedPatchPath
    inherited_retained_foundation=$(if([string]::IsNullOrWhiteSpace("$($Config.RetainedFoundation)")){$null}else{$Config.RetainedFoundation})
    patch_cache_root=$Config.CacheRoot
    source_scope_sha256=$(if(Get-Variable scopeHash -ErrorAction SilentlyContinue){$scopeHash}else{$null})
    fatal_failure=$script:Fatal
    guarantees=@{
      github_repo_writes=0;pushes=0;pr_updates=0;ref_updates=0;merges=0;deploys=0
    }
    attempts=@($script:Attempts)
    builder_specialists=@($script:BuilderSpecialists)
  }
  Write-JsonAtomic $ReportPath $obj 60
  Log "Repair Rat report: $ReportPath" 'Cyan'
}
trap {
  $script:Fatal=[ordered]@{
    reason=$_.Exception.Message
    type=$_.Exception.GetType().FullName
    stack="$($_.ScriptStackTrace)"
    position="$($_.InvocationInfo.PositionMessage)"
  }
  Write-Report $false
  Log ("REPAIR RAT FAILED: "+$script:Fatal.reason) 'Red'
  exit 2
}

Log "`nSITEBOSS REPAIR RAT v1.7.3-one-paid-call" 'Cyan'
Log 'HARD ONE-CALL CONTRACT: effective MaxAttempts=1' 'Green'
Log 'LOCAL BATCH REPAIR - AI may edit disposable workspace; GitHub publication is forbidden.' 'Green'
Log ("Provider={0}; max attempts={1}; repeat count={2}"-f$Config.Provider,$MaxAttempts,$RepeatCount) 'DarkGray'

$evidence=Latest-LabEvidence
if([string]::IsNullOrWhiteSpace($TargetSha)){
  $expectedHead="$($evidence.json.exact_head)"
  if([string]::IsNullOrWhiteSpace($expectedHead)){throw 'Repair-lab evidence has no exact_head'}
}else{
  if($RootPullRequest-lt1){throw 'RootPullRequest is required with TargetSha'}
  $expectedHead=$TargetSha
  if("$($evidence.json.exact_head)"-ne$TargetSha){
    Log "Historical repair-lab evidence head: $($evidence.json.exact_head)" 'Yellow'
    Log "Fresh controller target head: $TargetSha" 'Green'
  }
}

$caseProbe=Assert-CaseSensitiveRoot $Config.WorkspaceRoot
Log "Case-sensitive Repair Rat workspace: READY ($caseProbe)" 'Green'

$work=Join-Path $Config.WorkspaceRoot "$Stamp\repo"
New-Item -ItemType Directory -Force -Path (Split-Path $work -Parent)|Out-Null
$script:Workspace=$work

$r=Run 'git.exe' @('clone','--no-checkout','--filter=blob:none',$Config.RepoUrl,$work)
if($r.exit_code-ne0){throw "clone failed: $($r.stderr)"}
[void](Run 'git.exe' @('config','--local','core.autocrlf','false') $work)
[void](Run 'git.exe' @('config','--local','core.safecrlf','false') $work)
if([string]::IsNullOrWhiteSpace($TargetSha)){
  $r=Run 'git.exe' @('fetch','origin',"pull/$RepairPullRequest/head:refs/remotes/origin/repair-rat-target") $work
  if($r.exit_code-ne0){throw "fetch PR failed: $($r.stderr)"}
  $r=Run 'git.exe' @('rev-parse','refs/remotes/origin/repair-rat-target') $work
  if($r.exit_code-ne0){throw "resolve PR head failed: $($r.stderr)"}
  $head=$r.stdout.Trim()
  $branchName="repair-rat/pr$RepairPullRequest-$Stamp"
}else{
  $r=Run 'git.exe' @('fetch','--no-tags','origin',$TargetSha) $work
  if($r.exit_code-ne0){throw "fetch controller target SHA failed: $($r.stderr)"}
  $r=Run 'git.exe' @('rev-parse','FETCH_HEAD') $work
  if($r.exit_code-ne0){throw "resolve controller target SHA failed: $($r.stderr)"}
  $head=$r.stdout.Trim()
  $branchName="repair-rat/root-pr$RootPullRequest-$Stamp"
}
$script:ExactHead=$head
if($head-ne$expectedHead){throw "Exact-head mismatch: expected=$expectedHead resolved=$head"}
$r=Run 'git.exe' @('checkout','-b',$branchName,$head) $work
if($r.exit_code-ne0){throw "checkout failed: $($r.stderr)"}
[void](Run 'git.exe' @('config','user.name','SiteBoss Repair Rat') $work)
[void](Run 'git.exe' @('config','user.email','repair-rat@users.noreply.github.com') $work)
[void](Run 'git.exe' @('reset','--hard',$head) $work)
[void](Run 'git.exe' @('clean','-ffd') $work)
Assert-Pristine $work 'pre-model baseline'
if(-not[string]::IsNullOrWhiteSpace("$($Config.RetainedFoundation)")){
  $fm=Get-Content -LiteralPath $Config.RetainedFoundation -Raw|ConvertFrom-Json
  $foundationBase=$(if(-not[string]::IsNullOrWhiteSpace("$($fm.authoritative_base_sha)")){"$($fm.authoritative_base_sha)"}else{"$($fm.exact_head)"})
  if($foundationBase-ne"$head"){throw "Retained foundation base mismatch: $foundationBase != $head"}
  $pp=[IO.Path]::GetFullPath("$($fm.patch_path)")
  $check=Run 'git.exe' @('apply','--check','--',$pp) $work
  if($check.exit_code-ne0){throw "Retained foundation no longer applies cleanly: $($check.stderr)"}
  $apply=Run 'git.exe' @('apply','--',$pp) $work
  if($apply.exit_code-ne0){throw "Retained foundation apply failed: $($apply.stderr)"}
  $add=Run 'git.exe' @('add','--all') $work
  if($add.exit_code-ne0){throw "Retained foundation staging failed: $($add.stderr)"}
  $commit=Run 'git.exe' @('commit','-m','repair-rat: replay verified foundation') $work
  if($commit.exit_code-ne0){throw "Retained foundation local commit failed: $($commit.stderr)"}
  $newHead=Run 'git.exe' @('rev-parse','HEAD') $work
  if($newHead.exit_code-ne0){throw "Retained foundation HEAD resolve failed: $($newHead.stderr)"}
  $head=$newHead.stdout.Trim()
  $attemptBase=$head
  Assert-Pristine $work 'retained foundation baseline'
  Log ("REPAIR RAT FOUNDATION: verified sub-fix replayed and committed locally at "+$head.Substring(0,12)) 'Green'
}


$collisions=@(Get-CaseCollisionGroups $work)
if($collisions.Count-gt0){
  foreach($group in $collisions){Log ("CASE COLLISION: "+($group -join' <> ')) 'DarkGray'}
}
Log "Repair Rat baseline: PRISTINE before any paid model call" 'Green'
Log "Exact repair target verified: $head" 'Green'

$evidenceHash=Sha256Text $evidence.raw
Log "Repair-lab evidence SHA256: $evidenceHash" 'DarkGray'

$scope=Resolve-RepairScope $work $ScopeManifest
$sourcePaths=[string[]]@($scope.source_paths)
$controllerWriteAllowlist=[string[]]@($scope.write_allowlist)
$writeAllowlist=[string[]]@($scope.write_allowlist)
$focusedPacket=$null
if(-not[string]::IsNullOrWhiteSpace($Config.FocusedPacket)-and(Test-Path -LiteralPath $Config.FocusedPacket)){
  try{
    $fp=Get-Content -LiteralPath $Config.FocusedPacket -Raw|ConvertFrom-Json
    $packetExact=("$($fp.target_sha)"-eq"$head")
    $packetOnRetainedFoundation=(
      "$($fp.partial_foundation)"-eq'True' -and
      -not[string]::IsNullOrWhiteSpace("$($Config.RetainedFoundation)") -and
      "$($fp.authoritative_base_sha)"-eq"$expectedHead"
    )
    if(($packetExact-or$packetOnRetainedFoundation)-and@($fp.focused_files).Count-gt0){
      $focusedPacket=$fp
      if($packetOnRetainedFoundation-and-not$packetExact){
        Log "FOCUSED EVIDENCE HANDOFF: accepted packet from authoritative base after verified foundation replay." 'Green'
      }
      $sourcePaths=[string[]]@($fp.focused_files|ForEach-Object{"$($_.path)"})
      $writeAllowlist=[string[]]@($writeAllowlist|Where-Object{$sourcePaths-contains$_})
      if($writeAllowlist.Count-lt1){throw 'Focused packet contains no controller-approved writable source file; refusing to widen scope.'}
      Log ("COST FUNNEL: using {0} focused files / {1} chars instead of full source packet."-f@($fp.focused_files).Count,$fp.focused_source_chars) 'Green'
    }
  }catch{Log ("Focused debug packet unreadable; falling back to full bounded scope: "+$_.Exception.Message) 'Yellow'}
}
if($sourcePaths.Count-lt1){throw 'Repair Rat discovered no source files'}
if($writeAllowlist.Count-lt1){throw 'Repair Rat discovered no writable repair files'}
$scopeHash=Sha256Text (($sourcePaths|Sort-Object)-join"`n")

$referencePack=Load-ReferencePack
Log "Open-source reference pack SHA256: $($referencePack.sha256)" 'DarkGray'
$ratReviewFailure=Find-LatestRatReviewFailure

# ForgeBoss autonomy may supply fresh deterministic acceptance evidence from the
# immediately preceding failed cycle. It is accepted ONLY when bound to the exact
# current target SHA. Stale feedback is ignored.
$forgeBossFeedback=[Environment]::GetEnvironmentVariable('SITEBOSS_FORGEBOSS_FAILURE_FEEDBACK','Process')
if(-not[string]::IsNullOrWhiteSpace($forgeBossFeedback)-and(Test-Path -LiteralPath $forgeBossFeedback)){
  try{
    $fbRaw=Get-Content -LiteralPath $forgeBossFeedback -Raw
    $fbJson=$fbRaw|ConvertFrom-Json
    $feedbackExact=("$($fbJson.target_sha)"-eq"$head")
    $feedbackOnRetainedFoundation=(
      "$($fbJson.partial_proven)"-eq'True' -and
      -not[string]::IsNullOrWhiteSpace("$($Config.RetainedFoundation)") -and
      "$($fbJson.authoritative_base_sha)"-eq"$expectedHead"
    )
    if("$($fbJson.passed)"-eq'False'-and$null-ne$fbJson.acceptance-and($feedbackExact-or$feedbackOnRetainedFoundation)){
      $ratReviewFailure=[pscustomobject]@{path=$forgeBossFeedback;raw=$fbRaw;json=$fbJson}
      Log "ForgeBoss failure feedback accepted for current retained foundation: $forgeBossFeedback" 'Yellow'
    }else{
      Log 'ForgeBoss failure feedback ignored because it is stale, green, or not exact-target bound.' 'Yellow'
    }
  }catch{
    Log ("ForgeBoss failure feedback unreadable; ignoring: "+$_.Exception.Message) 'Yellow'
  }
}
$feedbackHash='NONE' 
if($null-ne$ratReviewFailure){
  $feedbackHash=Sha256Text $ratReviewFailure.raw
  Log "Clean Rat Review failure feedback: $($ratReviewFailure.path)" 'Yellow'
  Log "Clean feedback SHA256: $feedbackHash" 'DarkGray'
}else{
  Log 'No failed clean Rat Review report auto-discovered; continuing with repair-lab evidence + references.' 'Yellow'
}


Log ("Discovered bounded source packet: {0} files" -f $sourcePaths.Count) 'Cyan'
Log ("Discovered bounded write allowlist: {0} files" -f $writeAllowlist.Count) 'Cyan'
foreach($p in $sourcePaths){Log ("SOURCE: "+$p) 'DarkGray'}

$specialistRegistryHash=Sha256Text (Get-Content -LiteralPath (Join-Path $Root 'controller\specialists\registry.json') -Raw)
$repairContextHash=Sha256Text ("scope=$scopeHash`nrefs=$($referencePack.sha256)`nfeedback=$feedbackHash`nspecialists=$specialistRegistryHash")
# Historical repair-lab evidence is background only in parent-head-local mode.
# Before spending model credit, bind executable validation to the exact current target.
$freshEvidence=$null
if(-not[string]::IsNullOrWhiteSpace($TargetSha)){
  $freshEvidence=Get-FreshTargetEvidence $work $head
  $script:FreshTargetEvidence=$freshEvidence
  $freshHash=Sha256Text ($freshEvidence|ConvertTo-Json -Depth 80 -Compress)
  $repairContextHash=Sha256Text ("$repairContextHash`nfresh_target=$freshHash")
  Log "Fresh target evidence SHA256: $freshHash" 'DarkGray'
}

# Focused packets are intentionally narrow, but authoritative current failures may prove
# that the missing call-site/dependency was omitted. Expand SOURCE CONTEXT automatically,
# and restore WRITE permission only when the discovered path was already approved by the
# controller's original write allowlist. This is not scope escalation.
if($null-ne$freshEvidence){
  $dep=Get-EvidenceDependencyExpansion $work $freshEvidence $sourcePaths 8 140000
  $addedContext=@()
  $addedWrite=@()
  foreach($rel in @($dep.paths)){
    if($sourcePaths-notcontains$rel){
      $sourcePaths=[string[]](@($sourcePaths)+@($rel))
      $addedContext+=$rel
    }
    if(($controllerWriteAllowlist-contains$rel)-and($writeAllowlist-notcontains$rel)){
      $writeAllowlist=[string[]](@($writeAllowlist)+@($rel))
      $addedWrite+=$rel
    }
  }
  if($addedContext.Count-gt0){
    Log ("EVIDENCE CONTEXT EXPANDED: +{0} files / {1} chars from current failing stacks, test imports, and bounded dependency search."-f$addedContext.Count,$dep.chars) 'Green'
    foreach($p in $addedContext){Log ("EVIDENCE SOURCE: "+$p) 'DarkGray'}
  }
  if($addedWrite.Count-gt0){
    Log ("CONTROLLER-APPROVED WRITE RESTORED: "+($addedWrite-join', ')) 'Green'
  }
  $scopeHash=Sha256Text (($sourcePaths|Sort-Object)-join"`n")
  $repairContextHash=Sha256Text ("scope=$scopeHash`nrefs=$($referencePack.sha256)`nfeedback=$feedbackHash`nspecialists=$specialistRegistryHash`nfresh_target=$freshHash")
}
Log "Repair context SHA256: $repairContextHash" 'DarkGray'


$previousFingerprint=$null
$lastAcceptance=$(if($null-ne$freshEvidence){$freshEvidence}else{$null})
$attemptBase=$head

for($attempt=1;$attempt-le$MaxAttempts;$attempt++){
  if($script:ApiCalls-ge1){throw 'HARD ONE-CALL GUARD: a second paid model attempt was requested.'}
  Log "`n=== REPAIR RAT ATTEMPT $attempt/$MaxAttempts ===" 'Yellow'

  # Each attempt starts from the exact frozen PR head. The next model sees prior
  # failure evidence and must return a complete replacement repair, not an
  # unbounded delta on top of a failed attempt.
  [void](Run 'git.exe' @('reset','--hard',$attemptBase) $work)
  [void](Run 'git.exe' @('clean','-ffd') $work)
  Assert-Pristine $work "attempt $attempt baseline"

  $sources=Collect-Sources $work $sourcePaths
  $numberedSources=@()
  foreach($sf in @($sources)){
    $lines=@(Get-CanonicalSourceLines ([string]$sf.content))
    $numbered=for($li=0;$li-lt$lines.Count;$li++){
      $trim=$lines[$li].Trim()
      $tag=("L{0}#{1}"-f($li+1),(Sha256Text $trim).Substring(0,8))
      "{0} {1,6}: {2}"-f$tag,($li+1),$lines[$li]
    }
    $numberedSources+=[ordered]@{path=$sf.path;sha256=$sf.sha256;numbered_content=($numbered-join"`n")}
  }
  $priorFailures=@()
  if($null-ne$lastAcceptance){
    foreach($run in @($lastAcceptance.runs|Where-Object{$_.exit_code-ne0})){
      $priorFailures+=@{name=$run.name;failure_lines=$run.failure_lines;output_tail=$run.output_tail}
    }
  }

  # Local-first Repair Rat memory. Only previously PROVEN patches are replayed,
  # and only when every affected pre-fix file hash exactly matches.
  if($attempt-eq1-and$null-ne$focusedPacket-and(Test-Path -LiteralPath $Config.PlaybookScript)){
    $play=Run 'python.exe' @($Config.PlaybookScript,'apply','--funnel',$Config.FocusedPacket,'--repo',$work) $Root
    if($play.exit_code-eq0){
      Log 'REPAIR RAT MEMORY HIT: previously proven repair applied locally; AI spend=$0.' 'Green'
      $dr=Run 'git.exe' @('diff','--name-only') $work;$changed=@($dr.stdout -split "`r?`n"|Where-Object{$_})
      foreach($p in $changed){if($writeAllowlist-notcontains$p.Replace('\','/')){throw "Playbook changed path outside allowlist: $p"}}
      $rounds=[System.Collections.Generic.List[object]]::new()
      for($validationRound=1;$validationRound-le$ValidationRounds;$validationRound++){[void]$rounds.Add((Run-Acceptance $work 0 $validationRound))}
      $allRuns=@();foreach($round in $rounds){$allRuns+=@($round.runs)};$allFailures=@($allRuns|Where-Object{$_.exit_code-ne0})
      $allDiagnostics=@();foreach($round in $rounds){$allDiagnostics+=@($round.diagnostics)}
      $accept=[pscustomobject]@{passed=($allFailures.Count-eq0);validation_rounds=@($rounds);runs=@($allRuns);diagnostics=@($allDiagnostics);failure_count=$allFailures.Count}
      [void]$script:Attempts.Add([pscustomobject]@{attempt=0;source='repair-rat-playbook';model_summary='Proven compatible repair replayed locally';reasoning_summary='Exact pre-fix hashes matched; normal acceptance still required';changed_paths=@($changed);acceptance_passed=$accept.passed;failure_count=$accept.failure_count;failure_fingerprint=(Failure-Fingerprint $accept);validation_rounds=@($accept.validation_rounds);runs=@($accept.runs)})
      if($accept.passed){
        $aa=[string[]](@('add','--')+@($changed));[void](Run 'git.exe' $aa $work)
        $cr=Run 'git.exe' @('commit','-m',"repair-rat: proven local playbook repair for root PR #$RootPullRequest") $work
        if($cr.exit_code-ne0){throw "playbook commit failed: $($cr.stderr)"}
        $hr=Run 'git.exe' @('rev-parse','HEAD') $work;$script:FinalCommit=$hr.stdout.Trim();Write-Report $true
        Log 'REPAIR RAT PLAYBOOK PASS: no model call required.' 'Green';exit 0
      }
      $playMeta=$null
      try{$playMeta=$play.stdout.Trim().Split("`n")[-1]|ConvertFrom-Json}catch{}
      if($null-ne$playMeta-and"$($playMeta.outcome)"-eq'partial_proven'){
        $aa=[string[]](@('add','--')+@($changed));[void](Run 'git.exe' $aa $work)
        $cr=Run 'git.exe' @('commit','-m','repair-rat: replay proven sub-fix locally') $work
        if($cr.exit_code-ne0){throw "partial memory commit failed: $($cr.stderr)"}
        $hr=Run 'git.exe' @('rev-parse','HEAD') $work;$attemptBase=$hr.stdout.Trim()
        $lastAcceptance=$accept;$sources=Collect-Sources $work $sourcePaths
        Log 'REPAIR RAT MEMORY: retained a proven sub-fix as the clean local baseline; continuing to the next defect.' 'Green'
      }else{
        Log 'Remembered full repair no longer passes. Resetting baseline and escalating to AI.' 'Yellow'
        [void](Run 'git.exe' @('reset','--hard',$attemptBase) $work);[void](Run 'git.exe' @('clean','-ffd') $work);$lastAcceptance=$accept
      }
    }
  }

  if($attempt-eq1){
    $lessonEvidence=[ordered]@{fresh=$freshEvidence;prior_failures=$priorFailures;focused=$focusedPacket}
    $localLesson=Try-ValidatedLocalLesson $work $writeAllowlist $lessonEvidence
    if($localLesson.applied){
      $changed=@($localLesson.changed_paths)
      $rounds=[System.Collections.Generic.List[object]]::new()
      for($validationRound=1;$validationRound-le$ValidationRounds;$validationRound++){[void]$rounds.Add((Run-Acceptance $work 0 $validationRound))}
      $allRuns=@();foreach($round in $rounds){$allRuns+=@($round.runs)}
      $allFailures=@($allRuns|Where-Object{$_.exit_code-ne0})
      $allDiagnostics=@();foreach($round in $rounds){$allDiagnostics+=@($round.diagnostics)}
  $accept=[pscustomobject]@{passed=($allFailures.Count-eq0);validation_rounds=@($rounds);runs=@($allRuns);diagnostics=@($allDiagnostics);failure_count=$allFailures.Count}
      $lastAcceptance=$accept
      $fingerprint=Failure-Fingerprint $accept
      [void]$script:Attempts.Add([pscustomobject]@{attempt=0;source='validated-local-lesson';model_summary=$localLesson.summary;reasoning_summary='Exact matching evidence and source precondition matched a previously validated repair pattern; normal acceptance still required';changed_paths=@($changed);acceptance_passed=$accept.passed;failure_count=$accept.failure_count;failure_fingerprint=$fingerprint;validation_rounds=@($accept.validation_rounds);runs=@($accept.runs)})
      $targetedGreen=(Test-TargetedRegressionGatesGreen $accept)
      $focusedResolved=((Test-FocusedTargetResolved $accept $focusedPacket)-or(Test-FocusedFailureFamilyCleared $accept $focusedPacket)-or$targetedGreen)
      $introducedRegression=Test-IntroducedRegression $accept $focusedPacket

      if($accept.passed){
        [void](Run 'git.exe' @('add','--','src/travis/conversation.js') $work)
        $cr=Run 'git.exe' @('commit','-m','repair-rat: validated local lesson - Travis JSONB identity') $work
        if($cr.exit_code-ne0){throw "local lesson commit failed: $($cr.stderr)"}
        $hr=Run 'git.exe' @('rev-parse','HEAD') $work;$script:FinalCommit=$hr.stdout.Trim()
        Write-Report $true
        Log 'REPAIR RAT LOCAL LESSON PASS: all acceptance gates pass with zero model calls.' 'Green'
        exit 0
      }

      if($focusedResolved-and-not$introducedRegression){
        [void](Run 'git.exe' @('add','--','src/travis/conversation.js') $work)
        $cr=Run 'git.exe' @('commit','-m','repair-rat: validated local lesson partial win') $work
        if($cr.exit_code-ne0){throw "local lesson partial commit failed: $($cr.stderr)"}
        $hr=Run 'git.exe' @('rev-parse','HEAD') $work;$script:FinalCommit=$hr.stdout.Trim()
        $primary=$(if($null-ne$focusedPacket-and-not[string]::IsNullOrWhiteSpace("$($focusedPacket.primary_failed_step)")){"$($focusedPacket.primary_failed_step)"}else{'postgresql-22p05-jsonb'})
        [void](Save-RetainedPartialPatch $work $expectedHead $script:FinalCommit $primary)
        $script:PartialProven=$true;$script:ResolvedFocusedStep=$primary
        Write-Report $false
        Log 'REPAIR RAT LOCAL LESSON PARTIAL WIN: verified fix retained with zero model calls.' 'Green'
        exit 2
      }

      Log 'LOCAL LESSON DID NOT VALIDATE CLEANLY: resetting and escalating to paid repair.' 'Yellow'
      [void](Run 'git.exe' @('reset','--hard',$attemptBase) $work)
      [void](Run 'git.exe' @('clean','-ffd') $work)
      $lastAcceptance=$accept
    }
  }

  $routingPacket=[ordered]@{
    objective='Repair all currently evidenced PostgreSQL defect families together without widening controller scope.'
    reason='Repeated PostgreSQL integration failures on exact frozen target.'
    task='bounded repair'
    allowed_files=@($writeAllowlist)
    context_files=@($sourcePaths)
    failure_names=@($priorFailures|ForEach-Object{$_.name})
    failure_lines=@($priorFailures|ForEach-Object{@($_.failure_lines)}|ForEach-Object{$_})
  }
  $specialist=Get-SpecialistRouting 'builder' $routingPacket
  $builderSpecialists=@($specialist.routing.specialists|ForEach-Object{"$_"})
  $script:BuilderSpecialists=@($builderSpecialists)
  $specialistPlanHash=Sha256Text ($specialist|ConvertTo-Json -Depth 80 -Compress)
  $attemptContextHash=Sha256Text ("$repairContextHash`nspecialist_plan=$specialistPlanHash")
  Log ("Specialists selected: "+($builderSpecialists-join', ')) 'Cyan'
  Log ("Specialist prompt chars: "+$specialist.composition.approx_chars) 'DarkGray'

  $payload=[ordered]@{
    task=$(if($null-ne$focusedPacket){'Repair ONE focused failure family only. Fix the best-supported root cause in the supplied focused files. Do not require unrelated failing families to be understood in the same patch. ForgeBoss will validate the whole suite and handle the next remaining failure in a later cycle.'}else{'Repair the best-supported current PostgreSQL defect with surgical exact-match edits. Do not emit whole files or paper over tests.'})
    exact_pr_head=$head
    repair_lab_evidence=$(if($null-ne$focusedPacket){$null}else{($evidence.raw|ConvertFrom-Json)})
    repair_lab_evidence_is_historical=[bool]$evidence.historical
    fresh_target_evidence=$(if($null-ne$freshEvidence){Get-ModelEvidenceView $freshEvidence}else{$null})
    retained_foundation_evidence=$(if($null-ne$focusedPacket-and"$($focusedPacket.partial_foundation)"-eq'True'){
      [ordered]@{
        authoritative_base_sha=$focusedPacket.authoritative_base_sha
        retained_local_commit=$focusedPacket.retained_local_commit
        failure_signature=$focusedPacket.failure_signature
        failed_steps=@($focusedPacket.failed_steps)
        primary_failed_step=$focusedPacket.primary_failed_step
        evidence=@($focusedPacket.evidence)
        provenance='immediately preceding broad validation after verified retained foundation'
      }
    }else{$null})
    evidence_binding=@{
      authoritative_target_head=$head
      fresh_target_evidence_head=$(if($null-ne$freshEvidence){$freshEvidence.exact_head}else{$null})
      historical_evidence_head="$($evidence.json.exact_head)"
      diagnostic_rule='serializable_retry_trace is disposable instrumentation evidence and never modifies the retained/source worktree'
      rule=$(if($null-ne$focusedPacket-and"$($focusedPacket.partial_foundation)"-eq'True'){
        'retained_foundation_evidence and fresh_target_evidence are both current evidence. A single clean rerun does NOT erase repeated nondeterministic 40001 failures from the immediately preceding validated retained foundation.'
      }else{
        'fresh_target_evidence is authoritative for current repair; historical repair-lab evidence is background only'
      })
    }
    execution_contract=@{
      disposable_workspace_exists=$true
      workspace_path=$work
      exact_head_checked_out=$head
      forgeBoss_will_apply_patch=$true
      forgeBoss_will_run_tests=$true
      model_has_no_tool_execution_requirement=$true
      rule='Your job is to return a bounded patch from supplied code/evidence. ForgeBoss owns the local workspace, applies the patch, runs PostgreSQL/Docker tests, rejects bad patches, and retains evidence. Do NOT safe-refuse merely because you personally cannot execute shell/git/docker.'
    }

    target_mode=$(if([string]::IsNullOrWhiteSpace($TargetSha)){'existing-child'}else{'parent-head-local'})
    root_pr=$RootPullRequest
    prior_attempt_failures=$priorFailures
    allowed_paths=$writeAllowlist
    evidence_scope_policy='Context may expand from current stack/test dependency evidence; writes remain a subset of controller-approved write scope.'
    source_files=@($sources|ForEach-Object{[ordered]@{path=$_.path;sha256=$_.sha256;bytes=$_.bytes;fully_read=$_.fully_read}})
    current_numbered_source_files=$numberedSources
    open_source_reference_pack=$(if($null-ne$focusedPacket){$null}else{$referencePack.json})
    clean_rat_review_failure=$(if($null-ne$ratReviewFailure){$ratReviewFailure.json}else{$null})
    forgeboss_debug_funnel=$(if($null-ne$focusedPacket){$focusedPacket}else{$null})
    forgeboss_repair_memory=$(if($env:SITEBOSS_FORGEBOSS_REPAIR_MEMORY-and(Test-Path -LiteralPath $env:SITEBOSS_FORGEBOSS_REPAIR_MEMORY)){Get-Content -LiteralPath $env:SITEBOSS_FORGEBOSS_REPAIR_MEMORY -Raw|ConvertFrom-Json}else{$null})
    forgeboss_evidence_enrichment=$(if($env:SITEBOSS_FORGEBOSS_EVIDENCE_ENRICHMENT-and(Test-Path -LiteralPath $env:SITEBOSS_FORGEBOSS_EVIDENCE_ENRICHMENT)){Get-Content -LiteralPath $env:SITEBOSS_FORGEBOSS_EVIDENCE_ENRICHMENT -Raw|ConvertFrom-Json}else{$null})
    specialist_routing=$specialist.routing
    specialist_output_contract=$specialist.composition.sections[-1].content
    acceptance=@{
      non_postgres='npm test must pass'
      isolated_repeats="business invitations, production HTTP and Travis intake each $RepeatCount times"
      full_postgres="complete tests/postgres*.integration.test.js must pass $FullSuiteRepeats times per validation round"
      clean_reconstruction="all acceptance must pass across $ValidationRounds independent PostgreSQL/container rounds"
      migration_round_trip='migrate -> rollback -> migrate must pass'
      transaction_rule='safe bounded retry for PostgreSQL 40001/40P01 only at whole-transaction boundary; never retry aborted requests or ambiguous commit outcomes'
      integrity_rule='preserve idempotency/exact-once behavior and canonical locked-lead semantics'
    }
  }
  if($null-ne$focusedPacket){
    $instructions=@'
You are the SiteBoss Repair Rat making ONE bounded local repair attempt for ONE focused failure family.

ForgeBoss already owns the exact-head disposable workspace. ForgeBoss will apply your returned file contents and run the failing PostgreSQL test plus the full acceptance suite. You do NOT need shell, git, Docker, PostgreSQL, or test execution access yourself.

FOCUSED REPAIR RULES:
- Solve only the best-supported root cause in the supplied focused packet.
- `current_numbered_source_files` may include evidence-expanded dependency/call-site files discovered from authoritative current stacks and failing-test imports. Use them to avoid safe-refusing for missing implementation context.
- `allowed_paths` is still the only write authority. Evidence expansion may restore a file to `allowed_paths` ONLY when it was already in the controller's original approved write scope; never request or invent a wider path.
- For PostgreSQL 40001/40P01 concurrency failures, repeated failures from the immediately preceding retained-foundation validation remain authoritative even if one fresh rerun happens to pass. These failures are nondeterministic by nature; do not safe-refuse merely because a single current rerun is green.
- If `serializable_retry_trace` diagnostics are present, treat them as authoritative execution evidence from a disposable instrumented copy of the exact current source. Inspect decision rows: attempt, code, outcome, sameError, retryable, aborted and timestamps.
- A bounded delay/backoff is supported ONLY if the trace shows consecutive trusted `40001`/`40P01` attempts with outcome=`rolled_back`, sameError=true, retryable=true, and near-immediate re-entry. Do not increase retry count, weaken SERIALIZABLE isolation, or retry ambiguous commit outcomes.
- If the trace contradicts that pattern, diagnose from the trace instead of applying generic retry changes.
- Treat `retained_foundation_evidence` as current provenance-bound evidence when its authoritative base matches and ForgeBoss has replayed that verified foundation.
- Do NOT require every other failing PostgreSQL family to be explained in this same patch.
- If the evidence proves a narrow defect, repair that defect now and let ForgeBoss validation reveal what remains.
- Return a PATCH TRANSACTION, not whole files or free-form diffs.
- For every existing-file edit, anchor_locator is PRIMARY. Copy its exact current-line tag first, then set anchor_hint to ONE identifier token that visibly appears on that same line, and set anchor_role to `definition`, `reference`, or `any`. Never put prose, file names, explanations, or dotted descriptions in anchor_hint.
- When changing a function or class method implementation (for example `issue`, `revoke`, or `withSerializableRetry`), use anchor_role=`definition`. ForgeBoss recognizes function declarations, variable-bound functions, and method declarations.
- anchor_locator is required. Copy the exact `L<line>#<8hex>` tag shown beside the intended line in `current_numbered_source_files`; never invent it.
- line_start and line_end remain required; use 0/0 because anchor_locator is authoritative.
- To add an `await` statement at the start of an async function body, anchor the function definition and use mode=`insert_after`; NEVER insert await-bearing code before the function declaration.
- Prefer a symbol unique to the intended statement/function, such as `identity` or `withSerializableRetry`.
- ForgeBoss itself materializes old_text, adjacent context, exact file hash, transaction ID and base SHA from those exact current lines immediately before application.
- Never copy an old_text anchor from debug-funnel/history. Do not emit hashes or full source-anchor text; anchor_hint is only an intent guard against choosing the wrong current line range.
- line_start/line_end are 1-based inclusive and must describe the smallest current source range that should be replaced/deleted or used as the insert anchor.
- Supported modes are replace, insert_before, insert_after, delete, and create.
- replace_all is always false. ForgeBoss will not guess or fuzzy-match stale source.
- `path` is constrained by schema to an allowed file. Never emit an empty path.
- NEVER delete or replace a variable declaration if later code still references that variable. Preserve providerKey/messageId validation and surrounding preconditions unless the focused repair explicitly requires changing them.
- When replacing inside a function, context_before should normally include the function signature and immediately preceding declarations so the transaction cannot accidentally consume them.
- npm_test failure, ReferenceError, SyntaxError, TypeError, or "is not defined" after the patch is a candidate regression, never a partial win.
- Current `source_files` were read from the replayed current workspace and outrank any older snippet text embedded in the debug funnel.
- ForgeBoss applies the transaction atomically and validates staleness.
- You do NOT need enough output budget to reproduce an entire source file. Quote only the smallest unique old_text span needed for each edit.
- Truncation risk from complete-file output is therefore NOT a valid reason to refuse.
- Stay strictly inside allowed_paths. Never widen scope.
- Do not weaken, skip, delete, serialize, or reduce tests.
- Prefer the smallest production-code correction that preserves behavior and invariants.
- A secondary failing test without its underlying error is NOT, by itself, a reason to refuse a well-supported fix for the primary focused defect.
- Set safe=false only if the PRIMARY focused defect itself lacks enough source/evidence to choose a bounded code change, or the needed file is outside allowed_paths.
- If safe=false, name the exact missing fact/file for the PRIMARY focused defect. Do not cite lack of direct tools/workspace.
'@
  }else{
    $instructions=@'
You are the SiteBoss Repair Rat: a senior database/runtime engineer making ONE bounded local repair attempt.
Use the exact-head evidence to repair the currently evidenced PostgreSQL defect family without weakening tests or widening scope.
ForgeBoss owns the disposable workspace and runs validation after your response. Lack of direct shell/git/Docker access is NOT a reason to refuse.
Return typed patch-transaction operations only; do not reconstruct or emit complete files. Preserve exact-once/idempotency and tenant/canonical-lead invariants.
Every existing-file edit selects exact 1-based line_start/line_end from current source_files. ForgeBoss materializes the actual source anchor locally; never quote stale anchor text from historical evidence.
Set safe=false only when the supplied source/evidence is genuinely insufficient for a bounded repair.
'@
  }
  $governanceAndSpecialists=$specialist.composition.prompt
  $instructions="$governanceAndSpecialists`n`n## SITEBOSS_REPAIR_RAT_TASK`n$instructions"

  $patch=Get-OrCreatePatch -Attempt $attempt -Head $head -EvidenceHash $evidenceHash -ScopeHash $attemptContextHash -Instructions $instructions -Payload $payload -Repo $work -WriteAllowlist $writeAllowlist
  if("$($patch.safe)"-ne'True'){
    [void]$script:Attempts.Add([pscustomobject]@{
      attempt=$attempt
      model_summary="$($patch.summary)"
      reasoning_summary="$($patch.reasoning_summary)"
      changed_paths=@()
      acceptance_passed=$false
      failure_count=0
      failure_fingerprint='MODEL_SAFE_REFUSAL'
      runs=@()
    })
    Log ("MODEL SAFE REFUSAL: "+$patch.summary) 'Yellow'
    Log 'Stopping without another paid call on the same evidence packet.' 'Yellow'
    break
  }
  $changed=Apply-Patch $work $patch $writeAllowlist
  Log ("Changed paths: "+($changed-join', ')) 'Cyan'
  $fastSyntax=Test-FastCandidateSyntax $work @($changed)
  if(-not$fastSyntax.passed){
    Log $fastSyntax.reason 'Red'
    [void](Run 'git.exe' @('reset','--hard',$attemptBase) $work)
    [void](Run 'git.exe' @('clean','-ffd') $work)
    throw ("PATCH_CANDIDATE_INVALID: "+$fastSyntax.reason)
  }

  $rounds=[System.Collections.Generic.List[object]]::new()
  for($validationRound=1;$validationRound-le$ValidationRounds;$validationRound++){
    Log ("--- CLEAN VALIDATION ROUND {0}/{1} ---" -f $validationRound,$ValidationRounds) 'Cyan'
    $round=Run-Acceptance $work $attempt $validationRound
    [void]$rounds.Add($round)
  }
  $allRuns=@()
  foreach($round in $rounds){$allRuns+=@($round.runs)}
  $allFailures=@($allRuns|Where-Object{$_.exit_code-ne0})
  $accept=[pscustomobject]@{
    passed=($allFailures.Count-eq0)
    validation_rounds=@($rounds)
    runs=@($allRuns)
    failure_count=$allFailures.Count
  }
  $lastAcceptance=$accept
  $fingerprint=Failure-Fingerprint $accept

  [void]$script:Attempts.Add([pscustomobject]@{
    attempt=$attempt
    model_summary="$($patch.summary)"
    reasoning_summary="$($patch.reasoning_summary)"
    changed_paths=@($changed)
    acceptance_passed=$accept.passed
    failure_count=$accept.failure_count
    failure_fingerprint=$fingerprint
    focused_resolved=((Test-FocusedTargetResolved $accept $focusedPacket)-or(Test-FocusedFailureFamilyCleared $accept $focusedPacket)-or(Test-TargetedRegressionGatesGreen $accept))
    targeted_gates_green=(Test-TargetedRegressionGatesGreen $accept)
    validation_rounds=@($accept.validation_rounds)
    runs=@($accept.runs)
  })

  if($accept.passed){
    $addArgs=[string[]](@('add','--')+@($changed))
    $r=Run 'git.exe' $addArgs $work
    if($r.exit_code-ne0){throw "git add failed: $($r.stderr)"}
    $commitMessage=$(if([string]::IsNullOrWhiteSpace($TargetSha)){"repair-rat: batch repair PR #$RepairPullRequest"}else{"repair-rat: local candidate for root PR #$RootPullRequest"})
    $r=Run 'git.exe' @('commit','-m',$commitMessage) $work
    if($r.exit_code-ne0){throw "local commit failed: $($r.stderr)"}
    $r=Run 'git.exe' @('rev-parse','HEAD') $work
    if($r.exit_code-ne0){throw "resolve local repair commit failed: $($r.stderr)"}
    $script:FinalCommit=$r.stdout.Trim()
    Write-Report $true
    Log "`nREPAIR RAT: ALL ACCEPTANCE GATES PASS" 'Green'
    Log "Local-only repair commit: $($script:FinalCommit)" 'Green'
    Log "NO GitHub push/PR/ref/merge/deploy occurred." 'Green'
    exit 0
  }

  $targetedGreen=(Test-TargetedRegressionGatesGreen $accept)
  $focusedResolved=((Test-FocusedTargetResolved $accept $focusedPacket)-or(Test-FocusedFailureFamilyCleared $accept $focusedPacket)-or$targetedGreen)
  $introducedRegression=Test-IntroducedRegression $accept $focusedPacket
  if($introducedRegression){
    Log 'CANDIDATE REGRESSION: patch introduced a baseline/runtime failure; rejecting candidate and restoring attempt base.' 'Red'
    [void](Run 'git.exe' @('reset','--hard',$attemptBase) $work)
    [void](Run 'git.exe' @('clean','-ffd') $work)
    throw "PATCH_CANDIDATE_INVALID: validation introduced a new baseline/runtime regression"
  }
  if($focusedResolved-and-not$introducedRegression){
    $targets=@(Get-FocusedTargetSteps $focusedPacket)
    $primary=$(if($targets.Count-gt0){$targets[0]}elseif($targetedGreen){'targeted PostgreSQL regression gates'}else{'focused failure family'})
    $addArgs=[string[]](@('add','--')+@($changed));$ar=Run 'git.exe' $addArgs $work
    if($ar.exit_code-ne0){throw "partial git add failed: $($ar.stderr)"}
    $cr=Run 'git.exe' @('commit','-m',"repair-rat: retain verified sub-fix ($primary)") $work
    if($cr.exit_code-ne0){throw "partial local commit failed: $($cr.stderr)"}
    $hr=Run 'git.exe' @('rev-parse','HEAD') $work
    $script:FinalCommit=$hr.stdout.Trim();$script:PartialProven=$true;$script:ResolvedFocusedStep=$primary
    $retained=Save-RetainedPartialPatch $work $expectedHead $script:FinalCommit $primary
    Write-Report $false
    Log ("REPAIR RAT PARTIAL WIN: focused target '{0}' is green; retained locally."-f$primary) 'Green'
    Log 'Stopping this paid repair instead of asking the model to rediscover the same fix.' 'Green'
    exit 4
  }

  if(@($changed).Count-gt0){
    Log 'ONE-CALL RULE: one paid code-producing attempt completed. Stopping before any second AI call so ForgeBoss can re-focus from fresh validation evidence.' 'Yellow'
    break
  }
  if($null-ne$previousFingerprint-and$fingerprint-eq$previousFingerprint){
    Log 'Failure fingerprint repeated unchanged; stopping early to avoid wasting another paid model call.' 'Yellow'
    break
  }
  $previousFingerprint=$fingerprint
}

Write-Report $false
Log "`nREPAIR RAT STOPPED WITHOUT PUBLISHING" 'Yellow'
Log 'Acceptance still has failures or attempt budget was exhausted.' 'Yellow'
Log "Workspace retained for inspection: $work" 'Cyan'
exit 2
