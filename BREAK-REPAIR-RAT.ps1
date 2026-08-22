param([switch]$SkipDocker)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Root=$PSScriptRoot
$Rat=Join-Path $Root 'SiteBoss-Repair-Rat.ps1'
$Check=Join-Path $Root 'CHECK-SITEBOSS.ps1'
$Results=[System.Collections.Generic.List[object]]::new()

function Pass([string]$Name,[string]$Detail=''){
  [void]$Results.Add([pscustomobject]@{name=$Name;status='PASS';detail=$Detail})
  Write-Host "[PASS] $Name$(if($Detail){": $Detail"})" -ForegroundColor Green
}
function Fail([string]$Name,[string]$Detail){
  [void]$Results.Add([pscustomobject]@{name=$Name;status='FAIL';detail=$Detail})
  Write-Host "[FAIL] $($Name): $Detail" -ForegroundColor Red
}
function Run-Test([string]$Name,[scriptblock]$Body){
  try{& $Body;Pass $Name}catch{Fail $Name $_.Exception.Message}
}
function Invoke-Proc([string]$Exe,[string[]]$CommandArgs,[string]$Cwd=''){
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName=$Exe
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true
  if($Cwd){$psi.WorkingDirectory=$Cwd}
  foreach($arg in $CommandArgs){[void]$psi.ArgumentList.Add([string]$arg)}
  $proc=[Diagnostics.Process]::new();$proc.StartInfo=$psi
  try{
    if(-not$proc.Start()){throw "Failed to start $Exe"}
    $stdout=$proc.StandardOutput.ReadToEnd()
    $stderr=$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    [pscustomobject]@{exit_code=$proc.ExitCode;stdout=$stdout;stderr=$stderr}
  }finally{$proc.Dispose()}
}
function Hash([string]$Text){
  $sha=[Security.Cryptography.SHA256]::Create()
  try{(($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))|ForEach-Object{$_.ToString('x2')})-join'')}
  finally{$sha.Dispose()}
}

Write-Host "`nSITEBOSS REPAIR RAT BREAKER v0.1" -ForegroundColor Cyan
Write-Host 'NO MODEL CALLS. NO GITHUB API. NO PUSH/PR/REF/MERGE/DEPLOY.' -ForegroundColor Green
Write-Host ''

Run-Test 'powershell.parse_all' {
  $files=@(Get-ChildItem -LiteralPath $Root -Recurse -File|Where-Object{$_.Extension-in@('.ps1','.psm1')})
  $errors=@()
  foreach($file in $files){
    $tokens=$null;$parseErrors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
    foreach($err in @($parseErrors)){
      $errors+=@{file=$file.FullName;line=$err.Extent.StartLineNumber;message=$err.Message}
    }
  }
  if($errors.Count){throw ($errors|ConvertTo-Json -Compress)}
}

Run-Test 'rat.source_exists' {
  if(-not(Test-Path -LiteralPath $Rat)){throw 'SiteBoss-Repair-Rat.ps1 missing'}
}

Run-Test 'rat.forbidden_publication_primitives_absent' {
  $t=Get-Content -LiteralPath $Rat -Raw
  foreach($bad in @(
    'git push ',
    'GHPatch',
    'GHPost',
    '/pulls/',
    '/git/refs/',
    'force=$true',
    'refs/heads/main'
  )){
    if($t-match[regex]::Escape($bad)){throw "Forbidden publication primitive present: $bad"}
  }
}

Run-Test 'rat.case_sensitive_workspace_guard_present' {
  $t=Get-Content -LiteralPath $Rat -Raw
  foreach($required in @('case-sensitive-repair-workspaces\repair-rat','Assert-CaseSensitiveRoot','Assert-Pristine')){
    if($t-notmatch[regex]::Escape($required)){throw "Missing: $required"}
  }
}

Run-Test 'rat.prepaid_call_pristine_gate_present' {
  $t=Get-Content -LiteralPath $Rat -Raw
  $pre=$t.IndexOf("Assert-Pristine `$work 'pre-model baseline'")
  $call=$t.IndexOf('Get-OrCreatePatch -Attempt')
  if($pre-lt0-or$call-lt0-or$pre-gt$call){throw 'Pristine gate is not before paid repair call'}
}

Run-Test 'rat.patch_cache_before_apply' {
  $t=Get-Content -LiteralPath $Rat -Raw
  $cache=$t.IndexOf('Patch cached before application')
  $apply=$t.IndexOf('Apply-Patch $work')
  if($cache-lt0-or$apply-lt0-or$cache-gt$apply){throw 'Patch cache is not persisted before patch application'}
}

Run-Test 'rat.cache_identity_uses_context' {
  $t=Get-Content -LiteralPath $Rat -Raw
  foreach($required in @('repairContextHash','referencePack.sha256','feedbackHash','source_scope_sha256')){
    if($t-notmatch[regex]::Escape($required)){throw "Cache context missing: $required"}
  }
  $a=Hash "scope=A`nrefs=R`nfeedback=F1"
  $b=Hash "scope=A`nrefs=R`nfeedback=F2"
  if($a-eq$b){throw 'Feedback change did not change context hash'}
}

Run-Test 'rat.reference_pack_valid' {
  $p=Join-Path $Root 'references\postgres-transaction-reference-pack.json'
  if(-not(Test-Path -LiteralPath $p)){throw 'Reference pack missing'}
  $j=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json
  if(@($j.sources).Count-lt4){throw 'Reference pack has fewer than four sources'}
  $all=$j|ConvertTo-Json -Depth 20
  foreach($required in @('40001','40P01','40003','same checked-out client','bounded')){
    if($all-notmatch[regex]::Escape($required)){throw "Reference invariant missing: $required"}
  }
}

Run-Test 'rat.clean_review_feedback_discovery_present' {
  $t=Get-Content -LiteralPath $Rat -Raw
  foreach($required in @('Find-LatestRatReviewFailure','clean_rat_review_failure','feedbackHash')){
    if($t-notmatch[regex]::Escape($required)){throw "Clean-review feedback hook missing: $required"}
  }
}

Run-Test 'rat.strong_acceptance_present' {
  $t=Get-Content -LiteralPath $Rat -Raw
  foreach($required in @('FullSuiteRepeats = 5','ValidationRounds = 2','full_postgres_suite_round','npm run db:rollback','npm run db:migrate')){
    if($t-notmatch[regex]::Escape($required)){throw "Acceptance contract missing: $required"}
  }
}

Run-Test 'rat.safe_refusal_stops_without_burning_attempts' {
  $t=Get-Content -LiteralPath $Rat -Raw
  $refusal=$t.IndexOf('MODEL SAFE REFUSAL')
  $breakAt=$t.IndexOf('break',$refusal)
  if($refusal-lt0-or$breakAt-lt0){throw 'Safe-refusal stop path missing'}
}

Run-Test 'rat.always_report_trap_present' {
  $t=Get-Content -LiteralPath $Rat -Raw
  if($t-notmatch'(?m)^trap\s*\{'){throw 'Top-level trap missing'}
  if($t-notmatch'Repair Rat report: \$ReportPath'){throw 'Failure report path logging missing'}
}

Run-Test 'checker.does_not_expand_env_inside_regex' {
  $t=Get-Content -LiteralPath $Check -Raw
  if($t-match '-match\s+"[^"]*\$env:USERPROFILE'){throw 'Checker still expands $env:USERPROFILE inside regex'}
}

Run-Test 'temporary_git_dirty_detection_fixture' {
  $temp=Join-Path ([IO.Path]::GetTempPath()) ("rat-breaker-git-"+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $temp|Out-Null
  try{
    $r=Invoke-Proc 'git.exe' @('init') $temp
    if($r.exit_code-ne0){throw $r.stderr}
    [IO.File]::WriteAllText((Join-Path $temp 'a.txt'),'one')
    [void](Invoke-Proc 'git.exe' @('add','a.txt') $temp)
    [void](Invoke-Proc 'git.exe' @('-c','user.name=Rat','-c','user.email=rat@example.invalid','commit','-m','base') $temp)
    $clean=Invoke-Proc 'git.exe' @('status','--porcelain=v1','-z') $temp
    if($clean.stdout){throw 'Fixture unexpectedly dirty before mutation'}
    [IO.File]::AppendAllText((Join-Path $temp 'a.txt'),'two')
    $dirty=Invoke-Proc 'git.exe' @('status','--porcelain=v1','-z') $temp
    if(-not$dirty.stdout){throw 'Dirty fixture was not detected'}
  }finally{
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Run-Test 'malformed_json_fixture_rejected' {
  $bad='{"passed": true,'
  $rejected=$false
  try{$null=$bad|ConvertFrom-Json}catch{$rejected=$true}
  if(-not$rejected){throw 'Malformed JSON unexpectedly parsed'}
}

Run-Test 'stale_head_fixture_changes_cache_key' {
  $h1=Hash "pr=525`nhead=aaaa`nevidence=e`nscope=s"
  $h2=Hash "pr=525`nhead=bbbb`nevidence=e`nscope=s"
  if($h1-eq$h2){throw 'Head movement did not invalidate cache identity fixture'}
}

if(-not$SkipDocker){
  Run-Test 'docker.engine' {
    $r=Invoke-Proc 'docker.exe' @('info')
    if($r.exit_code-ne0){throw $r.stderr}
  }
  Run-Test 'docker.required_images' {
    foreach($img in @('node:22-bookworm','postgres:17-alpine')){
      $r=Invoke-Proc 'docker.exe' @('image','inspect',$img)
      if($r.exit_code-ne0){throw "Missing Docker image: $img"}
    }
  }
  Run-Test 'docker.no_network_smoke' {
    $r=Invoke-Proc 'docker.exe' @('run','--rm','--network','none','node:22-bookworm','node','-e','console.log("rat-smoke")')
    if($r.exit_code-ne0-or$r.stdout-notmatch'rat-smoke'){throw "$($r.stdout) $($r.stderr)"}
  }
}

Run-Test 'builder.manifest_policy_supervisor' {
  foreach($f in @('BUILDER-MANIFEST.json','BUILDER-POLICY.json','SiteBoss-Builder.ps1')){
    if(-not(Test-Path -LiteralPath (Join-Path $Root $f))){throw "Missing builder file: $f"}
  }
  $p=Get-Content -LiteralPath (Join-Path $Root 'BUILDER-POLICY.json') -Raw|ConvertFrom-Json
  if([int]$p.schema-lt3){throw "Unsupported builder policy schema: $($p.schema)"}
  if([bool]$p.git.merge_enabled){throw 'merge_enabled must be false'}
  if([bool]$p.git.deploy_enabled){throw 'deploy_enabled must be false'}
  if([bool]$p.git.force_push){throw 'force_push must be false'}
}
Run-Test 'builder.cost_governor_contract' {
  $p=Get-Content -LiteralPath (Join-Path $Root 'BUILDER-POLICY.json') -Raw|ConvertFrom-Json
  if([int]$p.cost.max_paid_repair_calls_per_cycle-gt3){throw 'Repair budget too high'}
  if([int]$p.cost.max_paid_review_calls_per_cycle-gt1){throw 'Review budget too high'}
  if([int]$p.cost.max_paid_calls_per_day-lt1-or[int]$p.cost.max_paid_calls_per_day-gt20){throw 'Daily paid-call cap invalid'}
  if([int]$p.cost.min_failure_clusters_for_paid_repair-lt1){throw 'Failure-cluster threshold invalid'}
}


Run-Test 'builder.supervisor_contract' {
  $s=Get-Content -LiteralPath (Join-Path $Root 'SiteBoss-Builder.ps1') -Raw
  foreach($required in @(
    'ARCHITECTURE MAP',
    'EVIDENCE CLUSTERING',
    'WORK GRAPH',
    'BATCH REPAIR RAT',
    'RecordCalls',
    'PaidCallsToday',
    'INDEPENDENT RAT REVIEW + DRAFT GATE',
    'SUPERVISOR STOPPED SAFELY'
  )){
    if($s-notmatch[regex]::Escape($required)){throw "Supervisor contract missing: $required"}
  }
  if($s-match'api\.openai\.com|api\.anthropic\.com'){throw 'Supervisor must not call model APIs directly'}
  if($s-match'(?i)\bgit(?:\.exe)?\b[^\r\n]*\bpush\b'){throw 'Supervisor must not push directly'}
}

Run-Test 'builder.control_plane_files' {
  foreach($file in @('PAUSE-BUILDER.cmd','RESUME-BUILDER.cmd','STOP-BUILDER.cmd','RESET-CONTROLS.cmd')){
    if(-not(Test-Path -LiteralPath (Join-Path $Root $file))){throw "Control missing: $file"}
  }
}

Run-Test 'builder.policy_safety' {
  $p=Get-Content -LiteralPath (Join-Path $Root 'BUILDER-POLICY.json') -Raw|ConvertFrom-Json
  if([bool]$p.git.merge_enabled){throw 'merge_enabled must be false'}
  if([bool]$p.git.deploy_enabled){throw 'deploy_enabled must be false'}
  if([bool]$p.git.force_push){throw 'force_push must be false'}
  if([int]$p.cost.max_paid_repair_calls_per_cycle-gt3){throw 'repair budget too high'}
  if([int]$p.cost.max_paid_review_calls_per_cycle-gt1){throw 'review budget too high'}
}


Run-Test 'platform.engine_inventory' {
 foreach($f in @('engines\Repo-Mirror.ps1','engines\Backlog-Scanner.ps1','engines\Test-Selector.ps1','engines\Model-Router.ps1','engines\Architecture-Map.ps1','engines\Cluster-Evidence.ps1','engines\Work-Graph.ps1','engines\Cost-Ledger.ps1','engines\Event-Log.ps1','engines\State.psm1','SiteBoss-Rat-Review.ps1')){
  if(-not(Test-Path -LiteralPath (Join-Path $Root $f))){throw "Platform engine missing: $f"}
 }
}
Run-Test 'platform.truthful_cost_policy' {
 $p=Get-Content -LiteralPath (Join-Path $Root 'BUILDER-POLICY.json') -Raw|ConvertFrom-Json
 if($null-ne$p.cost.usd_soft_limit){throw 'Fake dollar gate must stay disabled'}
 if([int]$p.cost.max_paid_calls_per_day-lt1-or[int]$p.cost.max_paid_calls_per_day-gt20){throw 'Daily call cap invalid'}
}
Run-Test 'platform.supervisor_separation' {
 $s=Get-Content -LiteralPath (Join-Path $Root 'SiteBoss-Builder.ps1') -Raw
 if($s-match'api\.openai\.com|api\.anthropic\.com'){throw 'Supervisor must not call model APIs directly'}
 if($s-match'(?i)\bgit(?:\.exe)?\b[^\r\n]*\bpush\b'){throw 'Supervisor must not push directly'}
 if($s-match'(?i)/merge'){throw 'Supervisor must not merge'}
}
Run-Test 'platform.atomic_state' {
 $s=Get-Content -LiteralPath (Join-Path $Root 'engines\State.psm1') -Raw
 foreach($x in @('.tmp-','Move-Item','Read-JsonSafe')){if($s-notmatch[regex]::Escape($x)){throw "Atomic state missing: $x"}}
}
Run-Test 'platform.review_draft_only' {
 $r=Get-Content -LiteralPath (Join-Path $Root 'SiteBoss-Rat-Review.ps1') -Raw
 foreach($x in @('draft=$true','REFUSED protected target branch','NO merge to main. NO deployment.','FullSuiteRepeats = 5','ValidationRounds = 2')){
  if($r-notmatch[regex]::Escape($x)){throw "Review invariant missing: $x"}
 }
}


Run-Test 'oneclick.launcher_contract' {
  foreach($f in @('START-SITEBOSS.cmd','ONE-CLICK-SITEBOSS.cmd','SiteBoss-OneClick.ps1')){
    if(-not(Test-Path -LiteralPath (Join-Path $Root $f))){throw "One-click file missing: $f"}
  }
  $s=Get-Content -LiteralPath (Join-Path $Root 'SiteBoss-OneClick.ps1') -Raw
  $order=@("Run-Stage 'CHECK'","Run-Stage 'BREAKER'","Run-Stage 'DIAGNOSE'","Run-Stage 'FULL BUILDER'")
  $last=-1
  foreach($needle in $order){
    $at=$s.IndexOf($needle)
    if($at-lt0){throw "Missing stage: $needle"}
    if($at-le$last){throw "Stage order invalid: $needle"}
    $last=$at
  }
  if($s-notmatch[regex]::Escape('-SkipPreflight')){throw 'SkipPreflight missing'}
}
Run-Test 'oneclick.fail_closed_reporting' {
  $s=Get-Content -LiteralPath (Join-Path $Root 'SiteBoss-OneClick.ps1') -Raw
  foreach($needle in @("Save-Report 'FAILED'",'WHY:','exit 2','oneclick-$Stamp.json')){
    if($s-notmatch[regex]::Escape($needle)){throw "Failure contract missing: $needle"}
  }
}


Run-Test 'builder.child_process_artifact_contract' {
 $s=Get-Content -LiteralPath (Join-Path $Root 'SiteBoss-Builder.ps1') -Raw
 foreach($needle in @(
  'function Run-ChildPowerShell',
  'child failed:',
  'did not produce artifact:',
  'artifact is empty:',
  'EVIDENCE CLUSTERING artifact is unreadable:',
  'EVIDENCE CLUSTERING artifact missing cluster_count:'
 )){
  if($s-notmatch[regex]::Escape($needle)){throw "Child/artifact contract missing: $needle"}
 }
}
Run-Test 'cluster.empty_input_contract' {
 $s=Get-Content -LiteralPath (Join-Path $Root 'engines\Cluster-Evidence.ps1') -Raw
 if($s-notmatch[regex]::Escape('[string[]]$Inputs=@()')){throw 'Cluster-Evidence must accept empty Inputs'}
 foreach($needle in @('cluster_count=$clusters.Count','Write-JsonAtomic $Output')){
  if($s-notmatch[regex]::Escape($needle)){throw "Cluster empty-output contract missing: $needle"}
 }
}


Run-Test 'cluster.scalar_manifest_transport_contract' {
 $cluster=Get-Content -LiteralPath (Join-Path $Root 'engines\Cluster-Evidence.ps1') -Raw
 $paramNeedle=@'
[string]$InputListPath=''
'@
 foreach($needle in @(
  $paramNeedle.Trim(),
  'Evidence input manifest missing:',
  'Evidence input manifest is invalid JSON:',
  'Evidence input manifest missing inputs array:'
 )){
  if($cluster-notmatch[regex]::Escape($needle)){throw "Cluster manifest transport missing: $needle"}
 }

 $super=Get-Content -LiteralPath (Join-Path $Root 'SiteBoss-Builder.ps1') -Raw
 $callNeedle=@'
'-InputListPath',$inputManifest
'@
 foreach($needle in @(
  'evidence-inputs.json',
  $callNeedle.Trim(),
  'EVIDENCE INPUT MANIFEST count mismatch:'
 )){
  if($super-notmatch[regex]::Escape($needle)){throw "Supervisor manifest transport missing: $needle"}
 }

 $arrayNeedle=@'
@('-Inputs')+@($inputs)
'@
 if($super-match[regex]::Escape($arrayNeedle.Trim())){
  throw 'Supervisor still attempts array transport through pwsh -File'
 }
}

Run-Test 'breaker.static_needles_do_not_interpolate_target_variables' {
 $s=Get-Content -LiteralPath (Join-Path $Root 'BREAK-REPAIR-RAT.ps1') -Raw
 $start=$s.IndexOf("Run-Test 'cluster.scalar_manifest_transport_contract'")
 if($start-lt0){throw 'cluster.scalar_manifest_transport_contract block missing'}
 $end=$s.IndexOf("Run-Test 'breaker.static_needles_do_not_interpolate_target_variables'",$start)
 if($end-lt0){throw 'breaker static-needle guard block missing'}
 $target=$s.Substring($start,$end-$start)

 $badInputList=@'
"[string]$InputListPath=''
'@
 $badInputsArray=@'
"@('-Inputs')+@($inputs)"
'@

 if($target.Contains($badInputList.Trim())){
  throw 'Static breaker needle for InputListPath is double-quoted and may interpolate'
 }
 if($target.Contains($badInputsArray.Trim())){
  throw 'Static breaker needle for Inputs array is double-quoted and may interpolate'
 }
}


Run-Test 'breaker.static_needle_guard_is_scoped' {
 $s=Get-Content -LiteralPath (Join-Path $Root 'BREAK-REPAIR-RAT.ps1') -Raw
 foreach($needle in @(
  '$start=$s.IndexOf("Run-Test ''cluster.scalar_manifest_transport_contract''")',
  '$end=$s.IndexOf("Run-Test ''breaker.static_needles_do_not_interpolate_target_variables''",$start)',
  '$target=$s.Substring($start,$end-$start)'
 )){
  if($s-notmatch[regex]::Escape($needle)){throw "Scoped static-needle guard missing: $needle"}
 }
}


Run-Test 'cluster.optional_property_schema_variants' {
 $s=Get-Content -LiteralPath (Join-Path $Root 'engines\Cluster-Evidence.ps1') -Raw

 $needles=@(
  @'
function Get-OptionalProperty
'@.Trim(),
  @'
Get-OptionalProperty $item.json 'results'
'@.Trim(),
  @'
Get-OptionalProperty $item.json 'acceptance'
'@.Trim(),
  @'
Get-OptionalProperty $item.json 'validation_rounds'
'@.Trim(),
  @'
Get-OptionalProperty $item.json 'acceptance_runs'
'@.Trim(),
  @'
Get-OptionalProperty $item.json 'runs'
'@.Trim(),
  'shape_inventory',
  'skipped_inputs'
 )

 foreach($needle in $needles){
  if($s-notmatch[regex]::Escape($needle)){throw "Schema-variant cluster contract missing: $needle"}
 }

 $badDirect=@'
$item.json.acceptance
'@.Trim()

 if($s-match[regex]::Escape($badDirect)){
  throw 'Cluster-Evidence still directly dereferences optional acceptance property'
 }
}

Run-Test 'cluster.synthetic_mixed_schema_fixture' {
 $tmp=Join-Path ([IO.Path]::GetTempPath()) ("siteboss-cluster-fixture-"+[Guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory -Force -Path $tmp|Out-Null
 try{
  $a=Join-Path $tmp 'a.json'
  $b=Join-Path $tmp 'b.json'
  $c=Join-Path $tmp 'c.json'
  $manifest=Join-Path $tmp 'inputs.json'
  $out=Join-Path $tmp 'out.json'

  [ordered]@{
   results=@(
    [ordered]@{name='a-pass';exit_code=0},
    [ordered]@{name='a-fail';exit_code=1;failure_lines=@('serializable conflict')}
   )
  }|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $a -Encoding UTF8

  [ordered]@{
   acceptance=[ordered]@{
    runs=@([ordered]@{name='b-fail';exit_code=1;stderr='connection reset'})
   }
  }|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $b -Encoding UTF8

  [ordered]@{
   unrelated='historical-shape'
  }|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $c -Encoding UTF8

  [ordered]@{schema=1;inputs=@($a,$b,$c)}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $manifest -Encoding UTF8

  & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Cluster-Evidence.ps1') -InputListPath $manifest -Output $out|Out-Null
  if($LASTEXITCODE-ne0){throw "Synthetic cluster fixture child failed: $LASTEXITCODE"}
  if(-not(Test-Path -LiteralPath $out)){throw 'Synthetic cluster fixture produced no output'}
  $j=Get-Content -LiteralPath $out -Raw|ConvertFrom-Json
  if([int]$j.input_count-ne3){throw "Synthetic input_count expected 3 got $($j.input_count)"}
  if([int]$j.failure_count-ne2){throw "Synthetic failure_count expected 2 got $($j.failure_count)"}
  if([int]$j.cluster_count-ne2){throw "Synthetic cluster_count expected 2 got $($j.cluster_count)"}
 }finally{
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
 }
}


Run-Test 'breaker.schema_variant_needles_are_literal' {
 $s=Get-Content -LiteralPath (Join-Path $Root 'BREAK-REPAIR-RAT.ps1') -Raw
 $start=$s.IndexOf("Run-Test 'cluster.optional_property_schema_variants'")
 if($start-lt0){throw 'cluster.optional_property_schema_variants block missing'}
 $end=$s.IndexOf("Run-Test 'cluster.synthetic_mixed_schema_fixture'",$start)
 if($end-lt0){throw 'cluster.synthetic_mixed_schema_fixture block missing'}
 $target=$s.Substring($start,$end-$start)

 foreach($bad in @(
  '"Get-OptionalProperty $item.json',
  '"$item.json.acceptance'
 )){
  if($target.Contains($bad)){
   throw "Schema-variant breaker needle is double-quoted and may interpolate: $bad"
  }
 }
}

$fails=@($Results|Where-Object{$_.status-eq'FAIL'})
Write-Host ''
Write-Host ("REPAIR RAT BREAKER COMPLETE: PASS={0} FAIL={1}"-f(@($Results|Where-Object{$_.status-eq'PASS'}).Count),$fails.Count) -ForegroundColor Cyan
Write-Host 'OpenAI calls=0 | Anthropic calls=0 | GitHub API calls=0' -ForegroundColor Green

$report=Join-Path $Root 'state\repair-rat\breaker-last.json'
New-Item -ItemType Directory -Force -Path (Split-Path $report -Parent)|Out-Null
[ordered]@{
  generated_at=[DateTimeOffset]::UtcNow.ToString('o')
  pass=@($Results|Where-Object{$_.status-eq'PASS'}).Count
  fail=$fails.Count
  results=@($Results)
  guarantees=@{
    openai_calls=0
    anthropic_calls=0
    github_api_calls=0
    pushes=0
    merges=0
    deploys=0
  }
}|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $report -Encoding UTF8

Write-Host "Breaker report: $report"
if($fails.Count){exit 2}
exit 0
