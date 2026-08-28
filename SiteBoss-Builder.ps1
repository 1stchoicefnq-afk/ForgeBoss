param([ValidateSet('diagnose','cycle')][string]$Mode='cycle',[int]$RepairPullRequest=525,[switch]$SkipPreflight)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$Root=$PSScriptRoot;$State=Join-Path $Root 'state\builder';New-Item -ItemType Directory -Force -Path $State|Out-Null
$Policy=Get-Content -LiteralPath (Join-Path $Root 'BUILDER-POLICY.json') -Raw|ConvertFrom-Json
$Events=Join-Path $State 'events.jsonl';$Ledger=Join-Path $State 'cost-ledger.json'
Import-Module (Join-Path $Root 'engines\State.psm1') -Force
function Event([string]$E,[string]$D=''){& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Event-Log.ps1') -EventName $E -Detail $D -Path $Events|Out-Null}
function Stage([string]$N,[scriptblock]$B){
 Write-Host "`n=== $N ===" -ForegroundColor Cyan
 Event 'stage.start' $N
 try{
  &$B
  Event 'stage.pass' $N
  Write-Host "[PASS] $N" -ForegroundColor Green
 }catch{
  $reason=$_.Exception.Message
  Event 'stage.fail' "$N :: $reason"
  Write-Host "[FAIL] $N :: $reason" -ForegroundColor Red
  throw
 }
}
function HaltRequested {
 if(Test-Path -LiteralPath (Join-Path $Root $Policy.supervisor.stop_file)){Write-Host 'STOP requested.' -ForegroundColor Yellow;return $true}
 while(Test-Path -LiteralPath (Join-Path $Root $Policy.supervisor.pause_file)){Write-Host 'PAUSED - run RESUME-BUILDER.cmd.' -ForegroundColor Yellow;Start-Sleep 3}
 return $false
}
function LatestReport([string]$Pattern,[string]$StateName){
 $d=Join-Path $env:USERPROFILE 'Downloads';if(-not(Test-Path $d)){return $null}
 $files=@(Get-ChildItem -LiteralPath $d -Recurse -File -Filter $Pattern -ErrorAction SilentlyContinue|Where-Object{$_.FullName-match"\\state\\$StateName\\"}|Sort-Object LastWriteTimeUtc -Descending)
 if($files.Count){return $files[0].FullName};return $null
}
function PaidCallsToday {
 # Cost-Ledger.ps1 runs as a separate child process, so its result must be parsed back
 # from the JSON it prints on stdout -- treating the raw captured text as an object
 # (the previous behavior) silently evaluated every property access to $null/0 and
 # made the daily paid-call cap check a permanent no-op.
 $raw=& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Cost-Ledger.ps1') -Mode read -LedgerPath $Ledger
 if($LASTEXITCODE-ne0){
  Write-Host "Cost ledger read failed (exit=$LASTEXITCODE); failing closed and treating the daily budget as exhausted." -ForegroundColor Red
  return [int]::MaxValue
 }
 try{
  $result=($raw-join"`n")|ConvertFrom-Json
  if("$($result.ledger_status)"-eq'corrupt'){Write-Host 'Cost ledger reports a corrupt/unreadable ledger file; failing closed.' -ForegroundColor Red}
  return [int]$result.today_paid_calls
 }catch{
  Write-Host "Cost ledger read result was unparseable; failing closed and treating the daily budget as exhausted." -ForegroundColor Red
  return [int]::MaxValue
 }
}
function Run-ChildPowerShell([string]$Name,[string]$File,[string[]]$CommandArgs,[string]$ExpectedArtifact=''){
 $display=[IO.Path]::GetFileName($File)
 & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File $File @CommandArgs
 $code=$LASTEXITCODE
 if($code-ne0){throw "$Name child failed: $display exit=$code"}
 if($ExpectedArtifact){
  if(-not(Test-Path -LiteralPath $ExpectedArtifact)){throw "$Name child reported success but did not produce artifact: $ExpectedArtifact"}
  $item=Get-Item -LiteralPath $ExpectedArtifact
  if($item.Length-eq0){throw "$Name artifact is empty: $ExpectedArtifact"}
 }
}

function RecordCalls([string]$Purpose,[string]$ReportPath){
 if(-not$ReportPath-or-not(Test-Path $ReportPath)){return}
 try{
  $j=Get-Content -LiteralPath $ReportPath -Raw|ConvertFrom-Json;$calls=0
  try{$calls=[int]$j.api_calls}catch{
   throw "RecordCalls could not read api_calls from $ReportPath :: $($_.Exception.Message)"
  }
  if($calls-gt0){
   $provider=$(if($j.provider){"$($j.provider)"}elseif($j.reviewer_provider){"$($j.reviewer_provider)"}else{'configured'})
   & pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'engines\Cost-Ledger.ps1') -Mode record -Provider $provider -Purpose $Purpose -PaidCalls $calls -Artifact $ReportPath -LedgerPath $Ledger|Out-Null
   if($LASTEXITCODE-ne0){throw "Cost-Ledger.ps1 -Mode record failed (exit=$LASTEXITCODE) while recording $calls paid call(s) for '$Purpose' from $ReportPath"}
  }
 }catch{
  # A paid call already happened; if we cannot durably record it, the daily cap can no
  # longer be trusted. Fail closed by surfacing this loudly and halting the cycle rather
  # than silently continuing as if nothing was spent.
  Write-Host "RecordCalls FAILED to record spend for '$Purpose' ($ReportPath): $($_.Exception.Message)" -ForegroundColor Red
  Event 'cost.record.failed' "$Purpose :: $ReportPath :: $($_.Exception.Message)"
  throw
 }
}
Write-Host "`nSITEBOSS BUILDER v0.4.7-oneclick-hotfix" -ForegroundColor Cyan
Write-Host 'Local-first engineering supervisor -> batch repair -> independent clean review -> draft PR only.' -ForegroundColor Green
for($cycle=1;$cycle-le[int]$Policy.supervisor.max_cycles_per_launch;$cycle++){
 if(HaltRequested){break};Event 'cycle.start' "$cycle"
 Write-JsonAtomic (Join-Path $State 'cycle-latest.json') ([ordered]@{schema=1;cycle=$cycle;started_at=[DateTimeOffset]::UtcNow.ToString('o');status='running'}) 20
 if(-not$SkipPreflight){
  Stage 'PRECHECK' {& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'CHECK-SITEBOSS.ps1');if($LASTEXITCODE-ne0){throw "CHECK=$LASTEXITCODE"}}
  Stage 'ADVERSARIAL BREAKER' {& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'BREAK-REPAIR-RAT.ps1');if($LASTEXITCODE-ne0){throw "BREAKER=$LASTEXITCODE"}}
 }else{
  Event 'preflight.skip' 'already completed by one-click launcher'
  Write-Host 'Preflight already completed by one-click launcher.' -ForegroundColor DarkGray
 }
 if($Mode-eq'diagnose'){Write-Host 'Diagnostic mode complete. Paid calls=0.' -ForegroundColor Green;break}
 Stage 'REPO MIRROR' {
  $artifact=Join-Path $State 'mirror.json'
  Run-ChildPowerShell 'REPO MIRROR' (Join-Path $Root 'engines\Repo-Mirror.ps1') @('-StatePath',$artifact) $artifact
 }
 $ratReports=@(Get-ChildItem -LiteralPath (Join-Path $env:USERPROFILE 'Downloads') -Recurse -File -Filter 'repair-rat-*.json' -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending)
 $repo=$null
 foreach($file in $ratReports){try{$j=Get-Content $file.FullName -Raw|ConvertFrom-Json;if("$($j.repair_pr)"-eq"$RepairPullRequest"-and(Test-Path "$($j.local_workspace)")){$repo="$($j.local_workspace)";break}}catch{}}
 if($repo){
  Stage 'ARCHITECTURE MAP' {
   $artifact=Join-Path $State 'architecture.json'
   Run-ChildPowerShell 'ARCHITECTURE MAP' (Join-Path $Root 'engines\Architecture-Map.ps1') @('-Repo',$repo,'-Output',$artifact) $artifact
  }
  Stage 'BACKLOG DISCOVERY' {
   $artifact=Join-Path $State 'backlog.json'
   Run-ChildPowerShell 'BACKLOG DISCOVERY' (Join-Path $Root 'engines\Backlog-Scanner.ps1') @('-Repo',$repo,'-Output',$artifact) $artifact
  }
 }
 $inputs=@();foreach($pkg in @(Get-ChildItem -LiteralPath (Join-Path $env:USERPROFILE 'Downloads') -Directory -Filter 'SiteBoss-*' -ErrorAction SilentlyContinue)){$inputs+=@(Get-ChildItem -LiteralPath $pkg.FullName -Recurse -File -Filter '*.json' -ErrorAction SilentlyContinue|Where-Object{$_.FullName-match'\\state\\(repair-rat|repair-lab|rat-review)\\'}|Select-Object -ExpandProperty FullName)}
 $inputs=@($inputs|Select-Object -Unique)
 Stage 'EVIDENCE CLUSTERING' {
  $artifact=Join-Path $State 'clusters.json'
  $inputManifest=Join-Path $State 'evidence-inputs.json'
  Write-JsonAtomic $inputManifest ([ordered]@{
    schema=1
    generated_at=[DateTimeOffset]::UtcNow.ToString('o')
    count=$inputs.Count
    inputs=@($inputs)
  }) 20
  try{$manifestCheck=Get-Content -LiteralPath $inputManifest -Raw|ConvertFrom-Json}
  catch{throw "EVIDENCE INPUT MANIFEST unreadable: $inputManifest :: $($_.Exception.Message)"}
  if([int]$manifestCheck.count-ne@($manifestCheck.inputs).Count){
    throw "EVIDENCE INPUT MANIFEST count mismatch: declared=$($manifestCheck.count) actual=$(@($manifestCheck.inputs).Count)"
  }
  Run-ChildPowerShell 'EVIDENCE CLUSTERING' (Join-Path $Root 'engines\Cluster-Evidence.ps1') @(
    '-InputListPath',$inputManifest,
    '-Output',$artifact
  ) $artifact
 }
 if($repo-and(Test-Path (Join-Path $State 'architecture.json'))){
  Stage 'WORK GRAPH' {
   $artifact=Join-Path $State 'work-graph.json'
   Run-ChildPowerShell 'WORK GRAPH' (Join-Path $Root 'engines\Work-Graph.ps1') @(
    '-ClusterPath',(Join-Path $State 'clusters.json'),
    '-ArchitecturePath',(Join-Path $State 'architecture.json'),
    '-BacklogPath',(Join-Path $State 'backlog.json'),
    '-Output',$artifact
   ) $artifact
  }
 }
 $clusterPath=Join-Path $State 'clusters.json'
 try{$clusters=Get-Content -LiteralPath $clusterPath -Raw|ConvertFrom-Json}
 catch{throw "EVIDENCE CLUSTERING artifact is unreadable: $clusterPath :: $($_.Exception.Message)"}
 if($null-eq$clusters.cluster_count){throw "EVIDENCE CLUSTERING artifact missing cluster_count: $clusterPath"}
 $today=PaidCallsToday
 if([int]$clusters.cluster_count-lt[int]$Policy.cost.min_failure_clusters_for_paid_repair-or$today-ge[int]$Policy.cost.max_paid_calls_per_day){Write-Host "Paid repair skipped: clusters=$($clusters.cluster_count) calls_today=$today" -ForegroundColor Yellow;break}
 $before=LatestReport 'repair-rat-*.json' 'repair-rat'
 Stage 'BATCH REPAIR RAT' {& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'SiteBoss-Repair-Rat.ps1') -RepairPullRequest $RepairPullRequest -MaxAttempts 1;$script:RepairExit=$LASTEXITCODE}
 $after=LatestReport 'repair-rat-*.json' 'repair-rat';if($after-and$after-ne$before){RecordCalls 'repair' $after}
 if($script:RepairExit-ne0){Write-Host "Repair not green; new evidence retained. exit=$($script:RepairExit)" -ForegroundColor Yellow;continue}
 if((PaidCallsToday)-ge[int]$Policy.cost.max_paid_calls_per_day){Write-Host 'Daily paid-call cap reached before review.' -ForegroundColor Yellow;break}
 $reviewBefore=LatestReport 'rat-review-*.json' 'rat-review'
 Stage 'INDEPENDENT RAT REVIEW + DRAFT GATE' {& pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'SiteBoss-Rat-Review.ps1') -RepairPullRequest $RepairPullRequest -RepeatCount ([int]$Policy.validation.isolated_repeats) -FullSuiteRepeats ([int]$Policy.validation.full_postgres_repeats) -ValidationRounds ([int]$Policy.validation.clean_validation_rounds);$script:ReviewExit=$LASTEXITCODE}
 $reviewAfter=LatestReport 'rat-review-*.json' 'rat-review';if($reviewAfter-and$reviewAfter-ne$reviewBefore){RecordCalls 'independent-review' $reviewAfter}
 if($script:ReviewExit-eq0){Write-Host 'REVIEWED DRAFT CHILD PR GATE COMPLETED.' -ForegroundColor Green;Write-JsonAtomic (Join-Path $State 'cycle-latest.json') ([ordered]@{schema=1;cycle=$cycle;finished_at=[DateTimeOffset]::UtcNow.ToString('o');status='reviewed-draft'}) 20;break}
 Write-Host 'Independent review did not pass/publish. No merge or deploy.' -ForegroundColor Yellow
}
Write-Host "`nSUPERVISOR STOPPED SAFELY" -ForegroundColor Cyan
Write-Host 'Automatic merge=OFF | deployment=OFF | force-push=OFF' -ForegroundColor Green
