param(
  [int]$RootPullRequest = 168,
  [int]$KnownRepairPullRequest = 525
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$GitHubGovernorModule=Join-Path $PSScriptRoot 'forgeboss\github\GitHub-Governor.psm1'
Import-Module $GitHubGovernorModule -Force

$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
$OutDir=Join-Path $Root 'state\diagnostics'
New-Item -ItemType Directory -Force -Path $OutDir|Out-Null
$Stamp=[DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')
$JsonPath=Join-Path $OutDir ("diagnostic-$Stamp.json")
$TextPath=Join-Path $OutDir ("diagnostic-$Stamp.txt")

$Config=@{
  AppId='4608230'
  InstallationId='154040429'
  Owner='1stchoicefnq-afk'
  Repo='siteboss-monster'
  PemPath="$env:USERPROFILE\.siteboss\secrets\github-app-private-key.pem"
  TestImage=$(if($env:SITEBOSS_TEST_IMAGE){$env:SITEBOSS_TEST_IMAGE}else{'node:22-bookworm'})
  CaseRoot=(Join-Path $env:USERPROFILE '.siteboss\autopilot\case-sensitive-repair-workspaces')
  ReviewProvider=$(if($env:SITEBOSS_REVIEW_PROVIDER){$env:SITEBOSS_REVIEW_PROVIDER.ToLowerInvariant()}else{'openai'})
  RepairProvider=$(if($env:SITEBOSS_REPAIR_PROVIDER){$env:SITEBOSS_REPAIR_PROVIDER.ToLowerInvariant()}else{'openai'})
  ChildReviewProvider=$(if($env:SITEBOSS_CHILD_REVIEW_PROVIDER){$env:SITEBOSS_CHILD_REVIEW_PROVIDER.ToLowerInvariant()}else{'openai'})
}

$script:Results=[System.Collections.Generic.List[object]]::new()
$script:Token=$null
$script:RootPr=$null
$script:RepairPr=$null
$script:DiagRepo=$null
$script:Counters=[ordered]@{
  openai_calls=0
  anthropic_calls=0
  github_repo_writes=0
  github_reads=0
  docker_runs=0
  clones=0
}

function Add-Result {
  param(
    [Parameter(Mandatory=$true)][string]$Stage,
    [Parameter(Mandatory=$true)][ValidateSet('PASS','FAIL','WARN','BLOCKED')][string]$Status,
    [Parameter(Mandatory=$true)][string]$Reason,
    [object]$Evidence=$null,
    [string[]]$BlockedBy=@()
  )
  $item=[pscustomobject][ordered]@{
    stage=$Stage
    status=$Status
    reason=$Reason
    blocked_by=@($BlockedBy)
    evidence=$Evidence
    timestamp=[DateTimeOffset]::UtcNow.ToString('o')
  }
  [void]$script:Results.Add($item)
  $colour=switch($Status){'PASS'{'Green'}'FAIL'{'Red'}'WARN'{'Yellow'}default{'DarkYellow'}}
  Write-Host ("[{0}] {1}: {2}" -f $Status,$Stage,$Reason) -ForegroundColor $colour
}

function Dependency-Failed([string[]]$Stages){
  foreach($stageName in $Stages){
    $bad=@($script:Results|Where-Object{$_.stage-eq$stageName-and$_.status-in@('FAIL','BLOCKED')})
    if($bad.Count-gt0){return $true}
  }
  return $false
}

function Run-Check {
  param(
    [Parameter(Mandatory=$true)][string]$Stage,
    [Parameter(Mandatory=$true)][scriptblock]$Body,
    [string[]]$DependsOn=@()
  )
  if($DependsOn.Count-gt0-and(Dependency-Failed $DependsOn)){
    Add-Result -Stage $Stage -Status BLOCKED -Reason 'Prerequisite failed or was blocked.' -BlockedBy $DependsOn
    return
  }
  try{
    $evidence=& $Body
    Add-Result -Stage $Stage -Status PASS -Reason 'Completed successfully.' -Evidence $evidence
  }catch{
    Add-Result -Stage $Stage -Status FAIL -Reason $_.Exception.Message -Evidence @{
      exception_type=$_.Exception.GetType().FullName
      script_stack="$($_.ScriptStackTrace)"
      position="$($_.InvocationInfo.PositionMessage)"
    }
  }
}

function Get-OptionalProperty($Object,[string]$Name){
  if($null-eq$Object){return $null}
  $prop=$Object.PSObject.Properties[$Name]
  if($null-eq$prop){return $null}
  return $prop.Value
}

function Invoke-External {
  param(
    [Parameter(Mandatory=$true)][string]$FileName,
    [Parameter(Mandatory=$true)][string[]]$CommandArgs,
    [string]$WorkingDirectory='',
    [switch]$AllowNonZero
  )
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName=$FileName
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true
  if($WorkingDirectory){$psi.WorkingDirectory=$WorkingDirectory}
  foreach($arg in $CommandArgs){[void]$psi.ArgumentList.Add([string]$arg)}
  $proc=[Diagnostics.Process]::new()
  $proc.StartInfo=$psi
  try{
    if(-not$proc.Start()){throw "Failed to start $FileName"}
    $stdout=$proc.StandardOutput.ReadToEnd()
    $stderr=$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $result=[pscustomobject]@{exit_code=$proc.ExitCode;stdout=$stdout;stderr=$stderr}
    if(-not$AllowNonZero-and$proc.ExitCode-ne0){
      throw "$FileName exited $($proc.ExitCode): $($stderr.Trim())"
    }
    return $result
  }finally{$proc.Dispose()}
}

function B64Url([byte[]]$Bytes){
  [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function New-GitHubReadToken {
  if(-not(Test-Path -LiteralPath $Config.PemPath)){throw "GitHub App key missing: $($Config.PemPath)"}
  $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $header=@{alg='RS256';typ='JWT'}|ConvertTo-Json -Compress
  $payload=@{iat=$now-60;exp=$now+540;iss=$Config.AppId}|ConvertTo-Json -Compress
  $unsigned="$(B64Url([Text.Encoding]::UTF8.GetBytes($header))).$(B64Url([Text.Encoding]::UTF8.GetBytes($payload)))"
  $rsa=[Security.Cryptography.RSA]::Create()
  try{
    $rsa.ImportFromPem((Get-Content -LiteralPath $Config.PemPath -Raw))
    $sig=$rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  }finally{$rsa.Dispose()}
  $jwt="$unsigned.$(B64Url $sig)"
  $headers=@{
    Authorization="Bearer $jwt"
    Accept='application/vnd.github+json'
    'X-GitHub-Api-Version'='2022-11-28'
  }
  $body=@{repositories=@($Config.Repo)}|ConvertTo-Json
  $script:Counters.github_reads++
  return Invoke-GovernedGitHubJson -Method POST -Url "https://api.github.com/app/installations/$($Config.InstallationId)/access_tokens" -Headers $headers -Body $body -CacheTtlMs 0
}

function GitHub-Get([string]$Path,[string]$Token){
  $headers=@{Authorization="Bearer $Token";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}
  $script:Counters.github_reads++
  $resp=Invoke-GovernedGitHubRaw -Method GET -Url "https://api.github.com$Path" -Headers $headers -CacheTtlMs 0 -AllowHttpError
  if([int]$resp.status-lt200-or[int]$resp.status-ge300){throw "GitHub GET $Path failed: HTTP $([int]$resp.status): $($resp.body)"}
  if([string]::IsNullOrWhiteSpace("$($resp.body)")){return $null}
  return "$($resp.body)"|ConvertFrom-Json
}


function GitHub-DownloadJobLog {
  param([Parameter(Mandatory=$true)][long]$JobId,[Parameter(Mandatory=$true)][string]$Token)
  $script:Counters.github_reads++
  $headers=@{Authorization="Bearer $Token";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28';'User-Agent'='SiteBoss-Autopilot-Diagnostics/1.0'}
  $uri="https://api.github.com/repos/$($Config.Owner)/$($Config.Repo)/actions/jobs/$JobId/logs"
  $response=Invoke-GovernedGitHubRaw -Method GET -Url $uri -Headers $headers -CacheTtlMs 0 -AllowHttpError
  if([int]$response.status-lt200-or[int]$response.status-ge300){throw ("Job log read failed for job {0}: HTTP {1}: {2}" -f $JobId,[int]$response.status,$response.body)}
  return "$($response.body)"
}

function Get-FailureExcerpt {
  param([string]$Text,[int]$MaxLines=160)
  if([string]::IsNullOrWhiteSpace($Text)){return @()}
  $lines=@($Text -split "`r?`n")
  $interesting=[System.Collections.Generic.SortedSet[int]]::new()
  for($i=0;$i-lt$lines.Count;$i++){
    if($lines[$i]-match '(?i)(##\[error\]|(^|\s)error(:|\s)|not ok|fail(ed|ure)?|assert|exception|process completed with exit code|npm err|postgres|psql|ECONN|timeout)'){
      $start=[Math]::Max(0,$i-4)
      $end=[Math]::Min($lines.Count-1,$i+8)
      for($j=$start;$j-le$end;$j++){[void]$interesting.Add($j)}
    }
  }
  if($interesting.Count-eq0){
    return @($lines|Select-Object -Last ([Math]::Min($MaxLines,$lines.Count)))
  }
  $selected=@()
  foreach($idx in $interesting){
    $selected+=("{0:D5}: {1}"-f($idx+1),$lines[$idx])
    if($selected.Count-ge$MaxLines){break}
  }
  return $selected
}

function Get-Pr([int]$Number,[string]$Token){
  GitHub-Get "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$Number" $Token
}

function Get-HeadInfo($Pr){
  $head=Get-OptionalProperty $Pr 'head'
  if($null-eq$head){throw 'PR response missing head object'}
  [pscustomobject]@{
    ref="$((Get-OptionalProperty $head 'ref'))"
    sha="$((Get-OptionalProperty $head 'sha'))"
  }
}
function Get-BaseInfo($Pr){
  $base=Get-OptionalProperty $Pr 'base'
  if($null-eq$base){throw 'PR response missing base object'}
  [pscustomobject]@{
    ref="$((Get-OptionalProperty $base 'ref'))"
    sha="$((Get-OptionalProperty $base 'sha'))"
  }
}

Write-Host "`nSITEBOSS DIAGNOSTIC MODE v1.0-alpha27" -ForegroundColor Cyan
Write-Host 'READ-ONLY / ZERO MODEL SPEND' -ForegroundColor Green
Write-Host "Root PR #$RootPullRequest | known repair PR #$KnownRepairPullRequest"
Write-Host 'Collecting independent failures instead of stopping at the first one.'
Write-Host 'No OpenAI/Anthropic calls. No GitHub repo writes. No push/ref/PR/merge/deploy.' -ForegroundColor DarkGray
Write-Host ''

Run-Check 'powershell.parse_all' {
  $files=@(Get-ChildItem -LiteralPath $Root -Recurse -File|Where-Object{$_.Extension-in@('.ps1','.psm1')})
  $errors=@()
  foreach($file in $files){
    $tokens=$null
    $parseErrors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
    foreach($err in @($parseErrors)){
      $errors+=@{file=$file.FullName;line=$err.Extent.StartLineNumber;message=$err.Message}
    }
  }
  if($errors.Count-gt0){throw ("Parser errors: "+($errors|ConvertTo-Json -Compress))}
  @{files=$files.Count}
}

Run-Check 'static.diagnostic_has_no_model_or_repo_write_code' {
  $diagnosticScriptPath=Join-Path $Root 'SiteBoss-Diagnostics.ps1'
  $text=Get-Content -LiteralPath $diagnosticScriptPath -Raw
  if($text-match'(?im)^\s*function\s+(Invoke-OpenAI|Invoke-Claude)\b'){throw 'Diagnostic harness defines a model-call function.'}
  if($text-match'https://api\.(openai|anthropic)\.com'){throw 'Diagnostic harness contains a model endpoint.'}
  if($text-match'(?im)^\s*function\s+(GHPatch|GHPost)\b'){throw 'Diagnostic harness defines a GitHub write helper.'}
  @{safe=$true}
}


Run-Check 'powershell.expandable_string_variable_colon' {
  # Detect the ambiguous "$Name:" pattern in source text, but explicitly ignore
  # valid PowerShell scope prefixes such as $script:Name and $env:NAME.
  $scopeNames=@('script','global','local','private','env','function','variable')
  $hits=@()

  foreach($file in @(Get-ChildItem -LiteralPath $Root -Recurse -File|Where-Object{$_.Extension-in@('.ps1','.psm1')})){
    $lines=@((Get-Content -LiteralPath $file.FullName))
    for($i=0;$i-lt$lines.Count;$i++){
      $line="$($lines[$i])"
      $trim=$line.TrimStart()
      if($trim.StartsWith('#')){continue}
      if($line -notmatch '"'){continue}

      foreach($m in [regex]::Matches($line,'(?<![\{\(])\$([A-Za-z_][A-Za-z0-9_]*):')){
        $name=$m.Groups[1].Value
        if($scopeNames -contains $name.ToLowerInvariant()){continue}
        $hits+=@{file=$file.FullName;line=$i+1;token=$m.Value;text=$line.Trim()}
      }
    }
  }

  if($hits.Count-gt0){
    throw ("Ambiguous expandable-string variable/colon pattern(s): "+($hits|ConvertTo-Json -Compress))
  }

  @{checked=$true;valid_scopes_ignored=$scopeNames}
} @('powershell.parse_all')

Run-Check 'provider.config' {
  $valid=@('openai','anthropic')
  foreach($entry in @(
    @{name='review';value=$Config.ReviewProvider},
    @{name='repair';value=$Config.RepairProvider},
    @{name='child_review';value=$Config.ChildReviewProvider}
  )){
    if($valid-notcontains$entry.value){throw "Invalid $($entry.name) provider '$($entry.value)'"}
  }
  $missing=@()
  if(($Config.ReviewProvider-eq'openai'-or$Config.RepairProvider-eq'openai'-or$Config.ChildReviewProvider-eq'openai')-and[string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)){
    $missing+='OPENAI_API_KEY'
  }
  if(($Config.ReviewProvider-eq'anthropic'-or$Config.RepairProvider-eq'anthropic'-or$Config.ChildReviewProvider-eq'anthropic')-and[string]::IsNullOrWhiteSpace($env:ANTHROPIC_API_KEY)){
    $missing+='ANTHROPIC_API_KEY'
  }
  @{review=$Config.ReviewProvider;repair=$Config.RepairProvider;child_review=$Config.ChildReviewProvider;missing_keys=$missing}
}

Run-Check 'git.executable' {
  $r=Invoke-External 'git.exe' @('--version')
  @{version=$r.stdout.Trim()}
}
Run-Check 'docker.executable' {
  $r=Invoke-External 'docker.exe' @('--version')
  @{version=$r.stdout.Trim()}
}
Run-Check 'docker.engine' {
  [void](Invoke-External 'docker.exe' @('info'))
  @{running=$true}
} @('docker.executable')
Run-Check 'docker.image' {
  $r=Invoke-External 'docker.exe' @('image','inspect',$Config.TestImage) -AllowNonZero
  if($r.exit_code-ne0){throw "Local image missing: $($Config.TestImage). Diagnostic mode will not pull images."}
  @{image=$Config.TestImage}
} @('docker.engine')


Run-Check 'docker.postgres_image' {
  $r=Invoke-External 'docker.exe' @('image','inspect','postgres:17-alpine') -AllowNonZero
  if($r.exit_code-ne0){
    Add-Result -Stage 'docker.postgres_image_pull_needed' -Status WARN -Reason 'postgres:17-alpine is not present locally; diagnostic reproduction will be blocked until the image is pulled manually.' -Evidence @{image='postgres:17-alpine'}
    throw 'Local image missing: postgres:17-alpine'
  }
  @{image='postgres:17-alpine'}
} @('docker.engine')

Run-Check 'filesystem.case_sensitive_root' {
  if(-not(Test-Path -LiteralPath $Config.CaseRoot)){throw "Missing case-sensitive workspace root: $($Config.CaseRoot)"}
  $r=Invoke-External 'fsutil.exe' @('file','queryCaseSensitiveInfo',$Config.CaseRoot) -AllowNonZero
  if($r.exit_code-ne0-or$r.stdout-notmatch'(?i)enabled'){throw "Case-sensitive root not enabled: $($r.stdout) $($r.stderr)"}
  @{path=$Config.CaseRoot}
}

Run-Check 'github.auth_readonly' {
  $auth=New-GitHubReadToken
  $script:Token="$($auth.token)"
  @{permissions=$auth.permissions;expires_at=$auth.expires_at}
}

Run-Check 'github.root_pr_shape' {
  $script:RootPr=Get-Pr $RootPullRequest $script:Token
  $head=Get-HeadInfo $script:RootPr
  $base=Get-BaseInfo $script:RootPr
  if("$($script:RootPr.state)"-ne'open'){throw "PR #$RootPullRequest is not open"}
  @{head_ref=$head.ref;head_sha=$head.sha;base_ref=$base.ref;base_sha=$base.sha;draft=$script:RootPr.draft}
} @('github.auth_readonly')

Run-Check 'github.repair_pr_shape' {
  $script:RepairPr=Get-Pr $KnownRepairPullRequest $script:Token
  $head=Get-HeadInfo $script:RepairPr
  $base=Get-BaseInfo $script:RepairPr
  if("$($script:RepairPr.state)"-ne'open'){throw "PR #$KnownRepairPullRequest is not open"}
  @{head_ref=$head.ref;head_sha=$head.sha;base_ref=$base.ref;base_sha=$base.sha;draft=$script:RepairPr.draft}
} @('github.auth_readonly')

Run-Check 'github.repair_parent_binding' {
  $parentHead=Get-HeadInfo $script:RootPr
  $childHead=Get-HeadInfo $script:RepairPr
  $childBase=Get-BaseInfo $script:RepairPr
  if($childBase.ref-ne$parentHead.ref){throw "Child base ref '$($childBase.ref)' != parent head ref '$($parentHead.ref)'"}
  if($childBase.sha-ne$parentHead.sha){throw "Child base SHA '$($childBase.sha)' != parent head SHA '$($parentHead.sha)'"}
  if(-not$childHead.ref.StartsWith("autopilot/repair-pr$RootPullRequest-",[StringComparison]::Ordinal)){throw "Unexpected repair head branch '$($childHead.ref)'"}
  @{parent_ref=$parentHead.ref;parent_sha=$parentHead.sha;child_ref=$childHead.ref;child_sha=$childHead.sha}
} @('github.root_pr_shape','github.repair_pr_shape')

Run-Check 'github.repair_checks' {
  $head=Get-HeadInfo $script:RepairPr
  $runs=GitHub-Get "/repos/$($Config.Owner)/$($Config.Repo)/commits/$($head.sha)/check-runs?per_page=100" $script:Token
  $summary=@()
  foreach($run in @($runs.check_runs)){
    $summary+=@{id=$run.id;name=$run.name;status=$run.status;conclusion=$run.conclusion;details_url=$run.details_url}
  }
  $failed=@($summary|Where-Object{$_.status-eq'completed'-and$_.conclusion-notin@('success','neutral','skipped')})
  if($failed.Count-gt0){throw ("Failing checks: "+(($failed|ForEach-Object{"$($_.name) [$($_.conclusion)]"})-join'; '))}
  @{checks=$summary}
} @('github.repair_pr_shape')

Run-Check 'github.repair_check_details' {
  $head=Get-HeadInfo $script:RepairPr
  $runs=GitHub-Get "/repos/$($Config.Owner)/$($Config.Repo)/commits/$($head.sha)/check-runs?per_page=100" $script:Token
  $details=@()
  foreach($run in @($runs.check_runs|Where-Object{$_.status-eq'completed'-and$_.conclusion-notin@('success','neutral','skipped')})){
    $annotations=@()
    try{
      $ann=GitHub-Get "/repos/$($Config.Owner)/$($Config.Repo)/check-runs/$($run.id)/annotations?per_page=100" $script:Token
      foreach($item in @($ann)){
        $annotations+=@{path=$item.path;start_line=$item.start_line;end_line=$item.end_line;title=$item.title;message=$item.message}
      }
    }catch{
      $annotations+=@{read_error=$_.Exception.Message}
    }
    $details+=@{
      name=$run.name
      conclusion=$run.conclusion
      details_url=$run.details_url
      output=$run.output
      annotations=$annotations
    }
  }
  @{failed_checks=$details}
} @('github.repair_pr_shape')


Run-Check 'github.failed_job_logs' {
  $head=Get-HeadInfo $script:RepairPr
  $runs=GitHub-Get "/repos/$($Config.Owner)/$($Config.Repo)/commits/$($head.sha)/check-runs?per_page=100" $script:Token
  $failed=@($runs.check_runs|Where-Object{$_.status-eq'completed'-and$_.conclusion-notin@('success','neutral','skipped')})
  $artifacts=@()
  foreach($run in $failed){
    $detailsUrl="$($run.details_url)"
    $jobId=$null
    if($detailsUrl-match'/job/(\d+)'){$jobId=[long]$Matches[1]}
    if($null-eq$jobId){
      $artifacts+=@{name=$run.name;log_status='NO_JOB_ID_IN_DETAILS_URL';details_url=$detailsUrl}
      continue
    }

    try{
      $log=GitHub-DownloadJobLog -JobId $jobId -Token $script:Token
      $logDir=Join-Path $OutDir ("diagnostic-$Stamp-artifacts")
      New-Item -ItemType Directory -Force -Path $logDir|Out-Null
      $safeName=("$($run.name)" -replace '[^A-Za-z0-9_.-]','_')
      $logPath=Join-Path $logDir ("job-$jobId-$safeName.log")
      Set-Content -LiteralPath $logPath -Value $log -Encoding UTF8
      $excerpt=@(Get-FailureExcerpt -Text $log)
      $artifacts+=@{
        name=$run.name
        job_id=$jobId
        conclusion=$run.conclusion
        log_path=$logPath
        failure_excerpt=$excerpt
      }
    }catch{
      $artifacts+=@{
        name=$run.name
        job_id=$jobId
        conclusion=$run.conclusion
        log_read_error=$_.Exception.Message
      }
    }
  }
  @{failed_job_logs=$artifacts}
} @('github.repair_pr_shape')

Run-Check 'github.fast_forward_relation' {
  $parentHead=Get-HeadInfo $script:RootPr
  $childHead=Get-HeadInfo $script:RepairPr
  $compare=GitHub-Get "/repos/$($Config.Owner)/$($Config.Repo)/compare/$($parentHead.sha)...$($childHead.sha)" $script:Token
  if("$($compare.status)"-ne'ahead'-or[int]$compare.ahead_by-lt1-or[int]$compare.behind_by-ne0){
    throw "Not clean fast-forward: status=$($compare.status) ahead=$($compare.ahead_by) behind=$($compare.behind_by)"
  }
  @{status=$compare.status;ahead_by=$compare.ahead_by;behind_by=$compare.behind_by;total_commits=$compare.total_commits}
} @('github.repair_parent_binding')

Run-Check 'github.repair_diff_inventory' {
  $files=GitHub-Get "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$KnownRepairPullRequest/files?per_page=100" $script:Token
  $items=@()
  foreach($file in @($files)){$items+=@{filename=$file.filename;status=$file.status;additions=$file.additions;deletions=$file.deletions;changes=$file.changes}}
  if($items.Count-eq0){throw "PR #$KnownRepairPullRequest has no changed files"}
  @{files=$items}
} @('github.repair_pr_shape')

Run-Check 'child_review.argument_binding' {
  $test=Join-Path $Root 'components\Test-ChildReviewArgs.ps1'
  if(-not(Test-Path -LiteralPath $test)){throw "Missing argument harness: $test"}
  $r=Invoke-External 'pwsh.exe' @(
    '-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$test,
    '-PullRequest','525','-ResultPath','unused.json','-ReviewOnly','-UseCache',
    '-ReviewMode','child',
    '-ExpectedBaseRef','beta/issue-155-travis-intake-orchestration',
    '-ExpectedBaseSha','0acc7149044fdc6403e8d8d781d9dfcca63bfb1b',
    '-ParentPullRequest','168'
  ) -AllowNonZero
  if($r.exit_code-ne0){throw "Argument harness failed: $($r.stdout) $($r.stderr)"}
  @{stdout=$r.stdout.Trim()}
}

Run-Check 'child_cycle.safety_contract' {
  $path=Join-Path $Root 'components\Child-Cycle.ps1'
  $text=Get-Content -LiteralPath $path -Raw
  foreach($fragment in @(
    'REFUSED: repair-child integration may never update main',
    'force=$false',
    'Child head moved after review',
    'Parent branch moved after child review',
    'MaxRepairDepth=4'
  )){
    if($text-notmatch[regex]::Escape($fragment)){throw "Missing invariant: $fragment"}
  }
  @{ok=$true}
}

Run-Check 'live_mode.default_guard' {
  $start=Get-Content -LiteralPath (Join-Path $Root 'START-SITEBOSS.cmd') -Raw
  if($start-notmatch'SITEBOSS_ALLOW_LIVE'){throw 'Live mode is not explicitly guarded.'}
  @{guard='SITEBOSS_ALLOW_LIVE=1'}
}

Run-Check 'repo.clone_exact_repair_head' {
  $head=Get-HeadInfo $script:RepairPr
  $diagRoot=Join-Path $Config.CaseRoot ("diagnostic-$Stamp")
  $repo=Join-Path $diagRoot 'repo'
  New-Item -ItemType Directory -Force -Path $diagRoot|Out-Null
  $script:DiagRepo=$repo
  [void](Invoke-External 'git.exe' @('clone','--no-checkout','--filter=blob:none',"https://github.com/$($Config.Owner)/$($Config.Repo).git",$repo))
  $script:Counters.clones++
  [void](Invoke-External 'git.exe' @('config','--local','core.autocrlf','false') $repo)
  [void](Invoke-External 'git.exe' @('config','--local','core.safecrlf','false') $repo)
  [void](Invoke-External 'git.exe' @('fetch','--no-tags','origin',$head.sha) $repo)
  [void](Invoke-External 'git.exe' @('checkout','--detach',$head.sha) $repo)
  @{repo=$repo;head=$head.sha}
} @('git.executable','filesystem.case_sensitive_root','github.repair_pr_shape')


Run-Check 'repo.postgres_workflow_inventory' {
  $workflowRoot=Join-Path $script:DiagRepo '.github\workflows'
  if(-not(Test-Path -LiteralPath $workflowRoot)){throw 'No .github/workflows directory in repair head'}
  $files=@(Get-ChildItem -LiteralPath $workflowRoot -File|Where-Object{$_.Extension-in@('.yml','.yaml')})
  $hits=@()
  foreach($file in $files){
    $text=Get-Content -LiteralPath $file.FullName -Raw
    if($text-match'(?i)postgres|postgres-integration'){
      $lines=@($text -split "`r?`n")
      $interesting=@()
      for($i=0;$i-lt$lines.Count;$i++){
        if($lines[$i]-match'(?i)postgres|npm test|node --test|run:'){
          $interesting+=("{0:D4}: {1}"-f($i+1),$lines[$i])
        }
      }
      $hits+=@{file=$file.FullName;interesting_lines=$interesting}
    }
  }
  if($hits.Count-eq0){throw 'No PostgreSQL-related workflow definition found in repair head'}
  @{workflows=$hits}
} @('repo.clone_exact_repair_head')

Run-Check 'repo.case_collision_inventory' {
  $r=Invoke-External 'git.exe' @('ls-tree','-r','--name-only','HEAD') $script:DiagRepo
  $groups=@{}
  foreach($path in @($r.stdout -split "`n"|Where-Object{$_})){
    $key=$path.ToLowerInvariant()
    if(-not$groups.ContainsKey($key)){$groups[$key]=@()}
    $groups[$key]+=$path
  }
  $collisions=@()
  foreach($key in $groups.Keys){
    $unique=@($groups[$key]|Select-Object -Unique)
    if($unique.Count-gt1){$collisions+=,@($unique)}
  }
  @{collisions=$collisions}
} @('repo.clone_exact_repair_head')

Run-Check 'repo.pristine_checkout' {
  [void](Invoke-External 'git.exe' @('reset','--hard','HEAD') $script:DiagRepo)
  [void](Invoke-External 'git.exe' @('clean','-ffd') $script:DiagRepo)
  $status=Invoke-External 'git.exe' @('status','--porcelain=v1','-z','--untracked-files=all') $script:DiagRepo
  if(-not[string]::IsNullOrEmpty($status.stdout)){throw "Checkout dirty after reset/clean: $($status.stdout)"}
  @{pristine=$true}
} @('repo.clone_exact_repair_head')

Run-Check 'docker.sandbox_topology' {
  $temp=Join-Path ([IO.Path]::GetTempPath()) ("siteboss-diag-"+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $temp|Out-Null
  Set-Content -LiteralPath (Join-Path $temp 'sentinel.txt') -Value 'siteboss' -NoNewline -Encoding UTF8
  $volume=("sb_diag_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  try{
    [void](Invoke-External 'docker.exe' @('volume','create',$volume));$script:Counters.docker_runs++
    [void](Invoke-External 'docker.exe' @(
      'run','--rm','--security-opt','no-new-privileges','--pids-limit','256',
      '--mount',"type=bind,src=$temp,dst=/source,readonly",
      '--mount',"type=volume,src=$volume,dst=/workspace",
      '-w','/workspace',$Config.TestImage,
      'sh','-lc','cp -a /source/. /workspace/ && test "$(cat /workspace/sentinel.txt)" = siteboss'
    ));$script:Counters.docker_runs++
    [void](Invoke-External 'docker.exe' @(
      'run','--rm','--network','none','--security-opt','no-new-privileges','--pids-limit','256',
      '--mount',"type=volume,src=$volume,dst=/workspace",
      '-w','/workspace',$Config.TestImage,
      'sh','-lc','test "$(cat sentinel.txt)" = siteboss'
    ));$script:Counters.docker_runs++
    @{volume=$volume}
  }finally{
    try{[void](Invoke-External 'docker.exe' @('volume','rm','-f',$volume) -AllowNonZero)}catch{}
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
  }
} @('docker.image')

Run-Check 'docker.repo_stage_npm_ci' {
  $volume=("sb_diag_repo_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  try{
    [void](Invoke-External 'docker.exe' @('volume','create',$volume));$script:Counters.docker_runs++
    $r=Invoke-External 'docker.exe' @(
      'run','--rm','--security-opt','no-new-privileges','--pids-limit','512',
      '--mount',"type=bind,src=$script:DiagRepo,dst=/source,readonly",
      '--mount',"type=volume,src=$volume,dst=/workspace",
      '-e','npm_config_cache=/tmp/npm-cache','--tmpfs','/tmp',
      '-w','/workspace',$Config.TestImage,
      'sh','-lc','cp -a /source/. /workspace/ && npm ci --ignore-scripts --no-audit --no-fund'
    ) -AllowNonZero
    if($r.exit_code-ne0){throw "npm ci failed: $($r.stderr) $($r.stdout)"}
    @{stdout_tail=@($r.stdout -split "`n"|Select-Object -Last 20)}
  }finally{
    try{[void](Invoke-External 'docker.exe' @('volume','rm','-f',$volume) -AllowNonZero)}catch{}
  }
} @('docker.image','repo.pristine_checkout')


Run-Check 'docker.postgres_ci_reproduction' {
  $network=("sb_diag_net_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  $pg=("sb_diag_pg_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  $workspace=("sb_diag_ws_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()

  $dbUser='siteboss'
  $dbName='siteboss_test'
  $dbPass='siteboss_test_password'
  $databaseUrl="postgresql://${dbUser}:${dbPass}@postgres:5432/$dbName"

  try{
    [void](Invoke-External 'docker.exe' @('network','create',$network))
    [void](Invoke-External 'docker.exe' @('volume','create',$workspace))
    $script:Counters.docker_runs+=2

    # Start a disposable PostgreSQL 17 service matching the GitHub workflow.
    $pgRun=Invoke-External 'docker.exe' @(
      'run','-d','--rm',
      '--name',$pg,
      '--network',$network,
      '--network-alias','postgres',
      '-e',"POSTGRES_DB=$dbName",
      '-e',"POSTGRES_USER=$dbUser",
      '-e',"POSTGRES_PASSWORD=$dbPass",
      'postgres:17-alpine'
    ) -AllowNonZero
    $script:Counters.docker_runs++
    if($pgRun.exit_code-ne0){throw "Failed to start PostgreSQL 17 container: $($pgRun.stderr) $($pgRun.stdout)"}

    # Wait for readiness with a bounded retry loop.
    $ready=$false
    for($attempt=1;$attempt-le30;$attempt++){
      $probe=Invoke-External 'docker.exe' @('exec',$pg,'pg_isready','-U',$dbUser,'-d',$dbName) -AllowNonZero
      if($probe.exit_code-eq0){$ready=$true;break}
      Start-Sleep -Seconds 1
    }
    if(-not$ready){throw 'PostgreSQL 17 container did not become ready within 30 seconds'}

    # Stage the exact repair head into a Docker-managed workspace and install deps.
    $setup=Invoke-External 'docker.exe' @(
      'run','--rm',
      '--network',$network,
      '--security-opt','no-new-privileges',
      '--pids-limit','512',
      '--mount',"type=bind,src=$script:DiagRepo,dst=/source,readonly",
      '--mount',"type=volume,src=$workspace,dst=/workspace",
      '-e','npm_config_cache=/tmp/npm-cache',
      '--tmpfs','/tmp',
      '-w','/workspace',
      $Config.TestImage,
      'sh','-lc','cp -a /source/. /workspace/ && npm ci --ignore-scripts --no-audit --no-fund'
    ) -AllowNonZero
    $script:Counters.docker_runs++
    if($setup.exit_code-ne0){throw "PostgreSQL diagnostic npm ci failed: $($setup.stderr) $($setup.stdout)"}

    $steps=@(
      @{name='npm_test'; command='npm test'},
      @{name='db_migrate'; command='npm run db:migrate'},
      @{name='postgres_integration'; command='RUN_POSTGRES_INTEGRATION=1 node --test tests/postgres*.integration.test.js'},
      @{name='db_rollback'; command='npm run db:rollback'},
      @{name='db_migrate_again'; command='npm run db:migrate'}
    )

    $stepResults=@()
    $failedNames=@()

    foreach($step in $steps){
      $run=Invoke-External 'docker.exe' @(
        'run','--rm',
        '--network',$network,
        '--security-opt','no-new-privileges',
        '--pids-limit','512',
        '--mount',"type=volume,src=$workspace,dst=/workspace",
        '-e',"DATABASE_URL=$databaseUrl",
        '-e','NODE_ENV=test',
        '-w','/workspace',
        $Config.TestImage,
        'sh','-lc',$step.command
      ) -AllowNonZero
      $script:Counters.docker_runs++

      $excerpt=@()
      $combined=("$($run.stdout)`n$($run.stderr)")
      $lines=@($combined -split "`r?`n")
      if($run.exit_code-ne0){
        $failedNames+=$step.name
        $excerpt=@($lines|Select-Object -Last ([Math]::Min(180,$lines.Count)))
      }else{
        $excerpt=@($lines|Select-Object -Last ([Math]::Min(40,$lines.Count)))
      }

      $stepResults+=@{
        name=$step.name
        command=$step.command
        exit_code=$run.exit_code
        output_tail=$excerpt
      }

      # Continue collecting all independent CI-step failures instead of stopping early.
    }

    if($failedNames.Count-gt0){
      throw ("Local PostgreSQL CI reproduction failures: "+($failedNames -join ', ')+" || "+($stepResults|ConvertTo-Json -Depth 12 -Compress))
    }

    @{steps=$stepResults}
  }finally{
    try{[void](Invoke-External 'docker.exe' @('rm','-f',$pg) -AllowNonZero)}catch{}
    try{[void](Invoke-External 'docker.exe' @('volume','rm','-f',$workspace) -AllowNonZero)}catch{}
    try{[void](Invoke-External 'docker.exe' @('network','rm',$network) -AllowNonZero)}catch{}
  }
} @('docker.image','docker.postgres_image','repo.pristine_checkout')

Run-Check 'focused_test.skip_evidence_policy' {
  $text=Get-Content -LiteralPath (Join-Path $Root 'components\Repair-PR.ps1') -Raw
  if($text-notmatch'(?i)SKIPPED_EVIDENCE|all.?skipped|focused.*skip'){
    throw 'Repair worker does not yet explicitly detect/label all-skipped focused tests.'
  }
  @{policy_present=$true}
}

Run-Check 'failure_reporting.common_contract' {
  $path=Join-Path $Root 'components\Failure-Reporting.psm1'
  if(-not(Test-Path -LiteralPath $path)){throw 'Common failure reporting module is missing.'}
  $text=Get-Content -LiteralPath $path -Raw
  foreach($field in @('stage','component','reason','exit_code','stdout','stderr','api_calls_this_cycle','github_mutations_this_cycle')){
    if($text-notmatch[regex]::Escape($field)){throw "Failure contract missing field '$field'"}
  }
  @{module=$path}
}

$Counts=[ordered]@{
  PASS=@($script:Results|Where-Object{$_.status-eq'PASS'}).Count
  FAIL=@($script:Results|Where-Object{$_.status-eq'FAIL'}).Count
  WARN=@($script:Results|Where-Object{$_.status-eq'WARN'}).Count
  BLOCKED=@($script:Results|Where-Object{$_.status-eq'BLOCKED'}).Count
}

$Report=[ordered]@{
  schema=1
  mode='diagnostic-readonly'
  package='Repair Rat v0.5-smokescreen'
  generated_at=[DateTimeOffset]::UtcNow.ToString('o')
  root_pr=$RootPullRequest
  known_repair_pr=$KnownRepairPullRequest
  guarantees=@{
    openai_calls=0
    anthropic_calls=0
    github_repo_writes=0
    pushes=0
    pr_creates=0
    ref_updates=0
    merges=0
    deploys=0
  }
  counters=$script:Counters
  counts=$Counts
  results=@($script:Results)
}

$Report|ConvertTo-Json -Depth 50|Set-Content -LiteralPath $JsonPath -Encoding UTF8

$lines=[System.Collections.Generic.List[string]]::new()
$lines.Add('SITEBOSS DIAGNOSTIC COMPLETE')
$lines.Add("Generated: $($Report.generated_at)")
$lines.Add("PASS=$($Counts.PASS) FAIL=$($Counts.FAIL) WARN=$($Counts.WARN) BLOCKED=$($Counts.BLOCKED)")
$lines.Add('OpenAI calls=0 | Anthropic calls=0 | GitHub repo writes=0')
$lines.Add('')
foreach($result in $script:Results){
  $lines.Add("[$($result.status)] $($result.stage)")
  $lines.Add("  $($result.reason)")
  if($result.blocked_by.Count-gt0){$lines.Add("  blocked_by: $($result.blocked_by -join ', ')")}
}
$lines.Add('')
$lines.Add("JSON: $JsonPath")
$lines.Add("TEXT: $TextPath")
$lines|Set-Content -LiteralPath $TextPath -Encoding UTF8

Write-Host "`nSITEBOSS DIAGNOSTIC COMPLETE" -ForegroundColor Cyan
Write-Host ("PASS={0} FAIL={1} WARN={2} BLOCKED={3}" -f $Counts.PASS,$Counts.FAIL,$Counts.WARN,$Counts.BLOCKED)
Write-Host "JSON: $JsonPath"
Write-Host "TEXT: $TextPath"
Write-Host 'OpenAI calls=0 | Anthropic calls=0 | GitHub repo writes=0' -ForegroundColor Green

if($Counts.FAIL-gt0){exit 2}
exit 0
