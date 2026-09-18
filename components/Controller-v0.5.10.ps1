$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$GitHubGovernorModule=Join-Path (Split-Path -Parent $PSScriptRoot) 'forgeboss\github\GitHub-Governor.psm1'
Import-Module $GitHubGovernorModule -Force

$Config = @{
  AppId="4608230"
  InstallationId="154040429"
  Owner="1stchoicefnq-afk"
  Repo="siteboss-monster"
  PemPath="$env:USERPROFILE\.siteboss\secrets\github-app-private-key.pem"
  Model=($(if($env:SITEBOSS_OPENAI_MODEL){$env:SITEBOSS_OPENAI_MODEL}else{"gpt-5.6"}))
  ControlIssue=233
  SchedulerIssue=423
  DeliveryIssue=505
  IntegrationIssue=143
  ScopeIssue=473
  OwnerCommandIssue=508
  SnapshotRoot=(Join-Path $env:USERPROFILE ".siteboss\worker-engine\controller-snapshots")
  MaxPlanFiles=10
  MaxFileChars=160000
  MaxReferencedIssues=30
  MaxOpenPulls=100
}


function B64Url([byte[]]$b){ [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }

function New-GitHubInstallationToken {
  if(-not (Test-Path -LiteralPath $Config.PemPath)){ throw "GitHub App private key not found: $($Config.PemPath)" }
  $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $h=@{alg="RS256";typ="JWT"}|ConvertTo-Json -Compress
  $p=@{iat=$now-60;exp=$now+540;iss=$Config.AppId}|ConvertTo-Json -Compress
  $u="$(B64Url ([Text.Encoding]::UTF8.GetBytes($h))).$(B64Url ([Text.Encoding]::UTF8.GetBytes($p)))"
  $rsa=[Security.Cryptography.RSA]::Create()
  try {
    $rsa.ImportFromPem((Get-Content $Config.PemPath -Raw))
    $sig=$rsa.SignData([Text.Encoding]::UTF8.GetBytes($u),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  } finally { $rsa.Dispose() }
  $jwt="$u.$(B64Url $sig)"
  $hdr=@{Authorization="Bearer $jwt";Accept="application/vnd.github+json";"X-GitHub-Api-Version"="2022-11-28"}
  $body=@{repositories=@($Config.Repo)}|ConvertTo-Json
  Invoke-GovernedGitHubJson -Method POST -Url "https://api.github.com/app/installations/$($Config.InstallationId)/access_tokens" -Headers $hdr -Body $body -CacheTtlMs 0
}

function GHHeaders($token){ @{Authorization="Bearer $token";Accept="application/vnd.github+json";"X-GitHub-Api-Version"="2022-11-28"} }
function GHGet($path,$token){ Invoke-GovernedGitHubJson -Method GET -Url "https://api.github.com$path" -Headers (GHHeaders $token) -CacheTtlMs 0 }
function GHGetDiagnostic($path,$token){
  try{
    $r=Invoke-GovernedGitHubRaw -Method GET -Url "https://api.github.com$path" -Headers (GHHeaders $token) -CacheTtlMs 0 -AllowHttpError
    if([int]$r.status-ge200-and[int]$r.status-lt300){$v=if([string]::IsNullOrWhiteSpace("$($r.body)")){$null}else{"$($r.body)"|ConvertFrom-Json};return @{ok=$true;status=[int]$r.status;value=$v;error=$null}}
    return @{ok=$false;status=[int]$r.status;value=$null;error="$($r.body)"}
  }catch{return @{ok=$false;status=$null;value=$null;error="$($_.Exception.Message)"}}
}
function GHPost($path,$token,$body){ Invoke-GovernedGitHubJson -Method POST -Url "https://api.github.com$path" -Headers (GHHeaders $token) -Body $body -CacheTtlMs 0 }
function GHPatch($path,$token,$body){ Invoke-GovernedGitHubJson -Method PATCH -Url "https://api.github.com$path" -Headers (GHHeaders $token) -Body $body -CacheTtlMs 0 }

function Assert-ControllerPermissions($auth){
  $perms=$auth.permissions
  $issues=if($perms.PSObject.Properties.Name -contains 'issues'){"$($perms.issues)"}else{'none'}
  $contents=if($perms.PSObject.Properties.Name -contains 'contents'){"$($perms.contents)"}else{'none'}
  $pulls=if($perms.PSObject.Properties.Name -contains 'pull_requests'){"$($perms.pull_requests)"}else{'none'}
  if($issues -ne 'write'){ throw "GitHub App needs Issues: Read and write for v0.5.10 controller publication. Current: $issues" }
  if($contents -notin @('read','write')){ throw "GitHub App needs Contents access to inspect repository truth. Current: $contents" }
  if($pulls -notin @('read','write')){ throw "GitHub App needs Pull requests access to inspect collision/review state. Current: $pulls" }
}

function Get-ControlVersion([string]$body){
  if($body -notmatch '(?m)^CONTROL_VERSION:\s*(\d+)\s*$'){ throw 'Could not parse current CONTROL_VERSION from #233' }
  [int]$Matches[1]
}
function Get-RecordedMain([string]$body){
  if($body -match '(?m)^MAIN:\s*([0-9a-f]{40})\s*$'){ return $Matches[1] }
  $null
}
function Test-NoActiveWriter([string]$body){
  # Parse the authoritative current board fields instead of depending on prose layout.
  # Ambiguous/missing writer or lease state fails closed.
  $writerMatch=[regex]::Match($body,'(?im)^ACTIVE_WRITERS:\s*([^\r\n]+?)\s*$')
  if(-not $writerMatch.Success){ return $false }
  $writerState=$writerMatch.Groups[1].Value.Trim()
  if($writerState -notmatch '^(none|0)$'){ return $false }

  $leaseMatches=[regex]::Matches($body,'(?im)^\s*LEASE:\s*([^\r\n]+?)\s*$')
  if($leaseMatches.Count -lt 1){ return $false }
  foreach($leaseMatch in $leaseMatches){
    if($leaseMatch.Groups[1].Value.Trim() -notmatch '^none$'){ return $false }
  }
  return $true
}

function Get-LatestExecutablePacketComment($token){
  $comments=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)/comments?per_page=100&sort=created&direction=desc" $token
  $matches=@($comments | Where-Object { $_.body -match 'API_EXECUTABLE_PACKET_SCHEMA:\s*1' })
  if($matches.Count -eq 0){ return $null }
  $matches | Sort-Object {[DateTimeOffset]$_.created_at} -Descending | Select-Object -First 1
}
function Parse-PacketFromComment([string]$body){
  if($body -notmatch '(?s)API_EXECUTABLE_PACKET_JSON\s*```json\s*(\{.*?\})\s*```'){ return $null }
  try { $Matches[1] | ConvertFrom-Json } catch { $null }
}

function New-AskPass([string]$dir){
  $path=Join-Path $dir 'git-askpass.cmd'
  @'
@echo off
set prompt=%~1
echo %prompt% | findstr /I "Username" >nul
if not errorlevel 1 (echo x-access-token& exit /b 0)
echo %SITEBOSS_GITHUB_TOKEN%
'@ | Set-Content -LiteralPath $path -Encoding ASCII
  $path
}
function Invoke-Git([string[]]$CommandArgs,[string]$WorkingDir=$null,[switch]$Capture){
  if(-not $CommandArgs -or $CommandArgs.Count -lt 1){ throw 'Internal error: git command arguments are empty' }
  if($WorkingDir){ Push-Location $WorkingDir }
  try {
    if($Capture){
      $out=& git @CommandArgs 2>&1; $code=$LASTEXITCODE
      if($code -ne 0){ throw "git $($CommandArgs[0]) failed ($code): $($out -join ' ')" }
      return ($out -join "`n").Trim()
    }
    & git @CommandArgs
    if($LASTEXITCODE -ne 0){ throw "git $($CommandArgs[0]) failed with exit code $LASTEXITCODE" }
  } finally { if($WorkingDir){ Pop-Location } }
}
function New-ReadOnlySnapshot([string]$sha,[string]$token){
  New-Item -ItemType Directory -Force -Path $Config.SnapshotRoot | Out-Null
  $dir=Join-Path $Config.SnapshotRoot ([DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss'))
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $ask=New-AskPass $dir
  $repo=Join-Path $dir 'repo'
  $env:SITEBOSS_GITHUB_TOKEN=$token; $env:GIT_ASKPASS=$ask; $env:GIT_TERMINAL_PROMPT='0'
  try {
    Invoke-Git -CommandArgs @('clone','--no-checkout','--filter=blob:none',"https://github.com/$($Config.Owner)/$($Config.Repo).git",$repo)
    Invoke-Git -CommandArgs @('fetch','--no-tags','origin',$sha) -WorkingDir $repo
    Invoke-Git -CommandArgs @('checkout','--detach',$sha) -WorkingDir $repo
    $actual=Invoke-Git -CommandArgs @('rev-parse','HEAD') -WorkingDir $repo -Capture
    if($actual -ne $sha){ throw "Snapshot checkout mismatch: $actual" }
  } finally {
    Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue
  }
  @{Root=$dir;Repo=$repo}
}

function Get-RepoTree([string]$repo){
  $raw=Invoke-Git -CommandArgs @('ls-tree','-r','--name-only','HEAD') -WorkingDir $repo -Capture
  @($raw -split "`n" | Where-Object { $_ })
}
function Get-PackageSummary([string]$repo){
  $path=Join-Path $repo 'package.json'
  if(-not (Test-Path -LiteralPath $path)){ throw 'package.json missing on current main' }
  $pkg=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
  $scripts=@{}
  if($pkg.scripts){ foreach($prop in $pkg.scripts.PSObject.Properties){ $scripts[$prop.Name]="$($prop.Value)" } }
  @{name="$($pkg.name)";scripts=$scripts}
}
function Read-SelectedFiles([string]$repo,[object[]]$paths){
  $total=0; $out=@()
  foreach($raw in $paths){
    $path="$raw".Replace('\','/')
    if([IO.Path]::IsPathRooted($path) -or $path -match '(^|/)\.\.(/|$)' -or $path -match '(^|/)\.git(/|$)'){ throw "Unsafe planned path: $path" }
    $full=Join-Path $repo $path
    if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ throw "Planned file does not exist on base: $path" }
    $text=Get-Content -LiteralPath $full -Raw
    $total += $text.Length
    if($total -gt $Config.MaxFileChars){ throw "Selected source context exceeds $($Config.MaxFileChars) characters" }
    $out+=@{path=$path;content=$text}
  }
  $out
}

function Get-OpenPullCollisionMap($token){
  $pulls=@(GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls?state=open&per_page=100&sort=updated&direction=desc" $token)
  $map=@{}
  foreach($pr in $pulls){
    if("$($pr.base.ref)" -ne 'main'){ continue }
    $files=@(GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$($pr.number)/files?per_page=100" $token)
    foreach($f in $files){
      $path="$($f.filename)"
      if(-not $map.ContainsKey($path)){ $map[$path]=@() }
      $map[$path]+= [int]$pr.number
    }
  }
  $map
}
function Assert-NoCollision([object[]]$paths,$collisionMap){
  $hits=@()
  foreach($p in $paths){ if($collisionMap.ContainsKey("$p")){ $hits+= "$p -> PR $($collisionMap["$p"] -join ',')" } }
  if($hits.Count){ throw "Open-PR path collision: $($hits -join '; ')" }
}

function Get-OpenPullEvidence($token){
  $pullDiag=GHGetDiagnostic "/repos/$($Config.Owner)/$($Config.Repo)/pulls?state=open&per_page=$($Config.MaxOpenPulls)&sort=updated&direction=desc" $token
  if(-not $pullDiag.ok){ throw "GitHub open-PR listing failed: HTTP $($pullDiag.status): $($pullDiag.error)" }
  $pulls=@($pullDiag.value)

  $baseCounts=@{}
  foreach($pr in $pulls){
    $b="$($pr.base.ref)"
    if(-not $baseCounts.ContainsKey($b)){ $baseCounts[$b]=0 }
    $baseCounts[$b]++
  }
  $baseSummary=@()
  foreach($k in ($baseCounts.Keys | Sort-Object)){ $baseSummary += "$k=$($baseCounts[$k])" }
  Write-Host ("GitHub /pulls: raw_open={0}; bases=[{1}]" -f $pulls.Count,($baseSummary -join ', ')) -ForegroundColor DarkGray

  # Independent cross-check through the issues endpoint, which also exposes PR-shaped items.
  # Paginate it so the count is not just the first 100 open issue/PR records.
  $issuePRs=@()
  $issuePage=1
  while($true){
    $issueDiag=GHGetDiagnostic "/repos/$($Config.Owner)/$($Config.Repo)/issues?state=open&per_page=100&sort=updated&direction=desc&page=$issuePage" $token
    if(-not $issueDiag.ok){ throw "GitHub open-issue cross-check failed on page ${issuePage}: HTTP $($issueDiag.status): $($issueDiag.error)" }
    $issueBatch=@($issueDiag.value)
    foreach($item in $issueBatch){
      # Under StrictMode, ordinary issue objects may not expose pull_request at all.
      $prop=$item.PSObject.Properties['pull_request']
      if(($null -ne $prop) -and ($null -ne $prop.Value)){ $issuePRs += $item }
    }
    if($issueBatch.Count -lt 100){ break }
    $issuePage++
    if($issuePage -gt 30){ throw 'GitHub /issues cross-check exceeded safety pagination bound' }
  }
  Write-Host ("GitHub /issues cross-check: open_PR_shaped_items={0}" -f $issuePRs.Count) -ForegroundColor DarkGray

  if($pulls.Count -ne $issuePRs.Count){
    Write-Host ("GitHub PR-count note: /pulls={0}; /issues PR-shaped={1}. Continuing because /pulls is authoritative for PR inventory; /issues is diagnostic only." -f $pulls.Count,$issuePRs.Count) -ForegroundColor DarkYellow
  }

  $out=@()
  foreach($pr in $pulls){
    if("$($pr.base.ref)" -ne 'main'){ continue }

    # The list-pulls response does not reliably include mergeability fields.
    # Fetch the detailed PR record before reading mergeable/mergeable_state.
    $detailDiag=GHGetDiagnostic "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$($pr.number)" $token
    if(-not $detailDiag.ok){ throw "PR #$($pr.number) detail read failed: HTTP $($detailDiag.status): $($detailDiag.error)" }
    $detail=$detailDiag.value

    $files=@()
    $page=1
    while($true){
      $batchDiag=GHGetDiagnostic "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$($pr.number)/files?per_page=100&page=$page" $token
      if(-not $batchDiag.ok){ throw "PR #$($pr.number) file inventory failed: HTTP $($batchDiag.status): $($batchDiag.error)" }
      $batch=@($batchDiag.value)
      foreach($f in $batch){
        $files+=@{
          path="$($f.filename)"
          status="$($f.status)"
          additions=[int]$f.additions
          deletions=[int]$f.deletions
          changes=[int]$f.changes
        }
      }
      if($batch.Count -lt 100){ break }
      $page++
      if($page -gt 30){ throw "PR #$($pr.number) changed-path inventory exceeded safety pagination bound" }
    }
    $out+=@{
      number=[int]$pr.number
      title="$($pr.title)"
      draft=[bool]$pr.draft
      state="$($pr.state)"
      head_ref="$($pr.head.ref)"
      head_sha="$($pr.head.sha)"
      base_ref="$($pr.base.ref)"
      base_sha="$($pr.base.sha)"
      mergeable=$detail.mergeable
      mergeable_state="$($detail.mergeable_state)"
      updated_at="$($detail.updated_at)"
      changed_files=@($files)
    }
  }
  Write-Host ("GitHub /pulls main-targeting inventories={0}" -f $out.Count) -ForegroundColor DarkGray
  $out
}

function Get-ReferencedIssueEvidence([object[]]$documents,$token){
  $known=@{}
  foreach($n in @($Config.ControlIssue,$Config.SchedulerIssue,$Config.DeliveryIssue,$Config.IntegrationIssue,$Config.ScopeIssue,$Config.OwnerCommandIssue)){
    $known[[int]$n]=$true
  }

  $numbers=New-Object System.Collections.Generic.HashSet[int]
  foreach($doc in $documents){
    $body="$($doc.body)"
    foreach($m in [regex]::Matches($body,'(?<![A-Za-z0-9])#(\d{1,6})\b')){
      $n=[int]$m.Groups[1].Value
      if(-not $known.ContainsKey($n)){ [void]$numbers.Add($n) }
    }
  }

  $ordered=@($numbers | Sort-Object)
  if($ordered.Count -gt $Config.MaxReferencedIssues){
    throw "Referenced issue evidence exceeds safety bound ($($ordered.Count) > $($Config.MaxReferencedIssues)); narrow scheduler/control references before planning"
  }

  $out=@()
  foreach($n in $ordered){
    try {
      $issue=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$n" $token
      # GitHub's issues endpoint also returns PR-shaped records. Preserve that fact.
      $labels=@()
      foreach($l in @($issue.labels)){ $labels+="$($l.name)" }
      $out+=@{
        number=$n
        title="$($issue.title)"
        state="$($issue.state)"
        body="$($issue.body)"
        labels=$labels
        is_pull_request=[bool](
          ($null -ne $issue.PSObject.Properties['pull_request']) -and
          ($null -ne $issue.PSObject.Properties['pull_request'].Value)
        )
        updated_at="$($issue.updated_at)"
      }
    } catch {
      $status=$null
      try { $status=[int]$_.Exception.Response.StatusCode } catch {}
      $reason="$($_.Exception.Message)"
      try { if($_.ErrorDetails -and $_.ErrorDetails.Message){ $reason="$($_.ErrorDetails.Message)" } } catch {}
      Write-Host ("Referenced #{0}: UNAVAILABLE HTTP {1}: {2}" -f $n,$status,$reason) -ForegroundColor DarkYellow
      $out+=@{number=$n;unavailable=$true;http_status=$status;reason=$reason}
    }
  }
  $out
}

function Get-CheckSummary([string]$sha,$token){
  $checks=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/commits/$sha/check-runs?per_page=100" $token
  $arr=@()
  foreach($c in @($checks.check_runs)){ $arr+=@{name="$($c.name)";status="$($c.status)";conclusion="$($c.conclusion)"} }
  $arr
}

function Invoke-OpenAIStructured([string]$instructions,[object]$payload,[string]$name,[object]$schema){
  $key=[Environment]::GetEnvironmentVariable('OPENAI_API_KEY','User'); if(-not $key){$key=$env:OPENAI_API_KEY}
  if(-not $key){ throw 'OPENAI_API_KEY missing' }
  # Do not name this parameter $input: $input is a PowerShell automatic variable.
  # Serialize the controller payload once, explicitly, and force the Responses API
  # top-level `input` member to remain a JSON string.
  [string]$inputText = ConvertTo-Json -InputObject $payload -Depth 80 -Compress
  if([string]::IsNullOrWhiteSpace($inputText)){ throw 'OpenAI input serialization produced an empty string' }

  $request=@{
    model=$Config.Model
    instructions=$instructions
    input=[string]$inputText
    text=@{format=@{type='json_schema';name=$name;strict=$true;schema=$schema}}
  }
  [string]$body = ConvertTo-Json -InputObject $request -Depth 100 -Compress

  $roundTrip = $body | ConvertFrom-Json
  if($roundTrip.input -isnot [string]){
    throw "OpenAI request invariant failed: top-level input must be a string, got $($roundTrip.input.GetType().FullName)"
  }

  $bodyBytes=[Text.Encoding]::UTF8.GetByteCount($body)
  Write-Host ("OpenAI request: model={0}; schema={1}; input_type=string; body_bytes={2}" -f $Config.Model,$name,$bodyBytes) -ForegroundColor DarkGray

  $resp=Invoke-WebRequest -Method Post -Uri 'https://api.openai.com/v1/responses' `
    -Headers @{Authorization="Bearer $key";'Content-Type'='application/json'} `
    -Body $body -SkipHttpErrorCheck

  if([int]$resp.StatusCode -lt 200 -or [int]$resp.StatusCode -ge 300){
    $detail="$($resp.Content)"
    try {
      $ej=$detail | ConvertFrom-Json
      if($ej.error){
        $parts=@()
        if($ej.error.type){$parts+="type=$($ej.error.type)"}
        if($ej.error.code){$parts+="code=$($ej.error.code)"}
        if($ej.error.param){$parts+="param=$($ej.error.param)"}
        if($ej.error.message){$parts+="message=$($ej.error.message)"}
        if($parts.Count){$detail=$parts -join '; '}
      }
    } catch {}
    if($detail.Length -gt 4000){$detail=$detail.Substring(0,4000)+'...'}
    throw "OpenAI API HTTP $([int]$resp.StatusCode): $detail"
  }

  $r=$resp.Content | ConvertFrom-Json
  if($r.status -and $r.status -ne 'completed'){ throw "OpenAI response status: $($r.status)" }
  $texts=@(); foreach($i in @($r.output)){ foreach($c in @($i.content)){ if($c.type -eq 'output_text'){$texts+=$c.text} } }
  if($texts.Count -eq 0){ throw 'OpenAI returned no output_text' }
  ($texts -join "`n") | ConvertFrom-Json
}

function Get-PlanningSchema {
  @{
    type='object';additionalProperties=$false
    properties=@{
      decision=@{type='string';enum=@('RELEASE_PACKET','NO_SAFE_PACKET')}
      reason=@{type='string'}
      pr168_disposition=@{type='string';enum=@('INTEGRATION_CANDIDATE_OWNER_GATE','CORRECTION_REQUIRED','WAIT_UNCHANGED','NOT_APPLICABLE')}
      target_issue=@{type='integer'}
      purpose=@{type='string'}
      candidate_paths=@{type='array';items=@{type='string'}}
      focused_test_commands=@{type='array';items=@{type='string'}}
      definition_of_done=@{type='array';items=@{type='string'}}
      reviewer_requirements=@{type='array';items=@{type='string'}}
      stop_boundary=@{type='string'}
    }
    required=@('decision','reason','pr168_disposition','target_issue','purpose','candidate_paths','focused_test_commands','definition_of_done','reviewer_requirements','stop_boundary')
  }
}
function Get-FinalSchema {
  @{
    type='object';additionalProperties=$false
    properties=@{
      safe_to_release=@{type='boolean'}
      reason=@{type='string'}
      purpose=@{type='string'}
      target_issue=@{type='integer'}
      path_allowlist=@{type='array';items=@{type='string'}}
      path_denylist=@{type='array';items=@{type='string'}}
      focused_test_commands=@{type='array';items=@{type='string'}}
      full_test_commands=@{type='array';items=@{type='string'}}
      definition_of_done=@{type='array';items=@{type='string'}}
      reviewer_requirements=@{type='array';items=@{type='string'}}
      stop_boundary=@{type='string'}
    }
    required=@('safe_to_release','reason','purpose','target_issue','path_allowlist','path_denylist','focused_test_commands','full_test_commands','definition_of_done','reviewer_requirements','stop_boundary')
  }
}

function Assert-SafeTestCommand([string]$cmd,[string]$repo){
  if([string]::IsNullOrWhiteSpace($cmd)){ throw 'Empty test command' }
  if($cmd -match '[;&|><`\r\n]'){ throw "Unsafe test command control character: $cmd" }
  if($cmd -match '^\s*npm(\.cmd)?\s+test\s*$'){ return }
  if($cmd -match '^\s*npm(\.cmd)?\s+run\s+([A-Za-z0-9:_-]+)\s*$'){
    $pkg=Get-Content (Join-Path $repo 'package.json') -Raw | ConvertFrom-Json
    $name=$Matches[2]
    if(-not $pkg.scripts.PSObject.Properties.Name.Contains($name)){ throw "Unknown npm script in packet: $name" }
    return
  }
  if($cmd -match '^\s*node(\.exe)?\s+--test\s+(.+?)\s*$'){
    $path=$Matches[2].Trim().Trim('"').Trim("'")
    if($path -match '[*?]'){ throw "Globs are not allowed in v0.5.10 focused test commands: $cmd" }
    if(-not (Test-Path -LiteralPath (Join-Path $repo $path) -PathType Leaf)){ throw "Focused test file does not exist: $path" }
    return
  }
  throw "Unsupported v0.4-compatible test command: $cmd"
}
function Assert-FinalPacketPlan($plan,[string]$repo,$tree,$collisionMap){
  if(-not $plan.safe_to_release){ return }
  $paths=@($plan.path_allowlist)
  if($paths.Count -lt 1 -or $paths.Count -gt $Config.MaxPlanFiles){ throw 'Final packet path count is invalid' }
  $seen=@{}
  foreach($raw in $paths){
    $p="$raw".Replace('\','/')
    if($p -match '[*?\[]'){ throw "v0.4 requires exact existing file paths; glob refused: $p" }
    if($seen.ContainsKey($p)){ throw "Duplicate packet path: $p" }; $seen[$p]=$true
    if($tree -notcontains $p){ throw "Packet path not on exact base: $p" }
    if($p -match '^(\.github/|migrations/|package(-lock)?\.json$|\.env|scripts/)'){ throw "v0.5.10 first-controller safety denylist refuses: $p" }
  }
  Assert-NoCollision $paths $collisionMap
  if(@($plan.focused_test_commands).Count -lt 1){ throw 'Focused tests required' }
  if(@($plan.full_test_commands).Count -lt 1){ throw 'Full tests required' }
  foreach($c in @($plan.focused_test_commands)){ Assert-SafeTestCommand "$c" $repo }
  foreach($c in @($plan.full_test_commands)){ Assert-SafeTestCommand "$c" $repo }
  if(-not (@($plan.full_test_commands) -contains 'npm test')){ throw 'v0.5.10 requires npm test as a full-suite command' }
}

function New-Slug([string]$s){
  $x=$s.ToLowerInvariant() -replace '[^a-z0-9]+','-'; $x=$x.Trim('-')
  if($x.Length -gt 45){$x=$x.Substring(0,45).Trim('-')}
  if(-not $x){$x='packet'}
  $x
}
function New-Packet($plan,[int]$newControl,[string]$mainSha){
  $stamp=[DateTimeOffset]::UtcNow.ToString('yyyyMMddHHmmss')
  $packetId="SB-API-C$newControl-$stamp"
  $lease="LEASE-$packetId"
  $branch="api/issue-$($plan.target_issue)-$(New-Slug $plan.purpose)-$stamp"
  [ordered]@{
    packet_id=$packetId
    control_version=$newControl
    purpose="$($plan.purpose)"
    target_issue=[int]$plan.target_issue
    base_ref='main'
    base_sha=$mainSha
    branch=$branch
    path_allowlist=@($plan.path_allowlist)
    path_denylist=@($plan.path_denylist)
    lease_id=$lease
    definition_of_done=@($plan.definition_of_done)
    focused_test_commands=@($plan.focused_test_commands)
    full_test_commands=@($plan.full_test_commands)
    reviewer_requirements=@($plan.reviewer_requirements)
    stop_boundary="$($plan.stop_boundary)"
  }
}

function New-ControlBody([string]$oldBody,[int]$oldControl,$packet,[string]$pr168Disposition){
  $newControl=$oldControl+1
  $body=$oldBody
  $body=[regex]::Replace($body,'(?m)^CONTROL_VERSION:\s*\d+\s*$',"CONTROL_VERSION: $newControl",1)
  $body=[regex]::Replace($body,'(?m)^PREVIOUS_CONTROL_VERSION:\s*\d+\s*$',"PREVIOUS_CONTROL_VERSION: $oldControl",1)
  $body=[regex]::Replace($body,'(?m)^ACTIVE_WRITERS:\s*none\s*$',"ACTIVE_WRITERS: API_WORKER_V0_4",1)
  $body=$body.Replace('Repository writers: none. Write leases: none.',"Repository writers: API_WORKER_V0_4. Write leases: $($packet.lease_id).")
  $section=@"

## Control$newControl - API controller released $($packet.packet_id)

Owner command #$($Config.OwnerCommandIssue) remains the durable objective. The API-native controller revalidated current main, #233/#423/#505, PR #168 exact-head evidence, open-PR path collisions, exact existing paths and v0.4-compatible tests before releasing this one bounded coding lease.

```yaml
API_CONTROLLER: v0.5.10
API_EXECUTOR: v0.4
PACKET_ID: $($packet.packet_id)
LEASE_ID: $($packet.lease_id)
LEASE_STATE: RELEASED_FOR_ONE_DRAFT_PR
TARGET_ISSUE: $($packet.target_issue)
BASE_SHA: $($packet.base_sha)
BRANCH: $($packet.branch)
PR168_INTEGRATION_DISPOSITION: $pr168Disposition
WRITE: true
MERGE: false
DEPLOY: false
SELF_REVIEW: false
```

Only the exact packet paths/tests below are authorised. The executor must stop after an exact-head draft PR. Independent review and later integration remain separate gates.
"@
  $anchor='(?m)^(## Control'+[regex]::Escape("$oldControl")+'\b)'
  if($body -match $anchor){ $body=[regex]::Replace($body,$anchor,($section+"`n`n`$1"),1) }
  else { $body += $section }
  $body
}

function Publish-Packet($token,$currentIssue,$packet,[string]$pr168Disposition){
  $oldControl=Get-ControlVersion "$($currentIssue.body)"
  $newBody=New-ControlBody "$($currentIssue.body)" $oldControl $packet $pr168Disposition
  Write-Host "Publishing Control $($oldControl+1) lease to #233..." -ForegroundColor Yellow
  $updated=GHPatch "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)" $token @{body=$newBody}
  if((Get-ControlVersion "$($updated.body)") -ne ($oldControl+1)){ throw 'Controller board update did not persist expected control version' }
  $json=$packet|ConvertTo-Json -Depth 30
  $comment=@"
API_EXECUTABLE_PACKET_SCHEMA: 1
CONTROLLER: SiteBoss Worker Engine v0.5.10
OWNER_COMMAND: #$($Config.OwnerCommandIssue)

API_EXECUTABLE_PACKET_JSON
```json
$json
```

This packet grants one bounded v0.4 executor lease only. It does not grant merge, deploy, approval, settings/secrets/permissions, provider/customer or financial authority. Any main/control movement invalidates the packet.
"@
  try {
    $posted=GHPost "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)/comments" $token @{body=$comment}
    return @{Issue=$updated;Comment=$posted}
  } catch {
    try {
      $now=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)" $token
      if((Get-ControlVersion "$($now.body)") -eq ($oldControl+1) -and "$($now.body)" -match [regex]::Escape("$($packet.packet_id)")){
        [void](GHPatch "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)" $token @{body="$($currentIssue.body)"})
      }
    } catch {}
    throw
  }
}

try {
  if($PSVersionTable.PSVersion.Major -lt 7){ throw 'PowerShell 7+ required' }
  if(-not (Get-Command git -ErrorAction SilentlyContinue)){ throw 'Git for Windows is required' }

  Write-Host "`nSITEBOSS WORKER ENGINE v0.5.10" -ForegroundColor Cyan
  Write-Host 'API CONTROLLER - live truth -> bounded packet -> #233 lease for v0.4.' -ForegroundColor DarkGray

  $auth=New-GitHubInstallationToken
  if(-not $auth.token){ throw 'No GitHub installation token' }
  Assert-ControllerPermissions $auth
  $token=$auth.token

  $control=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)" $token
  $controlVersion=Get-ControlVersion "$($control.body)"
  Write-Host "Current SiteBoss control: $controlVersion" -ForegroundColor DarkGray

  $latestPacketComment=Get-LatestExecutablePacketComment $token
  if($latestPacketComment){
    $latestPacket=Parse-PacketFromComment "$($latestPacketComment.body)"
    if($latestPacket -and [int]$latestPacket.control_version -eq $controlVersion){
      Write-Host "`nPACKET ALREADY RELEASED" -ForegroundColor Yellow
      Write-Host "Packet: $($latestPacket.packet_id)"
      Write-Host "Branch: $($latestPacket.branch)"
      Write-Host 'Run SiteBoss Worker Engine v0.4. v0.5.10 will not issue a duplicate lease.'
      exit 0
    }
  }

  if(-not (Test-NoActiveWriter "$($control.body)")){ throw 'Controller refuses to release a packet while #233 records an active writer or lease' }

  $main=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/ref/heads/main" $token
  $mainSha="$($main.object.sha)"
  $recorded=Get-RecordedMain "$($control.body)"
  if($recorded -and $recorded -ne $mainSha){ throw "#233/main drift: board=$recorded live=$mainSha. Reconcile controller state before packet release." }

  Write-Host 'Reading scheduler, delivery contract, integration gate and owner command...' -ForegroundColor Yellow
  $scheduler=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.SchedulerIssue)" $token
  $delivery=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.DeliveryIssue)" $token
  $integration=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.IntegrationIssue)" $token
  $scope=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ScopeIssue)" $token
  $ownerCommand=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.OwnerCommandIssue)" $token
  $pr168=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/168" $token
  $pr168Checks=Get-CheckSummary "$($pr168.head.sha)" $token

  Write-Host 'Creating exact read-only main snapshot...' -ForegroundColor Yellow
  $snapshot=New-ReadOnlySnapshot $mainSha $token
  Write-Host 'Read-only main snapshot: OK' -ForegroundColor DarkGray
  $tree=@(Get-RepoTree $snapshot.Repo)
  $package=Get-PackageSummary $snapshot.Repo
  $collisions=Get-OpenPullCollisionMap $token
  $collisionSummary=@()
  foreach($k in ($collisions.Keys | Sort-Object)){ $collisionSummary+=@{path=$k;prs=@($collisions[$k])} }

  Write-Host 'Collecting exact open-PR path inventories and referenced issue evidence...' -ForegroundColor Yellow
  $openPullEvidence=@(Get-OpenPullEvidence $token)
  $referencedIssues=@(Get-ReferencedIssueEvidence @($control,$scheduler,$delivery,$integration,$scope,$ownerCommand) $token)
  $unavailableRefs=@($referencedIssues | Where-Object {
    $p=$_.PSObject.Properties['unavailable']
    ($null -ne $p) -and ([bool]$p.Value)
  })
  Write-Host ("Evidence: {0} open main PR inventories; {1} referenced issues; {2} unavailable" -f $openPullEvidence.Count,$referencedIssues.Count,$unavailableRefs.Count) -ForegroundColor DarkGray

  $planInstructions=@"
You are the SiteBoss API controller. Select at most ONE small, high-value coding packet for the v0.4 executor.
The durable owner objective is the current owner-command issue. #233 is the sole live scheduler. #423/#505 governance must be obeyed.
Current mode is capability-conserving: do not create filler. Prefer Release-1 critical-path work.
You MUST explicitly disposition PR #168 from the supplied current exact-head evidence. INTEGRATION_CANDIDATE_OWNER_GATE means its current frozen head may proceed to later owner/controller integration without new code; it is NOT merge authority.
The executor can modify ONLY existing files, cannot create files, cannot edit migrations/package/workflows/scripts, and must run v0.4-supported npm/node tests plus npm test.
Do not choose any path currently touched by an open PR. Do not choose work requiring a new dependency, migration, secret, provider binding, customer send, financial action, deployment, merge, approval, or owner-setting change.
The input includes grouped exact changed-path inventories for every currently open main-targeting PR and live evidence for issue numbers referenced by the governance/owner documents. Use that evidence rather than assuming missing dependency or collision state.
If a referenced issue describes an actionable implementation but exact source content is still needed, you may select exact candidate paths from repository_tree for the second-stage source inspection; do not require source contents at this first stage merely to nominate candidate paths.
If no genuinely safe bounded packet can be proven from supplied truth, return NO_SAFE_PACKET. Do not invent an issue, file, test, dependency state, or authority.
"@
  $planInput=@{
    live_control=@{version=$controlVersion;body="$($control.body)";main_sha=$mainSha}
    owner_command=@{number=$Config.OwnerCommandIssue;body="$($ownerCommand.body)"}
    scheduler=@{number=$Config.SchedulerIssue;body="$($scheduler.body)"}
    delivery=@{number=$Config.DeliveryIssue;body="$($delivery.body)"}
    integration=@{number=$Config.IntegrationIssue;body="$($integration.body)"}
    release_scope=@{number=$Config.ScopeIssue;body="$($scope.body)"}
    pr168=@{state="$($pr168.state)";draft=[bool]$pr168.draft;head="$($pr168.head.sha)";base="$($pr168.base.sha)";mergeable=$pr168.mergeable;body="$($pr168.body)";checks=$pr168Checks}
    package=$package
    repository_tree=$tree
    open_pr_path_ownership=$collisionSummary
    open_pr_exact_inventories=$openPullEvidence
    referenced_issue_evidence=$referencedIssues
  }
  Write-Host 'Planning the next bounded packet with GPT-5.6...' -ForegroundColor Yellow
  $candidate=Invoke-OpenAIStructured $planInstructions $planInput 'siteboss_controller_candidate' (Get-PlanningSchema)
  if($candidate.decision -eq 'NO_SAFE_PACKET'){
    Write-Host "`nNO SAFE CODING PACKET" -ForegroundColor Yellow
    Write-Host "$($candidate.reason)"
    Write-Host "PR168 disposition: $($candidate.pr168_disposition)"
    Write-Host 'Nothing was changed on GitHub.'
    exit 0
  }
  if(@($candidate.candidate_paths).Count -lt 1){ throw 'Controller model selected RELEASE_PACKET with no candidate paths' }
  if(@($candidate.candidate_paths).Count -gt $Config.MaxPlanFiles){ throw 'Controller model selected too many candidate paths' }
  Assert-NoCollision @($candidate.candidate_paths) $collisions
  $files=Read-SelectedFiles $snapshot.Repo @($candidate.candidate_paths)

  $finalInstructions=@"
You are finalising ONE machine-readable SiteBoss coding packet for the already-selected purpose.
Use only exact existing source/test paths supplied in selected_files. You may omit a candidate path, but may not add any path not supplied.
Keep the change small. No migrations, package files, workflows, scripts, new files, dependencies, provider/customer/financial actions, merge/deploy/approval, or settings/permission changes.
Return v0.4-compatible focused test commands only: node --test <exact existing test file>, npm test, or an existing npm run <script> with no shell metacharacters. full_test_commands MUST include npm test.
Definition of Done must be objective. Independent review is required after the draft PR. If source inspection shows the selected work cannot be safely completed inside these paths, safe_to_release=false.
"@
  $finalInput=@{candidate=$candidate;base_sha=$mainSha;package=$package;selected_files=$files;open_pr_path_ownership=$collisionSummary;open_pr_exact_inventories=$openPullEvidence;referenced_issue_evidence=$referencedIssues}
  Write-Host 'Inspecting selected source and finalising paths/tests...' -ForegroundColor Yellow
  $final=Invoke-OpenAIStructured $finalInstructions $finalInput 'siteboss_controller_final_packet' (Get-FinalSchema)
  if(-not $final.safe_to_release){
    Write-Host "`nNO SAFE CODING PACKET AFTER SOURCE INSPECTION" -ForegroundColor Yellow
    Write-Host "$($final.reason)"
    Write-Host 'Nothing was changed on GitHub.'
    exit 0
  }
  Assert-FinalPacketPlan $final $snapshot.Repo $tree $collisions

  $freshControl=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)" $token
  if((Get-ControlVersion "$($freshControl.body)") -ne $controlVersion){ throw 'PUBLISH ABORTED: #233 control moved during planning' }
  if(-not (Test-NoActiveWriter "$($freshControl.body)")){ throw 'PUBLISH ABORTED: writer/lease appeared during planning' }
  $freshMain=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/ref/heads/main" $token
  if("$($freshMain.object.sha)" -ne $mainSha){ throw 'PUBLISH ABORTED: main moved during planning' }
  Assert-NoCollision @($final.path_allowlist) (Get-OpenPullCollisionMap $token)

  $packet=New-Packet $final ($controlVersion+1) $mainSha
  $published=Publish-Packet $token $freshControl $packet "$($candidate.pr168_disposition)"

  Write-Host "`nAPI EXECUTABLE PACKET RELEASED" -ForegroundColor Green
  Write-Host "Packet: $($packet.packet_id)"
  Write-Host "Control: $($packet.control_version)"
  Write-Host "Target issue: #$($packet.target_issue)"
  Write-Host "Purpose: $($packet.purpose)"
  Write-Host "Branch: $($packet.branch)"
  Write-Host "Paths: $(@($packet.path_allowlist).Count)"
  Write-Host "PR168 disposition: $($candidate.pr168_disposition)"
  Write-Host "`nNEXT: run RUN-SITEBOSS-WORKER-v0.4.cmd" -ForegroundColor Cyan
  Write-Host 'v0.4 should now detect this exact packet, build it, test it, open one DRAFT PR, and stop.'
} catch {
  Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue
  Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue
  Write-Host "`nSITEBOSS CONTROLLER v0.5.10 FAILED CLOSED" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  exit 1
}
