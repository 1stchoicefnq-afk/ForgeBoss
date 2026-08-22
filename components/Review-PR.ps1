param(
  [int]$PullRequest = 168,
  [string]$ResultPath = "",
  [switch]$ReviewOnly,
  [switch]$UseCache,
  [ValidateSet('main','child')][string]$ReviewMode = 'main',
  [string]$ExpectedBaseRef = '',
  [string]$ExpectedBaseSha = '',
  [int]$ParentPullRequest = 0
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Config = @{
  AppId="4608230"
  InstallationId="154040429"
  Owner="1stchoicefnq-afk"
  Repo="siteboss-monster"
  PemPath="$env:USERPROFILE\.siteboss\secrets\github-app-private-key.pem"
  Model=($(if($env:SITEBOSS_OPENAI_MODEL){$env:SITEBOSS_OPENAI_MODEL}else{"gpt-5.6"}))
  AnthropicModel=($(if($env:SITEBOSS_ANTHROPIC_MODEL){$env:SITEBOSS_ANTHROPIC_MODEL}else{"claude-sonnet-5"}))
  ReviewProvider=($(if($env:SITEBOSS_REVIEW_PROVIDER){$env:SITEBOSS_REVIEW_PROVIDER.ToLowerInvariant()}else{'openai'}))
  ControlIssue=233
  IntegrationIssue=143
  OwnerCommandIssue=508
  SnapshotRoot=(Join-Path $env:USERPROFILE ".siteboss\worker-engine\integration-snapshots")
  MaxDiffChars=180000
  MaxReviewChunkChars=65000
  MaxReviewChunks=8
  MaxFiles=150
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
  Invoke-RestMethod -Method Post -Uri "https://api.github.com/app/installations/$($Config.InstallationId)/access_tokens" -Headers $hdr -ContentType "application/json" -Body $body
}

function GHHeaders($token){ @{Authorization="Bearer $token";Accept="application/vnd.github+json";"X-GitHub-Api-Version"="2022-11-28"} }

function GHGet($path,$token){
  $uri="https://api.github.com$path"
  $resp=Invoke-WebRequest -Method Get -Uri $uri -Headers (GHHeaders $token) -SkipHttpErrorCheck
  if([int]$resp.StatusCode -lt 200 -or [int]$resp.StatusCode -ge 300){
    $accepted=''
    try { $accepted="$($resp.Headers['X-Accepted-GitHub-Permissions'])" } catch {}
    $detail="$($resp.Content)"
    try {
      $j=$detail|ConvertFrom-Json
      if($j.message){ $detail="$($j.message)" }
    } catch {}
    throw "GitHub GET $path failed: HTTP $([int]$resp.StatusCode); accepted_permissions=[$accepted]; message=$detail"
  }
  if([string]::IsNullOrWhiteSpace("$($resp.Content)")){ return $null }
  $resp.Content|ConvertFrom-Json
}

function GHPut($path,$token,$body){
  Invoke-RestMethod -Method Put -Uri "https://api.github.com$path" -Headers (GHHeaders $token) -ContentType "application/json" -Body ($body|ConvertTo-Json -Depth 30)
}

function Get-OptionalProperty($obj,[string]$name){
  if($null -eq $obj){ return $null }
  $p=$obj.PSObject.Properties[$name]
  if($null -eq $p){ return $null }
  $p.Value
}

function Get-ControlVersion([string]$body){
  if($body -notmatch '(?m)^CONTROL_VERSION:\s*(\d+)\s*$'){ throw 'Could not parse CONTROL_VERSION from #233' }
  [int]$Matches[1]
}
function Get-RecordedMain([string]$body){
  if($body -match '(?m)^MAIN:\s*([0-9a-f]{40})\s*$'){ return $Matches[1] }
  return $null
}

function Assert-ReadPermissions($auth){
  $perms=$auth.permissions
  $issues="$((Get-OptionalProperty $perms 'issues'))"
  $contents="$((Get-OptionalProperty $perms 'contents'))"
  $pulls="$((Get-OptionalProperty $perms 'pull_requests'))"
  $checks="$((Get-OptionalProperty $perms 'checks'))"
  $statuses="$((Get-OptionalProperty $perms 'statuses'))"

  Write-Host ("GitHub App permissions: issues={0}; contents={1}; pull_requests={2}; checks={3}; statuses={4}" -f $issues,$contents,$pulls,$checks,$statuses) -ForegroundColor DarkGray

  if($issues -notin @('read','write')){ throw "GitHub App needs Issues: read. Current: '$issues'" }
  if($contents -notin @('read','write')){ throw "GitHub App needs Contents: read. Current: '$contents'" }
  if($pulls -notin @('read','write')){ throw "GitHub App needs Pull requests: read. Current: '$pulls'" }
  if($checks -notin @('read','write')){ throw "GitHub App needs Checks: read so v0.6 can independently verify exact-head check runs. Current: '$checks'" }
  if($statuses -notin @('read','write')){ throw "GitHub App needs Commit statuses: read so v0.6 can independently verify combined commit status. Current: '$statuses'" }
}

function Assert-MergePermissions($auth){
  $perms=$auth.permissions
  $contents="$((Get-OptionalProperty $perms 'contents'))"
  $pulls="$((Get-OptionalProperty $perms 'pull_requests'))"
  if($contents -ne 'write'){ throw "Merge authority exists but GitHub App Contents permission is not write. Current: $contents" }
  if($pulls -ne 'write'){ throw "Merge authority exists but GitHub App Pull requests permission is not write. Current: $pulls" }
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

function Invoke-Git(
  [Parameter(Mandatory=$true)][string[]]$CommandArgs,
  [string]$WorkingDir=$null,
  [switch]$Capture
){
  if(-not $CommandArgs -or $CommandArgs.Count -lt 1){ throw 'Internal error: empty git command' }

  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName='git.exe'
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true
  if($WorkingDir){ $psi.WorkingDirectory=$WorkingDir }

  foreach($arg in $CommandArgs){
    [void]$psi.ArgumentList.Add([string]$arg)
  }

  $proc=[Diagnostics.Process]::new()
  $proc.StartInfo=$psi
  try {
    if(-not $proc.Start()){ throw 'Failed to start git.exe' }
    $stdout=$proc.StandardOutput.ReadToEnd()
    $stderr=$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if($proc.ExitCode -ne 0){
      $detail=$stderr.Trim()
      if([string]::IsNullOrWhiteSpace($detail)){ $detail=$stdout.Trim() }
      throw "git $($CommandArgs[0]) failed ($($proc.ExitCode)): $detail"
    }

    if(-not [string]::IsNullOrWhiteSpace($stderr)){
      Write-Host ($stderr.Trim()) -ForegroundColor DarkGray
    }

    if($Capture){ return $stdout.Trim() }
    if(-not [string]::IsNullOrWhiteSpace($stdout)){ Write-Host ($stdout.Trim()) }
  } finally {
    $proc.Dispose()
  }
}

function New-ReviewSnapshot([string]$baseSha,[string]$headSha,[string]$token){
  New-Item -ItemType Directory -Force -Path $Config.SnapshotRoot | Out-Null
  $dir=Join-Path $Config.SnapshotRoot ([DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss'))
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $ask=New-AskPass $dir
  $repo=Join-Path $dir 'repo'
  $env:SITEBOSS_GITHUB_TOKEN=$token
  $env:GIT_ASKPASS=$ask
  $env:GIT_TERMINAL_PROMPT='0'
  try {
    [string[]]$gitArgs=@('clone','--no-checkout','--filter=blob:none',"https://github.com/$($Config.Owner)/$($Config.Repo).git",$repo)
    Invoke-Git -CommandArgs $gitArgs
    [string[]]$gitArgs=@('fetch','--no-tags','origin',$baseSha,$headSha)
    Invoke-Git -CommandArgs $gitArgs -WorkingDir $repo
    [string[]]$gitArgs=@('checkout','--detach',$headSha)
    Invoke-Git -CommandArgs $gitArgs -WorkingDir $repo
    [string[]]$gitArgs=@('rev-parse','HEAD')
    $actual=Invoke-Git -CommandArgs $gitArgs -WorkingDir $repo -Capture
    if($actual -ne $headSha){ throw "Review snapshot mismatch: expected $headSha got $actual" }
  } finally {
    Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue
  }
  @{Root=$dir;Repo=$repo}
}

function Get-ChangedFiles([string]$repo,[string]$baseSha,[string]$headSha){
  [string[]]$gitArgs=@('diff','--name-status',"$baseSha...$headSha")
  $raw=Invoke-Git -CommandArgs $gitArgs -WorkingDir $repo -Capture
  if([string]::IsNullOrWhiteSpace($raw)){ return @() }
  $rows=@()
  foreach($line in ($raw -split "`n")){
    if([string]::IsNullOrWhiteSpace($line)){ continue }
    $parts=$line -split "`t"
    $status=$parts[0]
    $path=if($parts.Count -ge 2){$parts[-1]}else{''}
    $rows+=@{status=$status;path=$path}
  }
  if($rows.Count -gt $Config.MaxFiles){ throw "PR changes $($rows.Count) files, above v0.6.4 review bound $($Config.MaxFiles)" }
  $rows
}

function Get-Diff([string]$repo,[string]$baseSha,[string]$headSha){
  # Build the complete review diff with Git's ordinary 3-line context.
  # Large diffs are split into bounded review chunks later; changed hunks are never truncated.
  [string[]]$gitArgs=@('diff','--no-ext-diff','--unified=3',"$baseSha...$headSha",'--')
  $diff=Invoke-Git -CommandArgs $gitArgs -WorkingDir $repo -Capture
  Write-Host ("Complete review diff chars: {0}" -f $diff.Length) -ForegroundColor DarkGray
  $diff
}

function Get-CheckEvidence([string]$sha,$token){
  $runsResp=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/commits/$sha/check-runs?per_page=100" $token
  $runs=@()
  foreach($r in @($runsResp.check_runs)){
    $runs+=@{
      name="$($r.name)"
      status="$($r.status)"
      conclusion="$((Get-OptionalProperty $r 'conclusion'))"
      app="$((Get-OptionalProperty (Get-OptionalProperty $r 'app') 'name'))"
      url="$($r.html_url)"
    }
  }
  $statusResp=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/commits/$sha/status?per_page=100" $token
  $statuses=@()
  foreach($s in @($statusResp.statuses)){
    $statuses+=@{context="$($s.context)";state="$($s.state)";description="$($s.description)"}
  }
  @{
    check_runs=$runs
    combined_status="$($statusResp.state)"
    statuses=$statuses
  }
}

function Assert-ChecksGreen($checks){
  $bad=@()
  foreach($r in @($checks.check_runs)){
    if("$($r.status)" -ne 'completed'){ $bad+="CHECK PENDING: $($r.name) [$($r.status)]"; continue }
    if("$($r.conclusion)" -notin @('success','neutral','skipped')){ $bad+="CHECK FAILED: $($r.name) [$($r.conclusion)]" }
  }
  foreach($s in @($checks.statuses)){
    if("$($s.state)" -ne 'success'){ $bad+="STATUS NOT SUCCESS: $($s.context) [$($s.state)]" }
  }
  if($bad.Count){ throw "Integration checks are not all green: $($bad -join '; ')" }
}

function Get-ReviewEvidence([int]$pr,$token){
  $reviews=@()
  $page=1
  while($true){
    $batch=@(GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$pr/reviews?per_page=100&page=$page" $token)
    foreach($r in $batch){
      $reviews+=@{
        id="$($r.id)"
        user="$($r.user.login)"
        state="$($r.state)"
        commit_id="$($r.commit_id)"
        submitted_at="$($r.submitted_at)"
        body="$($r.body)"
      }
    }
    if($batch.Count -lt 100){ break }
    $page++
    if($page -gt 20){ throw 'Review pagination exceeded safety bound' }
  }
  $reviews
}

function Invoke-OpenAIStructured([string]$instructions,[object]$payload,[string]$name,[object]$schema){
  $key=[Environment]::GetEnvironmentVariable('OPENAI_API_KEY','User')
  if(-not $key){ $key=$env:OPENAI_API_KEY }
  if(-not $key){ throw 'OPENAI_API_KEY missing' }

  [string]$inputText=ConvertTo-Json -InputObject $payload -Depth 80 -Compress
  $request=@{
    model=$Config.Model
    instructions=$instructions
    input=[string]$inputText
    text=@{format=@{type='json_schema';name=$name;strict=$true;schema=$schema}}
  }
  [string]$body=ConvertTo-Json -InputObject $request -Depth 100 -Compress
  $roundTrip=$body|ConvertFrom-Json
  if($roundTrip.input -isnot [string]){ throw 'OpenAI request invariant failed: input is not string' }

  Write-Host ("OpenAI independent review: model={0}; body_bytes={1}" -f $Config.Model,[Text.Encoding]::UTF8.GetByteCount($body)) -ForegroundColor DarkGray
  $resp=Invoke-WebRequest -Method Post -Uri 'https://api.openai.com/v1/responses' `
    -Headers @{Authorization="Bearer $key";'Content-Type'='application/json'} `
    -Body $body -SkipHttpErrorCheck

  if([int]$resp.StatusCode -lt 200 -or [int]$resp.StatusCode -ge 300){
    $detail="$($resp.Content)"
    try {
      $ej=$detail|ConvertFrom-Json
      if($ej.error -and $ej.error.message){ $detail="$($ej.error.message)" }
    } catch {}
    throw "OpenAI API HTTP $([int]$resp.StatusCode): $detail"
  }
  $r=$resp.Content|ConvertFrom-Json
  $texts=@()
  foreach($i in @($r.output)){
    foreach($c in @($i.content)){
      if($c.type -eq 'output_text'){ $texts+=$c.text }
    }
  }
  if($texts.Count -eq 0){ throw 'OpenAI returned no output_text' }
  ($texts -join "`n")|ConvertFrom-Json
}


function Split-DiffIntoReviewChunks([string]$diff){
  if([string]::IsNullOrWhiteSpace($diff)){ return @() }

  # Split at git file boundaries. Preserve each complete file diff where possible.
  $parts=[regex]::Split($diff,'(?m)(?=^diff --git )') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  $chunks=@()
  $current=''

  foreach($part in $parts){
    if($part.Length -gt $Config.MaxReviewChunkChars){
      # A single file diff is too large. Split only at hunk boundaries, preserving complete hunks.
      $subparts=[regex]::Split($part,'(?m)(?=^@@ )') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
      foreach($sp in $subparts){
        if($sp.Length -gt $Config.MaxReviewChunkChars){
          throw "A single review hunk is $($sp.Length) chars, above chunk bound $($Config.MaxReviewChunkChars). Manual/bespoke review packet required."
        }
        if(($current.Length + $sp.Length) -gt $Config.MaxReviewChunkChars -and $current.Length -gt 0){
          $chunks += $current
          $current=''
        }
        $current += $sp
      }
      continue
    }

    if(($current.Length + $part.Length) -gt $Config.MaxReviewChunkChars -and $current.Length -gt 0){
      $chunks += $current
      $current=''
    }
    $current += $part
  }
  if($current.Length -gt 0){ $chunks += $current }

  if($chunks.Count -gt $Config.MaxReviewChunks){
    throw "PR requires $($chunks.Count) review chunks, above v0.6.4 bound $($Config.MaxReviewChunks). Split the PR or use a dedicated review job."
  }
  $chunks
}

function Get-ReviewSynthesisSchema {
  @{
    type='object'
    additionalProperties=$false
    required=@('verdict','summary','findings','required_actions')
    properties=@{
      verdict=@{type='string';enum=@('PASS','FAIL','NEEDS_EVIDENCE')}
      summary=@{type='string'}
      findings=@{
        type='array'
        items=@{
          type='object'
          additionalProperties=$false
          required=@('severity','title','evidence','path')
          properties=@{
            severity=@{type='string';enum=@('BLOCKER','HIGH','MEDIUM','LOW','INFO')}
            title=@{type='string'}
            evidence=@{type='string'}
            path=@{type='string'}
          }
        }
      }
      required_actions=@{type='array';items=@{type='string'}}
    }
  }
}

function Invoke-MultiPassReview([object]$baseReviewInput,[string]$diff,[string]$reviewInstructions){
  $chunks=@(Split-DiffIntoReviewChunks $diff)
  if($chunks.Count -eq 0){ throw 'No diff chunks were produced for review' }

  Write-Host ("Bounded independent review chunks: {0}" -f $chunks.Count) -ForegroundColor DarkGray
  $chunkResults=@()

  for($i=0;$i -lt $chunks.Count;$i++){
    $chunk=$chunks[$i]
    $payload=@{
      pr=$baseReviewInput.pr
      changed_files=$baseReviewInput.changed_files
      checks=$baseReviewInput.checks
      github_reviews=$baseReviewInput.github_reviews
      integration_gate=$baseReviewInput.integration_gate
      owner_command=$baseReviewInput.owner_command
      live_control=$baseReviewInput.live_control
      chunk=@{
        index=$i+1
        total=$chunks.Count
        exact_diff=$chunk
      }
    }

    Write-Host ("Reviewing chunk {0}/{1} ({2} chars)..." -f ($i+1),$chunks.Count,$chunk.Length) -ForegroundColor Yellow
    $r=Invoke-ReviewModel $reviewInstructions $payload ("siteboss_integration_review_chunk_{0}" -f ($i+1)) (Get-ReviewSchema)
    $chunkResults += @{
      chunk=$i+1
      verdict="$($r.verdict)"
      summary="$($r.summary)"
      findings=@($r.findings)
      required_actions=@($r.required_actions)
    }
  }

  # If any chunk found a substantive defect or lacked evidence, final result cannot be PASS.
  $hasFail=@($chunkResults | Where-Object { "$($_.verdict)" -eq 'FAIL' }).Count -gt 0
  $hasNeeds=@($chunkResults | Where-Object { "$($_.verdict)" -eq 'NEEDS_EVIDENCE' }).Count -gt 0

  $synthInstructions=@"
You are the final independent SiteBoss integration-review synthesizer.
You did NOT author the PR. You are given bounded independent chunk-review results for one exact frozen PR head.
Do not invent new code facts. Consolidate duplicate findings and preserve the strongest supported severity.
If any chunk verdict is FAIL, final verdict must be FAIL.
Else if any chunk verdict is NEEDS_EVIDENCE, final verdict must be NEEDS_EVIDENCE.
Else PASS only if all chunks passed.
Keep the synthesis concise because all detailed review work was already performed in the chunks.
"@

  $synthPayload=@{
    pr=$baseReviewInput.pr
    chunk_results=$chunkResults
    deterministic_flags=@{has_fail=$hasFail;has_needs_evidence=$hasNeeds}
  }

  Write-Host 'Synthesizing bounded review results...' -ForegroundColor Yellow
  $final=Invoke-ReviewModel $synthInstructions $synthPayload 'siteboss_integration_review_synthesis' (Get-ReviewSynthesisSchema)

  if($hasFail -and "$($final.verdict)" -ne 'FAIL'){ throw 'Review synthesis invariant failed: a chunk failed but synthesis did not FAIL' }
  if((-not $hasFail) -and $hasNeeds -and "$($final.verdict)" -ne 'NEEDS_EVIDENCE'){ throw 'Review synthesis invariant failed: chunk needed evidence but synthesis did not preserve it' }
  if((-not $hasFail) -and (-not $hasNeeds) -and "$($final.verdict)" -ne 'PASS'){ throw 'Review synthesis invariant failed: all chunks passed but synthesis did not PASS' }

  $final
}


# Provider-compatible structured review call. OpenAI remains the default.
# Claude uses a single forced tool whose input_schema is the same review schema.
function Invoke-ClaudeStructured([string]$instructions,[object]$payload,[string]$name,[object]$schema){
  $key=[Environment]::GetEnvironmentVariable('ANTHROPIC_API_KEY','User')
  if(-not $key){ $key=$env:ANTHROPIC_API_KEY }
  if(-not $key){ throw 'ANTHROPIC_API_KEY missing' }

  [string]$inputText=ConvertTo-Json -InputObject $payload -Depth 80 -Compress
  [string]$body=@{
    model=$Config.AnthropicModel
    max_tokens=4096
    system=$instructions
    messages=@(@{role='user';content=$inputText})
    tools=@(@{
      name=$name
      description="Return the exact structured SiteBoss review result."
      input_schema=$schema
    })
    tool_choice=@{type='tool';name=$name}
  } | ConvertTo-Json -Depth 100 -Compress

  Write-Host ("Claude independent review: model={0}; schema={1}; body_bytes={2}" -f $Config.AnthropicModel,$name,[Text.Encoding]::UTF8.GetByteCount($body)) -ForegroundColor DarkGray
  $resp=Invoke-WebRequest -Method Post -Uri 'https://api.anthropic.com/v1/messages' `
    -Headers @{'x-api-key'=$key;'anthropic-version'='2023-06-01';'Content-Type'='application/json'} `
    -Body $body -SkipHttpErrorCheck

  if([int]$resp.StatusCode -lt 200 -or [int]$resp.StatusCode -ge 300){
    throw "Anthropic API HTTP $([int]$resp.StatusCode): $($resp.Content)"
  }

  $r=$resp.Content|ConvertFrom-Json
  $call=@($r.content | Where-Object { $_.type -eq 'tool_use' -and $_.name -eq $name } | Select-Object -First 1)
  if($call.Count -ne 1){ throw "Anthropic returned no unique matching tool_use block for '$name'" }
  $call[0].input
}

function Invoke-ReviewModel([string]$instructions,[object]$payload,[string]$name,[object]$schema){
  switch("$($Config.ReviewProvider)"){
    'openai' { Invoke-OpenAIStructured $instructions $payload $name $schema }
    'anthropic' { Invoke-ClaudeStructured $instructions $payload $name $schema }
    default { throw "Unsupported SITEBOSS_REVIEW_PROVIDER '$($Config.ReviewProvider)'. Allowed: openai, anthropic" }
  }
}

function Get-ReviewSchema {
  @{
    type='object'
    additionalProperties=$false
    required=@('verdict','summary','findings','required_actions')
    properties=@{
      verdict=@{type='string';enum=@('PASS','FAIL','NEEDS_EVIDENCE')}
      summary=@{type='string'}
      findings=@{
        type='array'
        items=@{
          type='object'
          additionalProperties=$false
          required=@('severity','title','evidence','path')
          properties=@{
            severity=@{type='string';enum=@('BLOCKER','HIGH','MEDIUM','LOW','INFO')}
            title=@{type='string'}
            evidence=@{type='string'}
            path=@{type='string'}
          }
        }
      }
      required_actions=@{type='array';items=@{type='string'}}
    }
  }
}

function Get-LatestIntegrationAuthority($token,[int]$pr){
  $comments=@()
  $page=1
  while($true){
    $batch=@(GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)/comments?per_page=100&page=$page" $token)
    $comments += $batch
    if($batch.Count -lt 100){ break }
    $page++
    if($page -gt 20){ throw 'Control-comment pagination exceeded safety bound' }
  }

  $matches=@()
  foreach($c in $comments){
    if("$($c.body)" -notmatch 'API_INTEGRATION_AUTHORITY_SCHEMA:\s*1'){ continue }
    if("$($c.body)" -notmatch '(?s)API_INTEGRATION_AUTHORITY_JSON\s*```json\s*(\{.*?\})\s*```'){ continue }
    try {
      $a=$Matches[1]|ConvertFrom-Json
      if([int]$a.pr_number -eq $pr){
        $matches+=@{comment=$c;authority=$a}
      }
    } catch {}
  }
  if($matches.Count -eq 0){ return $null }
  $matches|Sort-Object {[DateTimeOffset]$_.comment.created_at} -Descending|Select-Object -First 1
}

function Assert-AuthorityMatches($authority,[int]$pr,[string]$head,[string]$base,[string]$main,[int]$controlVersion){
  if($null -eq $authority){ throw 'No explicit API_INTEGRATION_AUTHORITY_SCHEMA: 1 authority exists for this PR' }
  $a=$authority.authority
  if("$($a.action)" -ne 'MERGE'){ throw "Authority action is not MERGE: $($a.action)" }
  if([int]$a.pr_number -ne $pr){ throw 'Authority PR number mismatch' }
  if("$($a.head_sha)" -ne $head){ throw 'Authority head SHA mismatch' }
  if("$($a.base_sha)" -ne $base){ throw 'Authority base SHA mismatch' }
  if("$($a.expected_main_sha)" -ne $main){ throw 'Authority expected main SHA mismatch' }
  if([int]$a.control_version -ne $controlVersion){ throw 'Authority control version mismatch' }
  if("$($a.merge_method)" -notin @('squash','merge','rebase')){ throw 'Authority merge_method must be squash, merge, or rebase' }
  if(Get-OptionalProperty $a 'expires_at'){
    $expires=[DateTimeOffset]::Parse("$($a.expires_at)")
    if([DateTimeOffset]::UtcNow -ge $expires){ throw "Integration authority expired at $expires" }
  }
  $a
}

try {
  if($PSVersionTable.PSVersion.Major -lt 7){ throw 'PowerShell 7+ required' }
  if(-not (Get-Command git -ErrorAction SilentlyContinue)){ throw 'Git for Windows is required' }

  if("$($Config.ReviewProvider)" -notin @('openai','anthropic')){
    throw "Unsupported SITEBOSS_REVIEW_PROVIDER '$($Config.ReviewProvider)'. Allowed: openai, anthropic"
  }
  Write-Host ("Independent review provider: {0}" -f $Config.ReviewProvider) -ForegroundColor DarkGray

  Write-Host "`nSITEBOSS AUTOPILOT REVIEWER Repair Rat v0.5-smokescreen" -ForegroundColor Cyan
  if($ReviewMode -eq 'child'){
    Write-Host 'INDEPENDENT CHILD-REPAIR REVIEW - exact parent/base/head binding -> review-only verdict.' -ForegroundColor DarkGray
  }else{
    Write-Host 'INDEPENDENT INTEGRATION GATE - verify exact PR -> AI review -> authority-gated merge.' -ForegroundColor DarkGray
  }
  Write-Host "Target PR: #$PullRequest" -ForegroundColor DarkGray

  $auth=New-GitHubInstallationToken
  if(-not $auth.token){ throw 'No GitHub installation token' }
  Assert-ReadPermissions $auth
  $token=$auth.token

  $control=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)" $token
  $integration=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.IntegrationIssue)" $token
  $ownerCommand=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.OwnerCommandIssue)" $token
  $controlVersion=Get-ControlVersion "$($control.body)"

  $mainRef=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/ref/heads/main" $token
  $mainSha="$($mainRef.object.sha)"
  $recordedMain=Get-RecordedMain "$($control.body)"
  if($recordedMain -and $recordedMain -ne $mainSha){ throw "#233/main drift: board=$recordedMain live=$mainSha" }

  $pr=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$PullRequest" $token
  $prState=Get-OptionalProperty $pr 'state'
  $prHead=Get-OptionalProperty $pr 'head'
  $prBase=Get-OptionalProperty $pr 'base'
  if($null -eq $prHead -or $null -eq $prBase){ throw "PR #$PullRequest response is missing head/base detail" }
  $prHeadRef=Get-OptionalProperty $prHead 'ref'
  $prHeadSha=Get-OptionalProperty $prHead 'sha'
  $prBaseRef=Get-OptionalProperty $prBase 'ref'
  $prBaseSha=Get-OptionalProperty $prBase 'sha'
  if("$prState" -ne 'open'){ throw "PR #$PullRequest is not open" }
  if([string]::IsNullOrWhiteSpace("$prHeadSha") -or [string]::IsNullOrWhiteSpace("$prBaseSha")){ throw "PR #$PullRequest response is missing head/base SHA" }

  $headSha="$prHeadSha"
  $baseSha="$prBaseSha"

  if($ReviewMode -eq 'main'){
    if("$prBaseRef" -ne 'main'){ throw "PR #$PullRequest does not target main" }
    if($baseSha -ne $mainSha){ throw "PR #$PullRequest base is stale: PR base=$baseSha current main=$mainSha" }
  }else{
    if([string]::IsNullOrWhiteSpace($ExpectedBaseRef) -or [string]::IsNullOrWhiteSpace($ExpectedBaseSha)){
      throw 'Child review requires ExpectedBaseRef and ExpectedBaseSha'
    }
    if($ParentPullRequest -le 0){ throw 'Child review requires ParentPullRequest' }
    if("$prBaseRef" -ne $ExpectedBaseRef){ throw "Child PR #$PullRequest base ref mismatch: expected '$ExpectedBaseRef', got '$prBaseRef'" }
    if("$baseSha" -ne $ExpectedBaseSha){ throw "Child PR #$PullRequest base SHA mismatch: expected $ExpectedBaseSha, got $baseSha" }

    $parentPr=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$ParentPullRequest" $token
    $parentState=Get-OptionalProperty $parentPr 'state'
    $parentHead=Get-OptionalProperty $parentPr 'head'
    if("$parentState" -ne 'open' -or $null -eq $parentHead){ throw "Parent PR #$ParentPullRequest is not open or lacks head detail" }
    $parentHeadRef=Get-OptionalProperty $parentHead 'ref'
    $parentHeadSha=Get-OptionalProperty $parentHead 'sha'
    if("$parentHeadRef" -ne $ExpectedBaseRef -or "$parentHeadSha" -ne $ExpectedBaseSha){
      throw "Parent PR #$ParentPullRequest moved before child review"
    }
  }

  $mergeable=Get-OptionalProperty $pr 'mergeable'
  $mergeableState=Get-OptionalProperty $pr 'mergeable_state'
  if($ReviewMode -eq 'main' -and $mergeable -ne $true){
    throw "PR #$PullRequest is not presently mergeable (mergeable=$mergeable; state=$mergeableState)"
  }
  if($ReviewMode -eq 'child' -and $mergeable -eq $false){
    throw "Child PR #$PullRequest has a concrete merge conflict (state=$mergeableState)"
  }

  Write-Host "Exact head: $headSha" -ForegroundColor DarkGray
  if($ReviewMode -eq 'main'){
    Write-Host "Exact base/main: $baseSha" -ForegroundColor DarkGray
  }else{
    Write-Host "Exact child base: $prBaseRef @ $baseSha (parent PR #$ParentPullRequest)" -ForegroundColor DarkGray
  }

  if($UseCache -and -not [string]::IsNullOrWhiteSpace($ResultPath) -and (Test-Path -LiteralPath $ResultPath)){
    try {
      $cached=Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
      $cachedProvider=Get-OptionalProperty $cached 'provider'
      $providerMatches=$false
      if(-not [string]::IsNullOrWhiteSpace("$cachedProvider")){
        $providerMatches=("$cachedProvider" -eq "$($Config.ReviewProvider)")
      }elseif("$($Config.ReviewProvider)" -eq 'openai'){
        # Legacy caches from alpha1-alpha14 were OpenAI-only. Reuse them only for OpenAI.
        $providerMatches=$true
      }

      $cachedMode=Get-OptionalProperty $cached 'review_mode'
      if([string]::IsNullOrWhiteSpace("$cachedMode")){ $cachedMode='main' }
      $modeMatches=("$cachedMode" -eq "$ReviewMode")
      $parentMatches=$true
      if($ReviewMode -eq 'child'){
        $cachedParent=Get-OptionalProperty $cached 'parent_pr'
        $parentMatches=([int]$cachedParent -eq $ParentPullRequest)
      }

      if($providerMatches -and $modeMatches -and $parentMatches -and "$($cached.pr_number)" -eq "$PullRequest" -and "$($cached.head_sha)" -eq $headSha -and "$($cached.base_sha)" -eq $baseSha -and "$($cached.verdict)" -in @('PASS','FAIL','NEEDS_EVIDENCE')){
        Write-Host ("REVIEW CACHE HIT: provider={0}; mode={1}; exact head {2}; verdict={3}" -f $Config.ReviewProvider,$ReviewMode,$headSha,$cached.verdict) -ForegroundColor Green
        exit 0
      }
    } catch {
      Write-Host 'Existing review cache was unreadable; performing a fresh review.' -ForegroundColor DarkYellow
    }
  }

  Write-Host 'Reading exact checks and GitHub reviews...' -ForegroundColor Yellow
  Write-Host 'GitHub evidence read: check-runs...' -ForegroundColor DarkGray
  $checks=Get-CheckEvidence $headSha $token
  Assert-ChecksGreen $checks
  Write-Host 'GitHub evidence read: pull-request reviews...' -ForegroundColor DarkGray
  $reviews=@(Get-ReviewEvidence $PullRequest $token)
  Write-Host ("Checks green. GitHub review records: {0}" -f $reviews.Count) -ForegroundColor DarkGray

  Write-Host 'Creating exact read-only PR snapshot...' -ForegroundColor Yellow
  $snapshot=New-ReviewSnapshot $baseSha $headSha $token
  $changed=@(Get-ChangedFiles $snapshot.Repo $baseSha $headSha)
  $diff=Get-Diff $snapshot.Repo $baseSha $headSha
  Write-Host ("Snapshot OK. Changed files: {0}; diff chars: {1}" -f $changed.Count,$diff.Length) -ForegroundColor DarkGray

  $reviewInstructions=@"
You are an independent SiteBoss integration reviewer. You did NOT author this PR.
Review mode: $ReviewMode.
When review mode is child, this is a bounded repair child targeting another PR branch, NOT main.
Review only the supplied exact frozen diff and governance evidence.
Find concrete correctness, regression, security/privacy, data-integrity, test-coverage, and contract-compliance problems.
Do not approve based on prior prose claims. Bind every finding to supplied evidence.
PASS only when no BLOCKER/HIGH/MEDIUM defect is supported and the exact-head evidence is adequate.
NEEDS_EVIDENCE when the diff cannot be safely evaluated from supplied evidence.
You do not have merge, deploy, owner-setting, provider/customer, financial, or self-approval authority.
"@
  $reviewInput=@{
    pr=@{
      number=$PullRequest
      review_mode=$ReviewMode
      parent_pr=$(if($ReviewMode -eq 'child'){$ParentPullRequest}else{0})
      title="$($pr.title)"
      body="$($pr.body)"
      head_sha=$headSha
      base_sha=$baseSha
      mergeable=$mergeable
      mergeable_state="$mergeableState"
    }
    changed_files=$changed
    checks=$checks
    github_reviews=$reviews
    integration_gate=@{number=$Config.IntegrationIssue;body="$($integration.body)"}
    owner_command=@{number=$Config.OwnerCommandIssue;body="$($ownerCommand.body)"}
    live_control=@{version=$controlVersion;body="$($control.body)";main_sha=$mainSha}
  }

  Write-Host 'Running bounded independent GPT-5.6 integration review...' -ForegroundColor Yellow
  $aiReview=Invoke-MultiPassReview $reviewInput $diff $reviewInstructions

  Write-Host "`nINDEPENDENT REVIEW: $($aiReview.verdict)" -ForegroundColor Cyan
  Write-Host "$($aiReview.summary)"
  foreach($f in @($aiReview.findings)){
    Write-Host ("- [{0}] {1} ({2})" -f $f.severity,$f.title,$f.path)
  }

  if(-not [string]::IsNullOrWhiteSpace($ResultPath)){
    $resultDir=Split-Path -Parent $ResultPath
    if($resultDir){ New-Item -ItemType Directory -Force -Path $resultDir | Out-Null }
    $diffHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($diff))).ToLowerInvariant()
    $result=@{
      schema=1
      source='siteboss-autopilot-reviewer'
      review_mode=$ReviewMode
      parent_pr=$(if($ReviewMode -eq 'child'){$ParentPullRequest}else{0})
      provider="$($Config.ReviewProvider)"
      model=$(if($Config.ReviewProvider -eq 'openai'){$Config.Model}else{$Config.AnthropicModel})
      reviewed_at=[DateTimeOffset]::UtcNow.ToString('o')
      pr_number=$PullRequest
      title="$($pr.title)"
      head_ref="$prHeadRef"
      head_sha=$headSha
      base_ref="$prBaseRef"
      base_sha=$baseSha
      main_sha=$mainSha
      control_version=$controlVersion
      diff_sha256=$diffHash
      verdict="$($aiReview.verdict)"
      summary="$($aiReview.summary)"
      findings=@($aiReview.findings)
      required_actions=@($aiReview.required_actions)
    }
    $result | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    Write-Host "Review evidence saved: $ResultPath" -ForegroundColor DarkGray
  }

  if("$($aiReview.verdict)" -ne 'PASS'){
    Write-Host "`nINTEGRATION BLOCKED" -ForegroundColor Yellow
    foreach($a in @($aiReview.required_actions)){ Write-Host "- $a" }
    Write-Host 'Nothing was changed on GitHub.'
    exit 0
  }

  if($ReviewOnly){
    Write-Host "`nREVIEW-ONLY PASS" -ForegroundColor Green
    Write-Host 'No merge or GitHub mutation was attempted by the reviewer.'
    exit 0
  }

  # Re-read state AFTER AI review so authority can never apply to a moved PR/main/control.
  Write-Host "`nRevalidating exact live state after review..." -ForegroundColor Yellow
  $control2=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)" $token
  $controlVersion2=Get-ControlVersion "$($control2.body)"
  $mainRef2=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/ref/heads/main" $token
  $mainSha2="$($mainRef2.object.sha)"
  $pr2=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$PullRequest" $token

  if($controlVersion2 -ne $controlVersion){ throw "Control moved during review: $controlVersion -> $controlVersion2" }
  if($mainSha2 -ne $mainSha){ throw "main moved during review: $mainSha -> $mainSha2" }
  $pr2Head=Get-OptionalProperty $pr2 'head'
  $pr2Base=Get-OptionalProperty $pr2 'base'
  if($null -eq $pr2Head -or $null -eq $pr2Base){ throw 'PR response lost head/base detail during review' }
  $pr2HeadSha=Get-OptionalProperty $pr2Head 'sha'
  $pr2BaseSha=Get-OptionalProperty $pr2Base 'sha'
  if("$pr2HeadSha" -ne $headSha){ throw "PR head moved during review: $headSha -> $pr2HeadSha" }
  if("$pr2BaseSha" -ne $baseSha){ throw "PR base moved during review" }
  if((Get-OptionalProperty $pr2 'mergeable') -ne $true){ throw 'PR is no longer mergeable after review' }

  $checks2=Get-CheckEvidence $headSha $token
  Assert-ChecksGreen $checks2

  $authority=Get-LatestIntegrationAuthority $token $PullRequest
  if($null -eq $authority){
    Write-Host "`nREADY FOR EXPLICIT INTEGRATION AUTHORITY" -ForegroundColor Green
    Write-Host "PR #$PullRequest independently passed at exact head $headSha."
    Write-Host 'No API_INTEGRATION_AUTHORITY_SCHEMA: 1 record exists on #233, so v0.6.4 will not merge.'
    Write-Host 'Nothing was changed on GitHub.'
    exit 0
  }

  $a=Assert-AuthorityMatches $authority $PullRequest $headSha $baseSha $mainSha $controlVersion
  Assert-MergePermissions $auth

  Write-Host "`nEXPLICIT INTEGRATION AUTHORITY VERIFIED" -ForegroundColor Green
  Write-Host "Merge method: $($a.merge_method)"
  Write-Host 'Performing one exact-head GitHub merge...' -ForegroundColor Yellow

  $merge=GHPut "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$PullRequest/merge" $token @{
    sha=$headSha
    merge_method="$($a.merge_method)"
  }

  if(-not $merge.merged){ throw "GitHub refused merge: $($merge.message)" }

  $mainAfter=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/ref/heads/main" $token
  Write-Host "`nINTEGRATION COMPLETE" -ForegroundColor Green
  Write-Host "PR #$PullRequest merged from exact head $headSha."
  Write-Host "New main: $($mainAfter.object.sha)"
  Write-Host 'Controller must refresh live state before issuing any new coding packet.'
}
catch {
  Write-Host "`nSITEBOSS INTEGRATION GATE v0.6.4 FAILED CLOSED" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  exit 1
}
