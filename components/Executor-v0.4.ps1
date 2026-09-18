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
  Model="gpt-5.6"
  ControlIssue=233
  WorkspaceRoot=(Join-Path $env:USERPROFILE ".siteboss\worker-engine\workspaces")
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
function GHPost($path,$token,$body){ Invoke-GovernedGitHubJson -Method POST -Url "https://api.github.com$path" -Headers (GHHeaders $token) -Body $body -CacheTtlMs 0 }

function Get-LatestPacket($token){
  # Keep v0.3 semantics: newest matching comment from the current first 100 comments returned by GitHub.
  # If #233 ever exceeds this packet transport, controller should publish a dedicated packet issue/API endpoint.
  $comments=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)/comments?per_page=100&sort=created&direction=desc" $token
  $matches=@($comments | Where-Object { $_.body -match 'API_EXECUTABLE_PACKET_SCHEMA:\s*1' })
  if($matches.Count -eq 0){ return $null }
  $matches | Sort-Object {[DateTimeOffset]$_.created_at} -Descending | Select-Object -First 1
}

function Parse-Packet($body){
  if($body -notmatch '(?s)API_EXECUTABLE_PACKET_JSON\s*```json\s*(\{.*?\})\s*```'){
    throw "Packet found, but no machine-readable API_EXECUTABLE_PACKET_JSON block exists."
  }
  $Matches[1] | ConvertFrom-Json
}

function Assert-RelativeRepoPath([string]$path){
  if([string]::IsNullOrWhiteSpace($path)){ throw "Empty repository path" }
  if([IO.Path]::IsPathRooted($path)){ throw "Absolute repository path refused: $path" }
  $norm=$path.Replace('\\','/')
  if($norm -match '(^|/)\.\.(/|$)'){ throw "Parent traversal refused: $path" }
  if($norm -match '(^|/)\.git(/|$)'){ throw ".git mutation refused: $path" }
  if($norm.StartsWith('/')){ throw "Rooted repository path refused: $path" }
  $norm
}

function Test-PathMatchesRule([string]$path,[string]$rule){
  $p=$path.Replace('\\','/')
  $r=$rule.Replace('\\','/')
  if($r -match '[*?\[]'){ return $p -like $r }
  return $p -eq $r
}

function Assert-Packet($p,$token){
  $required=@("packet_id","control_version","purpose","target_issue","base_ref","base_sha","branch","path_allowlist","path_denylist","lease_id","definition_of_done","focused_test_commands","full_test_commands","stop_boundary")
  foreach($k in $required){
    if(-not $p.PSObject.Properties.Name.Contains($k) -or $null -eq $p.$k -or ("$($p.$k)" -eq "")){ throw "Packet missing required field: $k" }
  }
  if($p.base_ref -ne "main"){ throw "base_ref must be main" }
  if($p.base_sha -notmatch '^[0-9a-f]{40}$'){ throw "Invalid base_sha" }
  if($p.branch -eq "main" -or $p.branch -match '^refs/heads/main$'){ throw "Refusing main branch" }
  if($p.branch -notmatch '^[A-Za-z0-9._/-]+$' -or $p.branch -match '\.\.' -or $p.branch.StartsWith('/') -or $p.branch.EndsWith('/')){ throw "Unsafe branch name: $($p.branch)" }
  if(@($p.path_allowlist).Count -lt 1){ throw "Empty path allowlist" }
  foreach($rule in @($p.path_allowlist)){ [void](Assert-RelativeRepoPath "$rule") }
  foreach($rule in @($p.path_denylist)){ [void](Assert-RelativeRepoPath "$rule") }
  if(@($p.focused_test_commands).Count -lt 1){ throw "At least one focused test command is required" }
  if(@($p.full_test_commands).Count -lt 1){ throw "At least one full test command is required" }

  $main=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/ref/heads/main" $token
  if($main.object.sha -ne $p.base_sha){ throw "STALE PACKET: main is $($main.object.sha), packet base is $($p.base_sha)" }
  $issue=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)" $token
  if($issue.body -notmatch "CONTROL_VERSION:\s*$($p.control_version)(\D|$)"){ throw "STALE PACKET: control version no longer current" }

  # A packet must contain an explicit non-empty stop boundary. This remains an executor, never an orchestrator/merger.
  if([string]::IsNullOrWhiteSpace("$($p.stop_boundary)")){ throw "Missing stop_boundary" }
}

function Assert-GitHubWritePermissions($tokenResponse){
  $perms=$tokenResponse.permissions
  $contents = if($perms.PSObject.Properties.Name -contains 'contents'){ "$($perms.contents)" } else { "none" }
  $pulls = if($perms.PSObject.Properties.Name -contains 'pull_requests'){ "$($perms.pull_requests)" } else { "none" }
  if($contents -ne 'write'){ throw "GitHub App needs Contents: Read and write for v0.4 branch push. Current: $contents" }
  if($pulls -ne 'write'){ throw "GitHub App needs Pull requests: Read and write for v0.4 draft PR creation. Current: $pulls" }
}

function New-AskPass([string]$dir){
  $path=Join-Path $dir "git-askpass.cmd"
  @'
@echo off
set prompt=%~1
echo %prompt% | findstr /I "Username" >nul
if not errorlevel 1 (echo x-access-token& exit /b 0)
echo %SITEBOSS_GITHUB_TOKEN%
'@ | Set-Content -LiteralPath $path -Encoding ASCII
  $path
}

function Invoke-Git([string[]]$commandArgsLocal,[string]$workingDir=$null,[switch]$Capture){
  $display=($commandArgsLocal -join ' ')
  if($display -match 'gh[opsu]_[A-Za-z0-9_]+' -or $display -match 'x-access-token:'){ throw "Internal token exposure prevented" }
  $old=$ErrorActionPreference
  try {
    $ErrorActionPreference='Continue'
    if($workingDir){ Push-Location $workingDir }
    if($Capture){
      $out=& git @args 2>&1
      $code=$LASTEXITCODE
      if($code -ne 0){ throw "git $($commandArgsLocal[0]) failed ($code): $($out -join ' ')" }
      return ($out -join "`n").Trim()
    } else {
      & git @args
      $code=$LASTEXITCODE
      if($code -ne 0){ throw "git $($commandArgsLocal[0]) failed with exit code $code" }
    }
  } finally {
    if($workingDir){ Pop-Location }
    $ErrorActionPreference=$old
  }
}

function New-IsolatedCheckout($p,$token){
  New-Item -ItemType Directory -Force -Path $Config.WorkspaceRoot | Out-Null
  $safeId=("$($p.packet_id)" -replace '[^A-Za-z0-9._-]','_')
  $runId=[DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')
  $dir=Join-Path $Config.WorkspaceRoot "$safeId-$runId"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $ask=New-AskPass $dir
  $env:SITEBOSS_GITHUB_TOKEN=$token
  $env:GIT_ASKPASS=$ask
  $env:GIT_TERMINAL_PROMPT='0'
  try {
    $repoDir=Join-Path $dir 'repo'
    Invoke-Git @('clone','--no-checkout','--filter=blob:none',"https://github.com/$($Config.Owner)/$($Config.Repo).git",$repoDir)
    Invoke-Git @('fetch','--no-tags','origin',$p.base_sha) $repoDir
    Invoke-Git @('checkout','--detach',$p.base_sha) $repoDir
    $actual=Invoke-Git @('rev-parse','HEAD') $repoDir -Capture
    if($actual -ne $p.base_sha){ throw "Checkout mismatch: $actual" }
    Invoke-Git @('checkout','-b',$p.branch) $repoDir
    Invoke-Git @('config','user.name','SiteBoss Worker Engine') $repoDir
    Invoke-Git @('config','user.email','siteboss-worker-engine@users.noreply.github.com') $repoDir
    return @{Root=$dir;Repo=$repoDir;AskPass=$ask}
  } finally {
    # Never leave GitHub credentials in the process environment while model-authored code/tests run.
    Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue
  }
}

function Get-AllowlistedFiles($p,[string]$repoDir){
  $result=@()
  foreach($rule in @($p.path_allowlist)){
    if("$rule" -match '[*?\[]'){ throw "v0.4 requires exact file paths; globs are not accepted yet: $rule" }
    $path=Assert-RelativeRepoPath "$rule"
    $full=Join-Path $repoDir $path
    if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ throw "Allowlisted file does not exist at base SHA: $path" }
    $txt=Get-Content -LiteralPath $full -Raw
    $result+=@{path=$path;content=$txt}
  }
  $result
}

function Ask-ForPatch($p,[string]$repoDir){
  $key=[Environment]::GetEnvironmentVariable("OPENAI_API_KEY","User")
  if(-not $key){ $key=$env:OPENAI_API_KEY }
  if(-not $key){ throw "OPENAI_API_KEY missing" }

  $files=Get-AllowlistedFiles $p $repoDir
  $instructions=@"
You are a bounded SiteBoss coding worker. You are editing an isolated checkout at an exact controller-authorised base commit.
Modify ONLY supplied allowlisted files. Never invent additional paths.
Do not weaken tenant isolation, permissions, auditability, idempotency, concurrency, restart/recovery, financial integrity, approval gates, or tests.
Do not merge, deploy, approve, change settings/secrets/permissions, or perform customer/provider/financial actions.
Implement only the packet purpose and Definition of Done. If safe completion requires another path, dependency, permission, migration, generated artifact, or broader scope, return blocked=true with files=[].
For every changed file return its COMPLETE replacement UTF-8 content. Omit unchanged files.
"@

  $schema=@{
    type='object'; additionalProperties=$false
    properties=@{
      summary=@{type='string'}
      files=@{type='array';items=@{type='object';additionalProperties=$false;properties=@{path=@{type='string'};content=@{type='string'}};required=@('path','content')}}
      test_notes=@{type='array';items=@{type='string'}}
      blocked=@{type='boolean'}
      block_reason=@{type=@('string','null')}
    }
    required=@('summary','files','test_notes','blocked','block_reason')
  }
  $payloadJson=@{packet=$p;files=$files}|ConvertTo-Json -Depth 50
  $body=@{
    model=$Config.Model
    instructions=$instructions
    input=$payloadJson
    text=@{format=@{type='json_schema';name='siteboss_bounded_patch';strict=$true;schema=$schema}}
  }|ConvertTo-Json -Depth 50
  $headers=@{Authorization="Bearer $key";"Content-Type"="application/json"}
  $r=Invoke-RestMethod -Method Post -Uri "https://api.openai.com/v1/responses" -Headers $headers -Body $body
  if($r.status -and $r.status -ne 'completed'){ throw "OpenAI response status: $($r.status)" }
  $txt=@()
  foreach($i in @($r.output)){ foreach($c in @($i.content)){ if($c.type -eq 'output_text'){ $txt+=$c.text } } }
  if($txt.Count -eq 0){ throw "OpenAI returned no output_text" }
  ($txt -join "`n")|ConvertFrom-Json
}

function Apply-Proposal($proposal,$p,[string]$repoDir){
  if($proposal.blocked){
    if(@($proposal.files).Count -ne 0){ throw "Blocked model response must not contain file changes" }
    return
  }
  if(@($proposal.files).Count -eq 0){ throw "Model returned no changed files" }
  $seen=@{}
  foreach($f in @($proposal.files)){
    $path=Assert-RelativeRepoPath "$($f.path)"
    if($seen.ContainsKey($path)){ throw "Duplicate model file path: $path" }
    $seen[$path]=$true
    $allowed=$false
    foreach($rule in @($p.path_allowlist)){ if(Test-PathMatchesRule $path "$rule"){ $allowed=$true; break } }
    if(-not $allowed){ throw "Model attempted path outside allowlist: $path" }
    foreach($rule in @($p.path_denylist)){ if(Test-PathMatchesRule $path "$rule"){ throw "Model attempted denylisted path: $path" } }
    $full=Join-Path $repoDir $path
    $parent=Split-Path -Parent $full
    if(-not (Test-Path -LiteralPath $parent)){ throw "Model attempted to create path outside existing allowed tree: $path" }
    [IO.File]::WriteAllText($full,"$($f.content)",(New-Object Text.UTF8Encoding($false)))
  }
}

function Get-ChangedPaths([string]$repoDir){
  $raw=Invoke-Git @('status','--porcelain=v1','-z') $repoDir -Capture
  if([string]::IsNullOrEmpty($raw)){ return @() }
  # git output captured through PowerShell loses NUL reliably on some hosts; use name-only diff + untracked explicitly.
  $tracked=(Invoke-Git @('diff','--name-only','HEAD') $repoDir -Capture) -split "`n" | Where-Object { $_ }
  $untracked=(Invoke-Git @('ls-files','--others','--exclude-standard') $repoDir -Capture) -split "`n" | Where-Object { $_ }
  @($tracked + $untracked | Sort-Object -Unique)
}

function Assert-ChangedPaths($paths,$p){
  if(@($paths).Count -eq 0){ throw "No repository changes produced" }
  foreach($path in @($paths)){
    [void](Assert-RelativeRepoPath $path)
    $allowed=$false
    foreach($rule in @($p.path_allowlist)){ if(Test-PathMatchesRule $path "$rule"){ $allowed=$true; break } }
    if(-not $allowed){ throw "Changed path outside packet allowlist: $path" }
    foreach($rule in @($p.path_denylist)){ if(Test-PathMatchesRule $path "$rule"){ throw "Changed denylisted path: $path" } }
  }
}

function New-TestSandbox($p){
  if(-not (Get-Command docker -ErrorAction SilentlyContinue)){ throw "Docker Desktop is required for v0.4 test isolation" }
  & docker info *> $null
  if($LASTEXITCODE -ne 0){ throw "Docker Desktop is installed but not running" }
  $safe=("sbwe_$($p.packet_id)_$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" -replace '[^A-Za-z0-9_.-]','_').ToLowerInvariant()
  & docker volume create $safe *> $null
  if($LASTEXITCODE -ne 0){ throw "Could not create Docker test volume" }
  $safe
}

function Remove-TestSandbox([string]$volume){
  if($volume){ & docker volume rm -f $volume *> $null }
}

function Install-DependenciesInSandbox([string]$repoDir,[string]$volume){
  $pkg=Join-Path $repoDir 'package.json'
  $lock=Join-Path $repoDir 'package-lock.json'
  if(-not ((Test-Path -LiteralPath $pkg) -and (Test-Path -LiteralPath $lock))){
    throw "v0.4 currently requires package.json + package-lock.json for deterministic dependency setup"
  }
  Write-Host "Preparing locked dependencies from untouched base commit in isolated Node container..." -ForegroundColor DarkGray
  & docker run --rm --mount "type=bind,src=$repoDir,dst=/workspace,readonly" --mount "type=volume,src=$volume,dst=/workspace/node_modules" -w /workspace node:22-bookworm npm ci --ignore-scripts --no-audit --no-fund
  if($LASTEXITCODE -ne 0){ throw "Sandbox npm ci --ignore-scripts failed with exit code $LASTEXITCODE" }
}

function Assert-SafeTestCommand([string]$command){
  if([string]::IsNullOrWhiteSpace($command)){ throw "Empty test command" }
  if($command -match '[;&|><`\r\n]'){ throw "Unsafe shell control character in test command: $command" }
  if($command -notmatch '^\s*(npm(\.cmd)?\s+(test|run\s+[A-Za-z0-9:_-]+)|node(\.exe)?\s+--test\b)'){
    throw "Unsupported test command in v0.4: $command"
  }
}

function Split-SafeCommand([string]$command){
  $parseErrors=$null
  $tokens=[Management.Automation.PSParser]::Tokenize($command,[ref]$parseErrors) | Where-Object { $_.Type -in @('Command','CommandArgument','String','Number') } | ForEach-Object { $_.Content }
  if($parseErrors -or $tokens.Count -lt 1){ throw "Could not safely parse test command: $command" }
  @($tokens)
}

function Invoke-TestCommand([string]$command,[string]$repoDir,[string]$volume,[string]$logPath){
  Assert-SafeTestCommand $command
  $parts=@(Split-SafeCommand $command)
  $exe=$parts[0]
  if($exe -eq 'npm.cmd'){ $exe='npm' }
  if($exe -eq 'node.exe'){ $exe='node' }
  $commandArgsLocal=@(); if($parts.Count -gt 1){ $commandArgsLocal=@($parts[1..($parts.Count-1)]) }
  Write-Host "TEST[sandbox/no-network]> $command" -ForegroundColor Cyan
  $dockerArgs=@(
    'run','--rm','--network','none',
    '--mount',"type=bind,src=$repoDir,dst=/workspace",
    '--mount',"type=volume,src=$volume,dst=/workspace/node_modules",
    '-w','/workspace','node:22-bookworm',$exe
  ) + $commandArgsLocal
  & docker @dockerArgs *>&1 | Tee-Object -FilePath $logPath -Append
  $code=$LASTEXITCODE
  if($code -ne 0){ throw "Sandbox test failed ($code): $command" }
}

function Run-Tests($p,[string]$repoDir,[string]$root,[string]$volume){
  $log=Join-Path $root 'test-output.log'
  "SiteBoss Worker Engine v0.4 test evidence`npacket=$($p.packet_id)`nbase=$($p.base_sha)`nsandbox=docker-network-none`n" | Set-Content -LiteralPath $log -Encoding UTF8
  foreach($cmd in @($p.focused_test_commands)){ Invoke-TestCommand "$cmd" $repoDir $volume $log }
  foreach($cmd in @($p.full_test_commands)){ Invoke-TestCommand "$cmd" $repoDir $volume $log }
  $log
}

function Revalidate-BeforePublish($p,$token){
  $main=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/ref/heads/main" $token
  if($main.object.sha -ne $p.base_sha){ throw "PUBLISH ABORTED: main moved to $($main.object.sha)" }
  $issue=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/issues/$($Config.ControlIssue)" $token
  if($issue.body -notmatch "CONTROL_VERSION:\s*$($p.control_version)(\D|$)"){ throw "PUBLISH ABORTED: control version moved" }
  try {
    $existing=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/ref/heads/$($p.branch)" $token
    if($existing){ throw "PUBLISH ABORTED: remote branch already exists: $($p.branch)" }
  } catch {
    $msg=$_.Exception.Message
    if($msg -notmatch '404'){ throw }
  }
}

function Publish-DraftPR($p,[string]$repoDir,$token,[string]$askPass,[string[]]$changedPaths,[string]$summary){
  Revalidate-BeforePublish $p $token
  Invoke-Git @('add','--all') $repoDir
  $commitMsg="worker: $($p.packet_id)"
  Invoke-Git @('commit','-m',$commitMsg) $repoDir
  $head=Invoke-Git @('rev-parse','HEAD') $repoDir -Capture
  if($head -notmatch '^[0-9a-f]{40}$'){ throw "Could not resolve committed head" }

  $env:SITEBOSS_GITHUB_TOKEN=$token
  $env:GIT_ASKPASS=$askPass
  $env:GIT_TERMINAL_PROMPT='0'
  try { Invoke-GovernedGitPush -WorkingDirectory $repoDir -Remote 'origin' -RefSpec "HEAD:refs/heads/$($p.branch)" -ExtraArgs @('--set-upstream') | Out-Null }
  finally {
    Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue
  }

  $body=@"
## SiteBoss Worker Engine v0.4

Controller packet: `$($p.packet_id)`  
Control version: `$($p.control_version)`  
Base: `$($p.base_sha)`  
Executor commit: `$head`

### Purpose
$($p.purpose)

### Executor summary
$summary

### Changed paths
$($changedPaths | ForEach-Object { "- ``$_``" } | Out-String)
### Validation
All controller-specified focused and full test commands passed locally in the isolated checkout before publication.

### Safety boundary
Draft only. No merge, deployment, approval, settings/secrets/permissions, customer/provider or financial action was performed. Independent exact-head review remains required.
"@
  $pr=GHPost "/repos/$($Config.Owner)/$($Config.Repo)/pulls" $token @{title="[API worker] $($p.purpose)";head=$p.branch;base='main';body=$body;draft=$true}
  @{PR=$pr;Head=$head}
}

try {
  if($PSVersionTable.PSVersion.Major -lt 7){ throw "PowerShell 7+ required" }
  if(-not (Get-Command git -ErrorAction SilentlyContinue)){ throw "Git for Windows is required" }

  Write-Host "`nSITEBOSS WORKER ENGINE v0.4" -ForegroundColor Cyan
  Write-Host "API CODING EXECUTOR - packet -> isolated checkout -> tests -> branch -> DRAFT PR." -ForegroundColor DarkGray

  $auth=New-GitHubInstallationToken
  if(-not $auth.token){ throw "No GitHub installation token" }
  $token=$auth.token

  Write-Host "`nChecking SiteBoss #233 for an executable packet..." -ForegroundColor Yellow
  $comment=Get-LatestPacket $token
  if(-not $comment){
    Write-Host "`nNO EXECUTABLE PACKET YET" -ForegroundColor Yellow
    Write-Host "The controller has not released a coding packet. Nothing was changed."
    exit 0
  }

  $p=Parse-Packet $comment.body
  Assert-Packet $p $token
  Assert-GitHubWritePermissions $auth
  Write-Host "Valid packet: $($p.packet_id)" -ForegroundColor Green
  Write-Host "Purpose: $($p.purpose)"
  Write-Host "Base: $($p.base_sha)"
  Write-Host "Branch: $($p.branch)"

  Write-Host "`nCreating isolated checkout..." -ForegroundColor Yellow
  $ws=New-IsolatedCheckout $p $token
  $sandboxVolume=$null
  try {
    $sandboxVolume=New-TestSandbox $p
    # Dependency resolution happens before any model-authored file is applied.
    Install-DependenciesInSandbox $ws.Repo $sandboxVolume

    Write-Host "Generating bounded code change through OpenAI API..." -ForegroundColor Yellow
    $proposal=Ask-ForPatch $p $ws.Repo
    if($proposal.blocked){
      Write-Host "`nBLOCKED SAFELY: $($proposal.block_reason)" -ForegroundColor Yellow
      Write-Host "No GitHub branch or PR was created."
      exit 0
    }

    Apply-Proposal $proposal $p $ws.Repo
    $changed=@(Get-ChangedPaths $ws.Repo)
    Assert-ChangedPaths $changed $p
    Write-Host "Changed paths validated: $($changed.Count)" -ForegroundColor Green

    Write-Host "`nRunning controller-required tests..." -ForegroundColor Yellow
    $testLog=Run-Tests $p $ws.Repo $ws.Root $sandboxVolume
    Write-Host "All required tests passed." -ForegroundColor Green

    # Test/setup activity itself must not modify tracked paths outside the packet scope.
    $afterTests=@(Get-ChangedPaths $ws.Repo)
    Assert-ChangedPaths $afterTests $p

    Write-Host "`nRevalidating authority and publishing draft PR..." -ForegroundColor Yellow
    $published=Publish-DraftPR $p $ws.Repo $token $ws.AskPass $afterTests "$($proposal.summary)"

    Write-Host "`nDRAFT PR CREATED" -ForegroundColor Green
    Write-Host "PR #$($published.PR.number): $($published.PR.html_url)"
    Write-Host "Exact head: $($published.Head)"
    Write-Host "Test log: $testLog"
    Write-Host "STOP BOUNDARY REACHED - no merge/review/deploy performed." -ForegroundColor Yellow
  } finally {
    Remove-TestSandbox $sandboxVolume
    Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue
  }
} catch {
  Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue
  Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue
  Write-Host "`nSITEBOSS WORKER ENGINE FAILED CLOSED" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  exit 1
}
