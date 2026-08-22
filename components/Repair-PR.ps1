param(
  [Parameter(Mandatory=$true)][string]$ReviewPath
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Config=@{
  AppId='4608230'
  InstallationId='154040429'
  Owner='1stchoicefnq-afk'
  Repo='siteboss-monster'
  PemPath="$env:USERPROFILE\.siteboss\secrets\github-app-private-key.pem"
  Model=($(if($env:SITEBOSS_OPENAI_MODEL){$env:SITEBOSS_OPENAI_MODEL}else{'gpt-5.6'}))
  AnthropicModel=($(if($env:SITEBOSS_ANTHROPIC_MODEL){$env:SITEBOSS_ANTHROPIC_MODEL}else{'claude-sonnet-5'}))
  # Provider abstraction is live, but OpenAI remains the default.
  # Supported single-provider values: openai | anthropic.
  # Dual/cross-review is intentionally NOT enabled yet.
  Provider=($(if($env:SITEBOSS_REPAIR_PROVIDER){$env:SITEBOSS_REPAIR_PROVIDER.ToLowerInvariant()}else{'openai'}))
  WorkspaceRoot=(Join-Path $env:USERPROFILE '.siteboss\autopilot\case-sensitive-repair-workspaces')
  MaxPlanFiles=6
  MaxSourceChars=180000
  TestImage=($(if($env:SITEBOSS_TEST_IMAGE){$env:SITEBOSS_TEST_IMAGE}else{'node:22-bookworm'}))
  GitUserName='SiteBoss Autopilot'
  GitUserEmail='siteboss-autopilot@users.noreply.github.com'
}

function B64Url([byte[]]$b){[Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')}
function Get-OptionalProperty($o,[string]$n){if($null -eq $o){return $null};$p=$o.PSObject.Properties[$n];if($null -eq $p){return $null};$p.Value}

function New-GitHubInstallationToken{
  if(-not(Test-Path -LiteralPath $Config.PemPath)){throw "GitHub App private key not found: $($Config.PemPath)"}
  $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $h=@{alg='RS256';typ='JWT'}|ConvertTo-Json -Compress
  $p=@{iat=$now-60;exp=$now+540;iss=$Config.AppId}|ConvertTo-Json -Compress
  $u="$(B64Url([Text.Encoding]::UTF8.GetBytes($h))).$(B64Url([Text.Encoding]::UTF8.GetBytes($p)))"
  $rsa=[Security.Cryptography.RSA]::Create()
  try{
    $rsa.ImportFromPem((Get-Content $Config.PemPath -Raw))
    $sig=$rsa.SignData([Text.Encoding]::UTF8.GetBytes($u),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  }finally{$rsa.Dispose()}
  $jwt="$u.$(B64Url $sig)"
  $hdr=@{Authorization="Bearer $jwt";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}
  $body=@{repositories=@($Config.Repo)}|ConvertTo-Json
  Invoke-RestMethod -Method Post -Uri "https://api.github.com/app/installations/$($Config.InstallationId)/access_tokens" -Headers $hdr -ContentType 'application/json' -Body $body
}
function GHHeaders($t){@{Authorization="Bearer $t";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}}
function GHGet($p,$t){Invoke-RestMethod -Uri "https://api.github.com$p" -Headers (GHHeaders $t)}
function GHPost($p,$t,$b){Invoke-RestMethod -Method Post -Uri "https://api.github.com$p" -Headers (GHHeaders $t) -ContentType 'application/json' -Body ($b|ConvertTo-Json -Depth 50)}

function New-AskPass([string]$dir){
  $p=Join-Path $dir 'git-askpass.cmd'
@'
@echo off
set prompt=%~1
echo %prompt% | findstr /I "Username" >nul
if not errorlevel 1 (echo x-access-token& exit /b 0)
echo %SITEBOSS_GITHUB_TOKEN%
'@|Set-Content -LiteralPath $p -Encoding ASCII
  $p
}
function Invoke-GitProcess(
  [Parameter(Mandatory=$true)][string[]]$CommandArgs,
  [string]$WorkingDir=$null,
  [switch]$Capture
){
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

function Assert-GitProcessRunner {
  $temp=Join-Path ([IO.Path]::GetTempPath()) ("siteboss-git-selftest-"+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $temp|Out-Null
  try{
    [string[]]$a=@('init','--quiet',$temp)
    Invoke-GitProcess -CommandArgs $a
    [string[]]$b=@('rev-parse','--is-inside-work-tree')
    $v=Invoke-GitProcess -CommandArgs $b -WorkingDir $temp -Capture
    if("$v" -ne 'true'){throw "Git helper self-test returned unexpected value: $v"}
  }finally{
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Get-CaseSensitiveInfo([string]$path){
  if(-not (Test-Path -LiteralPath $path)){ return $false }
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName='fsutil.exe'
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  [void]$psi.ArgumentList.Add('file')
  [void]$psi.ArgumentList.Add('queryCaseSensitiveInfo')
  [void]$psi.ArgumentList.Add($path)

  $proc=[Diagnostics.Process]::new()
  $proc.StartInfo=$psi
  try{
    if(-not $proc.Start()){ return $false }
    $stdout=$proc.StandardOutput.ReadToEnd()
    $stderr=$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if($proc.ExitCode -ne 0){ return $false }
    return ($stdout -match '(?i)case sensitive attribute on directory .* is enabled|case sensitive attribute.*enabled')
  }finally{$proc.Dispose()}
}

function Assert-CaseSensitiveWorkspaceRoot([string]$path){
  if(-not (Test-Path -LiteralPath $path)){
    throw "Case-sensitive repair workspace root is not prepared: $path. Run PREPARE-SITEBOSS-WORKSPACE.cmd once as Administrator."
  }
  if(-not (Get-CaseSensitiveInfo $path)){
    throw "Repair workspace root is not case-sensitive: $path. Run PREPARE-SITEBOSS-WORKSPACE.cmd once as Administrator."
  }
  Write-Host "Case-sensitive repair workspace root: OK" -ForegroundColor DarkGray
}

function Get-CaseCollisions([string[]]$paths){
  $groups=@{}
  foreach($p in $paths){
    $key="$p".ToLowerInvariant()
    if(-not $groups.ContainsKey($key)){ $groups[$key]=@() }
    $groups[$key]+="$p"
  }
  $out=@()
  foreach($k in $groups.Keys){
    $unique=@($groups[$k] | Select-Object -Unique)
    if($unique.Count -gt 1){ $out += ,$unique }
  }
  $out
}

function Assert-NoUnrepresentableCaseCollision([string]$repo,[string]$sha){
  [string[]]$gitArgs=@('ls-tree','-r','--name-only',$sha)
  $raw=Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo -Capture
  $treePaths=@($raw -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  $collisions=@(Get-CaseCollisions $treePaths)

  if($collisions.Count -gt 0){
    Write-Host ("Git tree contains {0} case-colliding path group(s); case-sensitive workspace is required." -f $collisions.Count) -ForegroundColor DarkYellow
    foreach($g in $collisions){
      Write-Host ("  COLLISION: {0}" -f ($g -join ' <> ')) -ForegroundColor DarkYellow
    }
    if(-not (Get-CaseSensitiveInfo $Config.WorkspaceRoot)){
      throw 'The target Git tree contains paths that collide on a normal Windows filesystem. Prepare the dedicated case-sensitive workspace root before checkout.'
    }
  }
}

function Assert-RepoPath([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){throw 'Empty path'}
  $n=$p.Replace('\','/')
  if([IO.Path]::IsPathRooted($n)-or$n-match'(^|/)\.\.(/|$)'-or$n-match'(^|/)\.git(/|$)'){throw "Unsafe path: $p"}
  $n
}
function Invoke-OpenAI([string]$instructions,[object]$payload,[string]$name,[object]$schema){
  $key=[Environment]::GetEnvironmentVariable('OPENAI_API_KEY','User');if(-not$key){$key=$env:OPENAI_API_KEY};if(-not$key){throw 'OPENAI_API_KEY missing'}
  [string]$inputText=ConvertTo-Json -InputObject $payload -Depth 80 -Compress
  [string]$body=ConvertTo-Json -InputObject @{model=$Config.Model;instructions=$instructions;input=[string]$inputText;text=@{format=@{type='json_schema';name=$name;strict=$true;schema=$schema}}} -Depth 100 -Compress
  Write-Host("OpenAI repair call: model={0}; schema={1}; body_bytes={2}"-f$Config.Model,$name,[Text.Encoding]::UTF8.GetByteCount($body))-ForegroundColor DarkGray
  $resp=Invoke-WebRequest -Method Post -Uri 'https://api.openai.com/v1/responses' -Headers @{Authorization="Bearer $key";'Content-Type'='application/json'} -Body $body -SkipHttpErrorCheck
  if([int]$resp.StatusCode-lt200-or[int]$resp.StatusCode-ge300){throw "OpenAI API HTTP $([int]$resp.StatusCode): $($resp.Content)"}
  $r=$resp.Content|ConvertFrom-Json;$texts=@();foreach($i in @($r.output)){foreach($c in @($i.content)){if($c.type-eq'output_text'){$texts+=$c.text}}}
  if($texts.Count-eq0){throw 'OpenAI returned no output_text'}
  ($texts-join"`n")|ConvertFrom-Json
}

# Scaffolding for a future Anthropic provider path. Same contract as
# Invoke-OpenAI (instructions/payload/name/schema in, parsed object out) so
# call sites never need to change - only Invoke-Model's dispatch does.
# Structured output is forced via tool-use rather than a json_schema response
# format: the schema becomes a single forced tool's input_schema, and the
# tool_use content block's `input` arrives already parsed as an object.
function Invoke-Claude([string]$instructions,[object]$payload,[string]$name,[object]$schema){
  $key=[Environment]::GetEnvironmentVariable('ANTHROPIC_API_KEY','User');if(-not$key){$key=$env:ANTHROPIC_API_KEY};if(-not$key){throw 'ANTHROPIC_API_KEY missing'}
  [string]$inputText=ConvertTo-Json -InputObject $payload -Depth 80 -Compress
  $body=@{
    model=$Config.AnthropicModel
    max_tokens=4096
    system=$instructions
    messages=@(@{role='user';content=$inputText})
    tools=@(@{name=$name;description="Return $name as structured data.";input_schema=$schema})
    tool_choice=@{type='tool';name=$name}
  }|ConvertTo-Json -Depth 100 -Compress
  Write-Host("Claude repair call: model={0}; schema={1}; body_bytes={2}"-f$Config.AnthropicModel,$name,[Text.Encoding]::UTF8.GetByteCount($body))-ForegroundColor DarkGray
  $resp=Invoke-WebRequest -Method Post -Uri 'https://api.anthropic.com/v1/messages' -Headers @{'x-api-key'=$key;'anthropic-version'='2023-06-01';'Content-Type'='application/json'} -Body $body -SkipHttpErrorCheck
  if([int]$resp.StatusCode-lt200-or[int]$resp.StatusCode-ge300){throw "Anthropic API HTTP $([int]$resp.StatusCode): $($resp.Content)"}
  $r=$resp.Content|ConvertFrom-Json
  $call=@($r.content)|Where-Object{$_.type-eq'tool_use'-and$_.name-eq$name}|Select-Object -First 1
  if($null -eq $call){throw 'Anthropic returned no matching tool_use block'}
  $call.input
}

# Provider dispatcher. Config.Provider defaults to 'openai', so this is a
# no-op wrapper around existing behavior until that default is deliberately
# changed. 'anthropic' and any dual/cross-check mode are not implemented
# beyond this single-provider dispatch - adding a second, independent
# reviewer pass is a larger, separate design step, not a flag flip.
function Invoke-Model([string]$instructions,[object]$payload,[string]$name,[object]$schema){
  switch($Config.Provider){
    'openai'{Invoke-OpenAI $instructions $payload $name $schema}
    'anthropic'{Invoke-Claude $instructions $payload $name $schema}
    default{throw "Unknown Config.Provider: $($Config.Provider)"}
  }
}

function Get-PlanSchema{
@{type='object';additionalProperties=$false;required=@('safe','purpose','paths','focused_tests','definition_of_done','reason');properties=@{
safe=@{type='boolean'};purpose=@{type='string'};paths=@{type='array';items=@{type='string'}};focused_tests=@{type='array';items=@{type='string'}};definition_of_done=@{type='array';items=@{type='string'}};reason=@{type='string'}
}}
}
function Get-PatchSchema{
@{type='object';additionalProperties=$false;required=@('summary','files');properties=@{
summary=@{type='string'};files=@{type='array';items=@{type='object';additionalProperties=$false;required=@('path','content');properties=@{path=@{type='string'};content=@{type='string'}}}}
}}
}
function Invoke-DockerProcess(
  [Parameter(Mandatory=$true)][string[]]$CommandArgs,
  [switch]$Capture
){
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName='docker.exe'
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true
  foreach($arg in $CommandArgs){ [void]$psi.ArgumentList.Add([string]$arg) }

  $proc=[Diagnostics.Process]::new()
  $proc.StartInfo=$psi
  try{
    if(-not $proc.Start()){ throw 'Failed to start docker.exe' }
    $stdout=$proc.StandardOutput.ReadToEnd()
    $stderr=$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if($proc.ExitCode -ne 0){
      $detail=$stderr.Trim()
      if([string]::IsNullOrWhiteSpace($detail)){ $detail=$stdout.Trim() }
      throw "docker $($CommandArgs[0]) failed ($($proc.ExitCode)): $detail"
    }

    if(-not [string]::IsNullOrWhiteSpace($stderr)){
      Write-Host ($stderr.Trim()) -ForegroundColor DarkGray
    }
    if($Capture){ return $stdout.Trim() }
    if(-not [string]::IsNullOrWhiteSpace($stdout)){ Write-Host ($stdout.Trim()) }
  }finally{
    $proc.Dispose()
  }
}

function Ensure-TestImage {
  [string[]]$dockerArgs=@('image','inspect',$Config.TestImage)
  try{
    [void](Invoke-DockerProcess -CommandArgs $dockerArgs -Capture)
    Write-Host ("Docker test image: READY ({0})" -f $Config.TestImage) -ForegroundColor DarkGray
    return
  }catch{
    Write-Host ("Docker test image missing; pulling before any paid model call: {0}" -f $Config.TestImage) -ForegroundColor Yellow
  }

  [string[]]$dockerArgs=@('pull',$Config.TestImage)
  Invoke-DockerProcess -CommandArgs $dockerArgs
  Write-Host ("Docker test image: READY ({0})" -f $Config.TestImage) -ForegroundColor DarkGray
}

function New-UniqueDockerVolume([string]$prefix){
  $safe=($prefix.ToLowerInvariant() -replace '[^a-z0-9_.-]','_')
  $name=("{0}_{1}" -f $safe,[Guid]::NewGuid().ToString('N').Substring(0,10))
  [string[]]$dockerArgs=@('volume','create',$name)
  $actual=Invoke-DockerProcess -CommandArgs $dockerArgs -Capture
  if("$actual" -ne $name){ throw "Docker volume create returned unexpected name '$actual' (expected '$name')" }
  $name
}

function Remove-DockerVolume([string]$name){
  if([string]::IsNullOrWhiteSpace($name)){ return }
  [string[]]$dockerArgs=@('volume','rm','-f',$name)
  try{ [void](Invoke-DockerProcess -CommandArgs $dockerArgs -Capture) }catch{
    Write-Host ("Docker cleanup warning for volume {0}: {1}" -f $name,$_.Exception.Message) -ForegroundColor DarkYellow
  }
}

function Assert-DockerSandboxTopology {
  Ensure-TestImage

  $probeRoot=Join-Path ([IO.Path]::GetTempPath()) ("siteboss-sandbox-probe-"+[Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $probeRoot|Out-Null
  Set-Content -LiteralPath (Join-Path $probeRoot 'sentinel.txt') -Value 'siteboss' -NoNewline -Encoding UTF8
  $vol=$null

  try{
    $vol=New-UniqueDockerVolume 'sb_probe'

    # Stage from a read-only host bind into a Docker-managed writable workspace.
    [string[]]$dockerArgs=@(
      'run','--rm',
      '--security-opt','no-new-privileges',
      '--pids-limit','256',
      '--mount',"type=bind,src=$probeRoot,dst=/source,readonly",
      '--mount',"type=volume,src=$vol,dst=/workspace",
      '-w','/workspace',
      $Config.TestImage,
      'sh','-lc','cp -a /source/. /workspace/ && test "$(cat /workspace/sentinel.txt)" = siteboss'
    )
    Invoke-DockerProcess -CommandArgs $dockerArgs

    # Prove the staged volume can run with network disabled and without the host bind.
    [string[]]$dockerArgs=@(
      'run','--rm','--network','none',
      '--security-opt','no-new-privileges',
      '--pids-limit','256',
      '--mount',"type=volume,src=$vol,dst=/workspace",
      '-w','/workspace',
      $Config.TestImage,
      'sh','-lc','test "$(cat sentinel.txt)" = siteboss'
    )
    Invoke-DockerProcess -CommandArgs $dockerArgs

    Write-Host 'Docker sandbox topology self-test: PASS' -ForegroundColor DarkGray
  }finally{
    if($vol){ Remove-DockerVolume $vol }
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Initialize-TestWorkspace([string]$repo,[string]$vol,[string]$log){
  # No nested mount beneath a read-only bind. The source is read-only at /source;
  # the complete test copy and node_modules live in a Docker-managed volume at /workspace.
  [string[]]$dockerArgs=@(
    'run','--rm',
    '--security-opt','no-new-privileges',
    '--pids-limit','512',
    '--mount',"type=bind,src=$repo,dst=/source,readonly",
    '--mount',"type=volume,src=$vol,dst=/workspace",
    '-e','npm_config_cache=/tmp/npm-cache',
    '--tmpfs','/tmp',
    '-w','/workspace',
    $Config.TestImage,
    'sh','-lc','cp -a /source/. /workspace/ && npm ci --ignore-scripts --no-audit --no-fund'
  )
  try{
    $out=Invoke-DockerProcess -CommandArgs $dockerArgs -Capture
    if(-not [string]::IsNullOrWhiteSpace($out)){
      Add-Content -LiteralPath $log -Value $out
      Write-Host $out
    }
  }catch{
    Add-Content -LiteralPath $log -Value $_.Exception.Message
    throw "npm ci sandbox initialization failed: $($_.Exception.Message)"
  }
}

function Assert-SafeTest([string]$c){
  if([string]::IsNullOrWhiteSpace($c)-or$c-match'[;&|><`\r\n]'){throw "Unsafe test command: $c"}
  if($c-notmatch'^\s*(node(\.exe)?\s+--test\s+[A-Za-z0-9_./\\:-]+|npm(\.cmd)?\s+test)\s*$'){throw "Unsupported test command: $c"}
}
function Split-Safe([string]$c){
  $e=$null;$t=[Management.Automation.PSParser]::Tokenize($c,[ref]$e)|Where-Object { $_.Type -in @('Command','CommandArgument','String','Number') }|ForEach-Object{$_.Content}
  if($e-or$t.Count-lt1){throw "Cannot parse test: $c"};@($t)
}
function Run-Test([string]$c,[string]$vol,[string]$log,[switch]$Focused){
  Assert-SafeTest $c
  $p=@(Split-Safe $c)
  $exe=$p[0]
  if($exe-eq'npm.cmd'){$exe='npm'}
  if($exe-eq'node.exe'){$exe='node'}
  $exeArgs=@()
  if($p.Count-gt1){$exeArgs=@($p[1..($p.Count-1)])}

  Write-Host "TEST[sandbox/no-network]> $c" -ForegroundColor Cyan

  [string[]]$dockerArgs=@(
    'run','--rm','--network','none',
    '--security-opt','no-new-privileges',
    '--pids-limit','512',
    '--mount',"type=volume,src=$vol,dst=/workspace",
    '--tmpfs','/tmp',
    '-w','/workspace',
    $Config.TestImage,
    $exe
  )
  foreach($a in $exeArgs){ $dockerArgs += [string]$a }

  try{
    $out=Invoke-DockerProcess -CommandArgs $dockerArgs -Capture
    if(-not [string]::IsNullOrWhiteSpace($out)){
      Add-Content -LiteralPath $log -Value $out
      Write-Host $out

      if($Focused){
        # Node's TAP summary exposes total/pass/fail/skipped counts. A focused
        # regression command with every discovered test skipped is not evidence
        # that the repair works, even though the process exits 0.
        $testsMatch=[regex]::Match($out,'(?m)^# tests\s+(\d+)\s*$')
        $passMatch=[regex]::Match($out,'(?m)^# pass\s+(\d+)\s*$')
        $failMatch=[regex]::Match($out,'(?m)^# fail\s+(\d+)\s*$')
        $skipMatch=[regex]::Match($out,'(?m)^# skipped\s+(\d+)\s*$')

        if($testsMatch.Success-and$skipMatch.Success){
          $total=[int]$testsMatch.Groups[1].Value
          $skipped=[int]$skipMatch.Groups[1].Value
          $passed=$(if($passMatch.Success){[int]$passMatch.Groups[1].Value}else{0})
          $failed=$(if($failMatch.Success){[int]$failMatch.Groups[1].Value}else{0})

          if($total-gt0-and$skipped-eq$total-and$passed-eq0-and$failed-eq0){
            throw "SKIPPED_EVIDENCE: focused test '$c' discovered $total test(s) but executed none; all $skipped were skipped"
          }
        }
      }
    }
  }catch{
    Add-Content -LiteralPath $log -Value $_.Exception.Message
    throw "Test failed: $c :: $($_.Exception.Message)"
  }
}
try{
  if($PSVersionTable.PSVersion.Major-lt7){throw 'PowerShell 7+ required'}
  if(-not(Get-Command git -ErrorAction SilentlyContinue)){throw 'Git required'}
  Assert-GitProcessRunner
  Write-Host 'Local Git process-runner self-test: PASS' -ForegroundColor DarkGray
  if(-not(Get-Command docker -ErrorAction SilentlyContinue)){throw 'Docker Desktop required'}
  [string[]]$dockerInfoArgs=@('info')
  try{ [void](Invoke-DockerProcess -CommandArgs $dockerInfoArgs -Capture) }catch{ throw 'Docker Desktop is not running' }

  # Prove the exact sandbox topology before any repair-plan/patch API spend.
  Assert-DockerSandboxTopology

  if(-not(Test-Path -LiteralPath $ReviewPath)){throw "Review evidence missing: $ReviewPath"}
  $review=Get-Content -LiteralPath $ReviewPath -Raw|ConvertFrom-Json
  if("$($review.verdict)"-ne'FAIL'){Write-Host "No repair job: review verdict is $($review.verdict)";exit 0}

  if("$($Config.Provider)" -notin @('openai','anthropic')){
    throw "Unsupported SITEBOSS_REPAIR_PROVIDER '$($Config.Provider)'. Allowed: openai, anthropic"
  }
  Write-Host ("Repair model provider: {0}" -f $Config.Provider) -ForegroundColor DarkGray

  Write-Host "`nSITEBOSS AUTOPILOT REPAIR WORKER Repair Rat v0.5-smokescreen" -ForegroundColor Cyan
  Write-Host "Review target PR: #$($review.pr_number); frozen head: $($review.head_sha)" -ForegroundColor DarkGray

  $auth=New-GitHubInstallationToken;$token=$auth.token
  $contents="$((Get-OptionalProperty $auth.permissions 'contents'))";$pulls="$((Get-OptionalProperty $auth.permissions 'pull_requests'))"
  if($contents-ne'write'-or$pulls-ne'write'){throw "Repair publication requires Contents/Pull requests write; got contents=$contents pulls=$pulls"}

  Write-Host 'GitHub repair preflight: reading target PR detail...' -ForegroundColor DarkGray
  $pr=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$($review.pr_number)" $token

  $prState=Get-OptionalProperty $pr 'state'
  $prHead=Get-OptionalProperty $pr 'head'
  $prBase=Get-OptionalProperty $pr 'base'
  if($null -eq $prHead){throw 'Malformed GitHub target PR response: required `head` object is missing'}
  if($null -eq $prBase){throw 'Malformed GitHub target PR response: required `base` object is missing'}

  $prHeadSha=Get-OptionalProperty $prHead 'sha'
  $prHeadRef=Get-OptionalProperty $prHead 'ref'
  $prBaseSha=Get-OptionalProperty $prBase 'sha'
  if([string]::IsNullOrWhiteSpace("$prHeadSha")){throw 'Malformed GitHub target PR response: head.sha is missing'}
  if([string]::IsNullOrWhiteSpace("$prHeadRef")){throw 'Malformed GitHub target PR response: head.ref is missing'}
  if([string]::IsNullOrWhiteSpace("$prBaseSha")){throw 'Malformed GitHub target PR response: base.sha is missing'}

  if("$prState"-ne'open'){throw 'Reviewed PR is no longer open'}
  if("$prHeadSha"-ne"$($review.head_sha)"){throw "Reviewed PR head moved; refusing cached repair evidence"}
  if("$prBaseSha"-ne"$($review.base_sha)"){throw 'Reviewed PR base moved'}
  $targetBaseRef="$prHeadRef"
  $targetHeadSha="$prHeadSha"
  Write-Host ("GitHub repair preflight: target head/ref verified ({0} @ {1})" -f $targetBaseRef,$targetHeadSha) -ForegroundColor DarkGray

  $reviewProvider=Get-OptionalProperty $review 'provider'
  if([string]::IsNullOrWhiteSpace("$reviewProvider")){ $reviewProvider='openai-legacy-cache' }
  $repairIdentity="$($review.pr_number)|$($review.head_sha)|$($review.diff_sha256)|review=$reviewProvider|repair=$($Config.Provider)"
  $reviewKey=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($repairIdentity))).ToLowerInvariant()
  $branch=("autopilot/repair-pr{0}-{1}-{2}"-f$review.pr_number,$Config.Provider,$reviewKey.Substring(0,10))

  Write-Host 'GitHub repair preflight: checking exact deterministic repair head...' -ForegroundColor DarkGray
  $headFilter="$($Config.Owner):$branch"
  $existingRaw=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls?state=open&head=$([Uri]::EscapeDataString($headFilter))&per_page=10" $token

  # Normalize GitHub/PowerShell array shape explicitly. Invoke-RestMethod can surface
  # a one-item JSON array differently across PowerShell versions.
  $existing=@()
  if($null -ne $existingRaw){
    if($existingRaw -is [System.Array]){
      foreach($item in $existingRaw){ $existing += $item }
    } else {
      $existing += $existingRaw
    }
  }

  Write-Host ("GitHub repair preflight: matching open repair PRs={0}" -f $existing.Count) -ForegroundColor DarkGray
  if($existing.Count -gt 1){ throw "More than one open PR uses deterministic repair head '$branch'; refusing ambiguous duplicate state" }

  if($existing.Count -eq 1){
    $x=$existing[0]
    $xNumber=Get-OptionalProperty $x 'number'

    # If a PowerShell/GitHub list representation omits fields, use the list item's
    # number to fetch the canonical PR detail rather than assuming list shape.
    if($null -eq $xNumber){
      throw 'GitHub exact-head duplicate query returned an object without a PR number'
    }
    $xDetail=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$xNumber" $token
    $xHead=Get-OptionalProperty $xDetail 'head'
    if($null -eq $xHead){ throw "GitHub PR #$xNumber detail is missing required head object" }
    $xHeadRef=Get-OptionalProperty $xHead 'ref'
    if("$xHeadRef" -ne $branch){ throw "GitHub duplicate-query invariant failed: expected head '$branch', got '$xHeadRef'" }

    Write-Host "`nREPAIR PR ALREADY EXISTS: #$xNumber" -ForegroundColor Green
    Write-Host 'No duplicate API coding run was performed.'
    exit 0
  }

  Assert-CaseSensitiveWorkspaceRoot $Config.WorkspaceRoot
  $root=Join-Path $Config.WorkspaceRoot ([DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss'))
  New-Item -ItemType Directory -Force -Path $root|Out-Null
  $ask=New-AskPass $root;$repo=Join-Path $root 'repo'
  $env:SITEBOSS_GITHUB_TOKEN=$token;$env:GIT_ASKPASS=$ask;$env:GIT_TERMINAL_PROMPT='0'
  try{
    [string[]]$gitArgs=@('clone','--no-checkout','--filter=blob:none',"https://github.com/$($Config.Owner)/$($Config.Repo).git",$repo)
    Invoke-GitProcess -CommandArgs $gitArgs

    # Disposable repair workspace: preserve model-authored file content exactly.
    # Disable Git line-ending conversion/warnings locally in this clone only.
    [string[]]$gitArgs=@('config','--local','core.autocrlf','false')
    Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

    [string[]]$gitArgs=@('config','--local','core.safecrlf','false')
    Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

    [string[]]$gitArgs=@('config','--local','user.name',$Config.GitUserName)
    Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

    [string[]]$gitArgs=@('config','--local','user.email',$Config.GitUserEmail)
    Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

    [string[]]$gitArgs=@('fetch','--no-tags','origin',$targetHeadSha)
    Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

    Assert-NoUnrepresentableCaseCollision $repo $targetHeadSha

    [string[]]$gitArgs=@('checkout','--detach',$targetHeadSha)
    Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

    [string[]]$gitArgs=@('switch','-c',$branch)
    Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo
  }finally{Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue;Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue}

  # Pristine disposable baseline gate. This runs BEFORE any paid model call.
  # Re-materialize exact HEAD under the repo-local line-ending policy, remove
  # untracked artifacts, then prove the entire worktree is clean with NUL-safe status.
  [string[]]$gitArgs=@('reset','--hard','HEAD')
  Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

  [string[]]$gitArgs=@('clean','-ffd')
  Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

  [string[]]$gitArgs=@('status','--porcelain=v1','-z','--untracked-files=all')
  $baselineRaw=Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo -Capture
  if(-not [string]::IsNullOrEmpty($baselineRaw)){
    $display=($baselineRaw -replace "`0",' | ')
    throw "Repair workspace is not pristine before any model call: $display"
  }
  Write-Host 'Repair workspace baseline: PRISTINE' -ForegroundColor DarkGray

  [string[]]$gitArgs=@('ls-tree','-r','--name-only','HEAD')
  $tree=@((Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo -Capture)-split"`n"|Where-Object{$_})
  $testPaths=@($tree|Where-Object{$_-match'(^|/)(test|tests)/|\.test\.|\.spec\.'})
  $findingPaths=@()
  foreach($f in @($review.findings)){
    foreach($m in [regex]::Matches("$($f.path)",'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+')){
      if($tree-contains$m.Value){$findingPaths+=$m.Value}
    }
  }
  $findingPaths=@($findingPaths|Select-Object -Unique)
  $planInstructions=@"
You are SiteBoss repair planner. Select ONE coherent repair slice from the exact independent-review FAIL.
Work on the reviewed PR lineage, not main. Choose at most $($Config.MaxPlanFiles) existing repository paths.
Prioritise the highest-severity related findings that can be fixed and regression-tested together.
Do not add files, migrations, dependencies, package/workflow/script changes, settings, permissions, merge/deploy actions, or unrelated cleanup.
Paths must exist in repository_tree. Prefer source paths named in findings plus existing directly relevant tests.
focused_tests may contain only 'node --test <existing test path>'. Full npm test will always run separately.
If a safe bounded slice cannot be proven, safe=false.
"@
  $plan=Invoke-Model $planInstructions @{
    review=$review
    repository_tree=$tree
    finding_paths=$findingPaths
    candidate_test_paths=$testPaths
  } 'siteboss_repair_plan' (Get-PlanSchema)

  if(-not$plan.safe){Write-Host "`nNO SAFE BOUNDED REPAIR: $($plan.reason)" -ForegroundColor Yellow;exit 0}
  $paths=@($plan.paths|ForEach-Object{Assert-RepoPath "$_"})
  if($paths.Count-lt1-or$paths.Count-gt$Config.MaxPlanFiles){throw 'Repair plan path count invalid'}
  foreach($p in $paths){if($tree-notcontains$p){throw "Repair plan selected nonexistent path: $p"}}
  foreach($c in @($plan.focused_tests)){Assert-SafeTest "$c";if("$c"-match'node(?:\.exe)?\s+--test\s+(.+)$'){if($tree-notcontains$Matches[1]){throw "Focused test path missing: $($Matches[1])"}}}

  $files=@();$chars=0
  foreach($p in $paths){$content=Get-Content -LiteralPath (Join-Path $repo $p) -Raw;$chars+=$content.Length;if($chars-gt$Config.MaxSourceChars){throw 'Repair source context too large'};$files+=@{path=$p;content=$content}}
  $patchInstructions=@"
You are the bounded SiteBoss repair coder. Implement only the selected repair purpose using only supplied files.
Return complete replacement content for files you actually change. Do not change any path not supplied.
Preserve existing architecture and public contracts unless the repair purpose explicitly requires a contract correction.
Do not add dependencies, migrations, workflows, scripts, secrets, settings, permissions, deployment, merge logic, or unrelated refactors.
The result must address the stated independent-review defect and be testable by the supplied tests plus npm test.
"@
  $patch=Invoke-Model $patchInstructions @{review=$review;plan=$plan;files=$files} 'siteboss_repair_patch' (Get-PatchSchema)

  $written=@()
  foreach($f in @($patch.files)){
    $p=Assert-RepoPath "$($f.path)"
    if($paths-notcontains$p){throw "Model changed path outside repair allowlist: $p"}
    Set-Content -LiteralPath (Join-Path $repo $p) -Value "$($f.content)" -Encoding UTF8 -NoNewline
    $written+=$p
  }
  if($written.Count-lt1){throw 'Model returned no changed files'}

  [string[]]$gitArgs=@('diff','--name-only','-z','--no-ext-diff','--ignore-submodules=all','--')
  $changedRaw=Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo -Capture
  $changed=@($changedRaw -split "`0" | Where-Object { -not [string]::IsNullOrEmpty($_) } | ForEach-Object { Assert-RepoPath "$_" })
  foreach($p in $changed){if($paths-notcontains$p){throw "Changed path outside allowlist after write: $p"}}
  if($changed.Count-lt1){throw 'No actual repository changes produced'}

  $vol=$null
  $log=Join-Path $root 'test-output.log'
  try{
    $vol=New-UniqueDockerVolume ("sb_auto_"+$reviewKey.Substring(0,12))
    Initialize-TestWorkspace $repo $vol $log
    foreach($c in @($plan.focused_tests)){ Run-Test "$c" $vol $log -Focused }
    Run-Test 'npm test' $vol $log
  }finally{
    if($vol){ Remove-DockerVolume $vol }
  }

  # Revalidate reviewed PR head immediately before publication.
  $pr2=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$($review.pr_number)" $token
  $pr2Head=Get-OptionalProperty $pr2 'head'
  if($null -eq $pr2Head){throw 'Malformed GitHub target PR response during publication recheck: head is missing'}
  $pr2HeadSha=Get-OptionalProperty $pr2Head 'sha'
  if("$pr2HeadSha"-ne$targetHeadSha){throw 'Reviewed PR head moved during repair run; publication aborted'}

  [string[]]$gitArgs=@('add','--all')
  Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

  [string[]]$gitArgs=@('commit','-m',("repair: PR #{0} independent review" -f $review.pr_number))
  Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo

  [string[]]$gitArgs=@('rev-parse','HEAD')
  $repairHead=Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo -Capture

  $env:SITEBOSS_GITHUB_TOKEN=$token;$env:GIT_ASKPASS=$ask;$env:GIT_TERMINAL_PROMPT='0'
  [string[]]$gitArgs=@('push','--set-upstream','origin',"HEAD:refs/heads/$branch")
  try{Invoke-GitProcess -CommandArgs $gitArgs -WorkingDir $repo}
  finally{Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue;Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue}

  $body=@"
## SiteBoss Autopilot repair child PR

Parent PR: #$($review.pr_number)
Reviewed frozen parent head: `$targetHeadSha`
Independent review diff SHA256: `$($review.diff_sha256)`
Repair commit: `$repairHead`

### Repair purpose
$($plan.purpose)

### Model provider
`$($Config.Provider)`

### Definition of done
$(@($plan.definition_of_done)|ForEach-Object{"- $_"}|Out-String)

### Changed paths
$($changed|ForEach-Object{"- ``$_``"}|Out-String)

### Validation
All selected focused tests and `npm test` passed in Docker with test networking disabled.

### Safety boundary
This is a DRAFT child PR targeting the parent PR branch. It does not merge itself, modify main, deploy, approve itself, or change repository/settings/secrets/permissions.
"@
  $child=GHPost "/repos/$($Config.Owner)/$($Config.Repo)/pulls" $token @{
    title="[Autopilot repair] $($plan.purpose)"
    head=$branch
    base=$targetBaseRef
    body=$body
    draft=$true
  }

  $result=@{
    schema=1;parent_pr=[int]$review.pr_number;parent_head=$targetHeadSha;repair_pr=[int]$child.number;repair_head=$repairHead;branch=$branch;purpose="$($plan.purpose)";changed_paths=$changed;review_key=$reviewKey
  }
  $resultPath=Join-Path (Split-Path -Parent $ReviewPath) 'last-repair.json'
  $result|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $resultPath -Encoding UTF8

  Write-Host "`nREPAIR DRAFT PR CREATED: #$($child.number)" -ForegroundColor Green
  Write-Host "Parent PR: #$($review.pr_number) at $targetHeadSha"
  Write-Host "Repair head: $repairHead"
  Write-Host 'No merge was performed.'
}catch{
  Remove-Item Env:SITEBOSS_GITHUB_TOKEN -ErrorAction SilentlyContinue
  Remove-Item Env:GIT_ASKPASS -ErrorAction SilentlyContinue
  Write-Host "`nSITEBOSS AUTOPILOT REPAIR FAILED CLOSED" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  exit 1
}
