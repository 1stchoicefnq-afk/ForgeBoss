param(
  [int]$RepairPullRequest = 525,
  [string]$RepairRatReport = '',
  [int]$RepeatCount = 3,
  [int]$FullSuiteRepeats = 5,
  [int]$ValidationRounds = 2,
  [switch]$NoPublish,
  [int]$RootPullRequest = 0,
  [string]$TargetSha = '',
  [string]$SpecialistPlan = ''
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$GitHubGovernorModule=Join-Path $PSScriptRoot 'forgeboss\github\GitHub-Governor.psm1'
Import-Module $GitHubGovernorModule -Force

$Root=$PSScriptRoot
$State=Join-Path $Root 'state\rat-review'
$Cache=Join-Path $State 'review-cache'
New-Item -ItemType Directory -Force -Path $State,$Cache|Out-Null
$Stamp=[DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')
$ReportPath=Join-Path $State "rat-review-$Stamp.json"
$LogPath=Join-Path $State "rat-review-$Stamp.log"

$Config=@{
  AppId='4608230'
  InstallationId='154040429'
  Owner='1stchoicefnq-afk'
  Repo='siteboss-monster'
  RepoUrl='https://github.com/1stchoicefnq-afk/siteboss-monster.git'
  PemPath="$env:USERPROFILE\.siteboss\secrets\github-app-private-key.pem"
  NodeImage=$(if($env:SITEBOSS_TEST_IMAGE){$env:SITEBOSS_TEST_IMAGE}else{'node:22-bookworm'})
  PostgresImage='postgres:17-alpine'
  ReviewerProvider=$(if($env:SITEBOSS_RAT_REVIEW_PROVIDER){$env:SITEBOSS_RAT_REVIEW_PROVIDER.ToLowerInvariant()}elseif($env:SITEBOSS_REVIEW_PROVIDER){$env:SITEBOSS_REVIEW_PROVIDER.ToLowerInvariant()}else{'openai'})
  OpenAIModel=$(if($env:SITEBOSS_OPENAI_MODEL){$env:SITEBOSS_OPENAI_MODEL}else{'gpt-5.6'})
  AnthropicModel=$(if($env:SITEBOSS_ANTHROPIC_MODEL){$env:SITEBOSS_ANTHROPIC_MODEL}else{'claude-sonnet-5'})
  WorkspaceRoot=(Join-Path $env:USERPROFILE '.siteboss\autopilot\case-sensitive-repair-workspaces\rat-review')
}
if($RepeatCount-lt1-or$RepeatCount-gt5){throw 'RepeatCount must be 1..5'}
if($FullSuiteRepeats-lt2-or$FullSuiteRepeats-gt8){throw 'FullSuiteRepeats must be 2..8'}
if($ValidationRounds-lt1-or$ValidationRounds-gt3){throw 'ValidationRounds must be 1..3'}
if($Config.ReviewerProvider-notin@('openai','anthropic')){throw "Unsupported reviewer provider: $($Config.ReviewerProvider)"}

$script:ApiCalls=0
$script:GitHubWrites=0
$script:ExactHead=$null
$script:LocalCommit=$null
$script:CleanWorkspace=$null
$script:Acceptance=$null
$script:Review=$null
$script:PublishedPr=$null
$script:Failure=$null

function Log([string]$Message,[string]$Color='Gray'){
  Add-Content -LiteralPath $LogPath -Value $Message
  Write-Host $Message -ForegroundColor $Color
}
function Run(
  [string]$Exe,
  [string[]]$CommandArgs,
  [string]$Cwd='',
  [hashtable]$Environment=@{}
){
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName=$Exe
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true
  if($Cwd){$psi.WorkingDirectory=$Cwd}
  foreach($kv in $Environment.GetEnumerator()){$psi.Environment[$kv.Key]=[string]$kv.Value}
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
function Sha256Text([string]$Text){
  $sha=[Security.Cryptography.SHA256]::Create()
  try{
    (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))|ForEach-Object{$_.ToString('x2')})-join'')
  }finally{$sha.Dispose()}
}
function B64Url([byte[]]$Bytes){
  [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function Optional($Object,[string]$Name){
  if($null-eq$Object){return $null}
  $p=$Object.PSObject.Properties[$Name]
  if($null-eq$p){return $null}
  $p.Value
}
function New-GitHubToken {
  if(-not(Test-Path -LiteralPath $Config.PemPath)){throw "GitHub App private key missing: $($Config.PemPath)"}
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
  $headers=@{Authorization="Bearer $jwt";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}
  $body=@{repositories=@($Config.Repo)}|ConvertTo-Json
  Invoke-GovernedGitHubJson -Method POST -Url "https://api.github.com/app/installations/$($Config.InstallationId)/access_tokens" -Headers $headers -Body $body -CacheTtlMs 0
}
function GHRequest([string]$Method,[string]$Path,[string]$Token,[object]$Body=$null){
  $m=$Method.ToUpperInvariant();$headers=@{Authorization="Bearer $Token";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}
  $resp=Invoke-GovernedGitHubRaw -Method $m -Url "https://api.github.com$Path" -Headers $headers -Body $Body -CacheTtlMs 0 -AllowHttpError
  if([int]$resp.status-lt200-or[int]$resp.status-ge300){throw "GitHub $m $Path failed: HTTP $([int]$resp.status): $($resp.body)"}
  if($m-ne'GET'){$script:GitHubWrites++}
  if([string]::IsNullOrWhiteSpace("$($resp.body)")){return $null}
  "$($resp.body)"|ConvertFrom-Json
}
function GHGet([string]$Path,[string]$Token){GHRequest 'GET' $Path $Token}
function GHPost([string]$Path,[string]$Token,[object]$Body){GHRequest 'POST' $Path $Token $Body}

function Find-RepairRatReport {
  if($RepairRatReport){
    if(-not(Test-Path -LiteralPath $RepairRatReport)){throw "Repair Rat report not found: $RepairRatReport"}
    return (Resolve-Path -LiteralPath $RepairRatReport).Path
  }
  if($env:SITEBOSS_REPAIR_RAT_REPORT){
    if(-not(Test-Path -LiteralPath $env:SITEBOSS_REPAIR_RAT_REPORT)){throw "SITEBOSS_REPAIR_RAT_REPORT not found"}
    return (Resolve-Path -LiteralPath $env:SITEBOSS_REPAIR_RAT_REPORT).Path
  }

  $roots=@(
    (Join-Path $Root 'state\repair-rat'),
    (Join-Path $env:USERPROFILE 'Downloads')
  )
  $candidates=@()
  foreach($searchRoot in $roots){
    if(-not(Test-Path -LiteralPath $searchRoot)){continue}
    if($searchRoot-eq(Join-Path $Root 'state\repair-rat')){
      $candidates+=@(Get-ChildItem -LiteralPath $searchRoot -File -Filter 'repair-rat-*.json' -ErrorAction SilentlyContinue)
    }else{
      $packages=@(Get-ChildItem -LiteralPath $searchRoot -Directory -Filter 'SiteBoss-Repair-Rat-v0.*' -ErrorAction SilentlyContinue)
      foreach($pkg in $packages){
        $state=Join-Path $pkg.FullName ($pkg.Name+'\state\repair-rat')
        if(Test-Path -LiteralPath $state){
          $candidates+=@(Get-ChildItem -LiteralPath $state -File -Filter 'repair-rat-*.json' -ErrorAction SilentlyContinue)
        }
        $direct=Join-Path $pkg.FullName 'state\repair-rat'
        if(Test-Path -LiteralPath $direct){
          $candidates+=@(Get-ChildItem -LiteralPath $direct -File -Filter 'repair-rat-*.json' -ErrorAction SilentlyContinue)
        }
      }
    }
  }

  foreach($f in @($candidates|Sort-Object LastWriteTimeUtc -Descending)){
    try{
      $j=Get-Content -LiteralPath $f.FullName -Raw|ConvertFrom-Json
      if("$($j.repair_pr)"-eq"$RepairPullRequest"-and"$($j.passed)"-eq'True'-and"$($j.local_commit)"){
        return $f.FullName
      }
    }catch{}
  }
  throw 'Could not auto-discover a successful Repair Rat report. Set SITEBOSS_REPAIR_RAT_REPORT to its JSON path.'
}

function Assert-CaseSensitive([string]$Path){
  $probe=$Path
  while(-not(Test-Path -LiteralPath $probe)){
    $parent=Split-Path -Parent $probe
    if(-not$parent-or$parent-eq$probe){break}
    $probe=$parent
  }
  $r=Run 'fsutil.exe' @('file','queryCaseSensitiveInfo',$probe)
  if($r.exit_code-ne0-or$r.stdout-notmatch'(?i)enabled'){throw "Case-sensitive workspace required: $probe"}
}
function Assert-Clean([string]$Repo,[string]$Stage){
  $r=Run 'git.exe' @('status','--porcelain=v1','-z','--untracked-files=all') $Repo
  if($r.exit_code-ne0){throw "git status failed at $($Stage): $($r.stderr)"}
  if($r.stdout){throw "Workspace not clean at $($Stage): "+($r.stdout-replace"`0",' | ')}
}

function Run-Acceptance([string]$Repo){
  $net=("rat_review_net_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  $pg=("rat_review_pg_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  $ws=("rat_review_ws_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
  $u='siteboss';$db='siteboss_test';$pw='siteboss_test_password'
  $url="postgresql://${u}:${pw}@postgres:5432/$db"
  $runs=[System.Collections.Generic.List[object]]::new()

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
    $item=[pscustomobject]@{
      name=$Name
      exit_code=$r.exit_code
      failure_lines=@($lines|Where-Object{$_-match'(?i)not ok|error:|40001|40P01|500 !== 201|Trade pack fencing|AssertionError'}|Select-Object -First 100)
      output_tail=@($lines|Select-Object -Last ([Math]::Min(80,$lines.Count)))
    }
    [void]$runs.Add($item)
    Log ("[{0}] CLEAN ACCEPTANCE :: {1}"-f$(if($r.exit_code-eq0){'PASS'}else{'FAIL'}),$Name) $(if($r.exit_code-eq0){'Green'}else{'Red'})
  }

  try{
    foreach($img in @($Config.NodeImage,$Config.PostgresImage)){
      $q=Run 'docker.exe' @('image','inspect',$img)
      if($q.exit_code-ne0){throw "Missing Docker image: $img"}
    }
    $q=Run 'docker.exe' @('network','create',$net);if($q.exit_code-ne0){throw $q.stderr}
    $q=Run 'docker.exe' @('volume','create',$ws);if($q.exit_code-ne0){throw $q.stderr}
    $q=Run 'docker.exe' @('run','-d','--rm','--name',$pg,'--network',$net,'--network-alias','postgres',
      '-e',"POSTGRES_DB=$db",'-e',"POSTGRES_USER=$u",'-e',"POSTGRES_PASSWORD=$pw",$Config.PostgresImage)
    if($q.exit_code-ne0){throw "Postgres start failed: $($q.stderr)"}
    $ready=$false
    for($i=1;$i-le30;$i++){
      $q=Run 'docker.exe' @('exec',$pg,'pg_isready','-U',$u,'-d',$db)
      if($q.exit_code-eq0){$ready=$true;break}
      Start-Sleep -Seconds 1
    }
    if(-not$ready){throw 'Postgres readiness timeout'}

    $q=Run 'docker.exe' @('run','--rm','--network',$net,
      '--mount',"type=bind,src=$Repo,dst=/source,readonly",
      '--mount',"type=volume,src=$ws,dst=/workspace",
      '-e','npm_config_cache=/tmp/npm-cache','--tmpfs','/tmp',
      '-w','/workspace',$Config.NodeImage,'sh','-lc',
      'cp -a /source/. /workspace/ && npm ci --ignore-scripts --no-audit --no-fund')
    if($q.exit_code-ne0){throw "npm ci failed: $($q.stdout) $($q.stderr)"}

    Step 'npm_test' 'npm test' $false
    Step 'initial_migrate' 'npm run db:migrate' $true
    foreach($i in 1..$RepeatCount){
      Step "business_invitations_$i" 'node --test tests/postgresBusinessInvitations.integration.test.js' $true
      Step "production_http_$i" 'node --test tests/postgresProductionHttp.integration.test.js' $true
      Step "travis_intake_$i" 'node --test tests/postgresTravisIntake.integration.test.js' $true
    }
    foreach($i in 1..$FullSuiteRepeats){Step "full_postgres_suite_$i" 'node --test tests/postgres*.integration.test.js' $true}
    Step 'rollback' 'npm run db:rollback' $true
    Step 'migrate_again' 'npm run db:migrate' $true

    $fails=@($runs|Where-Object{$_.exit_code-ne0})
    [pscustomobject]@{passed=($fails.Count-eq0);failure_count=$fails.Count;runs=@($runs)}
  }finally{
    try{[void](Run 'docker.exe' @('rm','-f',$pg))}catch{}
    try{[void](Run 'docker.exe' @('volume','rm','-f',$ws))}catch{}
    try{[void](Run 'docker.exe' @('network','rm',$net))}catch{}
  }
}

function Get-SpecialistRouting([string]$Mode,[object]$Packet,[string[]]$BuilderSpecialists=@()){
  if($Mode-eq'reviewer'-and-not[string]::IsNullOrWhiteSpace($SpecialistPlan)){
    if(-not(Test-Path -LiteralPath $SpecialistPlan)){throw "Controller reviewer specialist plan missing: $SpecialistPlan"}
    $plan=Get-Content -LiteralPath $SpecialistPlan -Raw|ConvertFrom-Json
    if("$($plan.routing.mode)"-ne'reviewer'){throw 'Controller reviewer specialist plan mode mismatch'}
    if(@($plan.routing.specialists).Count-gt2){throw 'Controller reviewer specialist plan exceeds max reviewer profiles'}
    $ids=@($plan.routing.specialists|ForEach-Object{"$_"})
    if(@($ids|Where-Object{$BuilderSpecialists-contains$_}).Count-gt0){throw 'Controller reviewer plan violates builder/reviewer independence'}
    return $plan
  }
  $dir=Join-Path $Root 'state\specialists'
  New-Item -ItemType Directory -Force -Path $dir|Out-Null
  $id=[Guid]::NewGuid().ToString('N')
  $inputPath=Join-Path $dir "review-route-input-$id.json"
  $output=Join-Path $dir "review-route-output-$id.json"
  try{
    $Packet|ConvertTo-Json -Depth 80|Set-Content -LiteralPath $inputPath -Encoding UTF8
    $nodeArgs=@((Join-Path $Root 'controller\specialists-cli.js'),'route','--input',$inputPath,'--mode',$Mode,'--output',$output)
    if($BuilderSpecialists.Count-gt0){$nodeArgs+=@('--builder-specialists',($BuilderSpecialists-join','))}
    $r=Run 'node.exe' $nodeArgs $Root
    if($r.exit_code-ne0){throw "Specialist reviewer router failed: $($r.stderr) $($r.stdout)"}
    Get-Content -LiteralPath $output -Raw|ConvertFrom-Json
  }finally{
    Remove-Item -LiteralPath $inputPath,$output -Force -ErrorAction SilentlyContinue
  }
}

function Review-Schema {
  @{
    type='object';additionalProperties=$false
    required=@('verdict','summary','findings','required_actions')
    properties=@{
      verdict=@{type='string';enum=@('PASS','FAIL','NEEDS_EVIDENCE')}
      summary=@{type='string'}
      findings=@{
        type='array'
        items=@{
          type='object';additionalProperties=$false
          required=@('severity','title','detail','files')
          properties=@{
            severity=@{type='string';enum=@('HIGH','MEDIUM','LOW')}
            title=@{type='string'}
            detail=@{type='string'}
            files=@{type='array';items=@{type='string'}}
          }
        }
      }
      required_actions=@{type='array';items=@{type='string'}}
    }
  }
}
function Invoke-OpenAIReview([string]$Instructions,[object]$Payload){
  throw "REVIEW_BUDGET_LEDGER_REQUIRED: paid Rat Review disabled until authoritative reservation accounting."

  $key=[Environment]::GetEnvironmentVariable('OPENAI_API_KEY','User')
  if(-not$key){$key=$env:OPENAI_API_KEY}
  if(-not$key){throw 'OPENAI_API_KEY missing'}
  $body=ConvertTo-Json -InputObject @{
    model=$Config.OpenAIModel
    instructions=$Instructions
    input=(ConvertTo-Json -InputObject $Payload -Depth 80 -Compress)
    text=@{format=@{type='json_schema';name='repair_rat_review';strict=$true;schema=(Review-Schema)}}
  } -Depth 100 -Compress
  $script:ApiCalls++
  Log ("Independent review call: provider=openai model={0} body_bytes={1}"-f$Config.OpenAIModel,[Text.Encoding]::UTF8.GetByteCount($body)) 'DarkGray'
  $resp=Invoke-WebRequest -Method Post -Uri 'https://api.openai.com/v1/responses' -Headers @{Authorization="Bearer $key";'Content-Type'='application/json'} -Body $body -SkipHttpErrorCheck
  if([int]$resp.StatusCode-lt200-or[int]$resp.StatusCode-ge300){throw "OpenAI review HTTP $([int]$resp.StatusCode): $($resp.Content)"}
  $obj=$resp.Content|ConvertFrom-Json
  $texts=@()
  foreach($item in @($obj.output)){foreach($c in @($item.content)){if($c.type-eq'output_text'){$texts+=$c.text}}}
  if($texts.Count-eq0){throw 'OpenAI review returned no output_text'}
  ($texts-join"`n")|ConvertFrom-Json
}
function Invoke-ClaudeReview([string]$Instructions,[object]$Payload){
  throw "REVIEW_BUDGET_LEDGER_REQUIRED: paid Rat Review disabled until authoritative reservation accounting."

  $key=[Environment]::GetEnvironmentVariable('ANTHROPIC_API_KEY','User')
  if(-not$key){$key=$env:ANTHROPIC_API_KEY}
  if(-not$key){throw 'ANTHROPIC_API_KEY missing'}
  $body=ConvertTo-Json -InputObject @{
    model=$Config.AnthropicModel
    max_tokens=12000
    system=$Instructions
    messages=@(@{role='user';content=(ConvertTo-Json -InputObject $Payload -Depth 80 -Compress)})
    tools=@(@{name='repair_rat_review';description='Independent repair review verdict';input_schema=(Review-Schema)})
    tool_choice=@{type='tool';name='repair_rat_review'}
  } -Depth 100 -Compress
  $script:ApiCalls++
  Log ("Independent review call: provider=anthropic model={0} body_bytes={1}"-f$Config.AnthropicModel,[Text.Encoding]::UTF8.GetByteCount($body)) 'DarkGray'
  $resp=Invoke-WebRequest -Method Post -Uri 'https://api.anthropic.com/v1/messages' -Headers @{'x-api-key'=$key;'anthropic-version'='2023-06-01';'content-type'='application/json'} -Body $body -SkipHttpErrorCheck
  if([int]$resp.StatusCode-lt200-or[int]$resp.StatusCode-ge300){throw "Anthropic review HTTP $([int]$resp.StatusCode): $($resp.Content)"}
  $obj=$resp.Content|ConvertFrom-Json
  foreach($c in @($obj.content)){if($c.type-eq'tool_use'-and$c.name-eq'repair_rat_review'){return $c.input}}
  throw 'Anthropic review returned no forced tool result'
}
function Get-OrCreateReview([string]$Diff,[string]$DiffHash,[object]$RatReport,[object]$Acceptance){
  $routingIdentity=Sha256Text ((Get-Content -LiteralPath (Join-Path $Root 'controller\specialists\registry.json') -Raw)+"|"+(Get-Content -LiteralPath (Join-Path $Root 'controller\lib\specialists.js') -Raw)+"|"+(@($RatReport.builder_specialists)-join','))
  $cachePath=Join-Path $Cache ("pr{0}-{1}-{2}-{3}.json"-f$RepairPullRequest,$script:LocalCommit.Substring(0,12),$DiffHash.Substring(0,12),$routingIdentity.Substring(0,12))
  if(Test-Path -LiteralPath $cachePath){
    $cached=Get-Content -LiteralPath $cachePath -Raw|ConvertFrom-Json
    if("$($cached.local_commit)"-eq$script:LocalCommit-and"$($cached.diff_sha256)"-eq$DiffHash-and"$($cached.provider)"-eq$Config.ReviewerProvider){
      Log 'REVIEW CACHE HIT - no paid review call' 'Green'
      return $cached.review
    }
  }

  $builderSpecialists=@($RatReport.builder_specialists|ForEach-Object{"$_"})
  $changedPaths=@($RatReport.attempts|ForEach-Object{@($_.changed_paths)}|ForEach-Object{$_}|Where-Object{$_}|Select-Object -Unique)
  $routingPacket=[ordered]@{
    objective='Independently review the exact SiteBoss repair candidate.'
    reason='Independent review gate after clean acceptance.'
    task='code review'
    changed_files=$changedPaths
    findings=@('transaction safety','idempotency','security','regression risk')
  }
  $specialist=Get-SpecialistRouting 'reviewer' $routingPacket $builderSpecialists
  $reviewSpecialists=@($specialist.routing.specialists|ForEach-Object{"$_"})
  $script:ReviewSpecialists=@($reviewSpecialists)
  if(@($reviewSpecialists|Where-Object{$builderSpecialists-contains$_}).Count-gt0){throw 'Reviewer specialist independence violation'}
  Log ("Review specialists selected: "+($reviewSpecialists-join', ')) 'Cyan'

  $payload=[ordered]@{
    role='independent reviewer; you did not author this repair'
    parent_repair_pr=$RepairPullRequest
    exact_parent_head=$script:ExactHead
    local_repair_commit=$script:LocalCommit
    clean_acceptance=$Acceptance
    repair_rat_attempt_summary=@($RatReport.attempts|ForEach-Object{
      @{attempt=$_.attempt;acceptance_passed=$_.acceptance_passed;failure_count=$_.failure_count;changed_paths=$_.changed_paths}
    })
    exact_diff=$Diff
    specialist_routing=$specialist.routing
  }
  $instructions=@'
You are an independent SiteBoss repair reviewer. You did NOT author this patch.
Review the exact frozen diff for correctness, data integrity, transaction semantics,
idempotency, retry safety, security/privacy and regression risk.

Pay special attention to:
- PostgreSQL SERIALIZABLE retry behavior for 40001/40P01,
- whole-transaction retry boundaries,
- ambiguous commit outcomes,
- aborted/cancelled requests,
- replay-safe external side effects,
- exact-once/idempotency semantics,
- canonical lead/trade-pack fencing semantics.

Green tests are evidence, not proof. FAIL on any unresolved HIGH issue.
Return PASS only when this exact patch is suitable to publish as a DRAFT child repair PR.
'@
  $instructions="$($specialist.composition.prompt)`n`n## SITEBOSS_INDEPENDENT_REVIEW_TASK`n$instructions"
  $review=$(if($Config.ReviewerProvider-eq'openai'){Invoke-OpenAIReview $instructions $payload}else{Invoke-ClaudeReview $instructions $payload})
  [ordered]@{
    schema=1
    created_at=[DateTimeOffset]::UtcNow.ToString('o')
    provider=$Config.ReviewerProvider
    local_commit=$script:LocalCommit
    diff_sha256=$DiffHash
    review=$review
  }|ConvertTo-Json -Depth 80|Set-Content -LiteralPath $cachePath -Encoding UTF8
  $review
}

function Push-ReviewedCommit([string]$SourceRepo,[string]$Commit,[string]$Branch,[string]$Token){
  $basic=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("x-access-token:$Token"))
  $env:GIT_CONFIG_COUNT='1';$env:GIT_CONFIG_KEY_0='http.extraHeader';$env:GIT_CONFIG_VALUE_0="Authorization: Basic $basic"
  try{Invoke-GovernedGitPush -WorkingDirectory $SourceRepo -Remote $Config.RepoUrl -RefSpec ($Commit + ':refs/heads/' + $Branch) | Out-Null}
  finally{Remove-Item Env:GIT_CONFIG_COUNT -ErrorAction SilentlyContinue;Remove-Item Env:GIT_CONFIG_KEY_0 -ErrorAction SilentlyContinue;Remove-Item Env:GIT_CONFIG_VALUE_0 -ErrorAction SilentlyContinue}
  $script:GitHubWrites++
}

function Write-FinalReport([bool]$Passed){
  [ordered]@{
    schema=1
    name='Repair Rat Review'
    generated_at=[DateTimeOffset]::UtcNow.ToString('o')
    parent_repair_pr=$RepairPullRequest
    exact_parent_head=$script:ExactHead
    local_commit=$script:LocalCommit
    clean_workspace=$script:CleanWorkspace
    acceptance=$script:Acceptance
    reviewer_provider=$Config.ReviewerProvider
    reviewer_specialists=$(if($null-ne$script:ReviewSpecialists){@($script:ReviewSpecialists)}else{@()})
    api_calls=$script:ApiCalls
    review=$script:Review
    published_draft_pr=$script:PublishedPr
    github_writes=$script:GitHubWrites
    passed=$Passed
    failure=$script:Failure
    guarantees=@{merged_main=$false;deployed=$false;force_push=$false}
  }|ConvertTo-Json -Depth 80|Set-Content -LiteralPath $ReportPath -Encoding UTF8
  Log "Rat Review report: $ReportPath" 'Cyan'
}

trap {
  $script:Failure=[ordered]@{
    reason=$_.Exception.Message
    type=$_.Exception.GetType().FullName
    stack="$($_.ScriptStackTrace)"
    position="$($_.InvocationInfo.PositionMessage)"
  }
  Write-FinalReport $false
  Log ("RAT REVIEW FAILED CLOSED: "+$script:Failure.reason) 'Red'
  exit 2
}

Log "`nSITEBOSS REPAIR RAT REVIEW v0.2-controller-target" 'Cyan'
Log 'CLEAN RETEST -> INDEPENDENT REVIEW -> CONTROLLER REVIEW-ONLY / DRAFT-CHILD CAPABLE' 'Green'
Log ("Reviewer provider={0}; repeat count={1}"-f$Config.ReviewerProvider,$RepeatCount) 'DarkGray'

$reportFile=Find-RepairRatReport
$rat=Get-Content -LiteralPath $reportFile -Raw|ConvertFrom-Json
if("$($rat.passed)"-ne'True'){throw 'Repair Rat report is not a successful repair'}
if("$($rat.repair_pr)"-ne"$RepairPullRequest"){throw 'Repair Rat report PR mismatch'}
$sourceRepo="$($rat.local_workspace)"
$localCommit="$($rat.local_commit)"
$exactHead="$($rat.exact_head)"
if(-not[string]::IsNullOrWhiteSpace($TargetSha)-and$exactHead-ne$TargetSha){
 throw "Repair Rat report target mismatch: expected $TargetSha got $exactHead"
}
if(-not(Test-Path -LiteralPath $sourceRepo)){throw "Repair Rat local workspace no longer exists: $sourceRepo"}
if(-not$localCommit-or-not$exactHead){throw 'Repair Rat report lacks local_commit/exact_head'}
$script:LocalCommit=$localCommit
$script:ExactHead=$exactHead
Log "Successful Repair Rat report: $reportFile" 'Green'
Log "Candidate local commit: $localCommit" 'Green'

# Verify local commit ancestry and immutability before GitHub/API review.
$r=Run 'git.exe' @('cat-file','-e',"$localCommit^{commit}") $sourceRepo
if($r.exit_code-ne0){throw "Local repair commit missing from workspace: $localCommit"}
$r=Run 'git.exe' @('rev-parse',"$localCommit^") $sourceRepo
if($r.exit_code-ne0){throw "Cannot resolve repair commit parent: $($r.stderr)"}
if($r.stdout.Trim()-ne$exactHead){throw "Repair commit parent is not exact PR head: expected $exactHead got $($r.stdout.Trim())"}

$auth=New-GitHubToken
$token="$($auth.token)"
$contents="$(Optional $auth.permissions 'contents')"
$pulls="$(Optional $auth.permissions 'pull_requests')"
if($contents-ne'write'-or$pulls-ne'write'){throw "Publication needs contents/pull_requests write; got contents=$contents pulls=$pulls"}

if([string]::IsNullOrWhiteSpace($TargetSha)){
 $pr=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$RepairPullRequest" $token
 if("$($pr.state)"-ne'open'){throw "PR #$RepairPullRequest is not open"}
 $prHead=Optional $pr 'head';if($null-eq$prHead){throw 'Parent repair PR missing head'}
 $baseBranch="$(Optional $prHead 'ref')"
 $currentHead="$(Optional $prHead 'sha')"
 if($currentHead-ne$exactHead){throw "PR #$RepairPullRequest moved: expected $exactHead got $currentHead"}
}else{
 if($RootPullRequest-lt1){throw 'RootPullRequest is required with TargetSha'}
 $pr=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$RootPullRequest" $token
 if("$($pr.state)"-ne'open'){throw "Root PR #$RootPullRequest is not open"}
 $prHead=Optional $pr 'head';if($null-eq$prHead){throw 'Root PR missing head'}
 $baseBranch="$(Optional $prHead 'ref')"
 $currentHead="$(Optional $prHead 'sha')"
 if($currentHead-ne$exactHead){throw "Root PR #$RootPullRequest moved: expected $exactHead got $currentHead"}
}
if($baseBranch-in@('main','master','develop','production','release')){throw "REFUSED protected target branch: $baseBranch"}

# Fresh case-sensitive verification workspace.
Assert-CaseSensitive $Config.WorkspaceRoot
$clean=Join-Path $Config.WorkspaceRoot "$Stamp\repo"
New-Item -ItemType Directory -Force -Path (Split-Path $clean -Parent)|Out-Null
$script:CleanWorkspace=$clean
$r=Run 'git.exe' @('clone','--no-checkout','--filter=blob:none',$Config.RepoUrl,$clean)
if($r.exit_code-ne0){throw "Clean clone failed: $($r.stderr)"}
[void](Run 'git.exe' @('config','--local','core.autocrlf','false') $clean)
[void](Run 'git.exe' @('config','--local','core.safecrlf','false') $clean)
$r=Run 'git.exe' @('fetch','--no-tags','origin',$exactHead) $clean
if($r.exit_code-ne0){throw "Fetch parent head failed: $($r.stderr)"}
# Fetch candidate commit from the local Repair Rat workspace, not GitHub.
$r=Run 'git.exe' @('fetch','--no-tags',$sourceRepo,$localCommit) $clean
if($r.exit_code-ne0){throw "Fetch local candidate into clean clone failed: $($r.stderr)"}
$r=Run 'git.exe' @('checkout','--detach',$localCommit) $clean
if($r.exit_code-ne0){throw "Clean candidate checkout failed: $($r.stderr)"}
Assert-Clean $clean 'clean candidate checkout'
Log 'Clean candidate workspace: PRISTINE' 'Green'

# Deterministic tests BEFORE paid review.
$rounds=[System.Collections.Generic.List[object]]::new()
for($validationRound=1;$validationRound-le$ValidationRounds;$validationRound++){
  Log ("CLEAN RECONSTRUCTION ROUND {0}/{1}"-f$validationRound,$ValidationRounds) 'Cyan'
  [void]$rounds.Add((Run-Acceptance $clean))
}
$allRuns=@();foreach($round in $rounds){$allRuns+=@($round.runs)}
$allFailures=@($allRuns|Where-Object{$_.exit_code-ne0})
$accept=[pscustomobject]@{passed=($allFailures.Count-eq0);failure_count=$allFailures.Count;validation_rounds=@($rounds);runs=@($allRuns)}
$script:Acceptance=$accept
if(-not$accept.passed){
  Write-FinalReport $false
  Log 'CLEAN ACCEPTANCE FAILED - no review call and no GitHub publication.' 'Red'
  exit 2
}
Log 'CLEAN ACCEPTANCE: ALL GATES PASS' 'Green'

# Exact diff and independent review.
$r=Run 'git.exe' @('diff','--no-ext-diff','--binary',"$exactHead..$localCommit",'--') $clean
if($r.exit_code-ne0){throw "Exact diff failed: $($r.stderr)"}
$diff=$r.stdout
if([string]::IsNullOrWhiteSpace($diff)){throw 'Candidate diff is empty'}
if($diff.Length-gt220000){throw "Candidate diff too large for one bounded review: $($diff.Length) chars"}
$diffHash=Sha256Text $diff
Log "Exact candidate diff chars=$($diff.Length); SHA256=$diffHash" 'DarkGray'

$review=Get-OrCreateReview $diff $diffHash $rat $accept
$script:Review=$review
Log ("INDEPENDENT REVIEW: "+$review.verdict) $(if($review.verdict-eq'PASS'){'Green'}else{'Yellow'})
Log "$($review.summary)"

if("$($review.verdict)"-ne'PASS'){
  Write-FinalReport $false
  Log 'Review did not PASS. Nothing was pushed.' 'Yellow'
  exit 2
}

if($NoPublish){
 Write-FinalReport $true
 Log "`nREPAIR RAT REVIEW: PASS - CONTROLLER REVIEW-ONLY MODE" 'Green'
 Log 'No branch push or draft PR publication was attempted.' 'Green'
 exit 0
}

# Re-read the exact authoritative parent immediately before publication.
$publicationParentPr=$(if([string]::IsNullOrWhiteSpace($TargetSha)){$RepairPullRequest}else{$RootPullRequest})
$pr2=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$publicationParentPr" $token
$h2=Optional $pr2 'head'
if("$($pr2.state)"-ne'open'-or"$((Optional $h2 'sha'))"-ne$exactHead-or"$((Optional $h2 'ref'))"-ne$baseBranch){
  throw "Authoritative parent PR #$publicationParentPr moved after review; refusing publication"
}

$branch="repair-rat/review-pr$publicationParentPr-$($localCommit.Substring(0,12))"

# Duplicate-safe branch/PR check.
$encoded=[Uri]::EscapeDataString("heads/$branch")
$existingRef=$null
try{$existingRef=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/matching-refs/$encoded" $token}catch{}
$exactRef=@($existingRef|Where-Object{"$($_.ref)"-eq"refs/heads/$branch"})
if($exactRef.Count-gt0-and"$($exactRef[0].object.sha)"-ne$localCommit){
  throw "Deterministic publication branch already exists at a different SHA: $branch"
}

if($exactRef.Count-eq0){
  Push-ReviewedCommit $sourceRepo $localCommit $branch $token
  Log "Pushed reviewed candidate branch: $branch" 'Green'
}else{
  Log "Reviewed candidate branch already exists at exact commit: $branch" 'Green'
}

$headQuery=[Uri]::EscapeDataString("$($Config.Owner):$branch")
$existing=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls?state=open&head=$headQuery&base=$([Uri]::EscapeDataString($baseBranch))&per_page=20" $token
$matches=@($existing)
if($matches.Count-gt0){
  $script:PublishedPr=[int]$matches[0].number
  Log "DRAFT CHILD PR ALREADY EXISTS: #$($script:PublishedPr)" 'Green'
}else{
  $body=@"
Repair Rat Review independently verified local candidate `$localCommit` against exact authoritative parent PR #$publicationParentPr head `$exactHead`.

Clean acceptance:
- npm test
- PostgreSQL migrate
- business invitations x$RepeatCount
- production HTTP x$RepeatCount
- Travis intake x$RepeatCount
- full PostgreSQL suite x2
- rollback -> migrate

Independent review provider: $($Config.ReviewerProvider)
Verdict: PASS
Exact diff SHA256: $diffHash

This PR targets authoritative parent PR #$publicationParentPr's head branch `$baseBranch`.
It does NOT target or merge main and does not deploy.
"@
  $created=GHPost "/repos/$($Config.Owner)/$($Config.Repo)/pulls" $token @{
    title="Repair Rat reviewed batch repair for PR #$RepairPullRequest"
    head=$branch
    base=$baseBranch
    body=$body
    draft=$true
  }
  $script:PublishedPr=[int]$created.number
  Log "DRAFT CHILD PR CREATED: #$($script:PublishedPr)" 'Green'
}

Write-FinalReport $true
Log "`nREPAIR RAT REVIEW: PASS + DRAFT PUBLICATION COMPLETE" 'Green'
Log "Draft child PR: #$($script:PublishedPr)" 'Green'
Log 'NO merge to main. NO deployment.' 'Green'
exit 0
