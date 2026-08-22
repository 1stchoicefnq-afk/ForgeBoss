param([int]$RepairPullRequest=525,[int]$RepeatCount=5)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Root=$PSScriptRoot
$Out=Join-Path $Root 'state\repair-lab'
New-Item -ItemType Directory -Force -Path $Out|Out-Null
$stamp=[DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')
$reportPath=Join-Path $Out "repair-lab-$stamp.json"
$caseRoot=Join-Path $env:USERPROFILE '.siteboss\autopilot\case-sensitive-repair-workspaces'
$repo=Join-Path $caseRoot "repair-lab-$stamp\repo"
$nodeImage='node:22-bookworm'
$pgImage='postgres:17-alpine'
$results=[System.Collections.Generic.List[object]]::new()
$script:ExactHead=$null

trap {
  $fatal=[ordered]@{
    stage='repair_lab_runtime'
    reason=$_.Exception.Message
    exception_type=$_.Exception.GetType().FullName
    script_stack="$($_.ScriptStackTrace)"
    position="$($_.InvocationInfo.PositionMessage)"
  }

  $summary=@{}
  foreach($name in @($results.test|Select-Object -Unique)){
    $rows=@($results|Where-Object{$_.test-eq$name})
    $summary[$name]=@{
      runs=$rows.Count
      passes=@($rows|Where-Object{$_.exit_code-eq0}).Count
      failures=@($rows|Where-Object{$_.exit_code-ne0}).Count
    }
  }

  $failureReport=[ordered]@{
    schema=2
    mode='repair-lab-readonly'
    generated_at=[DateTimeOffset]::UtcNow.ToString('o')
    repair_pr=$RepairPullRequest
    exact_head=$script:ExactHead
    repeat_count=$RepeatCount
    completed=$false
    fatal_failure=$fatal
    guarantees=@{
      openai_calls=0
      anthropic_calls=0
      github_repo_writes=0
      pushes=0
      pr_updates=0
      ref_updates=0
      merges=0
      deploys=0
    }
    summary=$summary
    results=@($results)
  }

  $failureReport|ConvertTo-Json -Depth 40|Set-Content -LiteralPath $reportPath -Encoding UTF8
  Write-Host "`nREPAIR LAB FAILED - REPORT WRITTEN" -ForegroundColor Red
  Write-Host "Reason: $($fatal.reason)" -ForegroundColor Red
  Write-Host "Report: $reportPath" -ForegroundColor Yellow
  Write-Host 'OpenAI=0 | Anthropic=0 | GitHub writes=0' -ForegroundColor Green
  exit 2
}

function Run([string]$exe,[string[]]$CommandArgs,[string]$cwd=''){
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName=$exe;$psi.UseShellExecute=$false;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true;$psi.CreateNoWindow=$true
  if($cwd){$psi.WorkingDirectory=$cwd}
  foreach($a in $CommandArgs){[void]$psi.ArgumentList.Add([string]$a)}
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi
  try{
    if(-not$p.Start()){throw "Failed to start $exe"}
    $o=$p.StandardOutput.ReadToEnd();$e=$p.StandardError.ReadToEnd();$p.WaitForExit()
    [pscustomobject]@{exit_code=$p.ExitCode;stdout=$o;stderr=$e}
  }finally{$p.Dispose()}
}
function Record([string]$name,[int]$iteration,$r){
  $combined="$($r.stdout)`n$($r.stderr)"
  $lines=@($combined -split "`r?`n")
  $failures=@($lines|Where-Object{$_-match'(?i)not ok|error:|code: .40001.|500 !== 201|AssertionError|serialize access|Trade pack fencing'})
  [void]$results.Add([pscustomobject]@{
    test=$name;iteration=$iteration;exit_code=$r.exit_code
    failure_lines=@($failures|Select-Object -First 120)
    output_tail=@($lines|Select-Object -Last ([Math]::Min(100,$lines.Count)))
  })
  $status=$(if($r.exit_code-eq0){'PASS'}else{'FAIL'})
  Write-Host "[$status] $name iteration $iteration"
}

Write-Host "`nSITEBOSS REPAIR LAB v1.0-alpha27" -ForegroundColor Cyan
Write-Host 'NON-LIVE - zero model calls, zero GitHub writes.' -ForegroundColor Green
Write-Host "Repair PR #$RepairPullRequest | repeats=$RepeatCount"

# Read exact PR head with gh-free GitHub App logic borrowed from diagnostics by invoking it only for read state is avoided here:
# fetch PR ref directly, then resolve exact remote SHA.
New-Item -ItemType Directory -Force -Path (Split-Path $repo -Parent)|Out-Null
$r=Run 'git.exe' @('clone','--no-checkout','--filter=blob:none',"https://github.com/1stchoicefnq-afk/siteboss-monster.git",$repo)
if($r.exit_code-ne0){throw "clone failed: $($r.stderr)"}
[void](Run 'git.exe' @('config','--local','core.autocrlf','false') $repo)
[void](Run 'git.exe' @('config','--local','core.safecrlf','false') $repo)
$r=Run 'git.exe' @('fetch','origin',"pull/$RepairPullRequest/head:refs/remotes/origin/repair-lab-target") $repo
if($r.exit_code-ne0){throw "fetch PR failed: $($r.stderr)"}
$r=Run 'git.exe' @('rev-parse','refs/remotes/origin/repair-lab-target') $repo
if($r.exit_code-ne0){throw "resolve PR head failed: $($r.stderr)"}
$head=$r.stdout.Trim()
$script:ExactHead=$head
$r=Run 'git.exe' @('checkout','--detach',$head) $repo
if($r.exit_code-ne0){throw "checkout failed: $($r.stderr)"}
Write-Host "Exact repair head: $head"

$network=("sb_lab_net_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
$pg=("sb_lab_pg_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
$ws=("sb_lab_ws_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()
$user='siteboss';$db='siteboss_test';$pass='siteboss_test_password'
$dburl="postgresql://${user}:${pass}@postgres:5432/$db"

try{
  foreach($img in @($nodeImage,$pgImage)){
    $q=Run 'docker.exe' @('image','inspect',$img)
    if($q.exit_code-ne0){throw "Missing Docker image $img"}
  }
  [void](Run 'docker.exe' @('network','create',$network))
  [void](Run 'docker.exe' @('volume','create',$ws))
  $r=Run 'docker.exe' @('run','-d','--rm','--name',$pg,'--network',$network,'--network-alias','postgres',
    '-e',"POSTGRES_DB=$db",'-e',"POSTGRES_USER=$user",'-e',"POSTGRES_PASSWORD=$pass",$pgImage)
  if($r.exit_code-ne0){throw "postgres start failed: $($r.stderr)"}
  $ready=$false
  for($i=1;$i-le30;$i++){
    $q=Run 'docker.exe' @('exec',$pg,'pg_isready','-U',$user,'-d',$db)
    if($q.exit_code-eq0){$ready=$true;break};Start-Sleep 1
  }
  if(-not$ready){throw 'postgres readiness timeout'}

  # Stage/install only. Do not run DB commands until DATABASE_URL is explicitly present.
  $r=Run 'docker.exe' @('run','--rm','--network',$network,
    '--mount',"type=bind,src=$repo,dst=/source,readonly",'--mount',"type=volume,src=$ws,dst=/workspace",
    '-e','npm_config_cache=/tmp/npm-cache','--tmpfs','/tmp','-w','/workspace',$nodeImage,
    'sh','-lc','cp -a /source/. /workspace/ && npm ci --ignore-scripts --no-audit --no-fund')
  if($r.exit_code-ne0){throw "workspace setup failed: $($r.stdout) $($r.stderr)"}

  # Initial migration is DB-aware and therefore gets DATABASE_URL.
  $r=Run 'docker.exe' @('run','--rm','--network',$network,'--mount',"type=volume,src=$ws,dst=/workspace",
    '-e',"DATABASE_URL=$dburl",'-e','NODE_ENV=test','-w','/workspace',$nodeImage,
    'sh','-lc','npm run db:migrate')
  Record 'initial_db_migrate' 1 $r
  if($r.exit_code-ne0){throw "initial database migration failed: $($r.stdout) $($r.stderr)"}

  $tests=@(
    @{name='business_invitations';cmd='RUN_POSTGRES_INTEGRATION=1 node --test tests/postgresBusinessInvitations.integration.test.js'},
    @{name='production_http';cmd='RUN_POSTGRES_INTEGRATION=1 node --test tests/postgresProductionHttp.integration.test.js'},
    @{name='travis_intake';cmd='RUN_POSTGRES_INTEGRATION=1 node --test tests/postgresTravisIntake.integration.test.js'}
  )

  foreach($t in $tests){
    for($i=1;$i-le$RepeatCount;$i++){
      $r=Run 'docker.exe' @('run','--rm','--network',$network,'--mount',"type=volume,src=$ws,dst=/workspace",
        '-e',"DATABASE_URL=$dburl",'-e','NODE_ENV=test','-e','RUN_POSTGRES_INTEGRATION=1','-w','/workspace',$nodeImage,
        'sh','-lc',$t.cmd)
      Record $t.name $i $r
    }
  }

  # Full suite repeated twice to expose interactions/concurrency that isolated tests may miss.
  for($i=1;$i-le2;$i++){
    $r=Run 'docker.exe' @('run','--rm','--network',$network,'--mount',"type=volume,src=$ws,dst=/workspace",
      '-e',"DATABASE_URL=$dburl",'-e','NODE_ENV=test','-e','RUN_POSTGRES_INTEGRATION=1','-w','/workspace',$nodeImage,
      'sh','-lc','node --test tests/postgres*.integration.test.js')
    Record 'full_postgres_suite' $i $r
  }

  # Migration round-trip remains part of acceptance evidence.
  foreach($cmd in @('npm run db:rollback','npm run db:migrate')){
    $r=Run 'docker.exe' @('run','--rm','--network',$network,'--mount',"type=volume,src=$ws,dst=/workspace",
      '-e',"DATABASE_URL=$dburl",'-w','/workspace',$nodeImage,'sh','-lc',$cmd)
    Record ("migration_"+($cmd-replace'[^A-Za-z0-9]+','_')) 1 $r
  }
}finally{
  try{[void](Run 'docker.exe' @('rm','-f',$pg))}catch{}
  try{[void](Run 'docker.exe' @('volume','rm','-f',$ws))}catch{}
  try{[void](Run 'docker.exe' @('network','rm',$network))}catch{}
}

$summary=@{}
foreach($name in @($results.test|Select-Object -Unique)){
  $rows=@($results|Where-Object{$_.test-eq$name})
  $summary[$name]=@{runs=$rows.Count;passes=@($rows|Where-Object{$_.exit_code-eq0}).Count;failures=@($rows|Where-Object{$_.exit_code-ne0}).Count}
}
$report=[ordered]@{
  schema=2;mode='repair-lab-readonly';generated_at=[DateTimeOffset]::UtcNow.ToString('o')
  repair_pr=$RepairPullRequest;exact_head=$head;repeat_count=$RepeatCount;completed=$true;fatal_failure=$null
  guarantees=@{openai_calls=0;anthropic_calls=0;github_repo_writes=0;pushes=0;pr_updates=0;ref_updates=0;merges=0;deploys=0}
  summary=$summary;results=@($results)
}
$report|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Host "`nREPAIR LAB COMPLETE" -ForegroundColor Cyan
foreach($k in $summary.Keys){Write-Host ("{0}: runs={1} pass={2} fail={3}"-f$k,$summary[$k].runs,$summary[$k].passes,$summary[$k].failures)}
Write-Host "Report: $reportPath"
Write-Host 'OpenAI=0 | Anthropic=0 | GitHub writes=0' -ForegroundColor Green
if(@($results|Where-Object{$_.exit_code-ne0}).Count-gt0){exit 2}
exit 0
