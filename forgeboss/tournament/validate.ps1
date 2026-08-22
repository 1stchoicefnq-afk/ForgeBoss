param(
 [Parameter(Mandatory=$true)][string]$Repo,
 [Parameter(Mandatory=$true)][string]$Out
)
$ErrorActionPreference='Stop'
$net=("fb_net_"+[Guid]::NewGuid().ToString('N').Substring(0,8)).ToLowerInvariant()
$pg=("fb_pg_"+[Guid]::NewGuid().ToString('N').Substring(0,8)).ToLowerInvariant()
$ws=("fb_ws_"+[Guid]::NewGuid().ToString('N').Substring(0,8)).ToLowerInvariant()
$u='siteboss';$db='siteboss_test';$pw='siteboss_test_password'
$url="postgresql://${u}:${pw}@postgres:5432/$db"
$runs=[System.Collections.Generic.List[object]]::new()
function D([Parameter(Mandatory=$true)][string[]]$DockerArgs){
 if($null-eq$DockerArgs-or$DockerArgs.Count-eq0){throw 'docker argument list is empty'}
 $o=Join-Path $env:TEMP ("fb-o-"+[Guid]::NewGuid().ToString('N')+".txt")
 $e=Join-Path $env:TEMP ("fb-e-"+[Guid]::NewGuid().ToString('N')+".txt")
 $oldEap=$ErrorActionPreference
 $nativeVar=Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue
 $oldNative=$null
 try{
   # npm/docker can legitimately write notices to STDERR while returning exit code 0.
   # Do NOT allow PowerShell to reinterpret that STDERR text as a terminating
   # NativeCommandError. Docker's real process exit code remains authoritative.
   $ErrorActionPreference='Continue'
   if($nativeVar){
     $oldNative=$PSNativeCommandUseErrorActionPreference
     $PSNativeCommandUseErrorActionPreference=$false
   }

   & docker.exe @DockerArgs 1>$o 2>$e
   $c=$LASTEXITCODE

   [pscustomobject]@{
     code=$c
     stdout=$(if(Test-Path $o){Get-Content $o -Raw}else{''})
     stderr=$(if(Test-Path $e){Get-Content $e -Raw}else{''})
   }
 }finally{
   if($nativeVar){$PSNativeCommandUseErrorActionPreference=$oldNative}
   $ErrorActionPreference=$oldEap
   Remove-Item -LiteralPath $o,$e -Force -ErrorAction SilentlyContinue
 }
}

function Step([string]$Name,[string]$Cmd,[bool]$DbAware=$true){
 $a=@('run','--rm','--network',$net,'--mount',"type=volume,src=$ws,dst=/workspace",'-e','NODE_ENV=test','-w','/workspace','node:22-bookworm','sh','-lc',$Cmd)
 if($DbAware){$a=@('run','--rm','--network',$net,'--mount',"type=volume,src=$ws,dst=/workspace",'-e',"DATABASE_URL=$url",'-e','NODE_ENV=test','-e','RUN_POSTGRES_INTEGRATION=1','-w','/workspace','node:22-bookworm','sh','-lc',$Cmd)}
 $x=D $a;$all="$($x.stdout)`n$($x.stderr)";[void]$runs.Add([pscustomobject]@{name=$Name;exit_code=$x.code;tail=@(($all-split"`r?`n")|Select-Object -Last 60)})
 Write-Host "[$(if($x.code-eq0){'PASS'}else{'FAIL'})] $Name";return $x.code
}
try{
 foreach($img in @('node:22-bookworm','postgres:17-alpine')){if((D @('image','inspect',$img)).code-ne0){throw "Missing image $img"}}
 if((D @('network','create',$net)).code-ne0){throw 'network create failed'}
 if((D @('volume','create',$ws)).code-ne0){throw 'volume create failed'}
 if((D @('run','-d','--rm','--name',$pg,'--network',$net,'--network-alias','postgres','-e',"POSTGRES_DB=$db",'-e',"POSTGRES_USER=$u",'-e',"POSTGRES_PASSWORD=$pw",'postgres:17-alpine')).code-ne0){throw 'postgres start failed'}
 $ready=$false;for($i=0;$i-lt30;$i++){if((D @('exec',$pg,'pg_isready','-U',$u,'-d',$db)).code-eq0){$ready=$true;break};Start-Sleep 1};if(-not$ready){throw 'postgres readiness timeout'}
 $copy=D @('run','--rm','--network',$net,'--mount',"type=bind,src=$Repo,dst=/source,readonly",'--mount',"type=volume,src=$ws,dst=/workspace",'-e','npm_config_cache=/tmp/npm-cache','--tmpfs','/tmp','-w','/workspace','node:22-bookworm','sh','-lc','cp -a /source/. /workspace/ && npm ci --ignore-scripts --no-audit --no-fund')
 if($copy.code-ne0){throw "npm ci failed $($copy.stderr)"}
 [void](Step 'npm_test' 'npm test' $false)
 [void](Step 'initial_migrate' 'npm run db:migrate' $true)
 [void](Step 'business_invitations' 'node --test tests/postgresBusinessInvitations.integration.test.js' $true)
 [void](Step 'production_http' 'node --test tests/postgresProductionHttp.integration.test.js' $true)
 [void](Step 'travis_intake' 'node --test tests/postgresTravisIntake.integration.test.js' $true)
 [void](Step 'full_postgres_suite' 'node --test tests/postgres*.integration.test.js' $true)
 [void](Step 'rollback' 'npm run db:rollback' $true)
 [void](Step 'migrate_again' 'npm run db:migrate' $true)
 $fails=@($runs|Where-Object{$_.exit_code-ne0})
 $obj=[ordered]@{schema=1;passed=($fails.Count-eq0);failure_count=$fails.Count;runs=@($runs)}
 $obj|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $Out -Encoding utf8
 exit $(if($fails.Count-eq0){0}else{2})
}finally{
 try{[void](D @('rm','-f',$pg))}catch{};try{[void](D @('volume','rm','-f',$ws))}catch{};try{[void](D @('network','rm',$net))}catch{}
}
