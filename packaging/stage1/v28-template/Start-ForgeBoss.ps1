param(
 [string]$InstalledState=(Join-Path $env:LOCALAPPDATA 'ForgeBoss\stage1-installed.json'),
 [switch]$AuthorityOnly
)
$ErrorActionPreference='Stop'
function Sha([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function AssertFileHash([string]$path,[string]$want,[string]$label){
 if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw "$label missing"}
 if((Sha $path) -ne $want.ToLowerInvariant()){throw "$label identity changed"}
}
$s=Get-Content -LiteralPath $InstalledState -Raw | ConvertFrom-Json
$EngineRoot=(Resolve-Path -LiteralPath $s.engineRoot).Path
$RuntimePy=(Resolve-Path -LiteralPath $s.runtimePython).Path
AssertFileHash $RuntimePy ([string]$s.runtimePythonSha256) 'runtime python'
AssertFileHash ([string]$s.git.path) ([string]$s.git.sha256) 'git.exe'
AssertFileHash ([string]$s.docker.path) ([string]$s.docker.sha256) 'docker.exe'
if($null -ne $s.node){AssertFileHash ([string]$s.node.path) ([string]$s.node.sha256) 'node.exe'}
if($PSCommandPath){AssertFileHash $PSCommandPath ([string]$s.launcherFiles.start) 'Start-ForgeBoss.ps1'}
$authorityHost=Join-Path $s.launcherRoot 'authority_user_host.py'
$diag=Join-Path $s.launcherRoot 'authority_diagnose.py'
AssertFileHash $authorityHost ([string]$s.launcherFiles.host) 'authority host'
AssertFileHash $diag ([string]$s.launcherFiles.diagnose) 'authority diagnose'

# Installed state is authoritative. Replace any stale inherited value before the gate.
$env:FORGEBOSS_ENGINE_ROOT=$EngineRoot
& $RuntimePy -I -B (Join-Path $EngineRoot 'packaging\stage1\stage1_gate.py') $InstalledState
if($LASTEXITCODE -ne 0){throw 'ENGINE_IDENTITY_GATE_FAILED'}

$clientCfg=Get-Content -LiteralPath (Join-Path $s.clientRoot 'client-config.json') -Raw | ConvertFrom-Json
if([string]$clientCfg.pipeName -ne [string]$s.authorityPipe){throw 'AUTHORITY_PIPE_CONFIG_MISMATCH'}
$env:FORGEBOSS_AUTHORITY_PEER_KEY=$clientCfg.peerKeyFile
$env:FORGEBOSS_AUTHORITY_RECEIPT_PUBLIC_KEY=$clientCfg.receiptPublicKeyFile
$env:FORGEBOSS_AUTHORITY_PEER_ID=$clientCfg.peerId
$env:FORGEBOSS_AUTHORITY_PIPE_NAME=$clientCfg.pipeName
$env:FORGEBOSS_CONTROL_REVISION=[string]$clientCfg.controlRevision
$env:FORGEBOSS_ENGINE_ROOT=$EngineRoot
$env:FORGEBOSS_STATE_ROOT=$s.stateRoot
$env:FORGEBOSS_MINISWE_IMAGE=$s.builderImage
$env:FORGEBOSS_TRUSTED_DOCKER_PATH=$s.docker.path
$env:FORGEBOSS_TRUSTED_DOCKER_SHA256=$s.docker.sha256
$env:PYTHONNOUSERSITE='1'
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTHONUTF8='1'

$dirs=@(
 (Split-Path $RuntimePy -Parent),
 (Split-Path ([string]$s.git.path) -Parent),
 (Split-Path ([string]$s.docker.path) -Parent),
 (Join-Path $env:SystemRoot 'System32'),
 $env:SystemRoot
)
if($null -ne $s.node){$dirs += (Split-Path ([string]$s.node.path) -Parent)}
$env:PATH=($dirs|Where-Object{$_ -and (Test-Path -LiteralPath $_)}|Select-Object -Unique)-join ';'

function Diagnose(){
 $raw=& $RuntimePy -I -B $diag --installed $InstalledState 2>&1
 $text=($raw|Out-String).Trim()
 try{return ($text|ConvertFrom-Json)}
 catch{return [pscustomobject]@{ok=$false;code='DIAGNOSTIC_PARSE_FAILED';detail=$text}}
}

$d=Diagnose
if(-not $d.ok){
 Start-Process -FilePath $RuntimePy -ArgumentList @('-I','-B',$authorityHost,'--installed',$InstalledState) -WindowStyle Hidden | Out-Null
 $last=$null
 for($i=0;$i -lt 80;$i++){
  Start-Sleep -Milliseconds 250
  $last=Diagnose
  if($last.ok){break}
  if($last.code -and $last.code -notin @('IPC_CONNECT_FAILED','IPC_READ_FAILED','IPC_PREAUTH_TIMEOUT','IPC_CLIENT_DISCONNECTED')){break}
 }
 if(-not $last.ok){
  $log=Join-Path $s.protectedRoot 'authority-user.log'
  $tail=if(Test-Path -LiteralPath $log){(Get-Content -LiteralPath $log -Tail 80|Out-String)}else{'<no authority log>'}
  $nl=[Environment]::NewLine
  throw ('Protected authority did not become ready.'+$nl+'Diagnostic: '+($last|ConvertTo-Json -Compress)+$nl+'Log:'+$nl+$tail)
 }
 $d=$last
}
Write-Host ("[PASS] Protected authority ready trust="+$d.trustGrade+" revision="+$d.revision)
if($AuthorityOnly){exit 0}

$dash=Join-Path $EngineRoot 'dashboard\pro_shell.py'
Start-Process -FilePath $RuntimePy -ArgumentList @('-I','-B',$dash) -WorkingDirectory $EngineRoot -WindowStyle Hidden | Out-Null
