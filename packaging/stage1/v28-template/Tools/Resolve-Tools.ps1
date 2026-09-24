param([string]$Output)
$ErrorActionPreference='Stop'
function Sha([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function FirstExisting([string[]]$items){foreach($p in $items){if($p -and (Test-Path -LiteralPath $p -PathType Leaf)){return (Resolve-Path -LiteralPath $p).Path}};return $null}
$git=FirstExisting @(
  (Join-Path $env:ProgramFiles 'Git\cmd\git.exe'),
  (Join-Path $env:ProgramFiles 'Git\bin\git.exe')
)
if(!$git){throw 'TRUSTED_GIT_NOT_FOUND'}
$docker=FirstExisting @(
  (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'),
  (Join-Path $env:ProgramFiles 'Docker\Docker\resources\docker.exe')
)
if(!$docker){throw 'TRUSTED_DOCKER_NOT_FOUND'}
$pythonCandidates=@()
foreach($base in @('HKLM:\SOFTWARE\Python\PythonCore\3.13\InstallPath','HKCU:\SOFTWARE\Python\PythonCore\3.13\InstallPath')){
  try{
    $k=Get-ItemProperty -LiteralPath $base -ErrorAction Stop
    if($k.ExecutablePath){$pythonCandidates += [string]$k.ExecutablePath}
    $d=(Get-Item -LiteralPath $base -ErrorAction SilentlyContinue).GetValue('')
    if($d){$pythonCandidates += (Join-Path ([string]$d) 'python.exe')}
  }catch{}
}
$pythonCandidates += @(
  (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'),
  (Join-Path $env:ProgramFiles 'Python313\python.exe')
)
$python=FirstExisting $pythonCandidates
if(!$python){throw 'PYTHON_3_13_NOT_FOUND'}
$pv=& $python -I -S -c "import sys;print('%d.%d'%sys.version_info[:2])"
if($LASTEXITCODE -ne 0 -or $pv.Trim() -ne '3.13'){throw 'PYTHON_3_13_REQUIRED'}
$node=FirstExisting @((Join-Path $env:ProgramFiles 'nodejs\node.exe'))
$payload=[ordered]@{
 schema=1
 git=@{path=$git;sha256=(Sha $git);size=(Get-Item $git).Length}
 docker=@{path=$docker;sha256=(Sha $docker);size=(Get-Item $docker).Length}
 python=@{path=$python;sha256=(Sha $python);size=(Get-Item $python).Length}
 node=$(if($node){@{path=$node;sha256=(Sha $node);size=(Get-Item $node).Length}}else{$null})
}
$json=$payload|ConvertTo-Json -Depth 5 -Compress
if($Output){
  $dir=Split-Path -Parent $Output;if($dir){New-Item -ItemType Directory -Force -Path $dir|Out-Null}
  $json|Set-Content -LiteralPath $Output -Encoding UTF8
}
$json
