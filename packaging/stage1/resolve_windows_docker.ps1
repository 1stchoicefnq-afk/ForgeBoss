param(
  [string]$InstalledState,
  [switch]$PrintPath
)
$ErrorActionPreference='Stop'

function Normalize-Path([string]$Path) {
  return [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path)
}
function Is-Under([string]$Path,[string]$Root) {
  if([string]::IsNullOrWhiteSpace($Root)){ return $false }
  $p=[IO.Path]::GetFullPath($Path).TrimEnd('\\')+'\\'
  $r=[IO.Path]::GetFullPath($Root).TrimEnd('\\')+'\\'
  return $p.StartsWith($r,[StringComparison]::OrdinalIgnoreCase)
}
function Add-Candidate([System.Collections.Generic.List[string]]$List,[string]$Path) {
  if([string]::IsNullOrWhiteSpace($Path)){ return }
  $p=$Path.Trim().Trim('"')
  if($p -match ',\d+$'){ $p=$p -replace ',\d+$','' }
  if((Split-Path -Leaf $p) -ieq 'Docker Desktop.exe'){
    $p=Join-Path (Split-Path -Parent $p) 'resources\bin\docker.exe'
  } elseif((Split-Path -Leaf $p) -ine 'docker.exe') {
    $p=Join-Path $p 'resources\bin\docker.exe'
  }
  if(-not $List.Contains($p)){ [void]$List.Add($p) }
}
function Assert-DockerBinary([string]$Path) {
  $resolved=Normalize-Path $Path
  $item=Get-Item -LiteralPath $resolved -ErrorAction Stop
  if($item.PSIsContainer -or $item.Name -ine 'docker.exe'){ throw 'DOCKER_PATH_INVALID' }
  $machineTrusted=(Is-Under $resolved $env:ProgramFiles) -or (Is-Under $resolved ${env:ProgramFiles(x86)})
  if(-not $machineTrusted){
    $sig=Get-AuthenticodeSignature -FilePath $resolved
    $subject=if($sig.SignerCertificate){[string]$sig.SignerCertificate.Subject}else{''}
    if($sig.Status -ne 'Valid' -or $subject -notmatch '(?i)Docker'){
      throw 'DOCKER_USER_PATH_NOT_AUTHENTICODE_TRUSTED'
    }
  }
  $hash=(Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
  return [pscustomobject]@{path=$resolved;sha256=$hash;size=[int64]$item.Length;machineTrusted=$machineTrusted}
}

$candidates=New-Object 'System.Collections.Generic.List[string]'
Add-Candidate $candidates (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe')
if(${env:ProgramFiles(x86)}){ Add-Candidate $candidates (Join-Path ${env:ProgramFiles(x86)} 'Docker\Docker\resources\bin\docker.exe') }
Add-Candidate $candidates (Join-Path $env:LOCALAPPDATA 'Programs\Docker\Docker\resources\bin\docker.exe')
Add-Candidate $candidates (Join-Path $env:LOCALAPPDATA 'Docker\resources\bin\docker.exe')

$uninstallRoots=@(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach($base in $uninstallRoots){
  try{
    Get-ChildItem $base -ErrorAction Stop | ForEach-Object {
      try{
        $v=Get-ItemProperty $_.PSPath -ErrorAction Stop
        if(([string]$v.DisplayName) -like 'Docker Desktop*'){
          Add-Candidate $candidates ([string]$v.InstallLocation)
          Add-Candidate $candidates ([string]$v.DisplayIcon)
        }
      }catch{}
    }
  }catch{}
}
foreach($appKey in @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Docker Desktop.exe',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Docker Desktop.exe'
)){
  try{ Add-Candidate $candidates ([string](Get-ItemProperty $appKey -ErrorAction Stop).'(default)') }catch{}
}
try{ Add-Candidate $candidates ([string](Get-Command docker.exe -CommandType Application -ErrorAction Stop).Source) }catch{}

$expected=$null
if($InstalledState){
  $statePath=Normalize-Path $InstalledState
  $expected=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
  if(-not $expected.dockerPath -or -not $expected.dockerSha256 -or $null -eq $expected.dockerSize){ throw 'INSTALLED_DOCKER_IDENTITY_MISSING' }
  $candidates=New-Object 'System.Collections.Generic.List[string]'
  [void]$candidates.Add([string]$expected.dockerPath)
}

$errors=@()
foreach($candidate in $candidates){
  if(-not (Test-Path -LiteralPath $candidate -PathType Leaf)){ continue }
  try{
    $id=Assert-DockerBinary $candidate
    if($expected){
      if($id.path -ine [IO.Path]::GetFullPath([string]$expected.dockerPath)){ throw 'DOCKER_PATH_CHANGED' }
      if($id.sha256 -ne ([string]$expected.dockerSha256).ToLowerInvariant()){ throw 'DOCKER_SHA256_CHANGED' }
      if($id.size -ne [int64]$expected.dockerSize){ throw 'DOCKER_SIZE_CHANGED' }
    }
    if($PrintPath){ Write-Output $id.path } else { $id | ConvertTo-Json -Compress }
    exit 0
  }catch{ $errors += ($candidate+': '+$_.Exception.Message) }
}
throw ('TRUSTED_DOCKER_CLI_NOT_FOUND; checked='+($candidates -join '; ')+'; errors='+($errors -join ' | '))
