param(
 [Parameter(Mandatory=$true)][string]$Root,
 [Parameter(Mandatory=$true)][string]$UserSid,
 [Parameter(Mandatory=$true)][string]$PackageManifest
)
$ErrorActionPreference='Stop'
$manifestPath=(Resolve-Path -LiteralPath $PackageManifest).Path
$m=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$version=[string]$m.packageVersion
if($version -notmatch '^v([0-9]+)(?:\.[0-9]+)?-r[0-9]+(?:\.[0-9]+)?$'){throw 'PACKAGE_VERSION_INVALID'}
$stage1Major=$Matches[1]
$expected=[IO.Path]::GetFullPath(('C:\ForgeBossAuthorityStage1-v'+$stage1Major)).TrimEnd('\')
$actual=[IO.Path]::GetFullPath($Root).TrimEnd('\')
if(-not $actual.Equals($expected,[StringComparison]::OrdinalIgnoreCase)){throw 'PROTECTED_ROOT_IDENTITY_MISMATCH'}
$systemRoots=@([IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\'),[IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetPathRoot($env:SystemRoot)) 'Users')).TrimEnd('\'),[IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\'),[IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\'))
if(${env:ProgramFiles(x86)}){$systemRoots += [IO.Path]::GetFullPath(${env:ProgramFiles(x86)}).TrimEnd('\')}
if($systemRoots | Where-Object {$actual.Equals($_,[StringComparison]::OrdinalIgnoreCase)}){throw 'PROTECTED_ROOT_SYSTEM_DIRECTORY_DENIED'}
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ELEVATION_REQUIRED'}
if(Test-Path -LiteralPath $actual){$item=Get-Item -LiteralPath $actual -Force;if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'PROTECTED_ROOT_REPARSE_DENIED'}}else{New-Item -ItemType Directory -Path $actual|Out-Null}
$icacls=Join-Path $env:SystemRoot 'System32\icacls.exe'
& $icacls $actual /setowner "*$UserSid" /T /C | Out-Null
if($LASTEXITCODE -ne 0){throw 'PROTECTED_ROOT_OWNER_FAILED'}
& $icacls $actual /inheritance:r /grant:r "*${UserSid}:(OI)(CI)(F)" "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /T /C | Out-Null
if($LASTEXITCODE -ne 0){throw 'PROTECTED_ROOT_ACL_FAILED'}
Write-Host "[PASS] Protected machine authority root ready: $actual"
