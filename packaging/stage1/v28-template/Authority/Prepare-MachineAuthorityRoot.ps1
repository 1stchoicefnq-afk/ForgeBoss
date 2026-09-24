param(
 [Parameter(Mandatory=$true)][string]$Root,
 [Parameter(Mandatory=$true)][string]$UserSid
)
$ErrorActionPreference='Stop'
if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ELEVATION_REQUIRED'}
if($Root -notmatch '^[A-Za-z]:\\[^\\]+$'){throw 'PROTECTED_ROOT_INVALID'}
if(Test-Path -LiteralPath $Root){
 $item=Get-Item -LiteralPath $Root -Force
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'PROTECTED_ROOT_REPARSE_DENIED'}
}else{New-Item -ItemType Directory -Path $Root|Out-Null}
$icacls=Join-Path $env:SystemRoot 'System32\icacls.exe'
& $icacls $Root /setowner "*$UserSid" /T /C | Out-Null
if($LASTEXITCODE -ne 0){throw 'PROTECTED_ROOT_OWNER_FAILED'}
& $icacls $Root /inheritance:r /grant:r "*$UserSid:(OI)(CI)(F)" "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /T /C | Out-Null
if($LASTEXITCODE -ne 0){throw 'PROTECTED_ROOT_ACL_FAILED'}
Write-Host "[PASS] Protected machine authority root ready: $Root"
