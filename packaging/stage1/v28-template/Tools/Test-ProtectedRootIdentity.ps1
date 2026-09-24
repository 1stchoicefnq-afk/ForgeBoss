param([Parameter(Mandatory=$true)][string]$PackageRoot)
$ErrorActionPreference='Stop'
$PackageRoot=(Resolve-Path -LiteralPath $PackageRoot).Path
$manifest=Join-Path $PackageRoot 'PACKAGE-MANIFEST.json'
$helper=Join-Path $PackageRoot 'Authority\Prepare-MachineAuthorityRoot.ps1'
if(!(Test-Path -LiteralPath $helper -PathType Leaf)){throw 'PROTECTED_ROOT_HELPER_MISSING'}
$m=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json
$version=[string]$m.packageVersion
if($version -notmatch '^v([0-9]+)(?:\.[0-9]+)?-r[0-9]+(?:\.[0-9]+)?$'){throw 'PACKAGE_VERSION_INVALID'}
$major=$Matches[1]
$systemDrive=[IO.Path]::GetPathRoot($env:SystemRoot).TrimEnd('\')
if([string]::IsNullOrWhiteSpace($systemDrive)){throw 'SYSTEM_DRIVE_UNAVAILABLE'}
$expected=Join-Path ($systemDrive+'\') ('ForgeBossAuthorityStage1-v'+$major)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$systemPS=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Invoke-RootCase([string]$Root,[int]$WantRc,[string]$WantCode){
  $out=& $systemPS -NoLogo -NoProfile -ExecutionPolicy Bypass -File $helper -Root $Root -UserSid $sid -PackageManifest $manifest -ValidateOnly 2>&1
  $rc=$LASTEXITCODE
  $text=($out|Out-String)
  if($WantRc -eq 0){
    if($rc -ne 0){throw ("PROTECTED_ROOT_VALIDATION_EXPECTED_PASS rc="+$rc+" root="+$Root+" output="+$text)}
  }else{
    if($rc -eq 0){throw ("PROTECTED_ROOT_VALIDATION_EXPECTED_FAIL root="+$Root)}
    if($text -notmatch [regex]::Escape($WantCode)){
      throw ("PROTECTED_ROOT_VALIDATION_WRONG_ERROR expected="+$WantCode+" root="+$Root+" rc="+$rc+" output="+$text)
    }
  }
  [pscustomobject]@{root=$Root;exitCode=$rc;expectedCode=$WantCode;ok=$true}
}

$rows=@()
$rows += Invoke-RootCase $expected 0 'PASS'
$systemUsers=Join-Path ($systemDrive+'\') 'Users'
$rows += Invoke-RootCase $env:SystemRoot 13 'PROTECTED_ROOT_SYSTEM_DIRECTORY_DENIED'
$rows += Invoke-RootCase $systemUsers 13 'PROTECTED_ROOT_SYSTEM_DIRECTORY_DENIED'
$rows += Invoke-RootCase $env:ProgramFiles 13 'PROTECTED_ROOT_SYSTEM_DIRECTORY_DENIED'
$rows += Invoke-RootCase $env:ProgramData 13 'PROTECTED_ROOT_SYSTEM_DIRECTORY_DENIED'
$rows += Invoke-RootCase (Join-Path ($systemDrive+'\') 'anything') 13 'PROTECTED_ROOT_IDENTITY_MISMATCH'
$otherDrive=if($systemDrive -ieq 'C:'){'D:'}else{'C:'}
$rows += Invoke-RootCase (Join-Path ($otherDrive+'\') ('ForgeBossAuthorityStage1-v'+$major)) 13 'PROTECTED_ROOT_IDENTITY_MISMATCH'

$result=[pscustomobject]@{
  ok=$true
  expectedRoot=$expected
  systemDrive=$systemDrive
  cases=$rows
}
# The final validation case is intentionally a non-zero child exit. Reset the
# process-exit channel to success only after every expected result above matched.
& $systemPS -NoLogo -NoProfile -Command "exit 0" *> $null
$result | ConvertTo-Json -Depth 5 -Compress
