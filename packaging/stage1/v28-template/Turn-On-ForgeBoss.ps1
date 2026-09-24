param([Parameter(Mandatory=$true)][string]$PackageRoot)
$ErrorActionPreference='Stop'
$PackageRoot=$PackageRoot.Trim().Trim('"')
$PackageRoot=(Resolve-Path -LiteralPath $PackageRoot).Path
Write-Host '============================================================'
Write-Host 'FORGEBOSS STAGE 1 - V28 SELF-VERIFYING TURN-ON'
Write-Host '============================================================'
& (Join-Path $PackageRoot 'Tools\Verify-Package.ps1') -Root $PackageRoot | Write-Host
$tools=Join-Path $env:TEMP ('forgeboss-v28-tools-'+[guid]::NewGuid().ToString('N')+'.json')
try{
  & (Join-Path $PackageRoot 'Tools\Resolve-Tools.ps1') -Output $tools | Write-Host
  $t=Get-Content -LiteralPath $tools -Raw | ConvertFrom-Json
  & $t.python.path -I -B (Join-Path $PackageRoot 'Tools\verify_package.py') $PackageRoot
  if($LASTEXITCODE -ne 0){throw 'PYTHON_PACKAGE_VERIFICATION_FAILED'}
  & (Join-Path $PackageRoot 'Install-Stage1.ps1') -PackageRoot $PackageRoot -ToolsJson $tools
  if($LASTEXITCODE -ne 0){throw 'INSTALL_FAILED'}
}finally{
  Remove-Item -LiteralPath $tools -Force -ErrorAction SilentlyContinue
}
