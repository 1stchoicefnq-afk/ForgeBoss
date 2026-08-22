$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$root=Join-Path $env:USERPROFILE '.siteboss\autopilot\case-sensitive-repair-workspaces'

if(-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)){
  throw 'This preparation step must run as Administrator.'
}

if(Test-Path -LiteralPath $root){
  $items=@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
  if($items.Count -gt 0){
    throw "Preparation root already exists and is not empty: $root. Move/delete its contents first; SiteBoss will not change case sensitivity on a non-empty directory."
  }
}else{
  New-Item -ItemType Directory -Force -Path $root|Out-Null
}

& fsutil.exe file setCaseSensitiveInfo $root enable
if($LASTEXITCODE -ne 0){ throw "fsutil failed to enable case sensitivity on $root" }

$verify=& fsutil.exe file queryCaseSensitiveInfo $root
if($LASTEXITCODE -ne 0 -or "$verify" -notmatch '(?i)enabled'){
  throw "Could not verify case sensitivity on $root"
}

Write-Host 'SITEBOSS CASE-SENSITIVE WORKSPACE: PREPARED' -ForegroundColor Green
Write-Host $root
Write-Host 'This is a dedicated disposable repair-workspace root only. Global Git and Windows filesystem settings were not changed.'
