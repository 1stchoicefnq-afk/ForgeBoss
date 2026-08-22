param([string]$Repo,[string]$Output)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'State.psm1') -Force

function Run-Git([string[]]$CommandArgs){
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName='git.exe'
  $psi.WorkingDirectory=$Repo
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  foreach($arg in $CommandArgs){[void]$psi.ArgumentList.Add([string]$arg)}
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi
  try{
    if(-not$p.Start()){throw 'git start failed'}
    $stdout=$p.StandardOutput.ReadToEnd()
    $stderr=$p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if($p.ExitCode-ne0){throw $stderr}
    $stdout
  }finally{$p.Dispose()}
}

if(-not(Test-Path -LiteralPath $Repo)){throw "Repo missing: $Repo"}
$head=(Run-Git @('rev-parse','HEAD')).Trim()
$files=@((Run-Git @('ls-files','src','tests','migrations')) -split "`r?`n"|Where-Object{$_})
$modules=@{}
foreach($file in $files){
  $parts=$file -split '/'
  $key=$(if($parts.Count-ge2){"$($parts[0])/$($parts[1])"}else{$parts[0]})
  if(-not$modules.ContainsKey($key)){$modules[$key]=0}
  $modules[$key]++
}
$critical=@()
try{
  $critical=@((Run-Git @('grep','-n','-I','-E','withTransaction|SERIALIZABLE|40001|40P01|idempot|invitation|qualification|conversion','HEAD','--','src','tests')) -split "`r?`n"|Where-Object{$_})
}catch{}

Write-JsonAtomic $Output ([ordered]@{
  schema=1
  exact_head=$head
  file_count=$files.Count
  modules=$modules
  critical_call_sites=$critical
}) 50
