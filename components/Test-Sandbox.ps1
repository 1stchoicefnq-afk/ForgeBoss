$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Image=if($env:SITEBOSS_TEST_IMAGE){$env:SITEBOSS_TEST_IMAGE}else{'node:22-bookworm'}

function Docker([string[]]$dockerArgs,[switch]$Capture){
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName='docker.exe'
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true
  foreach($a in $dockerArgs){[void]$psi.ArgumentList.Add([string]$a)}
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi
  try{
    if(-not$p.Start()){throw 'Failed to start docker.exe'}
    $o=$p.StandardOutput.ReadToEnd();$e=$p.StandardError.ReadToEnd();$p.WaitForExit()
    if($p.ExitCode-ne0){$d=$e.Trim();if([string]::IsNullOrWhiteSpace($d)){$d=$o.Trim()};throw "docker $($dockerArgs[0]) failed ($($p.ExitCode)): $d"}
    if($Capture){return $o.Trim()}
  }finally{$p.Dispose()}
}

if(-not(Get-Command docker.exe -ErrorAction SilentlyContinue)){throw 'docker.exe not found'}
[void](Docker @('info') -Capture)

try{[void](Docker @('image','inspect',$Image) -Capture)}
catch{
  Write-Host "Pulling Docker test image before any paid model call: $Image" -ForegroundColor Yellow
  [void](Docker @('pull',$Image) -Capture)
}

$temp=Join-Path ([IO.Path]::GetTempPath()) ("siteboss-preflight-"+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temp|Out-Null
Set-Content -LiteralPath (Join-Path $temp 'sentinel.txt') -Value 'siteboss' -NoNewline -Encoding UTF8
$vol=("sb_preflight_"+[Guid]::NewGuid().ToString('N').Substring(0,10)).ToLowerInvariant()

try{
  [void](Docker @('volume','create',$vol) -Capture)

  [void](Docker @(
    'run','--rm','--security-opt','no-new-privileges','--pids-limit','256',
    '--mount',"type=bind,src=$temp,dst=/source,readonly",
    '--mount',"type=volume,src=$vol,dst=/workspace",
    '-w','/workspace',$Image,
    'sh','-lc','cp -a /source/. /workspace/ && test "$(cat /workspace/sentinel.txt)" = siteboss'
  ) -Capture)

  [void](Docker @(
    'run','--rm','--network','none','--security-opt','no-new-privileges','--pids-limit','256',
    '--mount',"type=volume,src=$vol,dst=/workspace",
    '-w','/workspace',$Image,
    'sh','-lc','test "$(cat sentinel.txt)" = siteboss'
  ) -Capture)

  Write-Host 'Docker sandbox topology: PASS' -ForegroundColor Green
}finally{
  try{[void](Docker @('volume','rm','-f',$vol) -Capture)}catch{}
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
