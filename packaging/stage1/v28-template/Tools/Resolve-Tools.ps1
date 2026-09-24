param([string]$Output)
$ErrorActionPreference='Stop'
function Sha([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function IsUnder([string]$Path,[string]$Root){if([string]::IsNullOrWhiteSpace($Root)){return $false};$p=[IO.Path]::GetFullPath($Path).TrimEnd('\')+'\';$r=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\';return $p.StartsWith($r,[StringComparison]::OrdinalIgnoreCase)}
function ResolveTrustedCandidate([string[]]$items,[string[]]$exactSignerNames){foreach($p in $items){if([string]::IsNullOrWhiteSpace($p) -or !(Test-Path -LiteralPath $p -PathType Leaf)){continue};$resolved=(Resolve-Path -LiteralPath $p).Path;$machine=(IsUnder $resolved $env:ProgramFiles) -or (IsUnder $resolved ${env:ProgramFiles(x86)});if($machine){return $resolved};$sig=Get-AuthenticodeSignature -FilePath $resolved;if($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate){continue};$simple=[string]$sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false);if($exactSignerNames -contains $simple.Trim()){return $resolved}};return $null}
$git=ResolveTrustedCandidate -items @((Join-Path $env:ProgramFiles 'Git\cmd\git.exe'),(Join-Path $env:ProgramFiles 'Git\bin\git.exe')) -exactSignerNames @()
if(!$git){throw 'TRUSTED_GIT_NOT_FOUND'}
function AddDockerCandidate([System.Collections.Generic.List[string]]$list,[string]$raw){if([string]::IsNullOrWhiteSpace($raw)){return};$p=$raw.Trim().Trim('"') -replace ',\d+$','';if((Split-Path -Leaf $p) -ieq 'Docker Desktop.exe'){$p=Join-Path (Split-Path -Parent $p) 'resources\bin\docker.exe'}elseif((Split-Path -Leaf $p) -ine 'docker.exe'){$p=Join-Path $p 'resources\bin\docker.exe'};if(!$list.Contains($p)){[void]$list.Add($p)}}
$dockerCandidates=New-Object 'System.Collections.Generic.List[string]'
AddDockerCandidate $dockerCandidates (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe')
if(${env:ProgramFiles(x86)}){AddDockerCandidate $dockerCandidates (Join-Path ${env:ProgramFiles(x86)} 'Docker\Docker\resources\bin\docker.exe')}
foreach($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){try{Get-ChildItem $base -ErrorAction Stop|ForEach-Object{try{$v=Get-ItemProperty $_.PSPath -ErrorAction Stop;if(([string]$v.DisplayName) -like 'Docker Desktop*'){AddDockerCandidate $dockerCandidates ([string]$v.InstallLocation);AddDockerCandidate $dockerCandidates ([string]$v.DisplayIcon)}}catch{}}}catch{}}
try{AddDockerCandidate $dockerCandidates ([string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Docker Desktop.exe' -ErrorAction Stop).'(default)')}catch{}
AddDockerCandidate $dockerCandidates (Join-Path $env:LOCALAPPDATA 'Programs\Docker\Docker\resources\bin\docker.exe')
AddDockerCandidate $dockerCandidates (Join-Path $env:LOCALAPPDATA 'Docker\resources\bin\docker.exe')
try{Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction Stop|ForEach-Object{try{$v=Get-ItemProperty $_.PSPath -ErrorAction Stop;if(([string]$v.DisplayName) -like 'Docker Desktop*'){AddDockerCandidate $dockerCandidates ([string]$v.InstallLocation);AddDockerCandidate $dockerCandidates ([string]$v.DisplayIcon)}}catch{}}}catch{}
try{AddDockerCandidate $dockerCandidates ([string](Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Docker Desktop.exe' -ErrorAction Stop).'(default)')}catch{}
try{AddDockerCandidate $dockerCandidates ([string](Get-Command docker.exe -CommandType Application -ErrorAction Stop).Source)}catch{}
$docker=ResolveTrustedCandidate -items $dockerCandidates.ToArray() -exactSignerNames @('Docker Inc','Docker, Inc.')
if(!$docker){throw ('TRUSTED_DOCKER_NOT_FOUND checked='+($dockerCandidates -join '; '))}
$pythonCandidates=New-Object 'System.Collections.Generic.List[string]'
foreach($base in @('HKLM:\SOFTWARE\Python\PythonCore\3.13\InstallPath')){try{$k=Get-ItemProperty -LiteralPath $base -ErrorAction Stop;if($k.ExecutablePath){[void]$pythonCandidates.Add([string]$k.ExecutablePath)};$d=(Get-Item -LiteralPath $base -ErrorAction SilentlyContinue).GetValue('');if($d){[void]$pythonCandidates.Add((Join-Path ([string]$d) 'python.exe'))}}catch{}}
[void]$pythonCandidates.Add((Join-Path $env:ProgramFiles 'Python313\python.exe'))
foreach($base in @('HKCU:\SOFTWARE\Python\PythonCore\3.13\InstallPath')){try{$k=Get-ItemProperty -LiteralPath $base -ErrorAction Stop;if($k.ExecutablePath){[void]$pythonCandidates.Add([string]$k.ExecutablePath)};$d=(Get-Item -LiteralPath $base -ErrorAction SilentlyContinue).GetValue('');if($d){[void]$pythonCandidates.Add((Join-Path ([string]$d) 'python.exe'))}}catch{}}
[void]$pythonCandidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'))
$python=ResolveTrustedCandidate -items $pythonCandidates.ToArray() -exactSignerNames @('Python Software Foundation')
if(!$python){throw 'PYTHON_3_13_NOT_FOUND_OR_UNTRUSTED'}
$pv=& $python -I -S -c "import sys;print('%d.%d'%sys.version_info[:2])"
if($LASTEXITCODE -ne 0 -or $pv.Trim() -ne '3.13'){throw 'PYTHON_3_13_REQUIRED'}
$node=ResolveTrustedCandidate -items @((Join-Path $env:ProgramFiles 'nodejs\node.exe')) -exactSignerNames @()
$payload=[ordered]@{schema=2;git=@{path=$git;sha256=(Sha $git);size=(Get-Item $git).Length};docker=@{path=$docker;sha256=(Sha $docker);size=(Get-Item $docker).Length};python=@{path=$python;sha256=(Sha $python);size=(Get-Item $python).Length};node=$(if($node){@{path=$node;sha256=(Sha $node);size=(Get-Item $node).Length}}else{$null})}
$json=$payload|ConvertTo-Json -Depth 5 -Compress
if($Output){$dir=Split-Path -Parent $Output;if($dir){New-Item -ItemType Directory -Force -Path $dir|Out-Null};$json|Set-Content -LiteralPath $Output -Encoding UTF8}
$json
