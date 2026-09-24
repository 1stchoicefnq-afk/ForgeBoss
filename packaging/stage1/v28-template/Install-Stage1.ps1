param(
 [Parameter(Mandatory=$true)][string]$PackageRoot,
 [Parameter(Mandatory=$true)][string]$ToolsJson
)
$ErrorActionPreference='Stop'
$PackageRoot=(Resolve-Path -LiteralPath $PackageRoot).Path
$EngineSha='@@ENGINE_SHA@@'
$EngineRef='@@ENGINE_REF@@'
$BuilderImage='@@IMAGE_DIGEST@@'
$PackageManifest=Join-Path $PackageRoot 'PACKAGE-MANIFEST.json'
$PackageInfo=Get-Content -LiteralPath $PackageManifest -Raw | ConvertFrom-Json
$PackageVersion=[string]$PackageInfo.packageVersion
if($PackageVersion -notmatch '^v([0-9]+)(?:\.[0-9]+)?-r[0-9]+(?:\.[0-9]+)?$'){throw 'PACKAGE_VERSION_INVALID'}
$Stage1Major=$Matches[1]
$Base=Join-Path $env:LOCALAPPDATA 'ForgeBoss'
$EngineRoot=Join-Path $Base ('engine\'+$EngineSha)
$RuntimeRoot=Join-Path $Base ('runtime\v'+$Stage1Major)
$RuntimePy=Join-Path $RuntimeRoot 'Scripts\python.exe'
$ProtectedRoot=('C:\ForgeBossAuthorityStage1-v'+$Stage1Major)
$ClientRoot=Join-Path $Base ('authority-client-stage1-v'+$Stage1Major)
$StateRoot=Join-Path $Base 'state'
$LauncherRoot=Join-Path $Base ('launcher\v'+$Stage1Major)
$Installed=Join-Path $Base 'stage1-installed.json'
$AuthorityPipe=('\\.\pipe\ForgeBossAuthorityStage1-v'+$Stage1Major)
$SystemPS=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Sha([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function AssertTool($row,[string]$name){
 if($null -eq $row -or !(Test-Path -LiteralPath $row.path -PathType Leaf)){throw "$name missing"}
 if((Sha ([string]$row.path)) -ne ([string]$row.sha256).ToLowerInvariant()){throw "$name identity changed"}
}

Write-Host '============================================================'
Write-Host 'FORGEBOSS STAGE 1 V28 INSTALL'
Write-Host '============================================================'
Write-Host "Exact engine: $EngineSha"

& (Join-Path $PackageRoot 'Tools\Verify-Package.ps1') -Root $PackageRoot | Write-Host
$t=Get-Content -LiteralPath $ToolsJson -Raw | ConvertFrom-Json
AssertTool $t.git 'git.exe'
AssertTool $t.docker 'docker.exe'
AssertTool $t.python 'python.exe'
if($null -ne $t.node){AssertTool $t.node 'node.exe'}

$Git=[string]$t.git.path
$Docker=[string]$t.docker.path
$BootstrapPython=[string]$t.python.path
& $BootstrapPython -I -B (Join-Path $PackageRoot 'Tools\verify_package.py') $PackageRoot
if($LASTEXITCODE -ne 0){throw 'PYTHON_PACKAGE_VERIFICATION_FAILED'}

New-Item -ItemType Directory -Force -Path $Base,$StateRoot,(Split-Path -Parent $EngineRoot) | Out-Null

if(Test-Path -LiteralPath $EngineRoot){
 AssertTool $t.git 'git.exe'
 $head=(& $Git -C $EngineRoot rev-parse --verify HEAD).Trim().ToLowerInvariant()
 $dirty=(& $Git -C $EngineRoot status --porcelain=v1 --untracked-files=all | Out-String)
 if($head -ne $EngineSha -or -not [string]::IsNullOrWhiteSpace($dirty)){throw 'EXISTING_ENGINE_IDENTITY_MISMATCH'}
}else{
 AssertTool $t.git 'git.exe'
 & $Git clone --filter=blob:none --no-checkout https://github.com/1stchoicefnq-afk/ForgeBoss.git $EngineRoot
 if($LASTEXITCODE -ne 0){throw 'ENGINE_CLONE_FAILED'}
 & $Git -C $EngineRoot config core.autocrlf false
 & $Git -C $EngineRoot config core.eol lf
 & $Git -C $EngineRoot config core.safecrlf false
 & $Git -C $EngineRoot fetch --no-tags origin $EngineRef
 if($LASTEXITCODE -ne 0){throw 'ENGINE_REF_FETCH_FAILED'}
 & $Git -c core.autocrlf=false -c core.eol=lf -C $EngineRoot checkout --force --detach $EngineSha
 if($LASTEXITCODE -ne 0){throw 'ENGINE_CHECKOUT_FAILED'}
}
AssertTool $t.git 'git.exe'
$head=(& $Git -C $EngineRoot rev-parse --verify HEAD).Trim().ToLowerInvariant()
if($head -ne $EngineSha){throw 'ENGINE_SHA_MISMATCH'}
$dirty=(& $Git -C $EngineRoot status --porcelain=v1 --untracked-files=all | Out-String)
if(-not [string]::IsNullOrWhiteSpace($dirty)){throw 'ENGINE_TREE_DIRTY'}
$blobCount=0
$treeLines=& $Git -C $EngineRoot ls-tree -r --full-tree $EngineSha
if($LASTEXITCODE -ne 0){throw 'ENGINE_TREE_ENUMERATION_FAILED'}
foreach($line in $treeLines){
 $entry=[string]$line
 if($entry -notmatch '^([0-9]{6}) blob ([0-9a-fA-F]{40,64})\t(.+)$'){continue}
 $want=$Matches[2].ToLowerInvariant();$rel=$Matches[3]
 $gotHash=(& $Git -C $EngineRoot hash-object --no-filters -- $rel).Trim().ToLowerInvariant()
 if($LASTEXITCODE -ne 0 -or $gotHash -ne $want){throw ('ENGINE_BLOB_BYTES_MISMATCH: '+$rel)}
 $blobCount++
}
if($blobCount -lt 1){throw 'ENGINE_BLOB_VERIFICATION_EMPTY'}
Write-Host ("[PASS] Exact clean ForgeBoss engine; blob bytes verified="+$blobCount)

if(Test-Path -LiteralPath $RuntimeRoot){Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force}
AssertTool $t.python 'python.exe'
& $BootstrapPython -I -m venv $RuntimeRoot
if($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $RuntimePy -PathType Leaf)){throw 'RUNTIME_VENV_FAILED'}
& $RuntimePy -I -m pip install --disable-pip-version-check --require-hashes --no-deps --only-binary :all: -r (Join-Path $PackageRoot 'requirements.lock')
if($LASTEXITCODE -ne 0){throw 'HASH_PINNED_RUNTIME_INSTALL_FAILED'}
$site=(& $RuntimePy -I -c "import site;print(site.getsitepackages()[0])").Trim()
if([string]::IsNullOrWhiteSpace($site)){throw 'RUNTIME_SITE_PACKAGES_UNAVAILABLE'}
Copy-Item -LiteralPath (Join-Path $PackageRoot 'Vendor\proxy_tools') -Destination (Join-Path $site 'proxy_tools') -Recurse -Force
& $RuntimePy -I -c "import cryptography,litellm,webview,proxy_tools;from minisweagent.agents.default import DefaultAgent;print('RUNTIME_IMPORT_OK')"
if($LASTEXITCODE -ne 0){throw 'RUNTIME_IMPORT_FAILED'}
Write-Host '[PASS] Hash-pinned user runtime'

AssertTool $t.docker 'docker.exe'
& $Docker pull $BuilderImage
if($LASTEXITCODE -ne 0){throw 'PINNED_BUILDER_IMAGE_PULL_FAILED'}
& $Docker image inspect $BuilderImage *> $null
if($LASTEXITCODE -ne 0){throw 'PINNED_BUILDER_IMAGE_INSPECT_FAILED'}
Write-Host '[PASS] Digest-pinned builder image'

$userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$prep=Join-Path $PackageRoot 'Authority\Prepare-MachineAuthorityRoot.ps1'
$argLine='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -Root "{1}" -UserSid "{2}" -PackageManifest "{3}"' -f $prep,$ProtectedRoot,$userSid,$PackageManifest
Write-Host 'Stage 1 needs one Windows UAC approval for the protected authority root/ACL only.'
$p=Start-Process -FilePath $SystemPS -ArgumentList $argLine -Verb RunAs -Wait -PassThru
if($p.ExitCode -ne 0){throw 'PROTECTED_ROOT_UAC_STEP_FAILED'}
Write-Host '[PASS] Protected machine authority root'

New-Item -ItemType Directory -Force -Path $ClientRoot,$LauncherRoot | Out-Null
$icacls=Join-Path $env:SystemRoot 'System32\icacls.exe'
& $icacls $ClientRoot /inheritance:r /grant:r "*$($userSid):(OI)(CI)(F)" "*S-1-5-18:(OI)(CI)(F)" "*S-1-5-32-544:(OI)(CI)(F)" /T /C | Out-Null
if($LASTEXITCODE -ne 0){throw 'CLIENT_ROOT_ACL_FAILED'}

$env:FORGEBOSS_INSTALL_USER_SID=$userSid
try{
 & $RuntimePy -I (Join-Path $PackageRoot 'Authority\generate_authority_material.py') --root $ProtectedRoot --client-root $ClientRoot --engine-root $EngineRoot --engine-sha $EngineSha --pipe-name $AuthorityPipe
 if($LASTEXITCODE -ne 0){throw 'AUTHORITY_MATERIAL_FAILED'}
}finally{
 Remove-Item Env:\FORGEBOSS_INSTALL_USER_SID -ErrorAction SilentlyContinue
}
Write-Host '[PASS] Protected authority identity + known-good manifest'

$launcherMap=[ordered]@{
 start='Start-ForgeBoss.ps1'
 verify='Verify-Stage1.ps1'
 host='authority_user_host.py'
 diagnose='authority_diagnose.py'
 noConsole='prove_no_console.py'
}
Copy-Item -LiteralPath (Join-Path $PackageRoot 'Start-ForgeBoss.ps1') -Destination (Join-Path $LauncherRoot $launcherMap.start) -Force
Copy-Item -LiteralPath (Join-Path $PackageRoot 'Verify-Stage1.ps1') -Destination (Join-Path $LauncherRoot $launcherMap.verify) -Force
Copy-Item -LiteralPath (Join-Path $PackageRoot 'Authority\authority_user_host.py') -Destination (Join-Path $LauncherRoot $launcherMap.host) -Force
Copy-Item -LiteralPath (Join-Path $PackageRoot 'Authority\authority_diagnose.py') -Destination (Join-Path $LauncherRoot $launcherMap.diagnose) -Force
Copy-Item -LiteralPath (Join-Path $PackageRoot 'Tools\prove_no_console.py') -Destination (Join-Path $LauncherRoot $launcherMap.noConsole) -Force

$packageManifest=Join-Path $PackageRoot 'PACKAGE-MANIFEST.json'
$state=[ordered]@{
 schema=2
 version=$PackageVersion
 engineRoot=$EngineRoot
 engineSha=$EngineSha
 engineRef=$EngineRef
 runtimePython=$RuntimePy
 runtimePythonSha256=(Sha $RuntimePy)
 bootstrapPython=@{path=$t.python.path;sha256=$t.python.sha256;size=$t.python.size}
 git=@{path=$t.git.path;sha256=$t.git.sha256;size=$t.git.size}
 docker=@{path=$t.docker.path;sha256=$t.docker.sha256;size=$t.docker.size}
 node=$(if($null -ne $t.node){@{path=$t.node.path;sha256=$t.node.sha256;size=$t.node.size}}else{$null})
 builderImage=$BuilderImage
 authorityPipe=$AuthorityPipe
 protectedRoot=$ProtectedRoot
 clientRoot=$ClientRoot
 stateRoot=$StateRoot
 launcherRoot=$LauncherRoot
 packageManifestSha256=(Sha $packageManifest)
 launcherFiles=@{
   start=(Sha (Join-Path $LauncherRoot $launcherMap.start))
   verify=(Sha (Join-Path $LauncherRoot $launcherMap.verify))
   host=(Sha (Join-Path $LauncherRoot $launcherMap.host))
   diagnose=(Sha (Join-Path $LauncherRoot $launcherMap.diagnose))
   noConsole=(Sha (Join-Path $LauncherRoot $launcherMap.noConsole))
 }
 installedAt=(Get-Date).ToUniversalTime().ToString('o')
}
$state|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $Installed -Encoding UTF8

& $RuntimePy -I (Join-Path $EngineRoot 'packaging\stage1\stage1_gate.py') $Installed
if($LASTEXITCODE -ne 0){throw 'INSTALLED_ENGINE_GATE_FAILED'}
Write-Host '[PASS] Installed engine gate'

$start=Join-Path $LauncherRoot 'Start-ForgeBoss.ps1'
& $SystemPS -NoLogo -NoProfile -ExecutionPolicy Bypass -File $start -InstalledState $Installed -AuthorityOnly
if($LASTEXITCODE -ne 0){throw 'AUTHORITY_START_FAILED'}

try{
 $shell=New-Object -ComObject WScript.Shell
 $lnk=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'ForgeBoss.lnk'))
 $lnk.TargetPath=$SystemPS
 $lnk.Arguments=('-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -InstalledState "{1}"' -f $start,$Installed)
 $lnk.WorkingDirectory=$EngineRoot
 $lnk.Save()
}catch{
 Write-Warning ("Desktop shortcut not created: "+$_.Exception.Message)
}
Write-Host '[PASS] ForgeBoss Stage 1 v28 installed'
