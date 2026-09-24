param([Parameter(Mandatory=$true)][string]$PackageRoot)
$ErrorActionPreference='Stop'
$PackageRoot=$PackageRoot.Trim().Trim('"')\n$PackageRoot=(Resolve-Path -LiteralPath $PackageRoot).Path
$Installed=Join-Path $env:LOCALAPPDATA 'ForgeBoss\stage1-installed.json'
function Sha([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function AssertHash([string]$path,[string]$want,[string]$label){
 if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw "$label missing"}
 if((Sha $path) -ne $want.ToLowerInvariant()){throw "$label identity changed"}
}
try{
 Write-Host '============================================================'
 Write-Host 'FORGEBOSS STAGE 1 V28 VERIFY - READ ONLY'
 Write-Host '============================================================'
 & (Join-Path $PackageRoot 'Tools\Verify-Package.ps1') -Root $PackageRoot | Write-Host
 $toolJson=& (Join-Path $PackageRoot 'Tools\Resolve-Tools.ps1')
 $boot=($toolJson|Out-String).Trim()|ConvertFrom-Json
 & $boot.python.path -I -B (Join-Path $PackageRoot 'Tools\verify_package.py') $PackageRoot
 if($LASTEXITCODE -ne 0){throw 'PYTHON_PACKAGE_VERIFICATION_FAILED'}
 if(!(Test-Path -LiteralPath $Installed -PathType Leaf)){throw 'STAGE1_NOT_INSTALLED'}
 $s=Get-Content -LiteralPath $Installed -Raw|ConvertFrom-Json
 if((Sha (Join-Path $PackageRoot 'PACKAGE-MANIFEST.json')) -ne ([string]$s.packageManifestSha256).ToLowerInvariant()){throw 'VERIFY_PACKAGE_DIFFERS_FROM_INSTALLED_PACKAGE'}
 $RuntimePy=(Resolve-Path -LiteralPath $s.runtimePython).Path
 AssertHash $RuntimePy ([string]$s.runtimePythonSha256) 'runtime python'
 AssertHash ([string]$s.git.path) ([string]$s.git.sha256) 'git.exe'
 AssertHash ([string]$s.docker.path) ([string]$s.docker.sha256) 'docker.exe'
 if($null -ne $s.node){AssertHash ([string]$s.node.path) ([string]$s.node.sha256) 'node.exe'}
 AssertHash (Join-Path $s.launcherRoot 'Start-ForgeBoss.ps1') ([string]$s.launcherFiles.start) 'launcher start'
 AssertHash (Join-Path $s.launcherRoot 'Verify-Stage1.ps1') ([string]$s.launcherFiles.verify) 'launcher verify'
 AssertHash (Join-Path $s.launcherRoot 'authority_user_host.py') ([string]$s.launcherFiles.host) 'authority host'
 AssertHash (Join-Path $s.launcherRoot 'authority_diagnose.py') ([string]$s.launcherFiles.diagnose) 'authority diagnose'
 AssertHash (Join-Path $s.launcherRoot 'prove_no_console.py') ([string]$s.launcherFiles.noConsole) 'no-console proof'
 Write-Host '[PASS] Package manifest + exact file-set + behaviour scan'

 & $RuntimePy -I (Join-Path $s.engineRoot 'packaging\stage1\stage1_gate.py') $Installed
 if($LASTEXITCODE -ne 0){throw 'ENGINE_IDENTITY_GATE_FAILED'}
 Write-Host '[PASS] Start and VERIFY share exact installed engine authority'

 & $RuntimePy -I -B (Join-Path $s.launcherRoot 'prove_no_console.py')
 if($LASTEXITCODE -ne 0){throw 'NO_CONSOLE_PROOF_FAILED'}
 Write-Host '[PASS] Native Windows no-console child-process proof'

 & $s.docker.path image inspect $s.builderImage *> $null
 if($LASTEXITCODE -ne 0){throw 'PINNED_BUILDER_IMAGE_MISSING'}
 Write-Host '[PASS] Immutable builder image present'

 $ws=Join-Path $s.protectedRoot 'self-build-workspaces'
 if(!(Test-Path -LiteralPath $ws -PathType Container)){throw 'PROTECTED_WORKSPACE_ROOT_MISSING'}
 $mount="type=bind,src=$ws,dst=/workspace,readonly"
 $probe=& $s.docker.path run --rm --network none --mount $mount $s.builderImage sh -lc 'echo MOUNT_OK' 2>&1
 if($LASTEXITCODE -ne 0 -or (($probe|Out-String) -notmatch 'MOUNT_OK')){throw ("DOCKER_BIND_MOUNT_FAILED: "+($probe|Out-String))}
 Write-Host '[PASS] Protected Stage 1 builder workspace is Docker bind-mountable'

 $clientCfg=Get-Content -LiteralPath (Join-Path $s.clientRoot 'client-config.json') -Raw|ConvertFrom-Json
 if([string]$clientCfg.pipeName -ne [string]$s.authorityPipe){throw 'AUTHORITY_PIPE_CONFIG_MISMATCH'}
 $diag=& $RuntimePy -I -B (Join-Path $s.launcherRoot 'authority_diagnose.py') --installed $Installed 2>&1
 $d=($diag|Out-String).Trim()|ConvertFrom-Json
 if(-not $d.ok){throw ("AUTHORITY_DIAGNOSTIC_FAILED: "+($d|ConvertTo-Json -Compress))}
 Write-Host ("[PASS] Signed protected authority receipt; trust="+$d.trustGrade)
 Write-Host ("[PASS] Known-good identity revision="+$d.revision+" phase="+$d.phase)

 if([string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)){throw 'OPENAI_API_KEY_MISSING'}
 Write-Host '[PASS] OpenAI API credential present'
 Write-Host '[PASS] VERIFY performed no engine-tree cleanup or evidence deletion'
 Write-Host '============================================================'
 Write-Host '[PASS] STAGE 1 IS READY FOR OWNER DECISION'
 Write-Host 'Do NOT press START BUILD until this exact candidate ZIP passes hostile review.'
 Write-Host '============================================================'
 exit 0
}catch{
 Write-Host ''
 Write-Host ('[FAIL] '+$_.Exception.Message) -ForegroundColor Red
 exit 13
}
