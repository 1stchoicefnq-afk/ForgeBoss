param([Parameter(Mandatory=$true)][string]$PackageRoot)
$ErrorActionPreference='Stop'
$PackageRoot=$PackageRoot.Trim().Trim('"')
$PackageRoot=(Resolve-Path -LiteralPath $PackageRoot).Path
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

 $rootProof=& (Join-Path $PackageRoot 'Tools\Test-ProtectedRootIdentity.ps1') -PackageRoot $PackageRoot 2>&1
 $rootRc=$LASTEXITCODE
 if($rootRc -ne 0){throw ("PROTECTED_ROOT_VALIDATION_FAILED rc="+$rootRc+": "+($rootProof|Out-String))}
 $rootObj=($rootProof|Out-String).Trim()|ConvertFrom-Json
 if(-not $rootObj.ok){throw 'PROTECTED_ROOT_VALIDATION_FAILED'}
 if([string]$s.protectedRoot -ne [string]$rootObj.expectedRoot){throw 'INSTALLED_PROTECTED_ROOT_IDENTITY_MISMATCH'}
 Write-Host ("[PASS] Protected root identity executed across "+$rootObj.cases.Count+" cases; root="+$rootObj.expectedRoot)

 $env:FORGEBOSS_ENGINE_ROOT=(Resolve-Path -LiteralPath $s.engineRoot).Path
 & $RuntimePy -I -B (Join-Path $s.engineRoot 'packaging\stage1\stage1_gate.py') $Installed
 if($LASTEXITCODE -ne 0){throw 'ENGINE_IDENTITY_GATE_FAILED'}
 Write-Host '[PASS] Start and VERIFY share exact installed engine authority'

 $budget=& $RuntimePy -I -B (Join-Path $PackageRoot 'Tools\prove_budget_policy.py') --engine-root $s.engineRoot 2>&1
 if($LASTEXITCODE -ne 0){throw ("ENGINE_BUDGET_POLICY_FAILED: "+($budget|Out-String))}
 $budgetObj=($budget|Out-String).Trim()|ConvertFrom-Json
 if(-not $budgetObj.ok){throw 'ENGINE_BUDGET_POLICY_FAILED'}
 Write-Host ("[PASS] Engine self-build budget policy maxAutomaticUsd="+$budgetObj.maxAutomaticUsd+" cycles="+$budgetObj.maxAutomaticCycles)

 & $RuntimePy -I -B (Join-Path $s.launcherRoot 'prove_no_console.py') --engine-root $s.engineRoot
 if($LASTEXITCODE -ne 0){throw 'NO_CONSOLE_PROOF_FAILED'}
 Write-Host '[PASS] Native Windows no-console child-process proof'

 $authorityContract=& $RuntimePy -I -B (Join-Path $PackageRoot 'Tools\prove_authority_contract.py') --engine-root $s.engineRoot 2>&1
 if($LASTEXITCODE -ne 0){throw ("STAGE1_AUTHORITY_CONTRACT_FAILED: "+($authorityContract|Out-String))}
 $authorityContractObj=($authorityContract|Out-String).Trim()|ConvertFrom-Json
 if(-not $authorityContractObj.ok -or $authorityContractObj.legacyIssueStage1Operations -or $authorityContractObj.obsoleteStage1ServiceParameters){
   throw 'STAGE1_AUTHORITY_CONTRACT_FAILED'
 }
 Write-Host '[PASS] Current Stage 1 authority contract loaded; obsolete issue_stage1 interface absent'

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
 $diagRc=$LASTEXITCODE
 $d=($diag|Out-String).Trim()|ConvertFrom-Json
 if($diagRc -ne 0 -or -not $d.ok){throw ("AUTHORITY_DIAGNOSTIC_FAILED rc="+$diagRc+": "+($d|ConvertTo-Json -Compress))}
 if([string]$d.authorityApi -ne 'self_build_runtime_receipts_v1'){throw 'STAGE1_AUTHORITY_API_MISMATCH'}
 if([string]$d.receiptOperation -ne 'self_build_current_known_good'){throw 'STAGE1_RECEIPT_OPERATION_MISMATCH'}
 Write-Host ("[PASS] Signed Stage 1 receipt api="+$d.authorityApi+" operation="+$d.receiptOperation+" trust="+$d.trustGrade)
 Write-Host ("[PASS] Known-good identity revision="+$d.revision+" phase="+$d.phase)

 if([string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)){throw 'OPENAI_API_KEY_MISSING'}
 Write-Host '[INFO] OpenAI API credential is present; VERIFY does not claim provider validity or spend API budget'
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
