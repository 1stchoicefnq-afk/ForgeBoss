param(
  [Parameter(Mandatory=$true)][int]$RootPullRequest,
  [Parameter(Mandatory=$true)][string]$RootReviewPath,
  [Parameter(Mandatory=$true)][string]$StateDir,
  [Parameter(Mandatory=$true)][string]$ReviewerPath,
  [Parameter(Mandatory=$true)][string]$RepairPath
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$GitHubGovernorModule=Join-Path (Split-Path -Parent $PSScriptRoot) 'forgeboss\github\GitHub-Governor.psm1'
Import-Module $GitHubGovernorModule -Force

$Config=@{
  AppId='4608230'
  InstallationId='154040429'
  Owner='1stchoicefnq-afk'
  Repo='siteboss-monster'
  PemPath="$env:USERPROFILE\.siteboss\secrets\github-app-private-key.pem"
  MaxRepairDepth=4
  ChildReviewProvider=$(if($env:SITEBOSS_CHILD_REVIEW_PROVIDER){$env:SITEBOSS_CHILD_REVIEW_PROVIDER.ToLowerInvariant()}elseif($env:SITEBOSS_REVIEW_PROVIDER){$env:SITEBOSS_REVIEW_PROVIDER.ToLowerInvariant()}else{'openai'})
  RequireCrossProvider=$(if($env:SITEBOSS_REQUIRE_CROSS_PROVIDER_CHILD_REVIEW -eq '1'){$true}else{$false})
}

function B64Url([byte[]]$b){[Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_')}
function Get-OptionalProperty($o,[string]$n){if($null-eq$o){return $null};$p=$o.PSObject.Properties[$n];if($null-eq$p){return $null};$p.Value}

function New-GitHubInstallationToken{
  if(-not(Test-Path -LiteralPath $Config.PemPath)){throw "GitHub App private key not found: $($Config.PemPath)"}
  $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $h=@{alg='RS256';typ='JWT'}|ConvertTo-Json -Compress
  $p=@{iat=$now-60;exp=$now+540;iss=$Config.AppId}|ConvertTo-Json -Compress
  $u="$(B64Url([Text.Encoding]::UTF8.GetBytes($h))).$(B64Url([Text.Encoding]::UTF8.GetBytes($p)))"
  $rsa=[Security.Cryptography.RSA]::Create()
  try{
    $rsa.ImportFromPem((Get-Content $Config.PemPath -Raw))
    $sig=$rsa.SignData([Text.Encoding]::UTF8.GetBytes($u),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  }finally{$rsa.Dispose()}
  $jwt="$u.$(B64Url $sig)"
  $hdr=@{Authorization="Bearer $jwt";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}
  $body=@{repositories=@($Config.Repo)}|ConvertTo-Json
  Invoke-GovernedGitHubJson -Method POST -Url "https://api.github.com/app/installations/$($Config.InstallationId)/access_tokens" -Headers $hdr -Body $body -CacheTtlMs 0
}
function GHHeaders($t){@{Authorization="Bearer $t";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}}
function GHRequest([string]$method,[string]$path,[string]$token,[object]$body=$null){
  $m=$method.ToUpperInvariant()
  $resp=Invoke-GovernedGitHubRaw -Method $m -Url "https://api.github.com$path" -Headers (GHHeaders $token) -Body $body -CacheTtlMs 0 -AllowHttpError
  if([int]$resp.status-lt200-or[int]$resp.status-ge300){throw "GitHub $m $path failed: HTTP $([int]$resp.status): $($resp.body)"}
  if([string]::IsNullOrWhiteSpace("$($resp.body)")){return $null}
  "$($resp.body)"|ConvertFrom-Json
}
function GHGet($p,$t){GHRequest 'GET' $p $t}
function GHPatch($p,$t,$b){GHRequest 'PATCH' $p $t $b}
function GHPost($p,$t,$b){GHRequest 'POST' $p $t $b}

function Invoke-PwshFile(
  [Parameter(Mandatory=$true)][string]$ScriptPath,
  [Parameter(Mandatory=$true)][string[]]$ArgumentList
){
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName='pwsh.exe'
  $psi.UseShellExecute=$false
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true

  [void]$psi.ArgumentList.Add('-NoLogo')
  [void]$psi.ArgumentList.Add('-NoProfile')
  [void]$psi.ArgumentList.Add('-ExecutionPolicy')
  [void]$psi.ArgumentList.Add('Bypass')
  [void]$psi.ArgumentList.Add('-File')
  [void]$psi.ArgumentList.Add($ScriptPath)
  foreach($a in $ArgumentList){ [void]$psi.ArgumentList.Add([string]$a) }

  $proc=[Diagnostics.Process]::new()
  $proc.StartInfo=$psi
  try{
    if(-not $proc.Start()){ throw "Failed to start pwsh.exe for $ScriptPath" }
    $stdout=$proc.StandardOutput.ReadToEnd()
    $stderr=$proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if(-not [string]::IsNullOrWhiteSpace($stdout)){ Write-Host $stdout.TrimEnd() }
    if($proc.ExitCode -ne 0){
      $detail=$stderr.Trim()
      if([string]::IsNullOrWhiteSpace($detail)){ $detail='No stderr was emitted.' }
      throw "Child subprocess failed ($($proc.ExitCode)): $detail"
    }
    if(-not [string]::IsNullOrWhiteSpace($stderr)){ Write-Host $stderr.TrimEnd() -ForegroundColor DarkGray }
  }finally{$proc.Dispose()}
}

function Get-GitRef([string]$branch,[string]$token){
  # Use the matching-refs endpoint so slash-containing branch names are handled
  # without ambiguous URL encoding.
  $prefix=[Uri]::EscapeDataString("heads/$branch")
  $raw=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/git/matching-refs/$prefix" $token
  $items=@()
  if($null-ne$raw){
    if($raw-is[System.Array]){$items=@($raw)}else{$items=@($raw)}
  }
  $exact="refs/heads/$branch"
  $matches=@($items|Where-Object{"$($_.ref)"-eq$exact})
  if($matches.Count-ne1){throw "Expected exactly one Git ref '$exact', found $($matches.Count)"}
  $matches[0]
}

function Update-GitRefFastForward([string]$branch,[string]$sha,[string]$token){
  # GitHub's update-ref endpoint takes the ref path after /git/refs/.
  # Escape each branch segment instead of encoding the '/' separators.
  $segments=@($branch -split '/')
  $encodedSegments=@($segments|ForEach-Object{[Uri]::EscapeDataString($_)})
  $branchPath=($encodedSegments -join '/')
  GHPatch "/repos/$($Config.Owner)/$($Config.Repo)/git/refs/heads/$branchPath" $token @{sha=$sha;force=$false}
}

function Get-Pr([int]$number,[string]$token){
  GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$number" $token
}
function Get-HeadInfo($pr){
  $head=Get-OptionalProperty $pr 'head'
  if($null-eq$head){throw "PR #$($pr.number) is missing head detail"}
  @{
    ref="$((Get-OptionalProperty $head 'ref'))"
    sha="$((Get-OptionalProperty $head 'sha'))"
  }
}
function Get-BaseInfo($pr){
  $base=Get-OptionalProperty $pr 'base'
  if($null-eq$base){throw "PR #$($pr.number) is missing base detail"}
  @{
    ref="$((Get-OptionalProperty $base 'ref'))"
    sha="$((Get-OptionalProperty $base 'sha'))"
  }
}

function Get-RepairChildren([int]$parentNumber,$parentPr,[string]$token){
  $parentHead=Get-HeadInfo $parentPr
  if([string]::IsNullOrWhiteSpace($parentHead.ref)-or[string]::IsNullOrWhiteSpace($parentHead.sha)){throw "Parent PR #$parentNumber lacks head ref/SHA"}
  $baseEncoded=[Uri]::EscapeDataString($parentHead.ref)
  $raw=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/pulls?state=open&base=$baseEncoded&per_page=100" $token
  $items=@()
  if($null-ne$raw){
    if($raw-is[System.Array]){$items=@($raw)}else{$items=@($raw)}
  }
  $prefix="autopilot/repair-pr$parentNumber-"
  $matches=@()
  foreach($pr in $items){
    $h=Get-OptionalProperty $pr 'head'
    $b=Get-OptionalProperty $pr 'base'
    if($null-eq$h-or$null-eq$b){continue}
    $hRef="$((Get-OptionalProperty $h 'ref'))"
    $bRef="$((Get-OptionalProperty $b 'ref'))"
    $bSha="$((Get-OptionalProperty $b 'sha'))"
    if($hRef.StartsWith($prefix,[StringComparison]::Ordinal)-and$bRef-eq$parentHead.ref-and$bSha-eq$parentHead.sha){
      $matches+=$pr
    }
  }
  $matches
}

function Get-RepairChain([int]$root,[string]$token){
  $chain=@()
  $currentNumber=$root
  for($depth=0;$depth-lt$Config.MaxRepairDepth;$depth++){
    $current=Get-Pr $currentNumber $token
    if("$((Get-OptionalProperty $current 'state'))"-ne'open'){throw "PR #$currentNumber is not open"}
    $chain+=@{number=$currentNumber;pr=$current}
    $children=@(Get-RepairChildren $currentNumber $current $token)
    if($children.Count-eq0){return $chain}
    if($children.Count-gt1){throw "Ambiguous repair chain: PR #$currentNumber has $($children.Count) open exact-base repair children"}
    $currentNumber=[int]$children[0].number
  }
  throw "Repair chain exceeded maximum depth $($Config.MaxRepairDepth)"
}

function Infer-AuthorProvider([string]$headRef){
  if($headRef-match'^autopilot/repair-pr\d+-(openai|anthropic)-'){return $Matches[1]}
  'unknown'
}

function Invoke-ChildReview([int]$childNumber,[int]$parentNumber,$parentPr,$childPr,[string]$resultPath){
  $parentHead=Get-HeadInfo $parentPr
  $childHead=Get-HeadInfo $childPr
  $authorProvider=Infer-AuthorProvider $childHead.ref

  if($Config.ChildReviewProvider-notin@('openai','anthropic')){throw "Unknown child review provider: $($Config.ChildReviewProvider)"}
  if($Config.RequireCrossProvider-and$authorProvider-ne'unknown'-and$Config.ChildReviewProvider-eq$authorProvider){
    throw "Cross-provider child review is required, but author=$authorProvider reviewer=$($Config.ChildReviewProvider)"
  }

  Write-Host ("Independent child review provider: {0}; inferred author provider: {1}" -f $Config.ChildReviewProvider,$authorProvider) -ForegroundColor DarkGray

  $expectedBaseRef=[string]$parentHead.ref
  $expectedBaseSha=[string]$parentHead.sha
  if([string]::IsNullOrWhiteSpace($expectedBaseRef)-or[string]::IsNullOrWhiteSpace($expectedBaseSha)){
    throw "Parent PR #$parentNumber produced an empty base ref/SHA for child review"
  }

  $reviewArgs=[string[]]@(
    '-PullRequest',"$childNumber",
    '-ResultPath',$resultPath,
    '-ReviewOnly',
    '-UseCache',
    '-ReviewMode','child',
    '-ExpectedBaseRef',$expectedBaseRef,
    '-ExpectedBaseSha',$expectedBaseSha,
    '-ParentPullRequest',"$parentNumber"
  )

  $oldProvider=$env:SITEBOSS_REVIEW_PROVIDER
  $env:SITEBOSS_REVIEW_PROVIDER=$Config.ChildReviewProvider
  try{
    Write-Host ("Launching child reviewer with exact base: {0} @ {1}" -f $expectedBaseRef,$expectedBaseSha) -ForegroundColor DarkGray
    Invoke-PwshFile -ScriptPath $ReviewerPath -ArgumentList $reviewArgs
  }finally{
    if($null-eq$oldProvider){Remove-Item Env:SITEBOSS_REVIEW_PROVIDER -ErrorAction SilentlyContinue}
    else{$env:SITEBOSS_REVIEW_PROVIDER=$oldProvider}
  }

  if(-not(Test-Path -LiteralPath $resultPath)){throw "Child reviewer produced no result: $resultPath"}
  Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
}

function Integrate-ReviewedChild([int]$childNumber,[int]$parentNumber,$review,[string]$token,[string]$stateDir){
  if("$($review.verdict)"-ne'PASS'){throw 'Internal error: integration called without PASS review'}
  if("$($review.review_mode)"-ne'child'){throw 'Integration requires child review evidence'}
  if([int]$review.parent_pr-ne$parentNumber){throw 'Child review parent mismatch'}

  # Re-read exact live state after paid review.
  $parent=Get-Pr $parentNumber $token
  $child=Get-Pr $childNumber $token
  if("$((Get-OptionalProperty $parent 'state'))"-ne'open'){throw "Parent PR #$parentNumber is no longer open"}
  if("$((Get-OptionalProperty $child 'state'))"-ne'open'){throw "Child PR #$childNumber is no longer open"}

  $parentHead=Get-HeadInfo $parent
  $childHead=Get-HeadInfo $child
  $childBase=Get-BaseInfo $child

  if($parentHead.ref-eq'main'){throw 'REFUSED: repair-child integration may never update main'}
  if($parentHead.ref-in@('master','develop','production','release')){throw "REFUSED: protected integration target '$($parentHead.ref)'"}
  if(-not $childHead.ref.StartsWith("autopilot/repair-pr$parentNumber-",[StringComparison]::Ordinal)){
    throw "Child head '$($childHead.ref)' is not a bounded repair branch for PR #$parentNumber"
  }

  if("$($review.head_sha)"-ne$childHead.sha){throw 'Child head moved after review'}
  if("$($review.base_sha)"-ne$childBase.sha){throw 'Child base moved after review'}
  if($childBase.ref-ne$parentHead.ref-or$childBase.sha-ne$parentHead.sha){throw 'Parent branch moved after child review'}

  $compare=GHGet "/repos/$($Config.Owner)/$($Config.Repo)/compare/$($parentHead.sha)...$($childHead.sha)" $token
  $status="$((Get-OptionalProperty $compare 'status'))"
  $ahead=[int](Get-OptionalProperty $compare 'ahead_by')
  $behind=[int](Get-OptionalProperty $compare 'behind_by')
  if($status-ne'ahead'-or$ahead-lt1-or$behind-ne0){
    throw "Child is not a clean fast-forward of parent: status=$status ahead=$ahead behind=$behind"
  }

  Write-Host "`nCHILD REVIEW PASS - exact fast-forward integration authorized by owner-run Autopilot policy" -ForegroundColor Green
  Write-Host "Parent PR #$parentNumber branch: $($parentHead.ref)"
  Write-Host "From: $($parentHead.sha)"
  Write-Host "To reviewed child head: $($childHead.sha)"
  Write-Host 'main is not a target.' -ForegroundColor DarkGray

  $refBefore=Get-GitRef $parentHead.ref $token
  $refBeforeSha="$($refBefore.object.sha)"
  if($refBeforeSha-ne$parentHead.sha){throw "Parent Git ref moved before update: expected $($parentHead.sha), got $refBeforeSha"}

  [void](Update-GitRefFastForward $parentHead.ref $childHead.sha $token)

  $refAfter=Get-GitRef $parentHead.ref $token
  $afterSha="$($refAfter.object.sha)"
  if($afterSha-ne$childHead.sha){throw "Parent ref verification failed after update: expected $($childHead.sha), got $afterSha"}

  $parentAfter=Get-Pr $parentNumber $token
  $parentAfterHead=Get-HeadInfo $parentAfter
  if($parentAfterHead.sha-ne$childHead.sha){throw 'Parent PR head did not advance to reviewed child head'}

  $comment=@"
SiteBoss Autopilot integrated this independently-reviewed repair by exact fast-forward into parent PR #$parentNumber's head branch.

Reviewed child head: `$($childHead.sha)`
Previous parent head: `$($parentHead.sha)`
Parent branch: `$($parentHead.ref)`

This did NOT update or merge `main`. The parent PR must receive a fresh exact-head review before any further integration decision.
"@
  [void](GHPost "/repos/$($Config.Owner)/$($Config.Repo)/issues/$childNumber/comments" $token @{body=$comment})

  # Close the child PR if GitHub did not already close it after the base branch advanced.
  $childAfter=Get-Pr $childNumber $token
  if("$((Get-OptionalProperty $childAfter 'state'))"-eq'open'){
    [void](GHPatch "/repos/$($Config.Owner)/$($Config.Repo)/pulls/$childNumber" $token @{state='closed'})
  }

  $evidence=@{
    schema=1
    integrated_at=[DateTimeOffset]::UtcNow.ToString('o')
    parent_pr=$parentNumber
    child_pr=$childNumber
    previous_parent_head=$parentHead.sha
    reviewed_child_head=$childHead.sha
    parent_branch=$parentHead.ref
    review_provider="$($review.provider)"
    review_model="$($review.model)"
    review_diff_sha256="$($review.diff_sha256)"
    main_touched=$false
  }
  $path=Join-Path $stateDir ("child-integration-pr{0}-into-pr{1}.json"-f$childNumber,$parentNumber)
  $evidence|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $path -Encoding UTF8

  Write-Host "`nREPAIR CHILD INTEGRATED INTO PARENT BRANCH" -ForegroundColor Green
  Write-Host "PR #$childNumber -> PR #$parentNumber head $($childHead.sha)"
  Write-Host 'Parent PR now requires a fresh exact-head independent review on the next cycle.'
}

try{
  New-Item -ItemType Directory -Force -Path $StateDir|Out-Null
  $auth=New-GitHubInstallationToken
  $token=$auth.token
  $contents="$((Get-OptionalProperty $auth.permissions 'contents'))"
  $pulls="$((Get-OptionalProperty $auth.permissions 'pull_requests'))"
  if($contents-ne'write'-or$pulls-ne'write'){throw "Child integration requires contents/pull_requests write; got contents=$contents pulls=$pulls"}

  $chain=@(Get-RepairChain $RootPullRequest $token)
  Write-Host ("Repair chain: {0}" -f (($chain|ForEach-Object{"#$($_.number)"})-join' -> ')) -ForegroundColor DarkGray

  if($chain.Count-eq1){
    Write-Host 'No existing repair child is attached to the current parent head.' -ForegroundColor DarkGray
    $rootRepairArgs=[string[]]@('-ReviewPath',$RootReviewPath)
    Invoke-PwshFile -ScriptPath $RepairPath -ArgumentList $rootRepairArgs

    $chain=@(Get-RepairChain $RootPullRequest $token)
    if($chain.Count-eq1){
      Write-Host 'No repair child exists after the bounded repair attempt. Nothing to review/integrate.' -ForegroundColor Yellow
      exit 0
    }
  }

  # Act only on the deepest repair leaf. One reviewed integration/new repair per cycle.
  $leaf=$chain[-1]
  $directParent=$chain[-2]
  $leafPr=Get-Pr ([int]$leaf.number) $token
  $parentPr=Get-Pr ([int]$directParent.number) $token
  $leafReviewPath=Join-Path $StateDir ("review-pr{0}.json"-f$leaf.number)

  Write-Host "`nREPAIR LEAF: #$($leaf.number) (parent #$($directParent.number))" -ForegroundColor Cyan
  $leafReview=Invoke-ChildReview ([int]$leaf.number) ([int]$directParent.number) $parentPr $leafPr $leafReviewPath

  switch("$($leafReview.verdict)"){
    'PASS'{
      Integrate-ReviewedChild ([int]$leaf.number) ([int]$directParent.number) $leafReview $token $StateDir
      exit 0
    }
    'FAIL'{
      Write-Host "`nCHILD REVIEW FAILED - creating one bounded repair child of PR #$($leaf.number)" -ForegroundColor Yellow
      $nestedArgs=[string[]]@('-ReviewPath',$leafReviewPath)
      Invoke-PwshFile -ScriptPath $RepairPath -ArgumentList $nestedArgs
      Write-Host 'Cycle stopped after one bounded nested repair attempt. No integration occurred.'
      exit 0
    }
    'NEEDS_EVIDENCE'{
      Write-Host "`nCHILD REVIEW NEEDS EVIDENCE - no mutation performed." -ForegroundColor Yellow
      exit 0
    }
    default{throw "Unknown child review verdict: $($leafReview.verdict)"}
  }
}catch{
  Write-Host "`nSITEBOSS REPAIR-CHAIN MANAGER FAILED CLOSED" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  exit 1
}
