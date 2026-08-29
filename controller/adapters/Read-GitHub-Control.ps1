param(
 [Parameter(Mandatory=$true)][string]$Owner,
 [Parameter(Mandatory=$true)][string]$Repo,
 [Parameter(Mandatory=$true)][int]$RootPr,
 [int]$PreferredRepairPr = 0,
 [Parameter(Mandatory=$true)][string]$AppId,
 [Parameter(Mandatory=$true)][string]$InstallationId,
 [Parameter(Mandatory=$true)][string]$PemPath,
 [Parameter(Mandatory=$true)][string]$InvocationId,
 [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($InvocationId-notmatch'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'){throw 'Invalid ForgeBoss InvocationId'}

function B64Url([byte[]]$Bytes){[Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')}
function Optional($Object,[string]$Name){if($null-eq$Object){return $null};$p=$Object.PSObject.Properties[$Name];if($null-eq$p){return $null};$p.Value}
function Write-TextAtomic([string]$Path,[string]$Text){
 $dir=Split-Path -Parent $Path;if($dir){New-Item -ItemType Directory -Force -Path $dir|Out-Null}
 if(Test-Path -LiteralPath $Path){throw "Control artifact already exists: $Path"}
 $tmp="$Path.tmp-$([Guid]::NewGuid().ToString('N'))"
 try{[IO.File]::WriteAllText($tmp,$Text,[Text.UTF8Encoding]::new($false));Move-Item -LiteralPath $tmp -Destination $Path}catch{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue;throw}
}
function Emit-ControlResult([object]$Object){
 $json=$Object|ConvertTo-Json -Depth 30 -Compress
 Write-TextAtomic $Output $json
 $b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
 Write-Output "FORGEBOSS_CONTROL_RESULT_B64=$b64"
}
function New-ReadToken {
 if(-not(Test-Path -LiteralPath $PemPath)){throw "GitHub App private key missing: $PemPath"}
 $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();$header=@{alg='RS256';typ='JWT'}|ConvertTo-Json -Compress;$payload=@{iat=$now-60;exp=$now+540;iss=$AppId}|ConvertTo-Json -Compress
 $unsigned="$(B64Url([Text.Encoding]::UTF8.GetBytes($header))).$(B64Url([Text.Encoding]::UTF8.GetBytes($payload)))";$rsa=[Security.Cryptography.RSA]::Create()
 try{$rsa.ImportFromPem((Get-Content -LiteralPath $PemPath -Raw));$sig=$rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned),[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)}finally{$rsa.Dispose()}
 $jwt="$unsigned.$(B64Url $sig)";$headers=@{Authorization="Bearer $jwt";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}
 $body=@{repositories=@($Repo);permissions=@{pull_requests='read';contents='read';checks='read';statuses='read'}}|ConvertTo-Json -Depth 10
 $tok=Invoke-RestMethod -Method Post -Uri "https://api.github.com/app/installations/$InstallationId/access_tokens" -Headers $headers -ContentType 'application/json' -Body $body
 "$($tok.token)"
}
function Headers([string]$Token){@{Authorization="Bearer $Token";Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}}
function Get-Pr([int]$Number,[string]$Token){Invoke-RestMethod -Method Get -Uri "https://api.github.com/repos/$Owner/$Repo/pulls/$Number" -Headers (Headers $Token)}
function Get-OpenBasePrs([string]$BaseRef,[string]$Token){$encoded=[Uri]::EscapeDataString($BaseRef);$uri="https://api.github.com/repos/$Owner/$Repo/pulls?state=open&base=$encoded&per_page=100&sort=updated&direction=desc";@(Invoke-RestMethod -Method Get -Uri $uri -Headers (Headers $Token))}
function PrSummary([object]$Pr){
 $h=Optional $Pr 'head';$b=Optional $Pr 'base'
 [ordered]@{number=[int]$Pr.number;state="$($Pr.state)";title="$($Pr.title)";node_id="$($Pr.node_id)";api_url="$($Pr.url)";html_url="$($Pr.html_url)";head_sha="$((Optional $h 'sha'))";head_ref="$((Optional $h 'ref'))";base_sha="$((Optional $b 'sha'))";base_ref="$((Optional $b 'ref'))";repo="$((Optional (Optional $h 'repo') 'full_name'))";updated_at="$($Pr.updated_at)"}
}
function Looks-LikeRepairChild([object]$Pr,[int]$ParentNumber){$h=Optional $Pr 'head';$headRef="$((Optional $h 'ref'))";$title="$($Pr.title)";$body="$($Pr.body)";$prefix="autopilot/repair-pr$ParentNumber-";if($headRef.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){return $true};if($title-match'(?i)\brepair\b'-and($title-match"#$ParentNumber\b"-or$body-match"#$ParentNumber\b")){return $true};if($body-match"(?i)(parent|target|integration)\s+PR\s*:?\s*#$ParentNumber\b"){return $true};return $false}

$token=New-ReadToken;$root=Get-Pr $RootPr $token;$rh=Optional $root 'head';$rb=Optional $root 'base'
if("$($root.state)"-ne'open'){throw "Root PR #$RootPr is not open"}
if("$((Optional (Optional $rh 'repo') 'full_name'))"-ne"$Owner/$Repo"){throw 'Root PR repository mismatch'}
$rootHeadSha="$((Optional $rh 'sha'))";$rootHeadRef="$((Optional $rh 'ref'))"
$preferred=$null;if($PreferredRepairPr-gt0){try{$preferred=Get-Pr $PreferredRepairPr $token}catch{$preferred=$null}}
$openOnBase=@(Get-OpenBasePrs $rootHeadRef $token);$exactCandidates=@()
foreach($pr in $openOnBase){$h=Optional $pr 'head';$b=Optional $pr 'base';$sameRepo="$((Optional (Optional $h 'repo') 'full_name'))"-eq"$Owner/$Repo";$exactBase="$((Optional $b 'sha'))"-eq$rootHeadSha;if($sameRepo-and$exactBase-and(Looks-LikeRepairChild $pr $RootPr)){$exactCandidates+=@($pr)}}
$selected=$null;$selectionReason=''
if($null-ne$preferred){$ph=Optional $preferred 'head';$pb=Optional $preferred 'base';$preferredValid=("$($preferred.state)"-eq'open'-and"$((Optional (Optional $ph 'repo') 'full_name'))"-eq"$Owner/$Repo"-and"$((Optional $pb 'sha'))"-eq$rootHeadSha-and"$((Optional $pb 'ref'))"-eq$rootHeadRef);if($preferredValid){$selected=$preferred;$selectionReason='preferred-exact'}}
if($null-eq$selected){if($exactCandidates.Count-eq1){$selected=$exactCandidates[0];$selectionReason='discovered-exact'}elseif($exactCandidates.Count-gt1){$numbers=($exactCandidates|ForEach-Object{"#$($_.number)"})-join', ';throw "Ambiguous exact repair children for root PR #$RootPr at $rootHeadSha`: $numbers"}}
$preferredSummary=$null;if($null-ne$preferred){$preferredSummary=PrSummary $preferred}
$rootSummary=[ordered]@{number=$RootPr;state="$($root.state)";node_id="$($root.node_id)";api_url="$($root.url)";html_url="$($root.html_url)";head_sha=$rootHeadSha;head_ref=$rootHeadRef;base_sha="$((Optional $rb 'sha'))";base_ref="$((Optional $rb 'ref'))"}
if($null-eq$selected){
 $preferredBase='';$preferredState='';if($null-ne$preferred){$preferredBase="$((Optional (Optional $preferred 'base') 'sha'))";$preferredState="$($preferred.state)"}
 $out=[ordered]@{schema=3;invocation_id=$InvocationId;generated_at=[DateTimeOffset]::UtcNow.ToString('o');owner=$Owner;repo=$Repo;root_pr=$rootSummary;repair_pr=$null;preferred_repair_pr=$preferredSummary;exact_repair_candidates=@($exactCandidates|ForEach-Object{PrSummary $_});binding=[ordered]@{status='NO_CURRENT_EXACT_REPAIR_CHILD';repair_base_equals_root_head=$false;repository="$Owner/$Repo";stale_preferred=$(if($null-ne$preferred){$true}else{$false});preferred_state=$preferredState;preferred_base_sha=$preferredBase}}
 Emit-ControlResult $out;exit 0
}
$selectedSummary=PrSummary $selected
$out=[ordered]@{schema=3;invocation_id=$InvocationId;generated_at=[DateTimeOffset]::UtcNow.ToString('o');owner=$Owner;repo=$Repo;root_pr=$rootSummary;repair_pr=$selectedSummary;preferred_repair_pr=$preferredSummary;exact_repair_candidates=@($exactCandidates|ForEach-Object{PrSummary $_});binding=[ordered]@{status='EXACT_REPAIR_CHILD_BOUND';repair_base_equals_root_head=$true;repository="$Owner/$Repo";selection_reason=$selectionReason}}
Emit-ControlResult $out
