param(
 [Parameter(Mandatory=$true)][string]$MarkdownPath,
 [int]$PullRequest=168
)

$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cfg=Get-Content -LiteralPath (Join-Path $Root 'controller\config.default.json') -Raw | ConvertFrom-Json

$Owner="$($cfg.control.owner)"
$Repo="$($cfg.control.repo)"
$AppId="$($cfg.control.github_app.app_id)"
$InstallationId="$($cfg.control.github_app.installation_id)"
$PemPath=[Environment]::ExpandEnvironmentVariables("$($cfg.control.github_app.pem_path)")

if(-not(Test-Path -LiteralPath $MarkdownPath)){throw "Run report markdown missing: $MarkdownPath"}
if(-not(Test-Path -LiteralPath $PemPath)){throw "GitHub App key missing: $PemPath"}

function B64Url([byte[]]$Bytes){
 [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function New-AppJwt {
 $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
 $header=@{alg='RS256';typ='JWT'} | ConvertTo-Json -Compress
 $payload=@{iat=$now-60;exp=$now+540;iss=$AppId} | ConvertTo-Json -Compress
 $unsigned="$(B64Url ([Text.Encoding]::UTF8.GetBytes($header))).$(B64Url ([Text.Encoding]::UTF8.GetBytes($payload)))"

 $pem=Get-Content -LiteralPath $PemPath -Raw
 $rsa=[Security.Cryptography.RSA]::Create()
 try{
   # ImportFromPem is unavailable on some Windows PowerShell/.NET combinations.
   if($rsa.PSObject.Methods.Name -contains 'ImportFromPem'){
     $rsa.ImportFromPem($pem)
   }else{
     throw 'RSA.ImportFromPem is unavailable in this Windows PowerShell runtime'
   }
   $sig=$rsa.SignData(
     [Text.Encoding]::UTF8.GetBytes($unsigned),
     [Security.Cryptography.HashAlgorithmName]::SHA256,
     [Security.Cryptography.RSASignaturePadding]::Pkcs1
   )
 }finally{
   if($null-ne$rsa){$rsa.Dispose()}
 }
 "$unsigned.$(B64Url $sig)"
}

function Headers([string]$Token){
 @{
   Authorization="Bearer $Token"
   Accept='application/vnd.github+json'
   'X-GitHub-Api-Version'='2022-11-28'
 }
}

function Get-InstallationToken {
 $jwt=New-AppJwt
 $body=@{
   repositories=@($Repo)
   permissions=@{
     issues='write'
     pull_requests='read'
     contents='read'
   }
 } | ConvertTo-Json -Depth 10

 Invoke-RestMethod -Method Post `
   -Uri "https://api.github.com/app/installations/$InstallationId/access_tokens" `
   -Headers (Headers $jwt) `
   -ContentType 'application/json' `
   -Body $body
}

$tok=Get-InstallationToken
$bodyText=Get-Content -LiteralPath $MarkdownPath -Raw
$comment=@{body=$bodyText} | ConvertTo-Json -Depth 5

$resp=Invoke-RestMethod -Method Post `
 -Uri "https://api.github.com/repos/$Owner/$Repo/issues/$PullRequest/comments" `
 -Headers (Headers "$($tok.token)") `
 -ContentType 'application/json' `
 -Body $comment

[pscustomobject]@{
 ok=$true
 comment_id=$resp.id
 html_url=$resp.html_url
 pull_request=$PullRequest
} | ConvertTo-Json -Compress
