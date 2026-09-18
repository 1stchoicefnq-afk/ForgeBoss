Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-GitHubGovernorCli {
  $p=Join-Path $PSScriptRoot 'github-gate-cli.js'
  if(-not(Test-Path -LiteralPath $p)){throw "GitHub governor CLI missing: $p"}
  $p
}

function Get-GitHubMutationKey([string]$Method,[string]$Url,$Body){
  if($Method-eq'GET'-or$Method-eq'HEAD'-or$Method-eq'OPTIONS'-or$Url-match'/access_tokens$'){return ''}
  $bodyText=if($null-eq$Body){''}elseif($Body-is[string]){$Body}else{$Body|ConvertTo-Json -Depth 80 -Compress}
  $raw="$Method`n$Url`n$bodyText"
  $sha=[Security.Cryptography.SHA256]::Create()
  try{(($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($raw))|ForEach-Object{$_.ToString('x2')})-join'')}
  finally{$sha.Dispose()}
}

function Invoke-GitHubGovernorCli {
  param([Parameter(Mandatory=$true)][hashtable]$InputObject,[switch]$AllowNonZero)
  $node=Get-Command node.exe -ErrorAction SilentlyContinue
  if(-not$node){$node=Get-Command node -ErrorAction SilentlyContinue}
  if(-not$node){throw 'Node.js is required for the shared GitHub governor.'}
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName=$node.Source
  $psi.UseShellExecute=$false
  $psi.RedirectStandardInput=$true
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $psi.CreateNoWindow=$true
  [void]$psi.ArgumentList.Add((Get-GitHubGovernorCli))
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi
  try{
    if(-not$p.Start()){throw 'Failed to start GitHub governor CLI'}
    $p.StandardInput.Write(($InputObject|ConvertTo-Json -Depth 100 -Compress));$p.StandardInput.Close()
    $stdout=$p.StandardOutput.ReadToEnd();$stderr=$p.StandardError.ReadToEnd();$p.WaitForExit()
    if([string]::IsNullOrWhiteSpace($stdout)){throw "GitHub governor failed (exit $($p.ExitCode)): $stderr"}
    $obj=$stdout|ConvertFrom-Json
    if($p.ExitCode-ne0-and-not$AllowNonZero){throw "GitHub governor failed (exit $($p.ExitCode)): HTTP $($obj.status) $($obj.body) $stderr"}
    $obj
  }finally{$p.Dispose()}
}

function Invoke-GovernedGitHubRaw {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('GET','HEAD','POST','PATCH','PUT','DELETE')][string]$Method,
    [Parameter(Mandatory=$true)][string]$Url,
    [hashtable]$Headers=@{},
    $Body=$null,
    [string]$DedupeKey='',
    [int]$CacheTtlMs=-1,
    [switch]$AllowHttpError
  )
  $h=@{};foreach($k in $Headers.Keys){$h[$k]=$Headers[$k]}
  if($null-ne$Body-and-not($h.ContainsKey('Content-Type'))){$h['Content-Type']='application/json'}
  if(-not$DedupeKey){$DedupeKey=Get-GitHubMutationKey -Method $Method -Url $Url -Body $Body}
  $i=@{mode='request';method=$Method;url=$Url;headers=$h}
  if($null-ne$Body){$i.body=$Body}
  if($DedupeKey){$i.dedupeKey=$DedupeKey}
  if($CacheTtlMs-ge0){$i.cacheTtlMs=$CacheTtlMs}
  Invoke-GitHubGovernorCli -InputObject $i -AllowNonZero:$AllowHttpError
}

function Invoke-GovernedGitHubJson {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('GET','HEAD','POST','PATCH','PUT','DELETE')][string]$Method,
    [Parameter(Mandatory=$true)][string]$Url,
    [hashtable]$Headers=@{},
    $Body=$null,
    [string]$DedupeKey='',
    [int]$CacheTtlMs=-1
  )
  $r=Invoke-GovernedGitHubRaw -Method $Method -Url $Url -Headers $Headers -Body $Body -DedupeKey $DedupeKey -CacheTtlMs $CacheTtlMs
  if($r.deduplicated){return [pscustomobject]@{deduplicated=$true}}
  if([string]::IsNullOrWhiteSpace("$($r.body)")){return $null}
  "$($r.body)"|ConvertFrom-Json
}

function Invoke-GovernedGitPush {
  param(
    [Parameter(Mandatory=$true)][string]$WorkingDirectory,
    [string]$Remote='origin',
    [Parameter(Mandatory=$true)][string]$RefSpec,
    [string[]]$ExtraArgs=@()
  )
  $r=Invoke-GitHubGovernorCli -InputObject @{mode='git-push';cwd=$WorkingDirectory;remote=$Remote;refspec=$RefSpec;extraArgs=@($ExtraArgs)}
  if(-not$r.ok){throw "Governed git push failed: $($r.stderr)"}
  $r
}

Export-ModuleMember -Function Invoke-GovernedGitHubRaw,Invoke-GovernedGitHubJson,Invoke-GovernedGitPush
