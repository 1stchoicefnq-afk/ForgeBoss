param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference='Stop'
$Root=(Resolve-Path -LiteralPath $Root).Path
$ManifestPath=Join-Path $Root 'PACKAGE-MANIFEST.json'
if(!(Test-Path -LiteralPath $ManifestPath -PathType Leaf)){throw 'PACKAGE_MANIFEST_MISSING'}
if(Test-Path -LiteralPath (Join-Path $Root 'PACKAGE-VERIFICATION.json')){throw 'STATIC_PACKAGE_VERIFICATION_DENIED'}
$m=Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if($null -eq $m.files){throw 'PACKAGE_MANIFEST_FILES_MISSING'}
$expected=@{}
foreach($p in $m.files.PSObject.Properties){
  $rel=[string]$p.Name
  if([string]::IsNullOrWhiteSpace($rel) -or [IO.Path]::IsPathRooted($rel) -or $rel -match '(^|[\\/])\.\.([\\/]|$)'){throw "PACKAGE_MANIFEST_PATH_INVALID: $rel"}
  $row=$p.Value
  $sha=if($row -is [string]){[string]$row}else{[string]$row.sha256}
  if($sha -notmatch '^[0-9a-fA-F]{64}$'){throw "PACKAGE_MANIFEST_HASH_INVALID: $rel"}
  $expected[$rel.Replace('\','/')]=@{sha=$sha.ToLowerInvariant();row=$row}
}
if($expected.Count -lt 1){throw 'PACKAGE_MANIFEST_EMPTY'}
$actual=@{}
Get-ChildItem -LiteralPath $Root -Recurse -File | ForEach-Object {
  $rel=$_.FullName.Substring($Root.Length).TrimStart('\','/').Replace('\','/')
  if($rel -ne 'PACKAGE-MANIFEST.json'){$actual[$rel]=$_.FullName}
}
$missing=@($expected.Keys | Where-Object {-not $actual.ContainsKey($_)})
$extra=@($actual.Keys | Where-Object {-not $expected.ContainsKey($_)})
if($missing.Count -or $extra.Count){throw ("PACKAGE_FILESET_MISMATCH missing="+($missing -join ',')+" extra="+($extra -join ','))}
foreach($rel in ($expected.Keys | Sort-Object)){
  $path=$actual[$rel]
  $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  if($hash -ne $expected[$rel].sha){throw "PACKAGE_HASH_MISMATCH: $rel"}
  $row=$expected[$rel].row
  $size=$null
  if($row -isnot [string]){
    if($null -ne $row.sizeBytes){$size=[int64]$row.sizeBytes}
    elseif($null -ne $row.size){$size=[int64]$row.size}
  }
  if($null -ne $size -and (Get-Item -LiteralPath $path).Length -ne $size){throw "PACKAGE_SIZE_MISMATCH: $rel"}
}
[pscustomobject]@{ok=$true;filesVerified=$expected.Count;manifestSha256=(Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json -Compress
