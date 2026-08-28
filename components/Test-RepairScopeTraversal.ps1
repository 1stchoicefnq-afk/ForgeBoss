$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

# Regression test: Resolve-RepairScope() in SiteBoss-Repair-Rat.ps1 validated
# controller-supplied source_paths/write_allowlist entries with only
# `$rel.StartsWith('src/')`, which a string like 'src/../../../../etc/passwd'
# satisfies while still escaping the repository once joined with Join-Path.
# Extract the live function from the real source file (not a copy) so this
# fails again if the containment check is ever weakened.

$root=Split-Path -Parent $PSScriptRoot
$src=Join-Path $root 'SiteBoss-Repair-Rat.ps1'
if(-not(Test-Path -LiteralPath $src)){throw "Missing $src"}

$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($src,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count -gt 0){throw "Parser errors in $src"}

$fn=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Resolve-RepairScope'},$true)
if($fn.Count -ne 1){throw "Expected exactly one Resolve-RepairScope function definition in $src, found $($fn.Count)"}
Invoke-Expression $fn[0].Extent.Text

$repo=Join-Path ([IO.Path]::GetTempPath()) ('repair-scope-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path (Join-Path $repo 'src') | Out-Null
Set-Content -LiteralPath (Join-Path $repo 'src/a.js') -Value 'module.exports = {};'

function New-Manifest($sourcePaths,$writeAllowlist){
  $manifestPath=Join-Path $repo ('manifest-'+[Guid]::NewGuid().ToString('N')+'.json')
  [ordered]@{
    repair_pr=525
    exact_head='deadbeef'
    source_paths=$sourcePaths
    write_allowlist=$writeAllowlist
    limits=[ordered]@{max_source_files=10;max_write_files=10}
  } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifestPath
  return $manifestPath
}

# Variables Resolve-RepairScope reads from the enclosing script scope.
$RepairPullRequest=525
$RootPullRequest=0
$TargetSha=''
$script:ExactHead='deadbeef'

try{
  # 1. A traversal attempt must be rejected, not silently joined and read from
  #    (or written to) outside the repo. write_allowlist must be a subset of
  #    source_paths, so the same malicious entry has to appear in both to reach
  #    the write_allowlist-is-empty/subset checks at all -- meaning any exploit
  #    attempt trips the source_paths check first, which is exactly what's
  #    being verified here.
  $badSource=New-Manifest @('src/../../../../etc/passwd') @('src/../../../../etc/passwd')
  $threw=$false
  try{Resolve-RepairScope -Repo $repo -ManifestPath $badSource | Out-Null}
  catch{$threw=$true;if($_.Exception.Message -notmatch 'Unsafe controller source path'){throw "Wrong rejection reason: $($_.Exception.Message)"}}
  if(-not $threw){throw 'REGRESSION: traversal manifest entry was not rejected'}

  # 2. A traversal entry mixed in among otherwise-valid source paths must still
  #    be caught (not just when it's the only entry).
  $badMixed=New-Manifest @('src/a.js','src/../../../../etc/passwd') @('src/a.js')
  $threw=$false
  try{Resolve-RepairScope -Repo $repo -ManifestPath $badMixed | Out-Null}
  catch{$threw=$true;if($_.Exception.Message -notmatch 'Unsafe controller source path'){throw "Wrong rejection reason: $($_.Exception.Message)"}}
  if(-not $threw){throw 'REGRESSION: traversal entry mixed with valid paths was not rejected'}

  # 3. An absolute path must also be rejected.
  $badAbsolute=New-Manifest @('/etc/passwd') @('/etc/passwd')
  $threw=$false
  try{Resolve-RepairScope -Repo $repo -ManifestPath $badAbsolute | Out-Null}
  catch{$threw=$true}
  if(-not $threw){throw 'REGRESSION: absolute source_paths entry was not rejected'}

  # 4. A legitimate in-scope manifest must still succeed (the fix must not be
  #    overly strict and break normal operation).
  $good=New-Manifest @('src/a.js') @('src/a.js')
  $result=Resolve-RepairScope -Repo $repo -ManifestPath $good
  if(@($result.source_paths) -notcontains 'src/a.js'){throw 'Valid manifest was incorrectly rejected'}
}finally{
  Remove-Item -LiteralPath $repo -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'REPAIR SCOPE TRAVERSAL SELFTEST: PASS' -ForegroundColor Green
