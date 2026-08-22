param([string]$Repo,[string[]]$ChangedFiles,[string]$Output)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'State.psm1') -Force
$tests=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$postgres=$false
foreach($file in @($ChangedFiles)){
 $f=$file.Replace('\','/');if($f-match'(?i)postgres|persistence|transaction|intake|crm|lead'){$postgres=$true}
}
if($postgres){foreach($tf in @(Get-ChildItem -LiteralPath (Join-Path $Repo 'tests') -File -Filter 'postgres*.integration.test.js' -ErrorAction SilentlyContinue)){[void]$tests.Add("tests/$($tf.Name)")}}
Write-JsonAtomic $Output ([ordered]@{schema=1;postgres_scope=$postgres;selected_tests=@($tests|Sort-Object)}) 20
