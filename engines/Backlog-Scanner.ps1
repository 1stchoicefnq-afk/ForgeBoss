param([string]$Repo,[string]$Output)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'State.psm1') -Force
if(-not(Test-Path -LiteralPath $Repo)){throw "Repo missing: $Repo"}
$items=@()
foreach($rootName in @('src','tests','docs','README.md')){
 $root=Join-Path $Repo $rootName;if(-not(Test-Path $root)){continue}
 $entry=Get-Item -LiteralPath $root
 $files=$(if($entry.PSIsContainer){Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue}else{@($entry)})
 foreach($file in @($files)){
  if($file.Length-gt2MB){continue};try{$lines=Get-Content -LiteralPath $file.FullName}catch{continue}
  for($i=0;$i-lt$lines.Count;$i++){foreach($tag in @('TODO','FIXME','HACK','XXX')){if("$($lines[$i])"-match"\b$tag\b"){
   $items+=@([ordered]@{kind='code-marker';tag=$tag;file=[IO.Path]::GetRelativePath($Repo,$file.FullName).Replace('\','/');line=$i+1;text="$($lines[$i])".Trim()});break
  }}}
 }
}
Write-JsonAtomic $Output ([ordered]@{schema=1;generated_at=[DateTimeOffset]::UtcNow.ToString('o');count=$items.Count;items=$items}) 40
