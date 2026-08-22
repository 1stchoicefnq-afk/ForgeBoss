param([ValidateSet('read','record')][string]$Mode='read',[string]$Provider='',[string]$Purpose='',[int]$PaidCalls=0,[string]$Model='',[string]$Artifact='',[string]$LedgerPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'State.psm1') -Force
$j=Read-JsonSafe $LedgerPath;if($null-eq$j){$j=[pscustomobject]@{schema=2;entries=@()}}
if($Mode-eq'record'){
 $entries=@($j.entries)+@([pscustomobject]@{at=[DateTimeOffset]::UtcNow.ToString('o');provider=$Provider;model=$Model;purpose=$Purpose;paid_calls=$PaidCalls;artifact=$Artifact})
 Write-JsonAtomic $LedgerPath ([ordered]@{schema=2;entries=$entries}) 30;$j=Read-JsonSafe $LedgerPath
}
$today=[DateTimeOffset]::Now.Date;$calls=0
foreach($e in @($j.entries)){try{if(([DateTimeOffset]::Parse($e.at)).Date-eq$today){$calls+=[int]$e.paid_calls}}catch{}}
[ordered]@{today_paid_calls=$calls;entry_count=@($j.entries).Count;dollar_gating='disabled-until-trustworthy-usage-data'}
