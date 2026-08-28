param([ValidateSet('read','record')][string]$Mode='read',[string]$Provider='',[string]$Purpose='',[int]$PaidCalls=0,[string]$Model='',[string]$Artifact='',[string]$LedgerPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'State.psm1') -Force

function Read-LedgerOrFail([string]$Path){
 # A missing ledger file is a legitimate empty ledger (first run). A ledger file that
 # exists but fails to parse (corrupt/partial write/lock contention) is NOT the same
 # thing: treating it as empty would silently reset the daily paid-call cap to zero
 # and let unlimited further paid calls through. Callers must fail closed on corrupt.
 if(-not(Test-Path -LiteralPath $Path)){return @{ledger=[pscustomobject]@{schema=2;entries=@()};corrupt=$false}}
 try{return @{ledger=(Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json);corrupt=$false}}
 catch{return @{ledger=$null;corrupt=$true}}
}

function Get-TodayTotal($ledger){
 $today=[DateTimeOffset]::Now.Date;$calls=0
 foreach($e in @($ledger.entries)){try{if(([DateTimeOffset]::Parse($e.at)).Date-eq$today){$calls+=[int]$e.paid_calls}}catch{}}
 return $calls
}

if($Mode-eq'record'){
 # Read-modify-write must be serialized across concurrent builder/ledger invocations,
 # otherwise two processes can both read the same baseline and one write silently
 # discards the other's recorded paid call, undercounting spend against the daily cap.
 $lockPath="$LedgerPath.lock";$deadline=[DateTime]::UtcNow.AddSeconds(15);$fs=$null
 try{
  while(-not $fs){
   try{$fs=[IO.File]::Open($lockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)}
   catch [IO.IOException]{
    if([DateTime]::UtcNow-ge$deadline){throw "Timed out waiting for cost ledger lock: $lockPath"}
    Start-Sleep -Milliseconds 100
   }
  }
  $r=Read-LedgerOrFail $LedgerPath
  if($r.corrupt){throw "Cost ledger at $LedgerPath exists but is unreadable/corrupt; refusing to record a paid call over an untrustworthy ledger. Repair or reset the ledger file before continuing."}
  $entries=@($r.ledger.entries)+@([pscustomobject]@{at=[DateTimeOffset]::UtcNow.ToString('o');provider=$Provider;model=$Model;purpose=$Purpose;paid_calls=$PaidCalls;artifact=$Artifact})
  Write-JsonAtomic $LedgerPath ([ordered]@{schema=2;entries=$entries}) 30
  $ledger=[pscustomobject]@{schema=2;entries=$entries}
 } finally {
  if($fs){$fs.Dispose()}
  Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
 }
 # Callers invoke this script as a separate `pwsh -File` child process and capture its
 # stdout, so the result MUST be emitted as compact JSON text, not a raw PowerShell
 # object/hashtable: across a process boundary a bare object is captured only as its
 # formatted-for-display text table, and `$result.today_paid_calls` on that silently
 # evaluates to $null (-> 0) instead of throwing, which defeats the daily cap check
 # entirely regardless of actual ledger content.
 [ordered]@{today_paid_calls=(Get-TodayTotal $ledger);entry_count=@($ledger.entries).Count;dollar_gating='disabled-until-trustworthy-usage-data';ledger_status='ok'}|ConvertTo-Json -Compress
} else {
 $r=Read-LedgerOrFail $LedgerPath
 if($r.corrupt){
  # Fail closed: report a sentinel that will never compare "under" a real daily cap,
  # instead of 0, which would look identical to a freshly-created empty ledger.
  [ordered]@{today_paid_calls=[int]::MaxValue;entry_count=-1;dollar_gating='disabled-until-trustworthy-usage-data';ledger_status='corrupt'}|ConvertTo-Json -Compress
 } else {
  [ordered]@{today_paid_calls=(Get-TodayTotal $r.ledger);entry_count=@($r.ledger.entries).Count;dollar_gating='disabled-until-trustworthy-usage-data';ledger_status='ok'}|ConvertTo-Json -Compress
 }
}
