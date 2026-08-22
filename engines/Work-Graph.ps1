param([string]$ClusterPath,[string]$ArchitecturePath,[string]$BacklogPath,[string]$Output)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'State.psm1') -Force
$c=Read-JsonSafe $ClusterPath;$a=Read-JsonSafe $ArchitecturePath;$b=Read-JsonSafe $BacklogPath
if($null-eq$c-or$null-eq$a){throw 'work graph prerequisites missing'}
$jobs=@();$priority=0
foreach($cl in @($c.clusters)){$priority++;$jobs+=@([ordered]@{id="failure-$($cl.id.Substring(0,12))";kind='repair';priority=$priority;status='ready';evidence_count=[int]$cl.count;names=@($cl.names);depends_on=@();paid_reasoning_candidate=$true})}
if($null-ne$b){foreach($item in @($b.items|Select-Object -First 100)){$priority++;$id=Get-TextSha256 "$($item.kind)|$($item.file)|$($item.line)|$($item.text)";$jobs+=@([ordered]@{id="backlog-$($id.Substring(0,12))";kind="$($item.kind)";priority=$priority;status='discovered';evidence_count=1;names=@("$($item.file):$($item.line)");depends_on=@();paid_reasoning_candidate=$false})}}
Write-JsonAtomic $Output ([ordered]@{schema=2;exact_head=$a.exact_head;job_count=$jobs.Count;jobs=$jobs}) 40
