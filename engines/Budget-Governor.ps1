param([string]$PolicyPath,[string]$ClusterPath,[int]$RepairCallsUsed=0,[int]$ReviewCallsUsed=0)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$p=Get-Content -LiteralPath $PolicyPath -Raw|ConvertFrom-Json
$c=Get-Content -LiteralPath $ClusterPath -Raw|ConvertFrom-Json
$d=$p.default
[ordered]@{
 repair_allowed=($RepairCallsUsed-lt[int]$d.max_paid_repair_calls_per_cycle -and [int]$c.failure_count-ge[int]$d.min_clustered_failures_before_repair)
 review_allowed=($ReviewCallsUsed-lt[int]$d.max_paid_review_calls_per_cycle)
 repair_calls_used=$RepairCallsUsed;repair_calls_max=[int]$d.max_paid_repair_calls_per_cycle
 review_calls_used=$ReviewCallsUsed;review_calls_max=[int]$d.max_paid_review_calls_per_cycle
}
