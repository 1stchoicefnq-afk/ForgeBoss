param([string]$PolicyPath,[string]$JobKind,[int]$EvidenceCount=0,[bool]$RequiresCode=$false)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$p=Get-Content -LiteralPath $PolicyPath -Raw|ConvertFrom-Json
if($JobKind-in@('classification','test-selection','architecture','backlog')){[ordered]@{paid=$false;engine='local';reason='deterministic/local'};exit 0}
if($JobKind-eq'review'){$r=$p.routing.independent_review;[ordered]@{paid=$true;provider=$r.provider;model=$r.model;reason='green candidate independent review'};exit 0}
if($RequiresCode-and$EvidenceCount-gt0){$r=$p.routing.database_repair;[ordered]@{paid=$true;provider=$r.provider;model=$r.model;reason='evidence-backed implementation'};exit 0}
[ordered]@{paid=$false;engine='local';reason='paid reasoning not justified'}
