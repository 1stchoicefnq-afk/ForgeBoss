param(
 [Parameter(Mandatory=$true)][string]$MarkdownPath,
 [int]$PullRequest=168
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Node=(Get-Command node -ErrorAction Stop).Source
$Publisher=Join-Path $Root 'forgeboss\github\publish-run-report.js'
# All GitHub writes are deliberately delegated to the single guarded Node writer.
# Do not add Invoke-RestMethod/gh write calls here; that would bypass serialization,
# throttling, duplicate suppression, retry/backoff, and rate-limit observability.
& $Node $Publisher --markdown $MarkdownPath --pr $PullRequest
if($LASTEXITCODE -ne 0){throw "Guarded GitHub publisher failed with exit code $LASTEXITCODE"}
