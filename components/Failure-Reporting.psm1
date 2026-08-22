Set-StrictMode -Version Latest

function Write-SiteBossFailure {
  param(
    [Parameter(Mandatory=$true)][string]$Stage,
    [Parameter(Mandatory=$true)][string]$Component,
    [Parameter(Mandatory=$true)][string]$Reason,
    [string]$Command='',
    [int]$ExitCode=-1,
    [string]$Stdout='',
    [string]$Stderr='',
    [hashtable]$Context=@{},
    [int]$ApiCallsThisCycle=0,
    [int]$GitHubMutationsThisCycle=0,
    [string]$StateRoot=''
  )
  if(-not$StateRoot){$StateRoot=Join-Path $PSScriptRoot '..\state\failures'}
  New-Item -ItemType Directory -Force -Path $StateRoot|Out-Null
  $stamp=[DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss-fff')
  $path=Join-Path $StateRoot ("$stamp-$Stage.json")
  [ordered]@{
    schema=1
    timestamp=[DateTimeOffset]::UtcNow.ToString('o')
    stage=$Stage
    component=$Component
    reason=$Reason
    command=$Command
    exit_code=$ExitCode
    stdout=$Stdout
    stderr=$Stderr
    context=$Context
    api_calls_this_cycle=$ApiCallsThisCycle
    github_mutations_this_cycle=$GitHubMutationsThisCycle
  }|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $path -Encoding UTF8

  Write-Host "`nSITEBOSS FAILURE REPORT" -ForegroundColor Red
  Write-Host "stage: $Stage"
  Write-Host "component: $Component"
  Write-Host "reason: $Reason"
  if($Command){Write-Host "command: $Command"}
  Write-Host "exit_code: $ExitCode"
  if($Stderr){Write-Host "stderr: $Stderr"}
  Write-Host "api_calls_this_cycle: $ApiCallsThisCycle"
  Write-Host "github_mutations_this_cycle: $GitHubMutationsThisCycle"
  Write-Host "failure_file: $path"
  return $path
}
Export-ModuleMember -Function Write-SiteBossFailure
