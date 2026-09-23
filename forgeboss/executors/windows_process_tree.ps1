[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$RootPid
)

$ErrorActionPreference = 'Stop'
$knownParents = [System.Collections.Generic.HashSet[int]]::new()
$knownParents.Add($RootPid) | Out-Null

function Get-Descendants {
    param(
        [System.Collections.Generic.HashSet[int]]$Known,
        [int]$Root
    )

    $rows = @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId)
    $live = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($row in $rows) {
        $live.Add([int]$row.ProcessId) | Out-Null
    }

    $targets = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($row in $rows) {
        $pid = [int]$row.ProcessId
        if ($pid -ne $Root -and $Known.Contains($pid)) {
            $targets.Add($pid) | Out-Null
        }
    }

    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($row in $rows) {
            $pid = [int]$row.ProcessId
            $parent = [int]$row.ParentProcessId
            if (($Known.Contains($parent) -or $targets.Contains($parent)) -and -not $Known.Contains($pid)) {
                if ($targets.Add($pid)) {
                    $changed = $true
                }
            }
        }
    }

    return [pscustomobject]@{
        Live = $live
        Targets = $targets
    }
}

for ($round = 0; $round -lt 6; $round++) {
    $snapshot = Get-Descendants -Known $knownParents -Root $RootPid
    $targets = @($snapshot.Targets)

    if ($targets.Count -eq 0) {
        exit 0
    }

    foreach ($pid in $targets) {
        $knownParents.Add([int]$pid) | Out-Null
    }

    foreach ($pid in ($targets | Sort-Object -Descending)) {
        try {
            Stop-Process -Id ([int]$pid) -Force -ErrorAction Stop
        }
        catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
            # Process exited between snapshot and termination.
        }
    }

    Start-Sleep -Milliseconds 50
}

$final = Get-Descendants -Known $knownParents -Root $RootPid
if (@($final.Targets).Count -gt 0) {
    exit 9
}

exit 0