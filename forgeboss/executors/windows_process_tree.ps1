[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$RootPid
)

$ErrorActionPreference = 'Stop'

$rows = @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId)
$children = @{}

foreach ($row in $rows) {
    $pid = [int]$row.ProcessId
    $parent = [int]$row.ParentProcessId
    if (-not $children.ContainsKey($parent)) {
        $children[$parent] = [System.Collections.Generic.List[int]]::new()
    }
    $children[$parent].Add($pid)
}

$queue = [System.Collections.Generic.Queue[int]]::new()
$seen = [System.Collections.Generic.HashSet[int]]::new()
$targets = [System.Collections.Generic.List[int]]::new()
$queue.Enqueue($RootPid) | Out-Null
$seen.Add($RootPid) | Out-Null

while ($queue.Count -gt 0) {
    $parent = $queue.Dequeue()
    if (-not $children.ContainsKey($parent)) {
        continue
    }
    foreach ($child in $children[$parent]) {
        if ($seen.Add($child)) {
            $targets.Add($child)
            $queue.Enqueue($child)
        }
    }
}

for ($i = $targets.Count - 1; $i -ge 0; $i--) {
    $pid = $targets[$i]
    try {
        Stop-Process -Id $pid -Force -ErrorAction Stop
    }
    catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
        # The process may have exited between snapshot and termination.
    }
}
