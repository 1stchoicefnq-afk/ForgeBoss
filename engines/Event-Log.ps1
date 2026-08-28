param([string]$EventName,[string]$Detail='',[string]$Path)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$dir=Split-Path -Parent $Path;if($dir){New-Item -ItemType Directory -Force -Path $dir|Out-Null}
[ordered]@{at=[DateTimeOffset]::UtcNow.ToString('o');event=$EventName;detail=$Detail}|ConvertTo-Json -Compress|Add-Content -LiteralPath $Path -Encoding UTF8
