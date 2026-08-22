Set-StrictMode -Version Latest
function Get-TextSha256([string]$Text){
 $sha=[Security.Cryptography.SHA256]::Create()
 try{(($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))|ForEach-Object{$_.ToString('x2')})-join'')}
 finally{$sha.Dispose()}
}
function Write-JsonAtomic([string]$Path,[object]$Object,[int]$Depth=80){
 $dir=Split-Path -Parent $Path;if($dir){New-Item -ItemType Directory -Force -Path $dir|Out-Null}
 $tmp="$Path.tmp-$([Guid]::NewGuid().ToString('N'))"
 try{$Object|ConvertTo-Json -Depth $Depth|Set-Content -LiteralPath $tmp -Encoding UTF8;Move-Item -LiteralPath $tmp -Destination $Path -Force}
 finally{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}
}
function Read-JsonSafe([string]$Path){
 if(-not(Test-Path -LiteralPath $Path)){return $null}
 try{return Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json}catch{return $null}
}
Export-ModuleMember -Function Get-TextSha256,Write-JsonAtomic,Read-JsonSafe
