param([string]$RepoUrl='https://github.com/1stchoicefnq-afk/siteboss-monster.git',[string]$MirrorPath=(Join-Path $env:USERPROFILE '.siteboss\builder\mirrors\siteboss-monster.git'),[string]$StatePath='')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'State.psm1') -Force
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'forgeboss\github\GitHub-Governor.psm1') -Force
function Run([string]$Exe,[string[]]$CommandArgs,[string]$Cwd=''){
 $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=$Exe;$psi.UseShellExecute=$false;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true;$psi.CreateNoWindow=$true
 if($Cwd){$psi.WorkingDirectory=$Cwd};foreach($arg in $CommandArgs){[void]$psi.ArgumentList.Add([string]$arg)}
 $p=[Diagnostics.Process]::new();$p.StartInfo=$psi
 try{$null=$p.Start();$o=$p.StandardOutput.ReadToEnd();$e=$p.StandardError.ReadToEnd();$p.WaitForExit();[pscustomobject]@{exit_code=$p.ExitCode;stdout=$o;stderr=$e}}finally{$p.Dispose()}
}
$parent=Split-Path -Parent $MirrorPath;New-Item -ItemType Directory -Force -Path $parent|Out-Null
if(-not(Test-Path -LiteralPath $MirrorPath)){$r=Invoke-GovernedGitNetwork -CommandArgs @('clone','--mirror','--filter=blob:none',$RepoUrl,$MirrorPath)}else{$r=Invoke-GovernedGitNetwork -WorkingDirectory $MirrorPath -CommandArgs @('remote','update','--prune')}
if($r.exit_code-ne0){throw "mirror update failed: $($r.stderr)"}
$head=Run 'git.exe' @('rev-parse','refs/heads/main') $MirrorPath
if($head.exit_code-ne0){$head=Run 'git.exe' @('rev-parse','HEAD') $MirrorPath}
$out=[ordered]@{schema=1;mirror=$MirrorPath;updated_at=[DateTimeOffset]::UtcNow.ToString('o');main_sha=$head.stdout.Trim()}
if($StatePath){Write-JsonAtomic $StatePath $out 20};$out
