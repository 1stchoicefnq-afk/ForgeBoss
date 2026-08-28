$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

# Regression test: components/Executor-v0.4.ps1's Invoke-Git previously splatted the
# automatic $args variable instead of its own $commandArgsLocal parameter, so every
# git invocation silently ran bare `git` with zero arguments. Extract the live
# function from the real source file (not a copy) so this fails again if the bug
# is reintroduced.

$root=$PSScriptRoot
$src=Join-Path $root 'Executor-v0.4.ps1'
if(-not(Test-Path -LiteralPath $src)){ throw "Missing $src" }

$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($src,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count -gt 0){ throw "Parser errors in $src" }

$fn=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Git'},$true)
if($fn.Count -ne 1){ throw "Expected exactly one Invoke-Git function definition in $src, found $($fn.Count)" }

Invoke-Expression $fn[0].Extent.Text

$temp=Join-Path ([IO.Path]::GetTempPath()) ('executor-git-arg-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $temp | Out-Null
try{
  Invoke-Git -commandArgsLocal @('init','--quiet',$temp) -Capture | Out-Null
  if(-not(Test-Path -LiteralPath (Join-Path $temp '.git'))){
    throw 'REGRESSION: Invoke-Git did not forward its arguments to git (git init did not run)'
  }
}finally{
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'EXECUTOR INVOKE-GIT ARGUMENT-FORWARDING SELFTEST: PASS' -ForegroundColor Green
