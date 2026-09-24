@echo off
setlocal
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\Turn-On-ForgeBoss.ps1" -PackageRoot "%ROOT%"
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" (
  echo [FAIL] ForgeBoss Stage 1 did not turn on.
  echo Run VERIFY-FORGEBOSS.cmd for the exact blocker.
  pause
  exit /b %RC%
)
echo [PASS] ForgeBoss Stage 1 turn-on completed.
pause
exit /b 0
