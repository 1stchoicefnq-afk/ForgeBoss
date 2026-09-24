@echo off
setlocal
set "ROOT=%~dp0"
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%ROOT%Verify-Stage1.ps1" -PackageRoot "%ROOT%"
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (echo [PASS] STAGE 1 VERIFY COMPLETE) else (echo [FAIL] STAGE 1 VERIFY FAILED)
pause
exit /b %RC%
