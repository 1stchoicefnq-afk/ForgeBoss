@echo off
setlocal EnableExtensions
title ForgeBoss Cline Executor Setup
cd /d "%~dp0"

echo ============================================================
echo FORGEBOSS OPTIONAL CLINE SETUP
echo Installs the official Apache-2.0 Cline CLI separately.
echo NO SiteBoss writes. NO model calls. NO automatic enabling.
echo ============================================================
echo.

where node.exe >nul 2>&1 || goto :NO_NODE
where npm.cmd >nul 2>&1 || goto :NO_NPM

set "RUNTIME=%USERPROFILE%\.forgeboss\runtime"
set "CLINEDATA=%RUNTIME%\cline-data"
if not exist "%RUNTIME%" mkdir "%RUNTIME%"
if not exist "%CLINEDATA%" mkdir "%CLINEDATA%"

echo [1/2] Installing official Cline CLI...
call npm install -g cline || goto :FAIL

echo [2/2] Verifying Cline command...
node "%~dp0forgeboss\tests\verify_cline.js" || goto :FAIL

echo.
echo ============================================================
echo CLINE INSTALLED FOR FORGEBOSS
echo.
echo It remains QUARANTINED by default.
echo Before paid use, authenticate the dedicated Cline data dir:
echo   cline --data-dir "%CLINEDATA%" auth
echo.
echo ForgeBoss still requires its paid-executor gate, explicit
echo Cline quarantine gate, executor lease, and verified isolation.
echo ============================================================
pause
exit /b 0

:NO_NODE
echo [FAIL] Node.js not found.
pause
exit /b 2
:NO_NPM
echo [FAIL] npm not found.
pause
exit /b 2
:FAIL
set EC=%ERRORLEVEL%
echo.
echo [FAIL] Cline setup stopped. Exit code %EC%.
pause
exit /b %EC%
