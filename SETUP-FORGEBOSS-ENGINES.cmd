@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
setlocal EnableExtensions
title ForgeBoss Open Source Engine Setup
cd /d "%~dp0"

echo ============================================================
echo FORGEBOSS OPEN-SOURCE ENGINE SETUP
echo Installs official MIT-licensed executor packages separately.
echo NO SiteBoss repo writes. NO model calls. NO GitHub publication.
echo ============================================================
echo.

where python.exe >nul 2>&1 || goto :NO_PYTHON
where node.exe >nul 2>&1 || goto :NO_NODE
where npm.cmd >nul 2>&1 || goto :NO_NPM

set "RUNTIME=%USERPROFILE%\.forgeboss\runtime"
if not exist "%RUNTIME%" mkdir "%RUNTIME%"
if not exist "%RUNTIME%\venv\Scripts\python.exe" (
  echo [1/5] Creating isolated Python runtime...
  python -m venv "%RUNTIME%\venv" || goto :FAIL
) else (
  echo [1/5] Python runtime already exists.
)

set "PY=%RUNTIME%\venv\Scripts\python.exe"
echo [2/5] Updating pip...
"%PY%" -m pip install --upgrade pip || goto :FAIL

echo [3/5] Installing official OpenHands / mini-SWE / Deep Agents packages...
"%PY%" -m pip install ^
  "openhands-sdk==1.22.1" ^
  "openhands-tools==1.22.1" ^
  "openhands-workspace==1.22.1" ^
  "mini-swe-agent==2.4.6" ^
  "deepagents==0.7.6" || goto :FAIL

echo [4/5] Installing official OpenCode CLI...
call npm install -g opencode-ai@latest || goto :FAIL

echo [5/5] Recording installed versions...
"%PY%" "%~dp0forgeboss\tests\verify_upstreams.py" || goto :FAIL
node "%~dp0forgeboss\tests\verify_opencode.js" || goto :FAIL

echo.
echo ============================================================
echo FORGEBOSS OPEN-SOURCE ENGINES READY
echo These are REAL upstream packages, not homemade replacements.
echo No model calls were made.
echo ============================================================
pause
exit /b 0

:NO_PYTHON
echo [FAIL] Python not found.
pause
exit /b 2
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
echo [FAIL] ForgeBoss engine setup stopped. Exit code %EC%.
echo Existing ForgeBoss/SiteBoss files were not replaced.
pause
exit /b %EC%
