@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
setlocal EnableExtensions
title ForgeBoss v0.1 - ONE CLICK LOCAL TEST
cd /d "%~dp0"

echo ============================================================
echo FORGEBOSS v0.1
echo Builds SiteBoss. ForgeBoss is NOT the SiteBoss app.
echo LOCAL TEST ONLY - ZERO MODEL SPEND - ZERO GITHUB WRITES
echo ============================================================
echo.

node ".\forgeboss\tests\selftest.js"
if errorlevel 1 goto :FAIL

node ".\controller\hybrid\selftest.js"
if errorlevel 1 goto :FAIL

node ".\controller\selftest-agency-core-team.js"
if errorlevel 1 goto :FAIL

python ".\controller\deepagents\tests\test_policy.py"
if errorlevel 1 goto :FAIL

node ".\controller\siteboss-autopilot.js" selftest
if errorlevel 1 goto :FAIL

echo.
echo ============================================================
echo FORGEBOSS LOCAL STACK PASSED
echo Next: run SETUP-FORGEBOSS-ENGINES.cmd once to install the
echo REAL OpenHands, mini-SWE-agent, Deep Agents and OpenCode code.
echo ============================================================
pause
exit /b 0

:FAIL
set EC=%ERRORLEVEL%
echo [FAIL] ForgeBoss test stopped at the last printed stage.
pause
exit /b %EC%
