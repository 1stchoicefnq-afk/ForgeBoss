@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
setlocal EnableExtensions
title SiteBoss v1.3.1 - ONE CLICK TEST - ZERO MODEL SPEND
cd /d "%~dp0"

echo ============================================================
echo SITEBOSS ONE-CLICK TEST
echo Hybrid - Agency - Deep Agents Security - Controller
echo ZERO MODEL SPEND / ZERO GITHUB WRITES
echo ============================================================
echo.

where node.exe >nul 2>&1
if errorlevel 1 goto :NO_NODE

echo [1/5] HYBRID SELFTEST
node ".\controller\hybrid\selftest.js"
if errorlevel 1 goto :FAIL
echo [PASS] HYBRID SELFTEST
echo.

echo [2/5] HYBRID BRIDGE SMOKE
node ".\controller\hybrid\bridge-smoke.js"
if errorlevel 1 goto :FAIL
echo [PASS] HYBRID BRIDGE SMOKE
echo.

if exist ".\controller\selftest-agency-core-team.js" (
  echo [3/5] AGENCY CORE TEAM
  node ".\controller\selftest-agency-core-team.js"
  if errorlevel 1 goto :FAIL
  echo [PASS] AGENCY CORE TEAM
) else (
  echo [3/5] AGENCY CORE TEAM - SKIPPED: test file absent
)
echo.

if exist ".\controller\deepagents\tests\test_policy.py" (
  echo [4/5] DEEP AGENTS SECURITY
  where python.exe >nul 2>&1
  if errorlevel 1 goto :NO_PYTHON
  python ".\controller\deepagents\tests\test_policy.py"
  if errorlevel 1 goto :FAIL
  echo [PASS] DEEP AGENTS SECURITY
) else (
  echo [4/5] DEEP AGENTS SECURITY - SKIPPED: prototype test absent
)
echo.

echo [5/5] SITEBOSS CONTROLLER SELFTEST
node ".\controller\siteboss-autopilot.js" selftest
if errorlevel 1 goto :FAIL
echo [PASS] SITEBOSS CONTROLLER SELFTEST
echo.

echo ============================================================
echo ALL ONE-CLICK TEST GATES PASSED
echo No model calls. No GitHub writes. No merge. No deploy.
echo Next live/free planning check: START-SITEBOSS.cmd
echo ============================================================
pause
exit /b 0

:NO_NODE
echo [FAIL] Node.js was not found in PATH.
echo Nothing was changed.
pause
exit /b 2

:NO_PYTHON
echo [FAIL] Python was not found in PATH.
echo Nothing was changed.
pause
exit /b 2

:FAIL
set EC=%ERRORLEVEL%
echo.
echo ============================================================
echo ONE-CLICK TEST FAILED
echo Exit code: %EC%
echo The failing stage is the last stage printed above.
echo No model calls or GitHub writes were performed by this launcher.
echo ============================================================
pause
exit /b %EC%
