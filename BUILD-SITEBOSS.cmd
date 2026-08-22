@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
setlocal EnableExtensions
title SiteBoss v1.4 AUTOBUILDER - LIVE BUILD CYCLE
cd /d "%~dp0"

echo ============================================================
echo SITEBOSS AUTOBUILDER v1.4.3
echo ONE CLICK: SAFETY GATES - LIVE GITHUB WORKLOAD - AI REPAIR
echo            TEST - INDEPENDENT REVIEW - DRAFT CHILD PR
echo.
echo MAY SPEND OPENAI API CREDIT.
echo MAY PUSH ONE REVIEWED BRANCH AND CREATE ONE DRAFT CHILD PR.
echo WILL NOT MERGE. WILL NOT DEPLOY. WILL NOT FORCE PUSH.
echo ============================================================
echo.

where node.exe >nul 2>&1 || goto :NO_NODE
where python.exe >nul 2>&1 || goto :NO_PYTHON

echo [1/4] LOCAL SAFETY SELFTEST
node ".\controller\hybrid\selftest.js"
if errorlevel 1 goto :FAIL
node ".\controller\selftest-agency-core-team.js"
if errorlevel 1 goto :FAIL
python ".\controller\deepagents\tests\test_policy.py"
if errorlevel 1 goto :FAIL
node ".\controller\siteboss-autopilot.js" selftest
if errorlevel 1 goto :FAIL
echo [PASS] LOCAL SAFETY SELFTEST
echo.

echo [2/4] LIVE AUTHORITATIVE WORKLOAD + BOUNDED PACKET
node ".\controller\siteboss-autopilot.js" run
if errorlevel 1 goto :FAIL
echo [PASS] LIVE WORKLOAD PACKET
echo.

echo [3/4] PAID BOUNDED BUILD + TEST + INDEPENDENT REVIEW
set SITEBOSS_ALLOW_PAID_REPAIR=YES
set SITEBOSS_ALLOW_DRAFT_PUBLISH=YES
node ".\controller\siteboss-autopilot.js" autobuild
if errorlevel 1 goto :FAIL
echo [PASS] BUILD / REVIEW
echo.

echo [4/4] FINAL STATUS
node ".\controller\siteboss-autopilot.js" status
if errorlevel 1 goto :FAIL
echo.
echo ============================================================
echo AUTOBUILDER CYCLE COMPLETE
echo Any publication is DRAFT CHILD PR ONLY.
echo NO MERGE. NO DEPLOY. NO FORCE PUSH.
echo Run this launcher again for another bounded cycle only after
echo the new GitHub state/checks are available.
echo ============================================================
pause
exit /b 0

:NO_NODE
echo [FAIL] Node.js not found. Nothing changed.
pause
exit /b 2

:NO_PYTHON
echo [FAIL] Python not found. Nothing changed.
pause
exit /b 2

:FAIL
set EC=%ERRORLEVEL%
echo.
echo ============================================================
echo AUTOBUILDER STOPPED SAFELY
echo Exit code: %EC%
echo The last printed stage shows exactly where it stopped.
echo Merge/deploy/force-push were never enabled.
echo ============================================================
pause
exit /b %EC%
