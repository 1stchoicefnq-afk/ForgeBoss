@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
setlocal
title SiteBoss Autopilot PAID Repair
echo This run MAY spend API credit. It cannot publish, merge, or deploy in v0.9.
set SITEBOSS_ALLOW_PAID_REPAIR=YES
node "%~dp0controller\siteboss-autopilot.js" repair
set EC=%ERRORLEVEL%
echo.
pause
exit /b %EC%
