@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
title SiteBoss Hybrid Bridge Smoke - ZERO MODEL SPEND
where node.exe >nul 2>&1 || (echo [FAIL] Node.js not found.& pause & exit /b 2)
node "%~dp0controller\hybrid\bridge-smoke.js"
set EC=%ERRORLEVEL%
echo.
pause
exit /b %EC%
