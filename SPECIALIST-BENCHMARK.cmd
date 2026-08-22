@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
title SiteBoss Specialist Benchmark - ZERO MODEL SPEND
node "%~dp0controller\benchmark-specialists.js"
set EC=%ERRORLEVEL%
echo.
pause
exit /b %EC%
