@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
setlocal
title SiteBoss Autopilot v1.1
where node.exe >nul 2>&1
if errorlevel 1 (
  echo [FAIL] Node.js is not installed or not on PATH.
  echo No SiteBoss repository changes were made.
  echo Install Node.js and run this launcher again.
  echo.
  pause
  exit /b 2
)
node "%~dp0controller\siteboss-autopilot.js" run
set EC=%ERRORLEVEL%
echo.
if not "%EC%"=="0" echo SiteBoss Autopilot stopped safely with exit code %EC%.
pause
exit /b %EC%
