@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
if not exist "%~dp0state\builder" mkdir "%~dp0state\builder"
type nul > "%~dp0state\builder\STOP"
echo SiteBoss Builder stop requested.
pause
