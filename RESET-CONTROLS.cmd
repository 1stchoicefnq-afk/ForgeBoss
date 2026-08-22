@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
del /q "%~dp0state\builder\PAUSE" 2>nul
del /q "%~dp0state\builder\STOP" 2>nul
echo Builder control flags cleared.
pause
