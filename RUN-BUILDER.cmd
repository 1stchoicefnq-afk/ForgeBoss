@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
echo [BLOCKED] RUN-BUILDER.cmd is a legacy direct-builder entrypoint.
echo Use SITEBOSS-AUTOPILOT.cmd for the controlled v0.9.1 path.
echo No API call or repository write was made.
pause
exit /b 3
