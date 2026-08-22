@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
title SiteBoss Autopilot Repair Rat v0.5-smokescreen - Regression Self-Test
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0SELFTEST-SITEBOSS.ps1"
echo.
pause
