@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
title SiteBoss - Prepare Case-Sensitive Repair Workspace
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Start-Process pwsh -Verb RunAs -Wait -ArgumentList '-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File','""%~dp0PREPARE-SITEBOSS-WORKSPACE.ps1""'"
echo.
pause
