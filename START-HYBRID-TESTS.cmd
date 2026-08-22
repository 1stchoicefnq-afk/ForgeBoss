@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
title SiteBoss v1.3 Hybrid Test Suite - ZERO MODEL SPEND
call "%~dp0HYBRID-SELFTEST.cmd"
if errorlevel 1 exit /b %ERRORLEVEL%
call "%~dp0HYBRID-BRIDGE-SMOKE.cmd"
if errorlevel 1 exit /b %ERRORLEVEL%
if exist "%~dp0AGENCY-CORE-TEAM-SELFTEST.cmd" call "%~dp0AGENCY-CORE-TEAM-SELFTEST.cmd"
exit /b %ERRORLEVEL%
