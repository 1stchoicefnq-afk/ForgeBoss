@echo off
if not exist "%~dp0controller\siteboss-autopilot.js" (
  echo [FAIL] ForgeBoss files are incomplete or are being run from inside the ZIP.
  echo Extract the entire ForgeBoss ZIP to a normal folder, then run this launcher again.
  pause
  exit /b 3
)
setlocal EnableExtensions
cd /d "%~dp0"
set "PYW=%USERPROFILE%\.forgeboss\runtime\venv\Scripts\pythonw.exe"
set "PY=%USERPROFILE%\.forgeboss\runtime\venv\Scripts\python.exe"
if not exist "%PYW%" set "PYW=pythonw"
if not exist "%PY%" set "PY=python"
start "" "%PYW%" "%~dp0ForgeBoss-Internal\dashboard\desktop.py"
if errorlevel 1 (
 "%PY%" "%~dp0ForgeBoss-Internal\dashboard\desktop.py"
 pause
)
exit /b 0
