@echo off
setlocal
cd /d "%~dp0"
set "PY=%USERPROFILE%\.forgeboss\runtime\venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" -m forgeboss.control.daemon
