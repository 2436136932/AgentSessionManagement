@echo off
REM Agent Session Manager launcher (Windows).
REM Starts the local web UI and opens the browser. Ctrl+C stops it.
setlocal
cd /d "%~dp0"

set "PY="
if exist "E:\Python\3.14\python.exe" set "PY=E:\Python\3.14\python.exe"
if not defined PY if exist "E:\Python314\python.exe" set "PY=E:\Python314\python.exe"
if not defined PY for /f "delims=" %%i in ('where python 2^>nul') do if not defined PY set "PY=%%i"

if not defined PY (
  echo.
  echo   [ERROR] Python not found. Install Python 3.14 or edit this file to set PY.
  echo.
  pause
  exit /b 1
)

echo Using Python: %PY%
"%PY%" server.py %*
