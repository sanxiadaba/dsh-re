@echo off
setlocal
if exist "%~dp0.venv\Scripts\re.exe" (
  "%~dp0.venv\Scripts\re.exe" %*
) else (
  python -m pwre %*
)
