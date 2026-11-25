@echo off
setlocal
set "PYTHONPATH=%~dp0src"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
"%~dp0.venv\Scripts\python.exe" -m pwre %*
