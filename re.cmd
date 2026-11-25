@echo off
setlocal
set "PYTHONPATH=%~dp0src"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo re: 还没建虚拟环境。在本目录执行：
  echo     python -m venv .venv
  echo     .venv\Scripts\pip install -e .
  exit /b 2
)
"%~dp0.venv\Scripts\python.exe" -m pwre %*