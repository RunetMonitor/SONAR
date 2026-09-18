@echo off
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: python is not installed. Please install Python 3.7+ and try again.
    pause
    exit /b 1
)

python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 7) else 1)"
if errorlevel 1 (
    echo Error: Python 3.7 or newer is required. This is:
    python -V
    pause
    exit /b 1
)

python run.py
if errorlevel 1 pause
