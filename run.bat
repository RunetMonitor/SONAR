@echo off
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: python is not installed. Please install Python 3.6+ and try again.
    pause
    exit /b 1
)

python run.py
if errorlevel 1 pause
