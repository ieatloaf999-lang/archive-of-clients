@echo off
setlocal
cd /d "%~dp0"
title Stinky Offline (Python)

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo Python 3 not found. Either install it from https://www.python.org
    echo ^(tick "Add Python to PATH"^), or just run StinkyOffline.exe instead
    echo ^(the .exe needs no Python^).
    pause
    exit /b
)

echo Launching current Python source: "%~dp0app\stinky_offline.py"
python "%~dp0app\stinky_offline.py"
echo.
echo Session ended.
pause
