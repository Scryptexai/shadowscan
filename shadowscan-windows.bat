@echo off
REM ShadowScan Windows Batch Runner
setlocal enabledelayedexpansion

echo 🔍 ShadowScan Windows Runner
echo =============================

REM Get script directory
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found! Please install Python 3.8+
    pause
    exit /b 1
)

REM Check .env file
if not exist ".env" (
    echo ❌ .env file not found! Please run installer first.
    pause
    exit /b 1
)

REM Parse command
set COMMAND=%1
if "%COMMAND%"=="" set COMMAND=help

REM Run commands
if "%COMMAND%"=="screen" (
    echo 🔍 Running screening...
    python shadowscan-standalone.py screen %*
) else if "%COMMAND%"=="s" (
    echo 🔍 Running screening...
    python shadowscan-standalone.py screen %*
) else if "%COMMAND%"=="attack" (
    echo ⚔️  Running attack analysis...
    python shadowscan-standalone.py attack %*
) else if "%COMMAND%"=="workflow" (
    echo 🔄 Running complete workflow test...
    python shadowscan-standalone.py workflow
) else if "%COMMAND%"=="status" (
    echo 📊 Checking system status...
    python shadowscan-standalone.py status
) else if "%COMMAND%"=="help" (
    echo Usage: %~nx0 {screen^|attack^|workflow^|status^|help}
    echo.
    echo Commands:
    echo   screen^|s    - Run contract screening
    echo   attack      - Run attack analysis/execution
    echo   workflow    - Run complete workflow test
    echo   status      - Check system status
    echo   help        - Show this help
) else (
    echo ❌ Unknown command: %COMMAND%
    echo Run "%~nx0 help" for usage information
)

pause