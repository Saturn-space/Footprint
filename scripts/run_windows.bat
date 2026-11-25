@echo off
REM ==============================================================================
REM FootprintIQ - Windows Localhost Deployment Launcher
REM Runs FootprintIQ locally at http://localhost:8000
REM ==============================================================================

setlocal enabledelayedexpansion

echo ======================================================================
echo  Starting FootprintIQ — Digital Footprint Investigation Platform
echo  Target URL: http://localhost:8000
echo ======================================================================

set "PROJECT_ROOT=%~dp0.."
cd /d "%PROJECT_ROOT%"

REM Check Python Virtual Environment
if exist "%PROJECT_ROOT%\.venv\Scripts\activate.bat" (
    echo [✓] Activating Python virtual environment...
    call "%PROJECT_ROOT%\.venv\Scripts\activate.bat"
) else if exist "%PROJECT_ROOT%\venv\Scripts\activate.bat" (
    echo [✓] Activating Python virtual environment...
    call "%PROJECT_ROOT%\venv\Scripts\activate.bat"
) else (
    echo [!] Virtual environment not detected. Running with system Python...
)

REM Set Environment Variables
set "PYTHONPATH=%PROJECT_ROOT%;%PYTHONPATH%"
set "SQL_SERVER_HOST=127.0.0.1"
set "SQL_SERVER_PORT=1433"
set "SQL_SERVER_DATABASE=FootprintIQ"

echo [✓] Starting Uvicorn web server at http://localhost:8000 ...
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload

pause

