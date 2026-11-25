<#
.SYNOPSIS
    FootprintIQ - PowerShell Localhost Deployment Launcher
    Accessible at: http://localhost:8000
#>

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Starting FootprintIQ — Windows Localhost Deployment" -ForegroundColor Cyan
Write-Host " Target URL: http://localhost:8000" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

# Activate Virtual Environment
$VenvActivate = Join-Path $ProjectRoot ".venv\Scripts\Activate.ps1"
if (Test-Path $VenvActivate) {
    Write-Host "[✓] Activating Python virtual environment..." -ForegroundColor Green
    & $VenvActivate
} else {
    Write-Host "[!] .venv not found. Proceeding with system Python." -ForegroundColor Yellow
}

# Set Environment Variables
$env:PYTHONPATH = "$ProjectRoot;$env:PYTHONPATH"
if (-not $env:SQL_SERVER_HOST) { $env:SQL_SERVER_HOST = "127.0.0.1" }
if (-not $env:SQL_SERVER_PORT) { $env:SQL_SERVER_PORT = "1433" }
if (-not $env:SQL_SERVER_DATABASE) { $env:SQL_SERVER_DATABASE = "FootprintIQ" }

Write-Host "[✓] Starting Uvicorn on http://localhost:8000..." -ForegroundColor Green
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000 --reload

