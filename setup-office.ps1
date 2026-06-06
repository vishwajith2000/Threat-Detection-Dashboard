# Run this from the project root on a new Windows machine.
# It installs backend and frontend dependencies with beginner-friendly commands.

$ErrorActionPreference = "Stop"

Write-Host "Setting up ThreatLookup App..." -ForegroundColor Cyan

if (-not (Test-Path ".\backend\.env")) {
    Write-Host "Missing backend\.env" -ForegroundColor Yellow
    Write-Host "Copy your real backend\.env from your main machine before running the app." -ForegroundColor Yellow
    Write-Host "A sample file exists at backend\.env.example." -ForegroundColor Yellow
}

if (-not (Test-Path ".\backend\venv\Scripts\python.exe")) {
    Write-Host "Creating backend virtual environment..." -ForegroundColor Cyan
    python -m venv .\backend\venv
}

Write-Host "Installing backend packages..." -ForegroundColor Cyan
.\backend\venv\Scripts\python.exe -m pip install -r .\backend\requirements.txt

Write-Host "Running Django migrations..." -ForegroundColor Cyan
.\backend\venv\Scripts\python.exe .\backend\manage.py migrate

Write-Host "Installing frontend packages..." -ForegroundColor Cyan
Push-Location .\frontend
npm.cmd install
Pop-Location

Write-Host ""
Write-Host "Setup finished." -ForegroundColor Green
Write-Host "Start backend with:  .\start-backend.ps1" -ForegroundColor Green
Write-Host "Start frontend with: .\start-frontend.ps1" -ForegroundColor Green
