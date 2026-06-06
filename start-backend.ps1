# Starts the Django backend from the project root.

$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\backend\.env")) {
    Write-Host "backend\.env is missing." -ForegroundColor Red
    Write-Host "Copy your real backend\.env from your main machine first." -ForegroundColor Yellow
    exit 1
}

Write-Host "Starting Django backend on http://127.0.0.1:8000" -ForegroundColor Cyan
.\backend\venv\Scripts\python.exe .\backend\manage.py runserver
