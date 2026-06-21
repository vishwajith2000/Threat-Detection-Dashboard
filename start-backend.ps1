# Starts the Django backend from the project root.

param(
    [string]$Host = "127.0.0.1",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\backend\.env")) {
    Write-Host "backend\.env is missing." -ForegroundColor Red
    Write-Host "Copy your real backend\.env from your main machine first." -ForegroundColor Yellow
    exit 1
}

Write-Host "Starting Django backend on http://${Host}:${Port}" -ForegroundColor Cyan
.\backend\venv\Scripts\python.exe .\backend\manage.py runserver "${Host}:${Port}"
