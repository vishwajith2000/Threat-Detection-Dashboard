# Starts the React frontend from the project root.

$ErrorActionPreference = "Stop"

Write-Host "Starting frontend on http://127.0.0.1:5173" -ForegroundColor Cyan
Push-Location .\frontend
npm.cmd run dev -- --host 127.0.0.1
Pop-Location
