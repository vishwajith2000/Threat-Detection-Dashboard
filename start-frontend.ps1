# Starts the React frontend from the project root.

param(
    [string]$Host = "127.0.0.1",
    [int]$Port = 5173
)

$ErrorActionPreference = "Stop"

Write-Host "Starting frontend on http://${Host}:${Port}" -ForegroundColor Cyan
Push-Location .\frontend
npm.cmd run dev -- --host $Host --port $Port
Pop-Location
