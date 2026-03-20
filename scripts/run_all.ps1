<#
    run_all.ps1 — Start all three auth-viewer services
    
    Usage:
    .\scripts\run_all.ps1
    
    Press Ctrl+C to stop all services.
#>

$ErrorActionPreference = "Stop"

# Ensure we're in the project root
$projectRoot = Split-Path $PSScriptRoot -Parent
Push-Location $projectRoot

Write-Host "Starting auth-viewer services..." -ForegroundColor Cyan

# Load .env for resource APIs
if (Test-Path .env) {
    Get-Content .env | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
        }
    }
}

# Start resource APIs as background jobs
$apiA = Start-Job -ScriptBlock {
    Set-Location $using:projectRoot
    # Re-load env vars in job
    if (Test-Path .env) {
        Get-Content .env | ForEach-Object {
            if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
                [Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
            }
        }
    }
    python -m uvicorn resource_api_a.main:app --host 127.0.0.1 --port 8001 --reload 2>&1
}
Write-Host "  API A started on http://localhost:8001 (Job $($apiA.Id))" -ForegroundColor Green

$apiB = Start-Job -ScriptBlock {
    Set-Location $using:projectRoot
    if (Test-Path .env) {
        Get-Content .env | ForEach-Object {
            if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
                [Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
            }
        }
    }
    python -m uvicorn resource_api_b.main:app --host 127.0.0.1 --port 8002 --reload 2>&1
}
Write-Host "  API B started on http://localhost:8002 (Job $($apiB.Id))" -ForegroundColor Green

Write-Host "`n  Client starting on http://localhost:8000..." -ForegroundColor Green
Write-Host "  Press Ctrl+C to stop all services.`n" -ForegroundColor Yellow

try {
    # Run client in foreground
    python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
} finally {
    Write-Host "`nStopping background services..." -ForegroundColor Yellow
    Stop-Job $apiA, $apiB -ErrorAction SilentlyContinue
    Remove-Job $apiA, $apiB -Force -ErrorAction SilentlyContinue
    Pop-Location
    Write-Host "All services stopped." -ForegroundColor Green
}
