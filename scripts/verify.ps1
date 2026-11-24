<#
.SYNOPSIS
    RAMPART verification gate: backend tests, bench tests, and the frontend build.

.DESCRIPTION
    Runs the three commands a change must pass before it is committed (see
    docs/plan/optimization-plan.md):

        backend pytest  ->  bench pytest  ->  npm run build

    Every gate runs even if an earlier one fails; the script exits non-zero when
    any gate failed, so it can be used as a pre-commit / CI smoke check.

.PARAMETER SkipBench
    Skip the bench pytest suite (useful while iterating on the backend).

.PARAMETER SkipFrontend
    Skip `npm run build` (useful when node_modules is not installed).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\verify.ps1

.EXAMPLE
    .\scripts\verify.ps1 -SkipFrontend
#>
[CmdletBinding()]
param(
    [switch]$SkipBench,
    [switch]$SkipFrontend
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root 'backend\.venv\Scripts\python.exe'
$script:Failed = @()

if (-not (Test-Path $Python)) {
    Write-Host "backend venv python not found: $Python" -ForegroundColor Red
    Write-Host "create it with: uv venv backend/.venv --python 3.13" -ForegroundColor Yellow
    exit 1
}

function Invoke-Gate {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $code = 1
    try {
        $code = & $Action
    }
    catch {
        Write-Host "    $($_.Exception.Message)" -ForegroundColor Red
        $code = 1
    }
    $sw.Stop()

    if ($code -ne 0) {
        Write-Host ("    FAILED (exit {0}, {1:N1}s)" -f $code, $sw.Elapsed.TotalSeconds) -ForegroundColor Red
        $script:Failed += $Name
    }
    else {
        Write-Host ("    ok ({0:N1}s)" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Green
    }
}

Invoke-Gate 'backend pytest (backend/)' {
    Push-Location (Join-Path $Root 'backend')
    try {
        & $Python -m pytest tests -q | Out-Host
        return $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
}

if (-not $SkipBench) {
    Invoke-Gate 'bench pytest (repo root)' {
        Push-Location $Root
        try {
            & $Python -m pytest bench\tests -q | Out-Host
            return $LASTEXITCODE
        }
        finally {
            Pop-Location
        }
    }
}
else {
    Write-Host ""
    Write-Host "==> bench pytest (skipped)" -ForegroundColor DarkGray
}

if (-not $SkipFrontend) {
    Invoke-Gate 'frontend build (frontend/)' {
        Push-Location (Join-Path $Root 'frontend')
        try {
            & npm run build | Out-Host
            return $LASTEXITCODE
        }
        finally {
            Pop-Location
        }
    }
}
else {
    Write-Host ""
    Write-Host "==> frontend build (skipped)" -ForegroundColor DarkGray
}

Write-Host ""
if ($script:Failed.Count -gt 0) {
    Write-Host "FAILED: $($script:Failed -join ', ')" -ForegroundColor Red
    exit 1
}

Write-Host "All gates passed." -ForegroundColor Green
exit 0
