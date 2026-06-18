$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$dockerDesktop = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
$dockerCli = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"

if (-not (Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue)) {
    if (Test-Path $dockerDesktop) {
        Start-Process $dockerDesktop -WindowStyle Hidden
        Write-Host "Starting Docker Desktop..."
    } else {
        throw "Docker Desktop not found: $dockerDesktop"
    }
}

$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        & $dockerCli info *> $null
        $ready = $true
        break
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $ready) {
    throw "Docker is not ready after waiting 120 seconds."
}

& $dockerCli compose up -d

$healthy = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $health = Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/health
        if ($health.Content -match '"status":"ok"') {
            $healthy = $true
            break
        }
    } catch {
    }
    Start-Sleep -Seconds 2
}

if (-not $healthy) {
    throw "Sub2API did not become healthy in time."
}

Write-Host "Sub2API is running."
Write-Host "Local: http://127.0.0.1:8080"
Write-Host "LAN:   http://192.168.0.60:8080"
