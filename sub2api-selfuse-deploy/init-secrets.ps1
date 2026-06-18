param(
    [string]$AdminEmail = "admin@sub2api.local",
    [int]$ServerPort = 8080
)

$ErrorActionPreference = "Stop"

function New-HexSecret([int]$bytes) {
    $buffer = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    return -join ($buffer | ForEach-Object { $_.ToString("x2") })
}

function New-Password([int]$length) {
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
    $buffer = New-Object byte[] ($length * 2)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buffer)
    $result = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $length; $i++) {
        $result.Append($chars[$buffer[$i] % $chars.Length]) | Out-Null
    }
    return $result.ToString()
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envExample = Join-Path $scriptDir ".env.example"
$envFile = Join-Path $scriptDir ".env"

if (-not (Test-Path $envExample)) {
    throw "Missing .env.example in $scriptDir"
}

$postgresPassword = New-Password 24
$adminPassword = New-Password 20
$jwtSecret = New-HexSecret 32
$totpKey = New-HexSecret 32

$content = Get-Content $envExample -Raw
$content = $content -replace '(?m)^SERVER_PORT=.*$', "SERVER_PORT=$ServerPort"
$content = $content -replace '(?m)^ADMIN_EMAIL=.*$', "ADMIN_EMAIL=$AdminEmail"
$content = $content -replace '(?m)^POSTGRES_PASSWORD=.*$', "POSTGRES_PASSWORD=$postgresPassword"
$content = $content -replace '(?m)^ADMIN_PASSWORD=.*$', "ADMIN_PASSWORD=$adminPassword"
$content = $content -replace '(?m)^JWT_SECRET=.*$', "JWT_SECRET=$jwtSecret"
$content = $content -replace '(?m)^TOTP_ENCRYPTION_KEY=.*$', "TOTP_ENCRYPTION_KEY=$totpKey"

Set-Content -Path $envFile -Value $content -Encoding UTF8

foreach ($dir in "data", "postgres_data", "redis_data") {
    $path = Join-Path $scriptDir $dir
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
    }
}

Write-Host "Created $envFile"
Write-Host "Admin email: $AdminEmail"
Write-Host "Admin password: $adminPassword"
Write-Host "Postgres password: $postgresPassword"
Write-Host "Port: $ServerPort"
Write-Host ""
Write-Host "Next:"
Write-Host "  1. Install Docker Desktop"
Write-Host "  2. cd `"$scriptDir`""
Write-Host "  3. docker compose up -d"
Write-Host "  4. Open http://localhost:$ServerPort"
