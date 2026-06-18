$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$dockerCli = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"

& $dockerCli compose down

Write-Host "Sub2API stack stopped."
