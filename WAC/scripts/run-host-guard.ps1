param(
    [switch]$Bootstrap,
    [switch]$SkipDocker,
    [switch]$OpenFirewall,
    [switch]$ForceFreePort,
    [int]$Port = 8000
)

$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Load-EnvFile([string]$Path) {
    if (-not (Test-Path $Path)) {
        return
    }

    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith('#')) { return }
        $parts = $line -split '=', 2
        if ($parts.Count -ne 2) { return }
        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        if ($value.StartsWith('"') -and $value.EndsWith('"') -and $value.Length -ge 2) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        Set-Item -Path "Env:$key" -Value $value
    }
}

function Load-DockerComposeEnvFallback([string]$ComposePath) {
    if (-not (Test-Path $ComposePath)) {
        return
    }

    $lines = Get-Content $ComposePath
    $kv = @{}
    foreach ($line in $lines) {
        if ($line -match '^\s*-\s*([A-Z0-9_]+)=(.*)\s*$') {
            $k = $matches[1]
            $v = $matches[2].Trim()
            if (-not $kv.ContainsKey($k)) {
                $kv[$k] = $v
            }
        }
    }

    foreach ($name in @('TELEGRAM_ENABLED', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID')) {
        if (-not (Get-Item -Path "Env:$name" -ErrorAction SilentlyContinue)) {
            if ($kv.ContainsKey($name) -and $kv[$name]) {
                Set-Item -Path "Env:$name" -Value $kv[$name]
            }
        }
    }
}

function Ensure-Venv([string]$AppDir, [string]$VenvPython, [switch]$ForceBootstrap) {
    if ($ForceBootstrap -or -not (Test-Path $VenvPython)) {
        Write-Step "Creating Python virtual environment"
        if (Test-Path (Join-Path $AppDir '.venv')) {
            Remove-Item -Recurse -Force (Join-Path $AppDir '.venv')
        }
        Push-Location $AppDir
        try {
            py -3.11 -m venv .venv
        }
        finally {
            Pop-Location
        }
    }

    Write-Step "Installing/updating dependencies"
    & $VenvPython -m ensurepip --upgrade | Out-Host
    & $VenvPython -m pip install -U pip | Out-Host
    & $VenvPython -m pip install -r (Join-Path $AppDir 'requirements.txt') | Out-Host
}

function Ensure-PortAvailable([int]$Port, [switch]$ForceFreePort) {
    $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    if (-not $listeners -or $listeners.Count -eq 0) {
        return
    }

    $ownerPid = ($listeners | Select-Object -First 1 -ExpandProperty OwningProcess)
    $owner = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
    $ownerName = if ($owner) { $owner.ProcessName } else { 'unknown' }

    if (-not $ForceFreePort) {
        throw "Port $Port is already in use by PID=$ownerPid ($ownerName). Use -ForceFreePort or run: Stop-Process -Id $ownerPid -Force"
    }

    Write-Step "Freeing port $Port (PID=$ownerPid $ownerName)"
    Stop-Process -Id $ownerPid -Force -ErrorAction Stop
    Start-Sleep -Seconds 1
}

$root = Split-Path -Parent $PSScriptRoot
$appDir = Join-Path $root 'webauthguard'
$venvPython = Join-Path $appDir '.venv\Scripts\python.exe'
$envFile = Join-Path $appDir '.env.host'
$composeFile = Join-Path $root 'docker-compose.yml'

Write-Step "Loading host config"
Load-EnvFile $envFile
Load-DockerComposeEnvFallback $composeFile

if (-not $env:RESOURCE_BASE) { $env:RESOURCE_BASE = 'http://localhost:8001' }
if (-not $env:OPENSEARCH_URL) { $env:OPENSEARCH_URL = 'http://localhost:9200' }
if (-not $env:TELEGRAM_ENABLED) { $env:TELEGRAM_ENABLED = 'false' }

if ($env:TELEGRAM_BOT_TOKEN -and $env:TELEGRAM_CHAT_ID) {
    $env:TELEGRAM_ENABLED = 'true'
}

if ($env:TELEGRAM_ENABLED -eq 'true' -and (-not $env:TELEGRAM_BOT_TOKEN -or -not $env:TELEGRAM_CHAT_ID)) {
    Write-Host "WARNING: TELEGRAM_ENABLED=true but TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID is missing. Disabling Telegram." -ForegroundColor Yellow
    $env:TELEGRAM_ENABLED = 'false'
}

Ensure-Venv -AppDir $appDir -VenvPython $venvPython -ForceBootstrap:$Bootstrap

if (-not $SkipDocker) {
    Write-Step "Ensuring docker dependencies are running (opensearch/resource/dashboards)"
    Push-Location $root
    try {
        docker compose up -d opensearch resource dashboards | Out-Host
        docker compose stop guard | Out-Host
        docker compose up -d --no-deps nginx | Out-Host
    }
    finally {
        Pop-Location
    }
}

if ($OpenFirewall) {
    Write-Step "Opening Windows Firewall for port $Port"
    $ruleName = "WAC Host Guard $Port"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Private | Out-Host
    }
}

$lanIp = $null
try {
    $lanIp = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -First 1 -ExpandProperty IPv4Address).IPAddress
}
catch {
    $lanIp = $null
}

Write-Step "Starting WebAuthGuard host mode"
Write-Host ("Guard URL: http://localhost:{0}/login" -f $Port) -ForegroundColor Green
Write-Host "Dashboards URL (HTTP): http://localhost/dashboards/" -ForegroundColor Green
Write-Host "Direct Dashboards URL (HTTP): http://localhost:5601/dashboards/" -ForegroundColor Green
if ($lanIp) {
    Write-Host ("Phone URL: http://{0}:{1}/login" -f $lanIp, $Port) -ForegroundColor Green
    Write-Host ("Phone Dashboards URL (HTTP): http://{0}/dashboards/" -f $lanIp) -ForegroundColor Green
}
Write-Host "TELEGRAM_ENABLED=$($env:TELEGRAM_ENABLED)"
Ensure-PortAvailable -Port $Port -ForceFreePort:$ForceFreePort

Push-Location $appDir
try {
    & $venvPython -m uvicorn app.main:app --host 0.0.0.0 --port $Port
}
finally {
    Pop-Location
}
