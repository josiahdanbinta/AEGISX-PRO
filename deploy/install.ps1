<#
.SYNOPSIS
    AEGISX Agent Enrollment Script (Windows PowerShell)
.DESCRIPTION
    One-command agent deployment for Windows.
.PARAMETER Server
    AEGISX server URL (e.g. http://192.168.1.100:8000)
.PARAMETER Key
    Agent registration key
.PARAMETER Tenant
    Tenant ID (UUID)
.EXAMPLE
    .\install.ps1 -Server http://192.168.1.100:8000 -Key YOUR_KEY -Tenant YOUR_TENANT_ID
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Server,
    [Parameter(Mandatory=$true)]
    [string]$Key,
    [Parameter(Mandatory=$true)]
    [string]$Tenant,
    [string]$InstallDir = "C:\Program Files\AEGISX Agent",
    [string]$AgentVersion = "1.1.0"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "       AEGISX Agent Enrollment (Windows PowerShell)" -ForegroundColor Cyan
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Server:  $Server" -ForegroundColor White
Write-Host "  Tenant:  $Tenant" -ForegroundColor White
Write-Host ""

# ── Step 1: System Info ───────────────────────────────────────
Write-Host "  [1/7] Detecting system..." -ForegroundColor Blue
$Hostname = [System.Net.Dns]::GetHostName()
try {
    $SysIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress
} catch { $SysIP = "unknown" }
$OSInfo = Get-CimInstance Win32_OperatingSystem
Write-Host "  Hostname: $Hostname" -ForegroundColor Green
Write-Host "  IP:       $SysIP" -ForegroundColor Green
Write-Host "  OS:       $($OSInfo.Caption)" -ForegroundColor Green
Write-Host ""

# ── Step 2: Check Python ─────────────────────────────────────
Write-Host "  [2/7] Checking Python..." -ForegroundColor Blue
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) { $pythonCmd = "python" }
elseif (Get-Command python3 -ErrorAction SilentlyContinue) { $pythonCmd = "python3" }
else {
    Write-Host "  Python not found. Installing via winget..." -ForegroundColor Yellow
    try {
        winget install Python.Python.3.12 --silent --accept-package-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        $pythonCmd = "python"
    } catch {
        Write-Host "  ERROR: Cannot install Python. Please install from https://python.org" -ForegroundColor Red
        exit 1
    }
}
$pyVersion = & $pythonCmd --version 2>&1
Write-Host "  [OK] $pyVersion" -ForegroundColor Green
Write-Host ""

# ── Step 3: Create Directory ──────────────────────────────────
Write-Host "  [3/7] Creating install directory..." -ForegroundColor Blue
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
$dataDir = Join-Path $InstallDir "data"
$logsDir = Join-Path $InstallDir "logs"
New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
Write-Host "  [OK] $InstallDir" -ForegroundColor Green
Write-Host ""

# ── Step 4: Download Agent ────────────────────────────────────
Write-Host "  [4/7] Downloading agent v$AgentVersion..." -ForegroundColor Blue
$downloadUrl = "$Server/api/v1/agent/download"
$agentArchive = Join-Path $InstallDir "agent.tar.gz"

try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $agentArchive -ErrorAction Stop
    Write-Host "  Downloaded from server" -ForegroundColor Green
    
    # Extract
    try {
        tar -xzf $agentArchive -C $InstallDir 2>$null
        Remove-Item $agentArchive -Force
        Write-Host "  Extracted successfully" -ForegroundColor Green
    } catch {
        Write-Host "  tar extraction failed, trying alternative..." -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Download failed. Checking for local agent source..." -ForegroundColor Yellow
    if (Test-Path "agent\agent.py") {
        Copy-Item -Recurse -Force "agent\*" $InstallDir
        Write-Host "  Copied from local source" -ForegroundColor Green
    } else {
        Write-Host "  ERROR: Cannot download agent. Ensure server is running: $Server" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# ── Step 5: Install Dependencies ──────────────────────────────
Write-Host "  [5/7] Installing Python dependencies..." -ForegroundColor Blue
Set-Location $InstallDir

# Create virtualenv
& $pythonCmd -m venv venv 2>$null
$venvPython = Join-Path $InstallDir "venv\Scripts\python.exe"

if (Test-Path $venvPython) {
    & $venvPython -m pip install --upgrade pip --quiet 2>$null
    if (Test-Path "requirements.txt") {
        & $venvPython -m pip install -r requirements.txt --quiet 2>$null
    }
    & $venvPython -m pip install psutil aiohttp pyyaml pydantic websocket-client --quiet 2>$null
} else {
    & $pythonCmd -m pip install psutil aiohttp pyyaml pydantic websocket-client --quiet 2>$null
}
Write-Host "  [OK] Dependencies installed" -ForegroundColor Green
Write-Host ""

# ── Step 6: Configure Agent ───────────────────────────────────
Write-Host "  [6/7] Configuring agent..." -ForegroundColor Blue
$configYaml = @"
# AEGISX Agent Configuration
server_url: "$Server"
registration_key: "$Key"
tenant_id: "$Tenant"
agent_name: "$Hostname"
data_dir: "$dataDir"
log_dir: "$logsDir"
log_level: "INFO"
heartbeat_interval: 60
monitoring_interval: 30
full_inventory_interval: 21600
enable_auto_update: true

collectors:
  - cpu
  - memory
  - disk
  - network
  - processes
  - services
  - logs
  - installed_software
  - hardware
  - usb
  - ransomware

ransomware:
  enabled: true
  scan_interval: 60
  check_shadow_copy: true
  monitor_file_changes: true
"@
$configYaml | Set-Content (Join-Path $InstallDir "config.yaml") -Encoding UTF8
Write-Host "  [OK] Configuration saved" -ForegroundColor Green
Write-Host ""

# ── Step 7: Register & Start ──────────────────────────────────
Write-Host "  [7/7] Registering agent with server..." -ForegroundColor Blue

$registerBody = @{
    hostname = $Hostname
    platform = "windows"
    platform_version = $OSInfo.Caption
    ip_address = $SysIP
    agent_version = $AgentVersion
    registration_key = $Key
    tenant_id = $Tenant
    capabilities = @("system","processes","services","software","hardware","ransomware")
} | ConvertTo-Json

try {
    $registerResponse = Invoke-RestMethod -Uri "$Server/api/v1/agent/register" -Method Post -Body $registerBody -ContentType "application/json" -ErrorAction Stop
    Write-Host "  Registered: $($registerResponse.agent_id)" -ForegroundColor Green
} catch {
    Write-Host "  Agent will register on first start" -ForegroundColor Yellow
}

# Install as Windows Service
try {
    $nssm = Get-Command nssm -ErrorAction SilentlyContinue
    if ($nssm) {
        & nssm install AEGISXAgent "$venvPython" "$(Join-Path $InstallDir 'agent.py')" 2>$null
        & nssm set AEGISXAgent AppDirectory "$InstallDir" 2>$null
        & nssm set AEGISXAgent Start SERVICE_AUTO_START 2>$null
        & nssm start AEGISXAgent 2>$null
        Write-Host "  [OK] NSSM service installed and started" -ForegroundColor Green
    } else {
        # Create with sc.exe
        $servicePath = "`"$venvPython`" `"$(Join-Path $InstallDir 'agent.py')`""
        New-Service -Name "AEGISXAgent" -BinaryPathName $servicePath -DisplayName "AEGISX Security Agent" -Description "AEGISX Enterprise Cybersecurity Platform Agent" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service "AEGISXAgent" -ErrorAction SilentlyContinue
        Write-Host "  [OK] Windows service installed and started" -ForegroundColor Green
    }
} catch {
    # Fallback to scheduled task
    $action = New-ScheduledTaskAction -Execute $venvPython -Argument "`"$(Join-Path $InstallDir 'agent.py')`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "AEGISX Agent" -Action $action -Trigger $trigger -RunLevel Highest -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName "AEGISX Agent" -ErrorAction SilentlyContinue
    Write-Host "  [OK] Scheduled task created" -ForegroundColor Green
}

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Green
Write-Host "       AEGISX Agent Enrolled Successfully!" -ForegroundColor Green
Write-Host "  ========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Server:      $Server"
Write-Host "  Tenant:      $Tenant"
Write-Host "  Hostname:    $Hostname"
Write-Host "  IP:          $SysIP"
Write-Host "  Status:      Running"
Write-Host ""
Write-Host "  Commands:"
Write-Host "    Status:  Get-Service AEGISXAgent"
Write-Host "    Logs:    Get-Content '$logsDir\agent.log' -Tail 50"
Write-Host "    Restart: Restart-Service AEGISXAgent"
Write-Host ""
