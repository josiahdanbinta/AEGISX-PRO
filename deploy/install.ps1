#Requires -Version 5.1
<#
.SYNOPSIS
    AEGISX Agent Enrollment Script - Windows PowerShell
.DESCRIPTION
    Downloads, installs, and configures the AEGISX security agent as a Windows Service.
.PARAMETER Server
    The AEGISX server URL (e.g., https://aegisx.company.com)
.PARAMETER Key
    The registration key for authenticating with the server
.PARAMETER Tenant
    The tenant ID for multi-tenant deployments
.PARAMETER InstallDir
    Custom installation directory (default: C:\Program Files\AEGISX Agent)
.PARAMETER DataDir
    Custom data directory (default: C:\ProgramData\AEGISX Agent\data)
.PARAMETER Port
    Agent local API port (default: auto-assigned)
.EXAMPLE
    .\install.ps1 -Server https://aegisx.company.com -Key "ABC123" -Tenant "tenant-001"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "AEGISX server URL")]
    [string]$Server,

    [Parameter(Mandatory = $true, HelpMessage = "Registration key")]
    [string]$Key,

    [Parameter(Mandatory = $true, HelpMessage = "Tenant ID")]
    [string]$Tenant,

    [Parameter(Mandatory = $false)]
    [string]$InstallDir = "$env:ProgramFiles\AEGISX Agent",

    [Parameter(Mandatory = $false)]
    [string]$DataDir = "$env:ProgramData\AEGISX Agent\data",

    [Parameter(Mandatory = $false)]
    [int]$Port = 0,

    [Parameter(Mandatory = $false)]
    [switch]$SkipService,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:LogDir = "$env:ProgramData\AEGISX Agent\logs"
$script:PythonVersion = ""
$script:AgentId = ""
$script:SystemIP = ""

function Write-ColorOutput {
    param([string]$Message, [string]$ForegroundColor = "White")
    Write-Host $Message -ForegroundColor $ForegroundColor
}

function Write-Banner {
    Write-ColorOutput "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-ColorOutput "║     AEGISX Agent Enrollment - Windows        ║" -ForegroundColor Cyan
    Write-ColorOutput "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([int]$Step, [string]$Description)
    Write-ColorOutput "[$Step/6] $Description" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "  " -NoNewline
    Write-ColorOutput "✓" -ForegroundColor Green
    Write-Host " $Message"
}

function Write-Error-Exit {
    param([string]$Message)
    Write-ColorOutput "ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem

    return @{
        Hostname    = $env:COMPUTERNAME
        OSVersion   = "$($os.Caption) ($($os.Version))"
        Arch        = $env:PROCESSOR_ARCHITECTURE
        TotalMemory = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        CPUs        = $cs.NumberOfLogicalProcessors
        Domain      = if ($cs.Domain) { $cs.Domain } else { "WORKGROUP" }
    }
}

function Get-AgentId {
    try {
        $guid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID
        if (-not $guid) {
            $guid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -ErrorAction SilentlyContinue).MachineGuid
        }
        $macAddrs = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object { $_.MacAddress })
        $macStr = ($macAddrs | Sort-Object) -join ","
        if (-not $guid) {
            $guid = [Guid]::NewGuid().ToString()
        }
        $hashInput = "$guid-$macStr"
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashInput))
        $agentId = -join ($hash[0..15] | ForEach-Object { "{0:x2}" -f $_ })
        return $agentId
    }
    catch {
        return [Guid]::NewGuid().ToString("N").Substring(0, 16)
    }
}

function Get-SystemIP {
    try {
        $ips = @()
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true -and $_.DefaultIPGateway -ne $null }
        foreach ($adapter in $adapters) {
            foreach ($ip in $adapter.IPAddress) {
                if ($ip -match '^\d+\.\d+\.\d+\.\d+$' -and $ip -ne '127.0.0.1') {
                    $ips += $ip
                }
            }
        }
        if ($ips.Count -gt 0) {
            return $ips[0]
        }
        return "127.0.0.1"
    }
    catch {
        return "127.0.0.1"
    }
}

function Test-PythonInstalled {
    $pythonCmd = $null
    try {
        $result = Get-Command python -ErrorAction SilentlyContinue
        if ($result) { $pythonCmd = "python" }
    }
    catch { }

    try {
        $result = Get-Command python3 -ErrorAction SilentlyContinue
        if ($result) { $pythonCmd = "python3" }
    }
    catch { }

    if (-not $pythonCmd) {
        return $false
    }

    try {
        $versionOutput = & $pythonCmd --version 2>&1
        if ($versionOutput -match 'Python (\d+)\.(\d+)') {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 8)) {
                $script:PythonVersion = $versionOutput
                return $true
            }
        }
    }
    catch { }

    return $false
}

function Install-Python {
    Write-Host "  Installing Python 3.11 (this may take a few minutes)..."

    $pythonUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    $pythonInstaller = "$env:TEMP\python-installer.exe"

    try {
        # Try winget first
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            & winget install Python.Python.3.11 --accept-package-agreements --accept-source-agreements --silent 2>&1 | Out-Null
            Start-Sleep -Seconds 30
            if (Test-PythonInstalled) {
                return $true
            }
        }

        Write-Host "  Downloading Python installer..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing

        Write-Host "  Running Python installer (silent)..."
        Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -NoNewWindow

        Remove-Item $pythonInstaller -Force -ErrorAction SilentlyContinue

        # Refresh PATH in current session
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

        if (Test-PythonInstalled) {
            return $true
        }
    }
    catch {
        Remove-Item $pythonInstaller -Force -ErrorAction SilentlyContinue
        Write-Error-Exit "Failed to install Python. Please install Python 3.8+ manually from https://python.org"
    }

    return $false
}

function Start-AgentRegistration {
    param([string]$InstallDir, [string]$Server, [string]$Key, [string]$Tenant)

    $configPath = Join-Path $InstallDir "config.yaml"
    $venvPython = Join-Path $InstallDir "venv\Scripts\python.exe"

    if (-not (Test-Path $venvPython)) {
        Write-ColorOutput "  Warning: Virtual environment not found, skipping immediate registration" -ForegroundColor Yellow
        return
    }

    try {
        $env:AEGISX_SERVER_URL = $Server
        $env:AEGISX_REGISTRATION_KEY = $Key
        $env:AEGISX_TENANT_ID = $Tenant

        $agentModule = Join-Path $InstallDir "agent" "agent.py"
        if (Test-Path $agentModule) {
            $proc = Start-Process -FilePath $venvPython `
                -ArgumentList "-m", "agent.agent" `
                -WorkingDirectory $InstallDir `
                -WindowStyle Hidden `
                -PassThru

            Write-Success "Agent process started (PID: $($proc.Id))"
        }
    }
    catch {
        Write-ColorOutput "  Warning: Could not start agent process: $_" -ForegroundColor Yellow
    }
}

function Install-WindowsService {
    param([string]$InstallDir, [string]$LogDir)

    $serviceName = "AEGISXAgent"
    $serviceDisplay = "AEGISX Security Agent"
    $venvPython = Join-Path $InstallDir "venv\Scripts\python.exe"
    $workDir = (Get-Item $InstallDir).FullName

    # Check if service already exists
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Host "  Existing service found. Stopping..."
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        Write-Host "  Removing existing service..."
        sc.exe delete $serviceName 2>&1 | Out-Null
        Start-Sleep -Seconds 3
    }

    # Try NSSM first (more reliable for Python services)
    $nssm = Get-Command nssm -ErrorAction SilentlyContinue
    if (-not $nssm) {
        $nssmPath = "$env:ProgramFiles\nssm\nssm.exe"
        if (Test-Path $nssmPath) { $nssm = $nssmPath }
    }
    if (-not $nssm) {
        $nssmPath = Join-Path $InstallDir "nssm.exe"
        if (Test-Path $nssmPath) { $nssm = $nssmPath }
    }

    if ($nssm) {
        Write-Host "  Installing service via NSSM..."

        $nssmCmd = if ($nssm -is [string]) { $nssm } else { $nssm.Source }

        # Install service
        & $nssmCmd install $serviceName $venvPython 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppDirectory $workDir 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppParameters "-m agent.agent" 2>&1 | Out-Null
        & $nssmCmd set $serviceName DisplayName $serviceDisplay 2>&1 | Out-Null
        & $nssmCmd set $serviceName Description "AEGISX platform security monitoring agent" 2>&1 | Out-Null
        & $nssmCmd set $serviceName Start SERVICE_AUTO_START 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppStdout (Join-Path $LogDir "agent.log") 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppStderr (Join-Path $LogDir "agent-error.log") 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppStdoutCreationDisposition 4 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppStderrCreationDisposition 4 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppRotateFiles 1 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppRotateOnline 1 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppRotateSeconds 86400 2>&1 | Out-Null
        & $nssmCmd set $serviceName AppRotateBytes 10485760 2>&1 | Out-Null

        # Set environment variables
        & $nssmCmd set $serviceName AppEnvironmentExtra "AEGISX_SERVER_URL=$Server" "AEGISX_REGISTRATION_KEY=$Key" "AEGISX_TENANT_ID=$Tenant" 2>&1 | Out-Null

        Write-Success "NSSM service configured"
    }
    else {
        Write-Host "  Installing service via sc.exe..."

        $binPath = "`"$venvPython`" -m agent.agent"
        $result = sc.exe create $serviceName `
            binPath= $binPath `
            start= auto `
            DisplayName= "$serviceDisplay" `
            obj= LocalSystem 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Host "  sc.exe output: $result"
            Write-Error-Exit "Failed to create Windows service. Try installing NSSM (https://nssm.cc)"
        }

        # Configure service recovery
        sc.exe failure $serviceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 2>&1 | Out-Null
        sc.exe description $serviceName "AEGISX platform security monitoring agent" 2>&1 | Out-Null

        Write-Success "Service created via sc.exe"
    }

    # Start service
    Write-Host "  Starting service..."
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Write-Success "Service started successfully"
    }
    else {
        Write-Host "  Service status: $($service.Status)"
        Write-ColorOutput "  Warning: Service may not have started. Check logs at $LogDir\agent-error.log" -ForegroundColor Yellow
    }
}

# ── MAIN ──

Write-Banner

# Check admin
if (-not (Test-Administrator)) {
    Write-Error-Exit "This script requires Administrator privileges. Please run PowerShell as Administrator."
}

Write-Step 1 "Detecting system..."
$sysInfo = Get-SystemInfo
Write-Host "  OS:      $($sysInfo.OSVersion)"
Write-Host "  Arch:    $($sysInfo.Arch)"
Write-Host "  Host:    $($sysInfo.Hostname)"
Write-Host "  Memory:  $($sysInfo.TotalMemory) GB"
Write-Host "  CPUs:    $($sysInfo.CPUs)"
Write-Host ""

Write-Step 2 "Checking prerequisites..."

if (-not (Test-PythonInstalled)) {
    Write-Host "  Python 3.8+ not found."
    if (-not (Install-Python)) {
        Write-Error-Exit "Failed to install Python. Please install manually from https://python.org"
    }
}
Write-Success "Python: $script:PythonVersion"
Write-Host ""

Write-Step 3 "Creating directories..."
$dirs = @($InstallDir, $DataDir, $script:LogDir)
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Write-Success $dir
}
Write-Host ""

Write-Step 4 "Downloading agent..."
$agentUrl = "$Server/api/v1/agent/download"
$agentArchive = Join-Path $InstallDir "agent.zip"

try {
    $headers = @{
        "X-Registration-Key" = $Key
        "X-Tenant-ID"        = $Tenant
    }

    # First try download from server
    try {
        Invoke-WebRequest -Uri $agentUrl -OutFile $agentArchive -Headers $headers -UseBasicParsing -TimeoutSec 120
        Write-Success "Agent downloaded from server"
    }
    catch {
        Write-ColorOutput "  Server download failed ($($_.Exception.Message)). Using bundled agent..." -ForegroundColor Yellow

        # Fallback: copy from current directory if running from extracted package
        $sourceAgent = Join-Path $PSScriptRoot ".." "agent"
        if (Test-Path $sourceAgent) {
            Write-Host "  Copying agent from $sourceAgent..."
            Copy-Item -Path "$sourceAgent\*" -Destination $InstallDir -Recurse -Force
        }
        else {
            Write-Error-Exit "Cannot download agent and no bundled agent found"
        }
    }

    if (Test-Path $agentArchive) {
        Expand-Archive -Path $agentArchive -DestinationPath $InstallDir -Force
        Remove-Item $agentArchive -Force
        Write-Success "Agent extracted to $InstallDir"
    }
}
catch {
    if ($_.Exception.Message -notmatch "Server download failed") {
        Write-Error-Exit "Failed to download agent: $($_.Exception.Message)"
    }
}
Write-Host ""

Write-Step 5 "Installing dependencies..."
$venvDir = Join-Path $InstallDir "venv"

# Check if bundled requirements.txt exists; if not, use a default set
$requirementsFile = Join-Path $InstallDir "requirements.txt"
if (-not (Test-Path $requirementsFile)) {
    $requirementsFile = Join-Path $InstallDir "agent\requirements.txt"
}
if (-not (Test-Path $requirementsFile)) {
    Write-ColorOutput "  Warning: requirements.txt not found, using default dependencies" -ForegroundColor Yellow
    @"
psutil>=5.9.0
requests>=2.31.0
pyyaml>=6.0
cryptography>=41.0.0
pydantic>=2.0.0
websocket-client>=1.6.0
aiohttp>=3.9.0
watchdog>=3.0.0
"@ | Out-File -FilePath $requirementsFile -Encoding utf8
}

# Create virtual environment
if (Test-Path $venvDir) {
    Remove-Item -Recurse -Force $venvDir
}

try {
    & python -m venv $venvDir
    $venvPython = Join-Path $venvDir "Scripts\python.exe"
    $venvPip = Join-Path $venvDir "Scripts\pip.exe"

    & $venvPython -m pip install --upgrade pip --quiet 2>&1 | Out-Null
    & $venvPip install -r $requirementsFile --quiet 2>&1 | Out-Null

    Write-Success "Dependencies installed ($((Get-ChildItem $venvDir\Lib\site-packages).Count) packages)"
}
catch {
    Write-Error-Exit "Failed to install dependencies: $($_.Exception.Message)"
}
Write-Host ""

Write-Step 6 "Configuring agent..."
$configYaml = @"
server_url: "$Server"
registration_key: "$Key"
tenant_id: "$Tenant"
data_dir: "$DataDir"
log_dir: "$($script:LogDir)"
log_level: "INFO"
heartbeat_interval: 60
monitoring_interval: 30
inventory_interval_seconds: 21600
enable_auto_update: true

collectors:
  cpu: true
  memory: true
  disk: true
  network: true
  processes: true
  services: true
  logs: true
  installed_software: true
  hardware: true
  usb: true
  registry: true
  ransomware: true

communication:
  reconnect_base_delay: 5
  reconnect_max_delay: 300
  reconnect_max_attempts: 0
  batch_size: 100
  compress_data: true

logs:
  sources:
    windows:
      - "System"
      - "Security"
      - "Application"
  severity_filter: ["ERROR", "WARNING", "CRITICAL"]
  real_time: true
  max_lines: 1000

suspicious_detection:
  unsigned_processes: true
  temp_location_execution: true
  unusual_parent_process: true

ransomware:
  scan_interval_seconds: 30
  change_window_seconds: 10
  change_threshold: 50
  high_io_threshold_mb_per_sec: 50
"@

$configPath = Join-Path $InstallDir "config.yaml"
$configYaml | Out-File -FilePath $configPath -Encoding utf8 -Force
Write-Success "Configuration saved"
Write-Host ""

# Install service
if (-not $SkipService) {
    Install-WindowsService -InstallDir $InstallDir -LogDir $script:LogDir
}

# Generate Agent ID
$script:AgentId = Get-AgentId
$script:SystemIP = Get-SystemIP

# Save agent identity file
$identityFile = Join-Path $DataDir "agent.identity"
@"
agent_id: "$script:AgentId"
created_at: "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')"
version: "1.1.0"
"@ | Out-File -FilePath $identityFile -Encoding utf8 -Force

Write-Host ""
Write-ColorOutput "╔══════════════════════════════════════════════╗" -ForegroundColor Green
Write-ColorOutput "║     AEGISX Agent Enrolled Successfully!      ║" -ForegroundColor Green
Write-ColorOutput "╚══════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Server:      " -NoNewline; Write-ColorOutput $Server -ForegroundColor White
Write-Host "  Tenant:      $Tenant"
Write-Host "  Agent ID:    $script:AgentId"
Write-Host "  Status:      " -NoNewline; Write-ColorOutput "Running" -ForegroundColor Green
Write-Host "  Listening on: http://${script:SystemIP}:$([math]::Max($Port, 9090))"
Write-Host "  Logs:        $script:LogDir\agent.log"
Write-Host ""
Write-Host "To check status: " -NoNewline; Write-ColorOutput "Get-Service AEGISXAgent" -ForegroundColor Cyan
Write-Host "To view logs:    " -NoNewline; Write-ColorOutput "Get-Content $script:LogDir\agent.log -Tail 50 -Wait" -ForegroundColor Cyan
Write-Host "To restart:      " -NoNewline; Write-ColorOutput "Restart-Service AEGISXAgent" -ForegroundColor Cyan
Write-Host ""
