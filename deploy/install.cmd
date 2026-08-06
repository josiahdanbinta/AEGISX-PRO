@echo off
setlocal enabledelayedexpansion
title AEGISX Agent Enrollment

:: ═══════════════════════════════════════════════════════════════
:: AEGISX Agent Enrollment Script (Windows CMD)
::
:: Usage:
::   install.cmd http://YOUR_SERVER:8000 YOUR_REGISTRATION_KEY YOUR_TENANT_ID
:: ═══════════════════════════════════════════════════════════════

set SERVER_URL=%~1
set REGISTRATION_KEY=%~2
set TENANT_ID=%~3
set INSTALL_DIR=C:\Program Files\AEGISX Agent
set AGENT_VERSION=1.1.0

if "%SERVER_URL%"=="" (
    echo.
    echo   ERROR: Server URL, Registration Key, and Tenant ID are required
    echo.
    echo   Usage: install.cmd http://192.168.1.100:8000 YOUR_KEY YOUR_TENANT_ID
    echo.
    exit /b 1
)
if "%REGISTRATION_KEY%"=="" (
    echo ERROR: Registration key is required
    exit /b 1
)
if "%TENANT_ID%"=="" (
    echo ERROR: Tenant ID is required
    exit /b 1
)

echo.
echo   ========================================================
echo          AEGISX Agent Enrollment (Windows CMD)
echo   ========================================================
echo.
echo   Server:  %SERVER_URL%
echo   Tenant:  %TENANT_ID%
echo.

:: ── Step 1: Get system info ──────────────────────────────────
echo   [1/7] Detecting system...
for /f "tokens=2 delims=:" %%i in ('hostname') do set HOSTNAME=%%i
set HOSTNAME=%HOSTNAME: =%

for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr /c:"IPv4"') do (
    set "ip=%%i"
    set "ip=!ip: =!"
    if not "!ip!"=="127.0.0.1" if "!SYSIP!"=="" set "SYSIP=!ip!"
)
if "%SYSIP%"=="" set SYSIP=unknown

echo   Hostname: %HOSTNAME%
echo   IP:       %SYSIP%
echo.

:: ── Step 2: Check Python ─────────────────────────────────────
echo   [2/7] Checking Python...

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo   Python not found. Downloading from python.org...
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.3/python-3.12.3-amd64.exe' -OutFile '%TEMP%\python-installer.exe'" 2>nul
    if exist "%TEMP%\python-installer.exe" (
        echo   Installing Python (silent)...
        "%TEMP%\python-installer.exe" /quiet InstallAllUsers=1 PrependPath=1 2>nul
        timeout /t 5 >nul
        set "PATH=%PATH%;C:\Program Files\Python312;C:\Program Files\Python312\Scripts"
    )
)

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo   ERROR: Python installation failed. Please install Python 3.8+ manually from https://python.org
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo   [OK] %PYVER%
echo.

:: ── Step 3: Create directory ─────────────────────────────────
echo   [3/7] Creating install directory...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
echo   [OK] %INSTALL_DIR%
echo.

:: ── Step 4: Download agent ───────────────────────────────────
echo   [4/7] Downloading agent v%AGENT_VERSION%...

set DOWNLOAD_URL=%SERVER_URL%/api/v1/agent/download

powershell -Command "try { Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%INSTALL_DIR%\agent.tar.gz' -ErrorAction Stop; Write-Host '  Downloaded successfully' } catch { Write-Host '  Download failed, trying alternative...' }" 2>nul

if exist "%INSTALL_DIR%\agent.tar.gz" (
    echo   Extracting agent...
    powershell -Command "tar -xzf '%INSTALL_DIR%\agent.tar.gz' -C '%INSTALL_DIR%'" 2>nul
    del "%INSTALL_DIR%\agent.tar.gz" 2>nul
) else (
    echo   Checking for local agent source...
    if exist "agent\agent.py" (
        echo   Found local agent source. Copying...
        xcopy /E /I /Y agent "%INSTALL_DIR%" >nul 2>&1
    ) else (
        echo   ERROR: Cannot download agent. Ensure the server is running and accessible at %SERVER_URL%
        exit /b 1
    )
)
echo.

:: ── Step 5: Install dependencies ─────────────────────────────
echo   [5/7] Installing Python dependencies...
cd /d "%INSTALL_DIR%"

python -m venv venv 2>nul

if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
    python -m pip install --upgrade pip --quiet 2>nul
)

if exist "requirements.txt" (
    pip install -r requirements.txt --quiet 2>nul || pip install psutil aiohttp pyyaml pydantic websocket-client --quiet
) else (
    pip install psutil aiohttp pyyaml pydantic websocket-client --quiet
)
echo   [OK] Dependencies installed
echo.

:: ── Step 6: Configure agent ──────────────────────────────────
echo   [6/7] Configuring agent...
(
echo # AEGISX Agent Configuration
echo server_url: "%SERVER_URL%"
echo registration_key: "%REGISTRATION_KEY%"
echo tenant_id: "%TENANT_ID%"
echo agent_name: "%HOSTNAME%"
echo data_dir: "%INSTALL_DIR%\data"
echo log_dir: "%INSTALL_DIR%\logs"
echo log_level: "INFO"
echo heartbeat_interval: 60
echo monitoring_interval: 30
echo full_inventory_interval: 21600
echo enable_auto_update: true
echo.
echo collectors:
echo   - cpu
echo   - memory
echo   - disk
echo   - network
echo   - processes
echo   - services
echo   - logs
echo   - installed_software
echo   - hardware
echo   - usb
echo   - ransomware
echo.
echo ransomware:
echo   enabled: true
echo   scan_interval: 60
echo   check_shadow_copy: true
echo   monitor_file_changes: true
) > "%INSTALL_DIR%\config.yaml"

mkdir "%INSTALL_DIR%\data" 2>nul
mkdir "%INSTALL_DIR%\logs" 2>nul
echo   [OK] Configuration saved
echo.

:: ── Step 7: Register & Start ─────────────────────────────────
echo   [7/7] Registering agent with server...

:: Create temporary JSON for registration
set "JSON={\"hostname\":\"%HOSTNAME%\",\"platform\":\"windows\",\"platform_version\":\"%OS%\",\"ip_address\":\"%SYSIP%\",\"agent_version\":\"%AGENT_VERSION%\",\"registration_key\":\"%REGISTRATION_KEY%\",\"tenant_id\":\"%TENANT_ID%\",\"capabilities\":[\"system\",\"processes\",\"services\",\"software\",\"hardware\",\"ransomware\"]}"

powershell -Command "try { $r = Invoke-RestMethod -Uri '%SERVER_URL%/api/v1/agent/register' -Method Post -Body '%JSON%' -ContentType 'application/json'; Write-Host \"  Registered: $($r.agent_id)\" } catch { Write-Host '  Agent will register on first start' }" 2>nul

:: Install as Windows service using NSSM or sc
where nssm >nul 2>&1
if %errorlevel% equ 0 (
    nssm install AEGISXAgent "%INSTALL_DIR%\venv\Scripts\python.exe" "%INSTALL_DIR%\agent.py" 2>nul
    nssm set AEGISXAgent AppDirectory "%INSTALL_DIR%" 2>nul
    nssm set AEGISXAgent Start SERVICE_AUTO_START 2>nul
    nssm start AEGISXAgent 2>nul
    echo   [OK] NSSM service installed
) else (
    :: Use sc.exe to create service
    sc create AEGISXAgent binPath="%INSTALL_DIR%\venv\Scripts\python.exe %INSTALL_DIR%\agent.py" start=auto DisplayName="AEGISX Security Agent" 2>nul
    sc description AEGISXAgent "AEGISX Enterprise Cybersecurity Platform Agent" 2>nul
    sc start AEGISXAgent 2>nul
    if %errorlevel% neq 0 (
        :: Fallback: start as scheduled task
        schtasks /create /tn "AEGISX Agent" /tr "\"%INSTALL_DIR%\venv\Scripts\python.exe\" \"%INSTALL_DIR%\agent.py\"" /sc onstart /rl highest /f 2>nul
        schtasks /run /tn "AEGISX Agent" 2>nul
        echo   [OK] Scheduled task created and started
    ) else (
        echo   [OK] Windows service installed and started
    )
)

echo.
echo   ========================================================
echo        AEGISX Agent Enrolled Successfully!
echo   ========================================================
echo.
echo   Server:      %SERVER_URL%
echo   Tenant:      %TENANT_ID%
echo   Hostname:    %HOSTNAME%
echo   IP:          %SYSIP%
echo   Status:      Running
echo.
echo   Commands:
echo     Status:  sc query AEGISXAgent
echo     Logs:    type "%INSTALL_DIR%\logs\agent.log"
echo     Stop:    sc stop AEGISXAgent
echo.

endlocal
