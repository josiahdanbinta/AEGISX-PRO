@echo off
setlocal enabledelayedexpansion

REM ╔══════════════════════════════════════════════╗
REM ║  AEGISX Agent - Windows Quick Enrollment    ║
REM ║       (Non-elevated / CMD)                   ║
REM ╚══════════════════════════════════════════════╝
REM
REM Usage:
REM   install.cmd https://aegisx.company.com YOUR_KEY YOUR_TENANT_ID
REM
REM Or use named environment variables:
REM   set AEGISX_SERVER=https://aegisx.company.com
REM   set AEGISX_KEY=YOUR_KEY
REM   set AEGISX_TENANT=YOUR_TENANT_ID
REM   install.cmd

set SCRIPT_VERSION=1.1.0

REM ── Parse arguments ──
if not "%~1"=="" set SERVER_URL=%~1
if not "%~2"=="" set REGISTRATION_KEY=%~2
if not "%~3"=="" set TENANT_ID=%~3

REM ── Check environment variables as fallback ──
if "%SERVER_URL%"=="" set SERVER_URL=%AEGISX_SERVER%
if "%REGISTRATION_KEY%"=="" set REGISTRATION_KEY=%AEGISX_KEY%
if "%TENANT_ID%"=="" set TENANT_ID=%AEGISX_TENANT%

if "%SERVER_URL%"=="" (
    echo [ERROR] Server URL is required.
    echo.
    echo Usage: install.cmd https://aegisx.company.com YOUR_KEY YOUR_TENANT_ID
    echo.
    echo Or set environment variables:
    echo   set AEGISX_SERVER=https://aegisx.company.com
    echo   set AEGISX_KEY=YOUR_KEY
    echo   set AEGISX_TENANT=YOUR_TENANT_ID
    echo   install.cmd
    exit /b 1
)
if "%REGISTRATION_KEY%"=="" (
    echo [ERROR] Registration key is required.
    exit /b 1
)
if "%TENANT_ID%"=="" (
    echo [ERROR] Tenant ID is required.
    exit /b 1
)

set "INSTALL_DIR=%ProgramFiles%\AEGISX Agent"
set "DATA_DIR=%ProgramData%\AEGISX Agent\data"
set "LOG_DIR=%ProgramData%\AEGISX Agent\logs"
set "VENV_DIR=%INSTALL_DIR%\venv"
set "PYTHON_CMD="

echo.
echo ==============================================
echo    AEGISX Agent - Quick Enrollment
echo    v%SCRIPT_VERSION%
echo ==============================================
echo.
echo Server:  %SERVER_URL%
echo Tenant:  %TENANT_ID%
echo.
echo This will install the AEGISX agent on this machine.
echo.

REM ── Check for Python ──
echo [1/5] Checking Python installation...

where python >nul 2>&1
if %ERRORLEVEL% EQU 0 set "PYTHON_CMD=python"

where python3 >nul 2>&1
if %ERRORLEVEL% EQU 0 set "PYTHON_CMD=python3"

if "%PYTHON_CMD%"=="" (
    echo [WARN] Python not found in PATH. Looking in common locations...

    for %%D in (
        "%LOCALAPPDATA%\Programs\Python\Python311"
        "%LOCALAPPDATA%\Programs\Python\Python310"
        "%LOCALAPPDATA%\Programs\Python\Python39"
        "%LOCALAPPDATA%\Programs\Python\Python38"
        "C:\Python311" "C:\Python310" "C:\Python39" "C:\Python38"
        "%ProgramFiles%\Python311" "%ProgramFiles%\Python310" "%ProgramFiles%\Python39"
    ) do (
        if exist "%%~D\python.exe" (
            set "PYTHON_CMD=%%~D\python.exe"
            set "PATH=%%~D;%PATH%"
            goto :python_found
        )
    )

    echo [ERROR] Python 3.8+ is required but was not found.
    echo.
    echo Please install Python from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)
:python_found

%PYTHON_CMD% --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python command failed. Path: %PYTHON_CMD%
    pause
    exit /b 1
)
echo [ OK ] Found: %PYTHON_CMD%
echo.

REM ── Create directories ──
echo [2/5] Creating directories...

for %%D in ("%INSTALL_DIR%" "%DATA_DIR%" "%LOG_DIR%") do (
    if not exist %%D mkdir %%D >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo [ OK ] %%D
    ) else (
        echo [ERROR] Cannot create %%D - try running as Administrator
        exit /b 1
    )
)
echo.

REM ── Download agent ──
echo [3/5] Downloading agent...

set "AGENT_URL=%SERVER_URL%/api/v1/agent/download"
set "AGENT_ZIP=%INSTALL_DIR%\agent.zip"

REM Create a PowerShell download script (more reliable than bitsadmin/curl on older Windows)
set "PS_SCRIPT=%TEMP%\aegisx_download.ps1"
(
    echo [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    echo $headers = @{ "X-Registration-Key" = "%REGISTRATION_KEY%"; "X-Tenant-ID" = "%TENANT_ID%" }
    echo try {
    echo     Invoke-WebRequest -Uri "%AGENT_URL%" -OutFile "%AGENT_ZIP%" -Headers $headers -UseBasicParsing -TimeoutSec 120
    echo     Write-Output "DOWNLOAD_SUCCESS"
    echo } catch {
    echo     Write-Output "DOWNLOAD_FAILED: $_"
    echo }
) > "%PS_SCRIPT%"

powershell -ExecutionPolicy Bypass -File "%PS_SCRIPT%" > "%TEMP%\aegisx_dl_result.txt" 2>&1
set /p DL_RESULT=<"%TEMP%\aegisx_dl_result.txt"
del "%PS_SCRIPT%" >nul 2>&1
del "%TEMP%\aegisx_dl_result.txt" >nul 2>&1

echo %DL_RESULT% | findstr /C:"DOWNLOAD_SUCCESS" >nul
if %ERRORLEVEL% EQU 0 (
    echo [ OK ] Agent package downloaded
) else (
    echo [WARN] Could not download from server. Trying bundled copy...

    REM Fallback: copy from script location if this script is part of a package
    if exist "%~dp0..\agent\agent.py" (
        echo [INFO] Copying bundled agent...
        xcopy "%~dp0..\agent\*" "%INSTALL_DIR%\" /E /I /Y /Q >nul 2>&1
        if %ERRORLEVEL% EQU 0 (
            echo [ OK ] Agent copied from bundle
            goto :skip_extract
        )
    )
    echo [ERROR] Download failed and no bundled agent found.
    echo Result: %DL_RESULT%
    pause
    exit /b 1
)

REM ── Extract ──
echo [INFO] Extracting agent files...
powershell -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%AGENT_ZIP%' -DestinationPath '%INSTALL_DIR%' -Force" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    del "%AGENT_ZIP%" >nul 2>&1
    echo [ OK ] Agent extracted
) else (
    echo [ERROR] Failed to extract agent package
    pause
    exit /b 1
)

:skip_extract
echo.

REM ── Install dependencies ──
echo [4/5] Installing Python dependencies...

REM Check for requirements.txt
if exist "%INSTALL_DIR%\requirements.txt" (
    set "REQ_FILE=%INSTALL_DIR%\requirements.txt"
) else if exist "%INSTALL_DIR%\agent\requirements.txt" (
    set "REQ_FILE=%INSTALL_DIR%\agent\requirements.txt"
)

if "%REQ_FILE%"=="" (
    echo [WARN] requirements.txt not found, creating default...
    (
        echo psutil^>=5.9.0
        echo requests^>=2.31.0
        echo pyyaml^>=6.0
        echo cryptography^>=41.0.0
        echo pydantic^>=2.0.0
        echo websocket-client^>=1.6.0
        echo aiohttp^>=3.9.0
        echo watchdog^>=3.0.0
    ) > "%INSTALL_DIR%\requirements.txt"
    set "REQ_FILE=%INSTALL_DIR%\requirements.txt"
)

REM Create venv
%PYTHON_CMD% -m venv "%VENV_DIR%" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to create virtual environment
    pause
    exit /b 1
)

REM Install packages
set "PIP_CMD=%VENV_DIR%\Scripts\pip.exe"
"%PIP_CMD%" install --upgrade pip --quiet >nul 2>&1
"%PIP_CMD%" install -r "%REQ_FILE%" --quiet >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] Some packages failed to install. Continuing anyway...
) else (
    echo [ OK ] Dependencies installed
)
echo.

REM ── Configure agent ──
echo [5/5] Configuring agent...

set "CONFIG_FILE=%INSTALL_DIR%\config.yaml"
(
    echo server_url: "%SERVER_URL%"
    echo registration_key: "%REGISTRATION_KEY%"
    echo tenant_id: "%TENANT_ID%"
    echo data_dir: "%DATA_DIR%"
    echo log_dir: "%LOG_DIR%"
    echo log_level: "INFO"
    echo heartbeat_interval: 60
    echo monitoring_interval: 30
    echo inventory_interval_seconds: 21600
    echo enable_auto_update: true
    echo.
    echo collectors:
    echo   cpu: true
    echo   memory: true
    echo   disk: true
    echo   network: true
    echo   processes: true
    echo   services: true
    echo   logs: true
    echo   installed_software: true
    echo   hardware: true
    echo   usb: true
    echo   registry: true
    echo   ransomware: true
    echo.
    echo communication:
    echo   reconnect_base_delay: 5
    echo   reconnect_max_delay: 300
    echo   reconnect_max_attempts: 0
    echo   batch_size: 100
    echo   compress_data: true
    echo.
    echo logs:
    echo   sources:
    echo     windows:
    echo       - "System"
    echo       - "Security"
    echo       - "Application"
    echo   severity_filter: ["ERROR", "WARNING", "CRITICAL"]
    echo   real_time: true
    echo   max_lines: 1000
    echo.
    echo suspicious_detection:
    echo   unsigned_processes: true
    echo   temp_location_execution: true
    echo   unusual_parent_process: true
    echo.
    echo ransomware:
    echo   scan_interval_seconds: 30
    echo   change_window_seconds: 10
    echo   change_threshold: 50
) > "%CONFIG_FILE%"
echo [ OK ] Configuration saved to %CONFIG_FILE%
echo.

REM ── Try to install as service (requires admin) ──
echo [INFO] Attempting service installation...
set "SERVICE_CMD=%VENV_DIR%\Scripts\python.exe"
set "SERVICE_NAME=AEGISXAgent"
set "EXISTING_SERVICE=0"

sc query %SERVICE_NAME% >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Existing service found, stopping...
    net stop %SERVICE_NAME% >nul 2>&1
    timeout /t 3 /nobreak >nul
    sc delete %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
)

sc create %SERVICE_NAME% binPath= "\"%SERVICE_CMD%\" -m agent.agent" start= auto DisplayName= "AEGISX Security Agent" obj= LocalSystem >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    sc description %SERVICE_NAME% "AEGISX platform security monitoring agent" >nul 2>&1
    sc failure %SERVICE_NAME% reset= 86400 actions= restart/10000/restart/30000/restart/60000 >nul 2>&1
    echo [ OK ] Service created

    net start %SERVICE_NAME% >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo [ OK ] Service started
    ) else (
        echo [WARN] Service created but could not start (may need admin rights)
        echo       Try running this script as Administrator.
    )
) else (
    echo [WARN] Could not install as Windows service (likely need Administrator rights)
    echo.
    echo Starting agent in current console instead...
    echo.
    echo ────────────────────────────────────────────
    echo Starting AEGISX Agent...
    echo Logs: %LOG_DIR%\agent.log
    echo Press Ctrl+C to stop.
    echo ────────────────────────────────────────────
    echo.

    REM Set environment and start agent in foreground
    set AEGISX_SERVER_URL=%SERVER_URL%
    set AEGISX_REGISTRATION_KEY=%REGISTRATION_KEY%
    set AEGISX_TENANT_ID=%TENANT_ID%

    "%SERVICE_CMD%" -m agent.agent
    exit /b %ERRORLEVEL%
)

echo.
echo ==============================================
echo    AEGISX Agent Installation Complete!
echo ==============================================
echo.
echo Server:     %SERVER_URL%
echo Tenant:     %TENANT_ID%
echo Installed:  %INSTALL_DIR%
echo Logs:       %LOG_DIR%
echo.
echo Commands:
echo   Check status:  sc query %SERVICE_NAME%
echo   Stop service:  net stop %SERVICE_NAME%
echo   Start service: net start %SERVICE_NAME%
echo   View logs:     type "%LOG_DIR%\agent.log"
echo.
echo ────────────────────────────────────────────
echo For a more robust installation, run:
echo   PowerShell -ExecutionPolicy Bypass -File deploy\install.ps1 ^
echo       -Server "%SERVER_URL%" ^
echo       -Key "%REGISTRATION_KEY%" ^
echo       -Tenant "%TENANT_ID%"
echo ────────────────────────────────────────────
echo.
pause
exit /b 0
