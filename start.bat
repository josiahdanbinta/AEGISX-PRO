@echo off
setlocal enabledelayedexpansion
title AEGISX Platform - Startup

:: ═══════════════════════════════════════════════════════════
:: AEGISX Platform Startup Script
:: Auto-detects system IP and launches all services
:: ═══════════════════════════════════════════════════════════

echo.
echo   ╔══════════════════════════════════════════════════════════╗
echo   ║          AEGISX Enterprise Security Platform            ║
echo   ╚══════════════════════════════════════════════════════════╝
echo.

:: Detect system IP
for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr /c:"IPv4"') do (
    set "ip=%%i"
    set "ip=!ip: =!"
    if not "!ip!"=="127.0.0.1" (
        if "!sysip!"=="" set "sysip=!ip!"
    )
)

if "%sysip%"=="" set "sysip=localhost"

echo   System IP Detected: %sysip%
echo.

:: Check Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Docker is not installed or not running.
    echo   Please install Docker Desktop from https://docker.com
    pause
    exit /b 1
)

echo   [1/4] Creating backend/.env from template (if needed)...
if not exist "backend\.env" (
    copy ".env.example" "backend\.env" >nul 2>&1
    echo         Created: backend\.env -- EDIT THIS FILE with your secrets
) else (
    echo         Already exists: backend\.env
)

echo.
echo   [2/4] Building Docker images...
docker-compose build --quiet 2>&1
if %errorlevel% neq 0 (
    echo   [ERROR] Docker build failed. Check Docker is running.
    pause
    exit /b 1
)

echo.
echo   [3/4] Starting AEGISX services...
docker-compose up -d
if %errorlevel% neq 0 (
    echo   [ERROR] Failed to start services.
    pause
    exit /b 1
)

echo.
echo   [4/4] Waiting for services to be ready...
echo         (this may take 30-60 seconds on first run)

:: Wait for backend health check
:wait_backend
docker inspect aegisx-backend --format="{{.State.Health.Status}}" 2>nul | findstr "healthy" >nul
if %errorlevel% neq 0 (
    <nul set /p ".=."
    timeout /t 2 >nul
    goto wait_backend
)

echo.
echo.
echo   ╔══════════════════════════════════════════════════════════╗
echo   ║              AEGISX IS NOW RUNNING                      ║
echo   ╚══════════════════════════════════════════════════════════╝
echo.
echo   Access the platform at:
echo.
echo     Dashboard  : http://%sysip%:80
echo     API Docs   : http://%sysip%:80/docs
echo     API Health : http://%sysip%:80/health
echo.
echo     Direct Backend : http://%sysip%:8000
echo     Direct Frontend: http://%sysip%:3000
echo.
echo   Agent Enrollment:
echo     Linux/macOS : curl -sSL http://%sysip%:8000/deploy/install.sh ^| bash -s -- --server http://%sysip%:8000 --key YOUR_KEY --tenant YOUR_TENANT
echo     Windows PS  : Invoke-WebRequest -Uri "http://%sysip%:8000/deploy/install.ps1" -OutFile install.ps1; .\install.ps1 -Server "http://%sysip%:8001" -Key "YOUR_KEY" -Tenant "YOUR_TENANT"
echo.
echo   Press any key to open the dashboard in your browser...
pause >nul
start http://%sysip%:80
endlocal
