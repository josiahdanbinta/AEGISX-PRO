#!/bin/bash
# AEGISX Agent - Build Native Installers
# Creates platform-specific installers for Windows, macOS, and Linux.
#
# Prerequisites:
#   - Python 3.8+ with pip
#   - PyInstaller (pip install pyinstaller)
#   - fpm (gem install fpm) for .deb/.rpm
#   - Packages for creating macOS .pkg (pkgbuild)
#
# Usage:
#   ./build_installers.sh --platform windows|macos|linux --version 1.1.0
#   ./build_installers.sh --all --version 1.1.0

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Configuration ──
AGENT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_SRC="$AGENT_ROOT/agent"
BUILD_DIR="$AGENT_ROOT/build_output"
DIST_DIR="$AGENT_ROOT/dist"
DEPLOY_DIR="$AGENT_ROOT/deploy"
PACKAGE_DIR="$BUILD_DIR/packages"

VERSION="${VERSION:-1.1.0}"
PLATFORM="${PLATFORM:-}"
BUILD_ALL=false
ARCH="$(uname -m)"

# ── Parse arguments ──
while [[ $# -gt 0 ]]; do
    case $1 in
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --all)
            BUILD_ALL=true
            shift
            ;;
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --output)
            DIST_DIR="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

if [ "$BUILD_ALL" = false ] && [ -z "$PLATFORM" ]; then
    echo -e "${RED}ERROR: --platform or --all is required${NC}"
    echo "Usage: $0 --platform windows|macos|linux [--version 1.1.0]"
    echo "       $0 --all [--version 1.1.0]"
    exit 1
fi

echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       AEGISX Agent - Build Installers        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Version:   ${BOLD}${VERSION}${NC}"
echo -e "  Platform:  ${BOLD}${PLATFORM:-all}${NC}"
echo -e "  Source:    ${AGENT_SRC}"
echo -e "  Output:    ${DIST_DIR}"
echo ""

# ── Check prerequisites ──
echo -e "${BLUE}[1/5]${NC} Checking prerequisites..."

if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo -e "${RED}Python 3.8+ is required${NC}"
    exit 1
fi
PYTHON_CMD=$(command -v python3 || command -v python)
echo -e "  ${GREEN}✓${NC} Python: $($PYTHON_CMD --version)"

$PYTHON_CMD -c "import PyInstaller" 2>/dev/null || {
    echo -e "${RED}PyInstaller is required. Install: pip install pyinstaller${NC}"
    exit 1
}
echo -e "  ${GREEN}✓${NC} PyInstaller: $($PYTHON_CMD -c 'import PyInstaller; print(PyInstaller.__version__)')"

if ! command -v fpm &> /dev/null; then
    echo -e "  ${YELLOW}⚠${NC} fpm not found (.deb/.rpm packaging will be skipped)"
    HAS_FPM=false
else
    echo -e "  ${GREEN}✓${NC} fpm: available"
    HAS_FPM=true
fi

echo ""

# ── Prepare build environment ──
echo -e "${BLUE}[2/5]${NC} Preparing build environment..."

rm -rf "$BUILD_DIR" 2>/dev/null || true
mkdir -p "$BUILD_DIR" "$DIST_DIR" "$PACKAGE_DIR"

# Create standalone bootstrap script (bundled into the executable)
BOOTSTRAP_SCRIPT="$BUILD_DIR/aegisx_bootstrap.py"
cat > "$BOOTSTRAP_SCRIPT" << 'BOOTSTRAP_EOF'
#!/usr/bin/env python3
"""
AEGISX Agent - Bootstrap / Entry Point
Handles first-run configuration and launches the agent.
"""

import argparse
import os
import sys
import json
from pathlib import Path


def get_default_data_dir() -> str:
    platform = sys.platform
    if platform == "win32":
        base = os.environ.get("ProgramData", "C:\\ProgramData")
        return os.path.join(base, "AEGISX Agent", "data")
    elif platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/AEGISX Agent/data")
    else:
        return "/var/lib/aegisx-agent"


def get_default_config_dir() -> str:
    platform = sys.platform
    if platform == "win32":
        return os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "AEGISX Agent")
    elif platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/AEGISX Agent")
    else:
        return "/opt/aegisx-agent"


def first_run_setup(config_dir: str):
    """Interactive first-run setup to collect server URL, key, and tenant."""
    config_path = Path(config_dir) / "config.yaml"

    if config_path.exists():
        return

    print("╔══════════════════════════════════════════════╗")
    print("║     AEGISX Agent - First Time Setup          ║")
    print("╚══════════════════════════════════════════════╝")
    print()
    print("Please provide the following information to enroll this agent:")
    print("(You can get these from your AEGISX admin console)")
    print()

    server_url = input("Server URL (e.g., https://aegisx.company.com): ").strip()
    if not server_url:
        print("ERROR: Server URL is required.")
        sys.exit(1)

    registration_key = input("Registration Key: ").strip()
    if not registration_key:
        print("ERROR: Registration Key is required.")
        sys.exit(1)

    tenant_id = input("Tenant ID: ").strip()
    if not tenant_id:
        print("ERROR: Tenant ID is required.")
        sys.exit(1)

    config_dir_path = Path(config_dir)
    config_dir_path.mkdir(parents=True, exist_ok=True)

    import yaml
    config = {
        "server_url": server_url,
        "registration_key": registration_key,
        "tenant_id": tenant_id,
        "data_dir": get_default_data_dir(),
        "log_dir": str(config_dir_path / "logs"),
        "log_level": "INFO",
        "heartbeat_interval": 60,
        "monitoring_interval": 30,
        "inventory_interval_seconds": 21600,
        "enable_auto_update": True,
        "collectors": {
            "cpu": True, "memory": True, "disk": True, "network": True,
            "processes": True, "services": True, "logs": True,
            "installed_software": True, "hardware": True, "usb": True,
            "ransomware": True,
        },
    }

    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, default_flow_style=False)

    print()
    print(f"✓ Configuration saved to {config_path}")
    print("Starting agent...")
    print()


def main():
    parser = argparse.ArgumentParser(description="AEGISX Security Agent")
    parser.add_argument("--config", "-c", help="Path to config file")
    parser.add_argument("--setup", action="store_true", help="Force first-run setup")
    args = parser.parse_args()

    config_dir = get_default_config_dir()
    data_dir = get_default_data_dir()

    for d in [config_dir, data_dir]:
        Path(d).mkdir(parents=True, exist_ok=True)

    config_path = args.config or os.path.join(config_dir, "config.yaml")

    if args.setup or not os.path.exists(config_path):
        first_run_setup(config_dir)
        config_path = os.path.join(config_dir, "config.yaml")

    # Import and run the actual agent
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    try:
        from agent.agent import main as agent_main
        sys.argv = [sys.argv[0]]
        agent_main()
    except ImportError as e:
        print(f"ERROR: Cannot import agent module: {e}")
        print("The agent package may be incomplete. Please reinstall.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAgent stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
BOOTSTRAP_EOF

echo -e "  ${GREEN}✓${NC} Bootstrap script created"
echo -e "  ${GREEN}✓${NC} Build directory: $BUILD_DIR"
echo ""

# ── Build Windows installer ──
build_windows() {
    echo -e "${BLUE}═══ Building Windows Installer ═══${NC}"
    echo ""

    # PyInstaller builds can't be cross-compiled from non-Windows
    if [ "$(uname -s)" != "MINGW"* ] && [ "$(uname -s)" != "MSYS"* ] && [ "$(uname -s)" != "CYGWIN"* ]; then
        echo -e "  ${YELLOW}⚠${NC} Windows builds require running on Windows."
        echo "  Generating Windows build script instead..."

        local WIN_BUILD_DIR="$PACKAGE_DIR/windows"
        mkdir -p "$WIN_BUILD_DIR"

        # Generate Windows PowerShell build script
        cat > "$WIN_BUILD_DIR/build_windows.ps1" << 'PS1_EOF'
# AEGISX Agent - Windows Build Script
# Run on a Windows machine with Python 3.8+ installed
# Usage: .\build_windows.ps1 -Version "1.1.0"

param(
    [string]$Version = "1.1.0",
    [string]$OutputDir = "$PSScriptRoot\..\..\..\dist",
    [string]$AgentSrc = "$PSScriptRoot\..\..\..\agent"
)

$ErrorActionPreference = "Stop"

Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     AEGISX Agent - Windows Build             ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$buildDir = "$env:TEMP\aegisx-build-windows-$Version"
$packageDir = "$OutputDir\windows\AEGISX-Agent-$Version"

# Cleanup
Remove-Item -Recurse -Force $buildDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $packageDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
New-Item -ItemType Directory -Path "$packageDir\agent" -Force | Out-Null

# Copy agent source
Write-Host "[1/5] Copying agent source..."
Copy-Item -Path "$AgentSrc\*" -Destination "$buildDir\agent\" -Recurse -Force

# Copy bootstrap
$bootstrapSrc = "$PSScriptRoot\..\..\build_output\aegisx_bootstrap.py"
if (Test-Path $bootstrapSrc) {
    Copy-Item -Path $bootstrapSrc -Destination "$buildDir\aegisx_bootstrap.py" -Force
} else {
    Write-Host "[WARN] Bootstrap script not found, generating..." -ForegroundColor Yellow
    # Minimal bootstrap
@'
import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent.agent import main as agent_main
if __name__ == "__main__":
    agent_main()
'@ | Out-File -FilePath "$buildDir\aegisx_bootstrap.py" -Encoding utf8
}

# Install PyInstaller
Write-Host "[2/5] Installing PyInstaller..."
pip install pyinstaller --quiet 2>&1 | Out-Null

# Build executable
Write-Host "[3/5] Building executable with PyInstaller..."
Push-Location $buildDir
pyinstaller --onefile --name "AEGISX-Agent" --clean --noconfirm `
    --add-data "agent;agent" `
    --hidden-import "yaml" `
    --hidden-import "aiohttp" `
    --hidden-import "psutil" `
    --hidden-import "cryptography" `
    --hidden-import "websocket" `
    --hidden-import "watchdog" `
    --hidden-import "agent.core.communication" `
    --hidden-import "agent.core.collector" `
    --hidden-import "agent.core.collectors.system" `
    --hidden-import "agent.core.collectors.processes" `
    --hidden-import "agent.core.collectors.services" `
    --hidden-import "agent.core.collectors.software" `
    --hidden-import "agent.core.collectors.hardware" `
    --hidden-import "agent.core.collectors.logs" `
    --hidden-import "agent.core.collectors.ransomware" `
    --hidden-import "agent.platforms" `
    aegisx_bootstrap.py 2>&1
Pop-Location

# Copy output
Write-Host "[4/5] Packaging..."
Copy-Item -Path "$buildDir\dist\AEGISX-Agent.exe" -Destination "$packageDir\" -Force

# Copy install scripts
if (Test-Path "$PSScriptRoot\..\install.ps1") {
    Copy-Item -Path "$PSScriptRoot\..\install.ps1" -Destination "$packageDir\" -Force
}
if (Test-Path "$PSScriptRoot\..\install.cmd") {
    Copy-Item -Path "$PSScriptRoot\..\install.cmd" -Destination "$packageDir\" -Force
}

# Create NSIS installer script
$nsisScript = @"
; AEGISX Agent NSIS Installer Script
!include "MUI2.nsh"

Name "AEGISX Agent ${Version}"
OutFile "AEGISX-Agent-${Version}-Setup.exe"
InstallDir "`$PROGRAMFILES\AEGISX Agent"
RequestExecutionLevel admin

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Section "Install"
    SetOutPath "`$INSTDIR"
    File "AEGISX-Agent.exe"
    File "install.ps1"
    File "install.cmd"

    WriteUninstaller "`$INSTDIR\uninstall.exe"

    CreateDirectory "`$SMPROGRAMS\AEGISX Agent"
    CreateShortcut "`$SMPROGRAMS\AEGISX Agent\AEGISX Agent.lnk" "`$INSTDIR\AEGISX-Agent.exe" "--setup"

    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGISX Agent" "DisplayName" "AEGISX Agent"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGISX Agent" "UninstallString" "`$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGISX Agent" "DisplayVersion" "${Version}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGISX Agent" "Publisher" "AEGISX"

    nsExec::ExecToLog '"`$INSTDIR\AEGISX-Agent.exe" --setup'
SectionEnd

Section "Uninstall"
    Delete "`$INSTDIR\AEGISX-Agent.exe"
    Delete "`$INSTDIR\install.ps1"
    Delete "`$INSTDIR\install.cmd"
    Delete "`$INSTDIR\uninstall.exe"
    RMDir "`$INSTDIR"
    Delete "`$SMPROGRAMS\AEGISX Agent\AEGISX Agent.lnk"
    RMDir "`$SMPROGRAMS\AEGISX Agent"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGISX Agent"
SectionEnd
"@

$nsisScript | Out-File -FilePath "$packageDir\installer.nsi" -Encoding utf8

# Check for NSIS
$nsis = Get-Command makensis -ErrorAction SilentlyContinue
if (-not $nsis) { $nsis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe" }
if (Test-Path $nsis) {
    Write-Host "[5/5] Building NSIS installer..."
    Push-Location $packageDir
    & $nsis installer.nsi 2>&1
    Pop-Location
    if (Test-Path "$packageDir\AEGISX-Agent-${Version}-Setup.exe") {
        Copy-Item -Path "$packageDir\AEGISX-Agent-${Version}-Setup.exe" -Destination "$OutputDir\windows\" -Force
        Write-Host "  MSI-style installer created: AEGISX-Agent-${Version}-Setup.exe" -ForegroundColor Green
    }
} else {
    Write-Host "[5/5] NSIS not found. Skipping installer build." -ForegroundColor Yellow
    Write-Host "  Install NSIS from: https://nsis.sourceforge.io/Download" -ForegroundColor Yellow
    Write-Host "  Then run: makensis $packageDir\installer.nsi" -ForegroundColor Yellow
}

# Create zip for distribution
Write-Host "  Creating distribution zip..."
Compress-Archive -Path "$packageDir\*" -DestinationPath "$OutputDir\windows\AEGISX-Agent-Windows-${Version}.zip" -Force

Write-Host ""
Write-Host "Windows build complete!" -ForegroundColor Green
Write-Host "  Output: $OutputDir\windows\" -ForegroundColor Green
PS1_EOF

        echo -e "  ${GREEN}✓${NC} Windows build script: $WIN_BUILD_DIR/build_windows.ps1"
        echo -e "  Run on a Windows machine with Python 3.8+ to produce the .exe and installer"
    else
        # Running on Windows (MSYS/Git Bash)
        echo "  Building Windows executable..."
        pushd "$BUILD_DIR" > /dev/null
        $PYTHON_CMD -m PyInstaller --onefile --name "AEGISX-Agent" --clean --noconfirm \
            --add-data "$AGENT_SRC;agent" \
            --hidden-import "yaml" \
            --hidden-import "aiohttp" \
            --hidden-import "psutil" \
            --hidden-import "cryptography" \
            --hidden-import "websocket" \
            --hidden-import "watchdog" \
            --hidden-import "agent.core.communication" \
            --hidden-import "agent.core.collector" \
            aegisx_bootstrap.py
        popd > /dev/null

        cp "$BUILD_DIR/dist/AEGISX-Agent.exe" "$DIST_DIR/windows/"
        echo -e "  ${GREEN}✓${NC} Windows executable: $DIST_DIR/windows/AEGISX-Agent.exe"
    fi

    echo ""
}

# ── Build macOS installer ──
build_macos() {
    echo -e "${BLUE}═══ Building macOS Installer ═══${NC}"
    echo ""

    if [ "$(uname -s)" != "Darwin" ]; then
        echo -e "  ${YELLOW}⚠${NC} macOS .pkg builds require macOS."
        echo "  Generating macOS build script..."
        local MAC_BUILD_DIR="$PACKAGE_DIR/macos"
        mkdir -p "$MAC_BUILD_DIR"

        cat > "$MAC_BUILD_DIR/build_macos.sh" << 'MAC_EOF'
#!/bin/bash
set -e

VERSION="${1:-1.1.0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_SRC="$(cd "$SCRIPT_DIR/../../.." && pwd)/agent"
BUILD_OUTPUT="$SCRIPT_DIR/../../.."
DIST_DIR="$BUILD_OUTPUT/dist"
BUILD_DIR="/tmp/aegisx-build-macos-$VERSION"

echo "Building AEGISX Agent v$VERSION for macOS..."
echo ""

# Cleanup
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR/macos"

# Copy agent
cp -R "$AGENT_SRC" "$BUILD_DIR/agent"

# Find bootstrap or create minimal one
BOOTSTRAP="$BUILD_OUTPUT/build_output/aegisx_bootstrap.py"
if [ ! -f "$BOOTSTRAP" ]; then
    cat > "$BUILD_DIR/aegisx_bootstrap.py" << 'BOOT'
import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agent.agent import main as agent_main
if __name__ == "__main__":
    agent_main()
BOOT
    BOOTSTRAP="$BUILD_DIR/aegisx_bootstrap.py"
fi

# Build with PyInstaller
cd "$BUILD_DIR"
pip3 install pyinstaller --quiet

echo "Building macOS application bundle..."
pyinstaller --onefile --name "AEGISX-Agent" --clean --noconfirm \
    --add-data "agent:agent" \
    --hidden-import "yaml" \
    --hidden-import "aiohttp" \
    --hidden-import "psutil" \
    --hidden-import "cryptography" \
    --hidden-import "agent.core.communication" \
    --hidden-import "agent.core.collector" \
    --hidden-import "agent.core.collectors.system" \
    --hidden-import "agent.core.collectors.processes" \
    --hidden-import "agent.core.collectors.services" \
    --hidden-import "agent.core.collectors.software" \
    --hidden-import "agent.core.collectors.hardware" \
    --hidden-import "agent.core.collectors.logs" \
    --hidden-import "agent.core.collectors.ransomware" \
    --hidden-import "agent.platforms" \
    "$BOOTSTRAP"

# Create .app bundle structure
APP_DIR="$DIST_DIR/macos/AEGISX-Agent.app"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

cp "dist/AEGISX-Agent" "$APP_DIR/Contents/MacOS/"

cat > "$APP_DIR/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>AEGISX Agent</string>
    <key>CFBundleDisplayName</key>
    <string>AEGISX Agent</string>
    <key>CFBundleIdentifier</key>
    <string>com.aegisx.agent</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleExecutable</key>
    <string>AEGISX-Agent</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
PLIST

echo "  .app bundle created at: $APP_DIR"

# Build .pkg installer
echo "Building .pkg installer..."
pkgbuild --root "$APP_DIR" \
    --identifier "com.aegisx.agent" \
    --version "$VERSION" \
    --install-location "/Applications/AEGISX Agent.app" \
    "$DIST_DIR/macos/AEGISX-Agent-${VERSION}.pkg"

echo "  .pkg installer created: $DIST_DIR/macos/AEGISX-Agent-${VERSION}.pkg"

# Copy install script
cp "$SCRIPT_DIR/../install.sh" "$DIST_DIR/macos/"

# Create distribution zip
cd "$DIST_DIR/macos"
zip -r "AEGISX-Agent-macOS-${VERSION}.zip" *.app install.sh *.pkg 2>/dev/null || true

echo ""
echo "macOS build complete!"
echo "  Output: $DIST_DIR/macos/"
echo "  App:    AEGISX-Agent.app"
echo "  PKG:    AEGISX-Agent-${VERSION}.pkg"
MAC_EOF

        chmod +x "$MAC_BUILD_DIR/build_macos.sh"
        echo -e "  ${GREEN}✓${NC} macOS build script: $MAC_BUILD_DIR/build_macos.sh"
    else
        echo "  Building macOS executable..."
        mkdir -p "$BUILD_DIR/macos_build"
        cp -R "$AGENT_SRC" "$BUILD_DIR/macos_build/agent"

        pushd "$BUILD_DIR/macos_build" > /dev/null
        $PYTHON_CMD -m PyInstaller --onefile --name "AEGISX-Agent" --clean --noconfirm \
            --add-data "agent:agent" \
            --hidden-import "agent.core.communication" \
            --hidden-import "agent.core.collector" \
            --hidden-import "agent.platforms" \
            "$BOOTSTRAP_SCRIPT"
        popd > /dev/null

        # Create .app bundle
        APP_DIR="$DIST_DIR/macos/AEGISX-Agent.app"
        mkdir -p "$APP_DIR/Contents/MacOS"
        mkdir -p "$APP_DIR/Contents/Resources"
        cp "$BUILD_DIR/macos_build/dist/AEGISX-Agent" "$APP_DIR/Contents/MacOS/"

        cat > "$APP_DIR/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>AEGISX Agent</string>
    <key>CFBundleDisplayName</key><string>AEGISX Agent</string>
    <key>CFBundleIdentifier</key><string>com.aegisx.agent</string>
    <key>CFBundleVersion</key><string>${VERSION}</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleExecutable</key><string>AEGISX-Agent</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>10.15</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

        # Build .pkg
        pkgbuild --root "$APP_DIR" \
            --identifier "com.aegisx.agent" \
            --version "$VERSION" \
            --install-location "/Applications/AEGISX Agent.app" \
            "$DIST_DIR/macos/AEGISX-Agent-${VERSION}.pkg"

        cd "$DIST_DIR/macos"
        zip -r "AEGISX-Agent-macOS-${VERSION}.zip" *.app install.sh *.pkg 2>/dev/null || true

        echo -e "  ${GREEN}✓${NC} macOS .app and .pkg created"
    fi

    echo ""
}

# ── Build Linux installers ──
build_linux() {
    echo -e "${BLUE}═══ Building Linux Installers ═══${NC}"
    echo ""

    local LINUX_BUILD_DIR="$BUILD_DIR/linux_build"
    rm -rf "$LINUX_BUILD_DIR"
    mkdir -p "$LINUX_BUILD_DIR"
    mkdir -p "$DIST_DIR/linux"

    # Copy agent
    cp -R "$AGENT_SRC" "$LINUX_BUILD_DIR/agent"

    # Build with PyInstaller
    echo "  Building Linux executable..."
    pushd "$LINUX_BUILD_DIR" > /dev/null
    $PYTHON_CMD -m PyInstaller --onefile --name "aegisx-agent" --clean --noconfirm \
        --add-data "agent:agent" \
        --hidden-import "yaml" \
        --hidden-import "aiohttp" \
        --hidden-import "psutil" \
        --hidden-import "cryptography" \
        --hidden-import "agent.core.communication" \
        --hidden-import "agent.core.collector" \
        --hidden-import "agent.platforms" \
        "$BOOTSTRAP_SCRIPT"
    popd > /dev/null

    if [ ! -f "$LINUX_BUILD_DIR/dist/aegisx-agent" ]; then
        echo -e "  ${RED}PyInstaller build failed${NC}"
        echo ""
        return 1
    fi

    echo -e "  ${GREEN}✓${NC} Executable built"

    # Build .deb package
    if [ "$HAS_FPM" = true ]; then
        echo "  Building .deb package..."

        local DEB_STAGING="$PACKAGE_DIR/deb-staging"
        rm -rf "$DEB_STAGING"
        mkdir -p "$DEB_STAGING/opt/aegisx-agent"
        mkdir -p "$DEB_STAGING/var/lib/aegisx-agent"
        mkdir -p "$DEB_STAGING/var/log/aegisx"
        mkdir -p "$DEB_STAGING/etc/systemd/system"
        mkdir -p "$DEB_STAGING/usr/bin"

        cp "$LINUX_BUILD_DIR/dist/aegisx-agent" "$DEB_STAGING/opt/aegisx-agent/"
        ln -s "/opt/aegisx-agent/aegisx-agent" "$DEB_STAGING/usr/bin/aegisx-agent" 2>/dev/null || true

        # Systemd service
        cat > "$DEB_STAGING/etc/systemd/system/aegisx-agent.service" << SERVICE_EOF
[Unit]
Description=AEGISX Security Agent
After=network.target
Documentation=https://aegisx.com/docs

[Service]
Type=simple
ExecStart=/opt/aegisx-agent/aegisx-agent
Restart=always
RestartSec=10
StandardOutput=append:/var/log/aegisx/agent.log
StandardError=append:/var/log/aegisx/agent-error.log
Environment="AEGISX_SERVER_URL="
Environment="AEGISX_REGISTRATION_KEY="
Environment="AEGISX_TENANT_ID="

[Install]
WantedBy=multi-user.target
SERVICE_EOF

        fpm -s dir -t deb \
            -n "aegisx-agent" \
            -v "$VERSION" \
            --description "AEGISX Security Monitoring Agent" \
            --url "https://aegisx.com" \
            --maintainer "AEGISX <support@aegisx.com>" \
            --license "Proprietary" \
            --architecture "$ARCH" \
            --depends "systemd" \
            --after-install "$DEPLOY_DIR/postinst.sh" \
            --before-remove "$DEPLOY_DIR/prerm.sh" \
            -C "$DEB_STAGING" \
            -p "$DIST_DIR/linux/aegisx-agent_${VERSION}_${ARCH}.deb" \
            .

        echo -e "  ${GREEN}✓${NC} .deb package: $DIST_DIR/linux/aegisx-agent_${VERSION}_${ARCH}.deb"

        # Build .rpm package
        echo "  Building .rpm package..."

        fpm -s dir -t rpm \
            -n "aegisx-agent" \
            -v "$VERSION" \
            --description "AEGISX Security Monitoring Agent" \
            --url "https://aegisx.com" \
            --maintainer "AEGISX <support@aegisx.com>" \
            --license "Proprietary" \
            --architecture "$(uname -m)" \
            --depends "systemd" \
            -C "$DEB_STAGING" \
            -p "$DIST_DIR/linux/aegisx-agent-${VERSION}-1.${ARCH}.rpm" \
            .

        echo -e "  ${GREEN}✓${NC} .rpm package: $DIST_DIR/linux/aegisx-agent-${VERSION}-1.${ARCH}.rpm"
    else
        echo -e "  ${YELLOW}⚠${NC} fpm not available. Creating tar.gz archive instead."

        local TAR_STAGING="$PACKAGE_DIR/tar-staging"
        rm -rf "$TAR_STAGING"
        mkdir -p "$TAR_STAGING/aegisx-agent-$VERSION"
        mkdir -p "$TAR_STAGING/aegisx-agent-$VERSION/bin"
        mkdir -p "$TAR_STAGING/aegisx-agent-$VERSION/data"

        cp "$LINUX_BUILD_DIR/dist/aegisx-agent" "$TAR_STAGING/aegisx-agent-$VERSION/bin/"
        cp "$DEPLOY_DIR/install.sh" "$TAR_STAGING/aegisx-agent-$VERSION/"

        cd "$TAR_STAGING"
        tar -czf "$DIST_DIR/linux/aegisx-agent-${VERSION}-linux-${ARCH}.tar.gz" "aegisx-agent-$VERSION"
    fi

    # Copy install script
    cp "$DEPLOY_DIR/install.sh" "$DIST_DIR/linux/"

    echo ""
    echo -e "  ${GREEN}✓${NC} Linux packages created in $DIST_DIR/linux/"
    echo ""
}

# ── Create post-install / pre-remove scripts ──
create_package_scripts() {
    mkdir -p "$DEPLOY_DIR"

    # postinst
    cat > "$DEPLOY_DIR/postinst.sh" << 'POSTINST'
#!/bin/bash
set -e

echo "AEGISX Agent v${VERSION:-1.0.0} installed."

# Enable and start the service
if command -v systemctl &>/dev/null; then
    systemctl daemon-reload
    systemctl enable aegisx-agent 2>/dev/null || true
    systemctl start aegisx-agent 2>/dev/null || true
    echo "Service started. Run 'aegisx-agent --setup' to configure."
fi

echo ""
echo "Configure your agent:"
echo "  sudo aegisx-agent --setup"
echo ""
POSTINST
    chmod +x "$DEPLOY_DIR/postinst.sh"

    # prerm
    cat > "$DEPLOY_DIR/prerm.sh" << 'PRERM'
#!/bin/bash
set -e

if command -v systemctl &>/dev/null; then
    systemctl stop aegisx-agent 2>/dev/null || true
    systemctl disable aegisx-agent 2>/dev/null || true
fi
PRERM
    chmod +x "$DEPLOY_DIR/prerm.sh"
}

# ── Create universal distribution package ──
create_universal_package() {
    echo -e "${BLUE}[4/5]${NC} Creating universal distribution package..."

    local UNIVERSAL_DIR="$PACKAGE_DIR/universal"
    rm -rf "$UNIVERSAL_DIR"
    mkdir -p "$UNIVERSAL_DIR/aegisx-agent-$VERSION"
    mkdir -p "$UNIVERSAL_DIR/aegisx-agent-$VERSION/agent"

    cp -R "$AGENT_SRC/"* "$UNIVERSAL_DIR/aegisx-agent-$VERSION/agent/"
    cp "$DEPLOY_DIR/install.sh" "$UNIVERSAL_DIR/aegisx-agent-$VERSION/"
    cp "$DEPLOY_DIR/install.ps1" "$UNIVERSAL_DIR/aegisx-agent-$VERSION/"
    cp "$DEPLOY_DIR/install.cmd" "$UNIVERSAL_DIR/aegisx-agent-$VERSION/"

    # Create README
    cat > "$UNIVERSAL_DIR/aegisx-agent-$VERSION/README.txt" << READEOF
AEGISX Agent v${VERSION} - Universal Package

Installation:
  - Linux/macOS:  bash install.sh --server URL --key KEY --tenant TENANT
  - Windows (PS): powershell -File install.ps1 -Server URL -Key KEY -Tenant TENANT
  - Windows (CMD): install.cmd URL KEY TENANT

For more information, visit https://aegisx.com/docs
READEOF

    cd "$UNIVERSAL_DIR"
    zip -r "$DIST_DIR/aegisx-agent-universal-${VERSION}.zip" "aegisx-agent-$VERSION"

    echo -e "  ${GREEN}✓${NC} Universal package: $DIST_DIR/aegisx-agent-universal-${VERSION}.zip"
    echo ""
}

# ── Cleanup ──
cleanup() {
    echo -e "${BLUE}[5/5]${NC} Cleaning up..."
    rm -rf "$BUILD_DIR" 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} Build artifacts cleaned"
    echo ""
}

# ── Execute builds ──
create_package_scripts

if [ "$BUILD_ALL" = true ]; then
    build_windows
    build_macos
    build_linux
else
    case "$PLATFORM" in
        windows|win32) build_windows ;;
        macos|darwin)  build_macos ;;
        linux)         build_linux ;;
        *)
            echo -e "${RED}Unknown platform: $PLATFORM. Use windows, macos, or linux.${NC}"
            exit 1
            ;;
    esac
fi

create_universal_package
cleanup

echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        Build Complete!                       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Output:  ${BOLD}${DIST_DIR}${NC}"
echo ""
echo "  Distribution files:"
if ls "$DIST_DIR"/windows/*.exe 2>/dev/null || ls "$DIST_DIR"/windows/*.zip 2>/dev/null; then
    echo -e "    ${CYAN}Windows:${NC}  $DIST_DIR/windows/"
fi
if ls "$DIST_DIR"/macos/*.pkg 2>/dev/null || ls "$DIST_DIR"/macos/*.app 2>/dev/null; then
    echo -e "    ${CYAN}macOS:${NC}    $DIST_DIR/macos/"
fi
if ls "$DIST_DIR"/linux/*.deb 2>/dev/null || ls "$DIST_DIR"/linux/*.rpm 2>/dev/null || ls "$DIST_DIR"/linux/*.tar.gz 2>/dev/null; then
    echo -e "    ${CYAN}Linux:${NC}    $DIST_DIR/linux/"
fi
echo -e "    ${CYAN}Universal:${NC} $DIST_DIR/aegisx-agent-universal-${VERSION}.zip"
echo ""
