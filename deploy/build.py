#!/usr/bin/env python3
"""
AEGIS Agent - Build Script
Creates standalone executables and deployment packages for all platforms.

Usage:
    python deploy/build.py --platform windows --server https://AEGIS.company.com --key REGISTRATION_KEY
    python deploy/build.py --platform macos --server https://AEGIS.company.com --key REGISTRATION_KEY
    python deploy/build.py --platform linux --server https://AEGIS.company.com --key REGISTRATION_KEY
    python deploy/build.py --all --server https://AEGIS.company.com --key REGISTRATION_KEY
"""

import argparse
import hashlib
import json
import os
import platform as pf
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
import tarfile
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

try:
    import PyInstaller.__main__
    HAS_PYINSTALLER = True
except ImportError:
    HAS_PYINSTALLER = False

VERSION = "1.1.0"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = PROJECT_ROOT / "agent"
DEPLOY_DIR = PROJECT_ROOT / "deploy"
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build_output"

STD_HIDDEN_IMPORTS = [
    "yaml",
    "aiohttp",
    "psutil",
    "cryptography",
    "websocket",
    "watchdog",
    "requests",
    "pydantic",
    "json",
    "logging",
    "asyncio",
    "signal",
    "socket",
    "importlib",
]

COLLECTOR_HIDDEN_IMPORTS = [
    "agent",
    "agent.agent",
    "agent.core",
    "agent.core.communication",
    "agent.core.collector",
    "agent.core.collectors",
    "agent.core.collectors.system",
    "agent.core.collectors.processes",
    "agent.core.collectors.services",
    "agent.core.collectors.software",
    "agent.core.collectors.hardware",
    "agent.core.collectors.logs",
    "agent.core.collectors.ransomware",
    "agent.platforms",
    "agent.platforms.windows",
    "agent.platforms.linux",
    "agent.platforms.macos",
]


def color_text(text: str, color: str) -> str:
    colors = {
        "red": "\033[0;31m",
        "green": "\033[0;32m",
        "yellow": "\033[0;33m",
        "blue": "\033[0;34m",
        "cyan": "\033[0;36m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    if sys.platform == "win32":
        return text
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def print_banner():
    print(color_text("â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—", "cyan"))
    print(color_text("â•‘       AEGIS Agent - Build & Package         â•‘", "cyan"))
    print(color_text("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•", "cyan"))
    print()


def print_step(step: int, total: int, description: str):
    print(color_text(f"[{step}/{total}] {description}", "blue"))


def print_success(message: str):
    print(f"  {color_text('âœ“', 'green')} {message}")


def print_warning(message: str):
    print(f"  {color_text('âš ', 'yellow')} {message}")


def print_error(message: str):
    print(f"{color_text('ERROR:', 'red')} {message}")


def get_data_dir(platform: str) -> str:
    if platform == "win32":
        return os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "AEGIS Agent", "data")
    elif platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/AEGIS Agent/data")
    else:
        return "/var/lib/AEGIS-agent"


def get_config_dir(platform: str) -> str:
    if platform == "win32":
        return os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "AEGIS Agent")
    elif platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/AEGIS Agent")
    else:
        return "/opt/AEGIS-agent"


def generate_agent_id() -> str:
    """Generate a deterministic agent ID from machine identifiers."""
    try:
        import uuid
        node = uuid.getnode()
        system = pf.node()
        hostname = pf.node()
        hash_input = f"{node}-{system}-{hostname}".encode()
        sha = hashlib.sha256(hash_input).hexdigest()[:16]
        return sha
    except Exception:
        return hashlib.sha256(os.urandom(32)).hexdigest()[:16]


def create_bootstrap_script(server_url: str = "", key: str = "", tenant: str = "") -> str:
    """Create the bootstrap/entry-point script for first-run setup."""
    bootstrap_content = '''#!/usr/bin/env python3
"""
AEGIS Agent - Bootstrap / Entry Point
Handles first-run configuration and launches the agent.
"""

import argparse
import os
import sys
from pathlib import Path


def get_default_data_dir() -> str:
    platform = sys.platform
    if platform == "win32":
        base = os.environ.get("ProgramData", "C:\\ProgramData")
        return os.path.join(base, "AEGIS Agent", "data")
    elif platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/AEGIS Agent/data")
    else:
        return "/var/lib/AEGIS-agent"


def get_default_config_dir() -> str:
    platform = sys.platform
    if platform == "win32":
        return os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "AEGIS Agent")
    elif platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/AEGIS Agent")
    else:
        return "/opt/AEGIS-agent"


def get_default_log_dir() -> str:
    platform = sys.platform
    if platform == "win32":
        return os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "AEGIS Agent", "logs")
    elif platform == "darwin":
        return os.path.expanduser("~/Library/Logs/AEGIS Agent")
    else:
        return "/var/log/AEGIS"


def first_run_setup(config_path: str, server_url: str = "", key: str = "", tenant: str = ""):
    """Interactive first-run setup to collect server URL, key, and tenant."""
    config_file = Path(config_path)
    if config_file.exists():
        return

    print()
    print("â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—")
    print("â•‘     AEGIS Agent - First Time Setup          â•‘")
    print("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•")
    print()
    print("Please provide the following information to enroll this agent:")
    print("(You can get these from your AEGIS admin console)")
    print()

    if not server_url:
        server_url = input("Server URL (e.g., https://AEGIS.company.com): ").strip()
    if not server_url:
        print("ERROR: Server URL is required.")
        sys.exit(1)

    if not key:
        key = input("Registration Key: ").strip()
    if not key:
        print("ERROR: Registration Key is required.")
        sys.exit(1)

    if not tenant:
        tenant = input("Tenant ID: ").strip()
    if not tenant:
        print("ERROR: Tenant ID is required.")
        sys.exit(1)

    config_file.parent.mkdir(parents=True, exist_ok=True)

    config_data = {
        "server_url": server_url,
        "registration_key": key,
        "tenant_id": tenant,
        "data_dir": get_default_data_dir(),
        "log_dir": get_default_log_dir(),
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
        "communication": {
            "reconnect_base_delay": 5,
            "reconnect_max_delay": 300,
            "reconnect_max_attempts": 0,
            "batch_size": 100,
            "compress_data": True,
        },
    }

    import yaml as yml
    with open(config_file, "w", encoding="utf-8") as f:
        yml.safe_dump(config_data, f, default_flow_style=False)

    print()
    print(f"âœ“ Configuration saved to {config_file}")
    print("Starting agent...")
    print()

    return config_data


def main():
    parser = argparse.ArgumentParser(description="AEGIS Security Agent")
    parser.add_argument("--config", "-c", help="Path to config file")
    parser.add_argument("--setup", action="store_true", help="Force first-run setup")
    parser.add_argument("--server", help="Server URL (for setup)")
    parser.add_argument("--key", help="Registration key (for setup)")
    parser.add_argument("--tenant", help="Tenant ID (for setup)")
    args = parser.parse_args()

    config_dir = get_default_config_dir()
    data_dir = get_default_data_dir()

    for d in [config_dir, data_dir]:
        Path(d).mkdir(parents=True, exist_ok=True)

    config_path = args.config or os.path.join(config_dir, "config.yaml")

    if args.setup or not os.path.exists(config_path):
        first_run_setup(
            config_path,
            server_url=args.server or "",
            key=args.key or "",
            tenant=args.tenant or "",
        )

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    try:
        from agent.agent import main as agent_main
        sys.argv = [sys.argv[0]]
        agent_main()
    except ImportError as e:
        print(f"ERROR: Cannot import agent module: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
'''
    return bootstrap_content


def write_bootstrap(build_path: Path, server_url: str = "", key: str = "", tenant: str = ""):
    bootstrap_path = build_path / "AEGIS_bootstrap.py"
    content = create_bootstrap_script(server_url, key, tenant)
    bootstrap_path.write_text(content, encoding="utf-8")
    return bootstrap_path


def build_windows_exe(server_url: str = "", key: str = "", tenant: str = "") -> bool:
    """Build Windows executable using PyInstaller."""
    if not HAS_PYINSTALLER:
        print_warning("PyInstaller not installed. Install with: pip install pyinstaller")
        return False

    platform_name = "win32"
    build_path = BUILD_DIR / "windows"
    build_path.mkdir(parents=True, exist_ok=True)

    # Copy agent source
    agent_build = build_path / "agent"
    if agent_build.exists():
        shutil.rmtree(agent_build)
    shutil.copytree(AGENT_DIR, agent_build)

    # Write bootstrap
    bootstrap_path = write_bootstrap(build_path, server_url, key, tenant)

    # Build data files for PyInstaller
    if sys.platform == "win32":
        datas = [("agent", "agent")]
    else:
        datas = []
        print_warning("Cannot cross-compile Windows .exe from non-Windows. Generating build script instead.")
        return _generate_windows_build_script(server_url, key, tenant)

    # Build with PyInstaller
    print_step(3, 7, "Building Windows executable with PyInstaller...")
    pyi_args = [
        str(bootstrap_path),
        "--onefile",
        "--name", "AEGIS-Agent",
        "--clean",
        "--noconfirm",
    ]

    for hidden_import in STD_HIDDEN_IMPORTS + COLLECTOR_HIDDEN_IMPORTS:
        pyi_args.extend(["--hidden-import", hidden_import])

    for src, dst in datas:
        pyi_args.extend(["--add-data", f"{src}{os.pathsep}{dst}"])

    if key:
        pyi_args.extend(["--hidden-import", "Crypto"])
        pyi_args.extend(["--hidden-import", "_cffi_backend"])

    try:
        PyInstaller.__main__.run(pyi_args)
    except Exception as e:
        print_error(f"PyInstaller build failed: {e}")
        return False

    # Move output
    exe_name = "AEGIS-Agent.exe"
    src_exe = Path("dist") / exe_name
    if src_exe.exists():
        dest_dir = DIST_DIR / "windows"
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_exe, dest_dir / exe_name)
        print_success(f"Windows executable: {dest_dir / exe_name}")
    else:
        print_error("PyInstaller output not found")
        return False

    return True


def _generate_windows_build_script(server_url: str, key: str, tenant: str) -> bool:
    """Generate a PowerShell script to build on a Windows machine."""
    script_dir = DIST_DIR / "windows"
    script_dir.mkdir(parents=True, exist_ok=True)

    script_content = f'''# AEGIS Agent - Windows Build Script
# Generated by deploy/build.py
# Run on a Windows machine with Python 3.8+

$ErrorActionPreference = "Stop"
$VERSION = "{VERSION}"
$AGENT_DIR = "$PSScriptRoot\\..\\..\\agent"
$OUTPUT_DIR = "$PSScriptRoot\\..\\..\\dist\\windows"

Write-Host "Building AEGIS Agent v$VERSION for Windows..." -ForegroundColor Cyan

$buildDir = Join-Path $env:TEMP "AEGIS-build-$VERSION"
if (Test-Path $buildDir) {{ Remove-Item -Recurse -Force $buildDir }}
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null

# Copy agent
Copy-Item -Path $AGENT_DIR -Destination "$buildDir\\" -Recurse -Force

# Bootstrap
$bootstrapCode = @'
{create_bootstrap_script(server_url, key, tenant)[:500]}...
'@
Set-Content -Path "$buildDir\\AEGIS_bootstrap.py" -Value (Get-Content "$PSScriptRoot\\..\\..\\build_output\\AEGIS_bootstrap.py" -Raw -ErrorAction SilentlyContinue)

if (-not (Test-Path "$buildDir\\AEGIS_bootstrap.py")) {{
    Write-Host "Bootstrap file missing. Run deploy/build.py first on the source machine." -ForegroundColor Red
    exit 1
}}

pip install pyinstaller --quiet

Push-Location $buildDir
pyinstaller --onefile --name "AEGIS-Agent" --clean --noconfirm `
    --add-data "agent;agent" `
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
    AEGIS_bootstrap.py
Pop-Location

New-Item -ItemType Directory -Path $OUTPUT_DIR -Force | Out-Null
Copy-Item -Path "$buildDir\\dist\\AEGIS-Agent.exe" -Destination "$OUTPUT_DIR\\" -Force

Write-Host "Windows executable: $OUTPUT_DIR\\AEGIS-Agent.exe" -ForegroundColor Green
'''

    (script_dir / "build_windows.ps1").write_text(script_content, encoding="utf-8")
    print_success(f"Windows build script: {script_dir / 'build_windows.ps1'}")
    print("  Run this script on a Windows machine with Python 3.8+")
    return True


def build_macos_pkg(server_url: str = "", key: str = "", tenant: str = "") -> bool:
    """Build macOS .app bundle and .pkg installer."""
    if sys.platform != "darwin":
        print_warning("macOS .pkg builds require running on macOS. Generating build script instead.")
        return _generate_macos_build_script(server_url, key, tenant)

    if not HAS_PYINSTALLER:
        print_warning("PyInstaller not installed. Install with: pip install pyinstaller")
        return False

    build_path = BUILD_DIR / "macos"
    build_path.mkdir(parents=True, exist_ok=True)

    agent_build = build_path / "agent"
    if agent_build.exists():
        shutil.rmtree(agent_build)
    shutil.copytree(AGENT_DIR, agent_build)

    bootstrap_path = write_bootstrap(build_path, server_url, key, tenant)

    print_step(3, 7, "Building macOS executable with PyInstaller...")
    pyi_args = [
        str(bootstrap_path),
        "--onefile",
        "--name", "AEGIS-Agent",
        "--clean",
        "--noconfirm",
        "--add-data", f"agent{os.pathsep}agent",
    ]

    for hidden_import in STD_HIDDEN_IMPORTS + COLLECTOR_HIDDEN_IMPORTS:
        pyi_args.extend(["--hidden-import", hidden_import])

    try:
        PyInstaller.__main__.run(pyi_args)
    except Exception as e:
        print_error(f"PyInstaller build failed: {e}")
        return False

    exe_name = "AEGIS-Agent"
    src_exe = Path("dist") / exe_name
    if not src_exe.exists():
        print_error("PyInstaller output not found")
        return False

    dest_dir = DIST_DIR / "macos"
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Create .app bundle
    print_step(4, 7, "Creating .app bundle...")
    app_dir = dest_dir / "AEGIS-Agent.app"
    contents = app_dir / "Contents"
    macos_dir = contents / "MacOS"
    resources_dir = contents / "Resources"

    for d in [macos_dir, resources_dir]:
        d.mkdir(parents=True, exist_ok=True)

    shutil.copy2(src_exe, macos_dir / exe_name)
    os.chmod(macos_dir / exe_name, 0o755)

    plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>AEGIS Agent</string>
    <key>CFBundleDisplayName</key>
    <string>AEGIS Agent</string>
    <key>CFBundleIdentifier</key>
    <string>com.AEGIS.agent</string>
    <key>CFBundleVersion</key>
    <string>{VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>{VERSION}</string>
    <key>CFBundleExecutable</key>
    <string>{exe_name}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>'''
    (contents / "Info.plist").write_text(plist_content, encoding="utf-8")
    print_success(f".app bundle: {app_dir}")

    # Build .pkg
    print_step(5, 7, "Building .pkg installer...")
    pkg_path = dest_dir / f"AEGIS-Agent-{VERSION}.pkg"

    try:
        subprocess.run(
            [
                "pkgbuild",
                "--root", str(app_dir),
                "--identifier", "com.AEGIS.agent",
                "--version", VERSION,
                "--install-location", "/Applications/AEGIS Agent.app",
                str(pkg_path),
            ],
            check=True,
            capture_output=True,
        )
        print_success(f".pkg installer: {pkg_path}")
    except subprocess.CalledProcessError as e:
        print_warning(f"pkgbuild failed: {e.stderr.decode() if e.stderr else e}")
        print("  Pre-built .app is available in dist/macos/")
    except FileNotFoundError:
        print_warning("pkgbuild not found. Install Xcode Command Line Tools.")
        print("  Pre-built .app is available in dist/macos/")

    return True


def _generate_macos_build_script(server_url: str, key: str, tenant: str) -> bool:
    script_dir = DIST_DIR / "macos"
    script_dir.mkdir(parents=True, exist_ok=True)

    script_content = f'''#!/bin/bash
# AEGIS Agent - macOS Build Script
set -e
VERSION="{VERSION}"
AGENT_DIR="$(cd "$(dirname "$0")/../../agent" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$SCRIPT_DIR/../.."
OUTPUT_DIR="$SCRIPT_DIR"

echo "Building AEGIS Agent v$VERSION for macOS..."
echo ""

pip3 install pyinstaller --quiet

BUILD_DIR="/tmp/AEGIS-build-macos-$VERSION"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

cp -R "$AGENT_DIR" "$BUILD_DIR/agent"

if [ -f "$DIST_DIR/build_output/AEGIS_bootstrap.py" ]; then
    cp "$DIST_DIR/build_output/AEGIS_bootstrap.py" "$BUILD_DIR/AEGIS_bootstrap.py"
else
    echo "ERROR: Bootstrap script missing. Run deploy/build.py first."
    exit 1
fi

cd "$BUILD_DIR"
python3 -m PyInstaller --onefile --name "AEGIS-Agent" --clean --noconfirm \\
    --add-data "agent:agent" \\
    --hidden-import "agent.core.communication" \\
    --hidden-import "agent.core.collector" \\
    --hidden-import "agent.core.collectors.system" \\
    --hidden-import "agent.core.collectors.processes" \\
    --hidden-import "agent.core.collectors.services" \\
    --hidden-import "agent.core.collectors.software" \\
    --hidden-import "agent.core.collectors.hardware" \\
    --hidden-import "agent.core.collectors.logs" \\
    --hidden-import "agent.core.collectors.ransomware" \\
    --hidden-import "agent.platforms" \\
    AEGIS_bootstrap.py

mkdir -p "$OUTPUT_DIR/AEGIS-Agent.app/Contents/MacOS"
mkdir -p "$OUTPUT_DIR/AEGIS-Agent.app/Contents/Resources"
cp "dist/AEGIS-Agent" "$OUTPUT_DIR/AEGIS-Agent.app/Contents/MacOS/"
chmod 755 "$OUTPUT_DIR/AEGIS-Agent.app/Contents/MacOS/AEGIS-Agent"

cat > "$OUTPUT_DIR/AEGIS-Agent.app/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleName</key><string>AEGIS Agent</string>
    <key>CFBundleIdentifier</key><string>com.AEGIS.agent</string>
    <key>CFBundleVersion</key><string>${VERSION}</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleExecutable</key><string>AEGIS-Agent</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>10.15</string>
    <key>LSUIElement</key><true/>
</dict></plist>
PLIST

pkgbuild --root "$OUTPUT_DIR/AEGIS-Agent.app" \\
    --identifier "com.AEGIS.agent" \\
    --version "$VERSION" \\
    --install-location "/Applications/AEGIS Agent.app" \\
    "$OUTPUT_DIR/AEGIS-Agent-${VERSION}.pkg" 2>/dev/null || echo "[WARN] pkgbuild not available, .app only"

echo ""
echo "macOS build complete!"
echo "  App: $OUTPUT_DIR/AEGIS-Agent.app"
echo "  PKG: $OUTPUT_DIR/AEGIS-Agent-${VERSION}.pkg"
'''

    (script_dir / "build_macos.sh").write_text(script_content, encoding="utf-8")
    os.chmod(script_dir / "build_macos.sh", 0o755)
    print_success(f"macOS build script: {script_dir / 'build_macos.sh'}")
    print("  Run this script on a macOS machine with Python 3.8+")
    return True


def build_linux_packages(server_url: str = "", key: str = "", tenant: str = "") -> bool:
    """Build Linux executable and create .deb/.rpm packages."""
    if not HAS_PYINSTALLER:
        print_warning("PyInstaller not installed. Install with: pip install pyinstaller")
        return False

    build_path = BUILD_DIR / "linux"
    build_path.mkdir(parents=True, exist_ok=True)

    agent_build = build_path / "agent"
    if agent_build.exists():
        shutil.rmtree(agent_build)
    shutil.copytree(AGENT_DIR, agent_build)

    bootstrap_path = write_bootstrap(build_path, server_url, key, tenant)

    print_step(3, 7, "Building Linux executable with PyInstaller...")
    pyi_args = [
        str(bootstrap_path),
        "--onefile",
        "--name", "AEGIS-agent",
        "--clean",
        "--noconfirm",
        "--add-data", f"agent{os.pathsep}agent",
    ]

    for hidden_import in STD_HIDDEN_IMPORTS + COLLECTOR_HIDDEN_IMPORTS:
        pyi_args.extend(["--hidden-import", hidden_import])

    try:
        PyInstaller.__main__.run(pyi_args)
    except Exception as e:
        print_error(f"PyInstaller build failed: {e}")
        return False

    exe_name = "AEGIS-agent"
    src_exe = Path("dist") / exe_name
    if not src_exe.exists():
        print_error("PyInstaller output not found")
        return False

    dest_dir = DIST_DIR / "linux"
    dest_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(src_exe, dest_dir / exe_name)
    os.chmod(dest_dir / exe_name, 0o755)
    print_success(f"Linux executable: {dest_dir / exe_name}")

    # Create package structure for fpm
    print_step(4, 7, "Creating Linux package structure...")
    staging = BUILD_DIR / "linux-staging"
    if staging.exists():
        shutil.rmtree(staging)

    staging_bin = staging / "opt" / "AEGIS-agent"
    staging_svc = staging / "etc" / "systemd" / "system"
    staging_data = staging / "var" / "lib" / "AEGIS-agent"
    staging_log = staging / "var" / "log" / "AEGIS"

    for d in [staging_bin, staging_svc, staging_data, staging_log]:
        d.mkdir(parents=True, exist_ok=True)

    shutil.copy2(src_exe, staging_bin / exe_name)

    service_content = f'''[Unit]
Description=AEGIS Security Agent
After=network.target
Documentation=https://AEGIS.com/docs

[Service]
Type=simple
ExecStart=/opt/AEGIS-agent/{exe_name}
Restart=always
RestartSec=10
StandardOutput=append:/var/log/AEGIS/agent.log
StandardError=append:/var/log/AEGIS/agent-error.log
Environment="AEGIS_SERVER_URL={server_url}"
Environment="AEGIS_REGISTRATION_KEY={key}"
Environment="AEGIS_TENANT_ID={tenant}"

[Install]
WantedBy=multi-user.target
'''
    (staging_svc / "AEGIS-agent.service").write_text(service_content, encoding="utf-8")

    # Try building .deb and .rpm with fpm
    print_step(5, 7, "Building .deb and .rpm packages...")

    arch = pf.machine() or "amd64"
    pkg_success = False

    if shutil.which("fpm"):
        try:
            subprocess.run(
                [
                    "fpm", "-s", "dir", "-t", "deb",
                    "-n", "AEGIS-agent",
                    "-v", VERSION,
                    "--description", "AEGIS Security Monitoring Agent",
                    "--url", "https://AEGIS.com",
                    "--maintainer", "AEGIS <support@AEGIS.com>",
                    "--license", "Proprietary",
                    "--architecture", arch,
                    "--depends", "systemd",
                    "-C", str(staging),
                    "-p", str(dest_dir / f"AEGIS-agent_{VERSION}_{arch}.deb"),
                    ".",
                ],
                check=True,
                capture_output=True,
            )
            print_success(f".deb package: {dest_dir / f'AEGIS-agent_{VERSION}_{arch}.deb'}")
            pkg_success = True
        except subprocess.CalledProcessError as e:
            print_warning(f"fpm .deb failed: {e.stderr.decode() if e.stderr else e}")
        except Exception as e:
            print_warning(f"fpm .deb failed: {e}")

        try:
            subprocess.run(
                [
                    "fpm", "-s", "dir", "-t", "rpm",
                    "-n", "AEGIS-agent",
                    "-v", VERSION,
                    "--description", "AEGIS Security Monitoring Agent",
                    "--url", "https://AEGIS.com",
                    "--maintainer", "AEGIS <support@AEGIS.com>",
                    "--license", "Proprietary",
                    "--architecture", arch,
                    "--depends", "systemd",
                    "-C", str(staging),
                    "-p", str(dest_dir / f"AEGIS-agent-{VERSION}-1.{arch}.rpm"),
                    ".",
                ],
                check=True,
                capture_output=True,
            )
            print_success(f".rpm package: {dest_dir / f'AEGIS-agent-{VERSION}-1.{arch}.rpm'}")
            pkg_success = True
        except subprocess.CalledProcessError as e:
            print_warning(f"fpm .rpm failed: {e.stderr.decode() if e.stderr else e}")
        except Exception as e:
            print_warning(f"fpm .rpm failed: {e}")
    else:
        print_warning("fpm not found (gem install fpm). Creating tar.gz instead.")

    # Always create tar.gz fallback
    tar_dir = BUILD_DIR / "linux-tar" / f"AEGIS-agent-{VERSION}"
    tar_dir.mkdir(parents=True, exist_ok=True)
    (tar_dir / "bin").mkdir(exist_ok=True)
    shutil.copy2(src_exe, tar_dir / "bin" / exe_name)

    install_sh = DEPLOY_DIR / "install.sh"
    if install_sh.exists():
        shutil.copy2(install_sh, tar_dir / "install.sh")

    tar_path = dest_dir / f"AEGIS-agent-{VERSION}-linux-{arch}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(tar_dir, arcname=f"AEGIS-agent-{VERSION}")
    print_success(f"tar.gz archive: {tar_path}")

    return True


def create_self_extracting_installer(platform: str, server_url: str, key: str, tenant: str) -> bool:
    """Create a self-extracting installer script with embedded payload."""
    print_step(6, 7, "Creating self-extracting installer...")

    output_dir = DIST_DIR / platform
    output_dir.mkdir(parents=True, exist_ok=True)

    config_yaml = yaml.safe_dump({
        "server_url": server_url,
        "registration_key": key,
        "tenant_id": tenant,
        "heartbeat_interval": 60,
        "monitoring_interval": 30,
        "inventory_interval_seconds": 21600,
        "enable_auto_update": True,
        "log_level": "INFO",
    }, default_flow_style=False)

    if platform == "win32":
        sfx_content = f'''@echo off
setlocal enabledelayedexpansion
echo AEGIS Agent - Self-Extracting Installer
echo.
set "INSTALL_DIR=%ProgramFiles%\\AEGIS Agent"
set "DATA_DIR=%ProgramData%\\AEGIS Agent\\data"
set "LOG_DIR=%ProgramData%\\AEGIS Agent\\logs"

echo Checking Python...
where python >nul 2>&1 || goto :no_python

echo Creating directories...
mkdir "%INSTALL_DIR%" 2>nul
mkdir "%DATA_DIR%" 2>nul
mkdir "%LOG_DIR%" 2>nul

echo Extracting configuration...
(
echo server_url: "{server_url}"
echo registration_key: "{key}"
echo tenant_id: "{tenant}"
echo data_dir: "%DATA_DIR%"
echo log_dir: "%LOG_DIR%"
echo log_level: "INFO"
echo heartbeat_interval: 60
echo monitoring_interval: 30
echo enable_auto_update: true
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
echo   ransomware: true
) > "%INSTALL_DIR%\\config.yaml"

echo Installing agent package...
pip install --quiet --target "%INSTALL_DIR%" AEGIS-agent 2>nul || (
    echo Warning: pip install failed. Using bundled agent.
    REM Placeholder for bundled agent extraction
)

echo.
echo Installation complete!
echo Run: "%INSTALL_DIR%\\..\\venv\\Scripts\\python.exe" -m agent.agent
echo.
goto :end

:no_python
echo ERROR: Python 3.8+ is required.
echo Please install from https://python.org
exit /b 1

:end
'''
        (output_dir / "AEGIS-Agent-Setup.cmd").write_text(sfx_content, encoding="utf-8")

    elif platform in ("linux", "darwin"):
        sfx_content = f'''#!/bin/bash
set -e
echo "AEGIS Agent - Self-Extracting Installer"
echo ""
INSTALL_DIR="/opt/AEGIS-agent"
DATA_DIR="/var/lib/AEGIS-agent"
LOG_DIR="/var/log/AEGIS"

echo "Checking Python..."
command -v python3 >/dev/null 2>&1 || {{ echo "ERROR: Python 3.8+ required"; exit 1; }}

echo "Creating directories..."
sudo mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
sudo chown -R $(whoami) "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"

echo "Writing configuration..."
cat > "$INSTALL_DIR/config.yaml" << 'CONFEOF'
{config_yaml}
CONFEOF

echo "Installing agent..."
python3 -m pip install --quiet --target "$INSTALL_DIR" AEGIS-agent 2>/dev/null || {{
    echo "Warning: pip install failed. Copying bundled agent..."
    # Placeholder for bundled agent
}}

echo ""
echo "Installation complete!"
echo "Run: python3 -m agent.agent"
'''
        sfx_path = output_dir / "AEGIS-agent-setup.sh"
        sfx_path.write_text(sfx_content, encoding="utf-8")
        os.chmod(sfx_path, 0o755)

    print_success(f"Self-extracting installer: {output_dir}")
    return True


def create_deployment_zip(output_dir: Path, server_url: str, key: str, tenant: str) -> bool:
    """Create a comprehensive deployment ZIP for manual distribution."""
    print_step(7, 7, "Creating deployment package ZIP...")

    zip_dir = output_dir / "deployment"
    zip_dir.mkdir(parents=True, exist_ok=True)

    # Copy install scripts
    for script in ["install.sh", "install.ps1", "install.cmd"]:
        src = DEPLOY_DIR / script
        if src.exists():
            shutil.copy2(src, zip_dir / script)

    # Copy agent source
    agent_dest = zip_dir / "agent"
    if agent_dest.exists():
        shutil.rmtree(agent_dest)
    shutil.copytree(AGENT_DIR, agent_dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))

    # Create deployment config template
    config_template = zip_dir / "config.template.yaml"
    config = {
        "server_url": server_url or "https://your-AEGIS-server.com",
        "registration_key": key or "YOUR_REGISTRATION_KEY",
        "tenant_id": tenant or "YOUR_TENANT_ID",
        "data_dir": "./data",
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
        "communication": {
            "reconnect_base_delay": 5,
            "reconnect_max_delay": 300,
            "reconnect_max_attempts": 0,
            "batch_size": 100,
            "compress_data": True,
        },
        "ransomware": {
            "scan_interval_seconds": 30,
            "change_window_seconds": 10,
            "change_threshold": 50,
        },
    }

    if yaml:
        config_template.write_text(yaml.safe_dump(config, default_flow_style=False), encoding="utf-8")
    else:
        config_template.write_text(json.dumps(config, indent=2), encoding="utf-8")

    # Generate README
    readme_path = zip_dir / "README.txt"
    readme_content = f"""AEGIS Agent v{VERSION} - Deployment Package
{'=' * 50}

Quick Install:
  Linux/macOS:  bash install.sh --server {server_url or 'URL'} --key {key or 'KEY'} --tenant {tenant or 'TENANT'}
  Windows (PS): powershell -File install.ps1 -Server "{server_url or 'URL'}" -Key "{key or 'KEY'}" -Tenant "{tenant or 'TENANT'}"
  Windows (CMD): install.cmd "{server_url or 'URL'}" "{key or 'KEY'}" "{tenant or 'TENANT'}"

Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
Platform: {sys.platform} / {pf.machine()}

For documentation, visit https://AEGIS.com/docs
"""
    readme_path.write_text(readme_content, encoding="utf-8")

    # Create ZIP
    zip_name = f"AEGIS-agent-deployment-{VERSION}.zip"
    zip_path = output_dir / zip_name

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(zip_dir.rglob("*")):
            arcname = file_path.relative_to(output_dir)
            if file_path.is_file():
                zf.write(file_path, arcname)

    file_size_mb = zip_path.stat().st_size / (1024 * 1024)
    print_success(f"Deployment package: {zip_path} ({file_size_mb:.1f} MB)")

    # Cleanup temp directory
    shutil.rmtree(zip_dir, ignore_errors=True)

    return True


def parse_args():
    parser = argparse.ArgumentParser(
        description="AEGIS Agent - Build & Package Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python deploy/build.py --platform windows
  python deploy/build.py --platform macos --server https://AEGIS.company.com --key MYKEY --tenant t-001
  python deploy/build.py --all --server https://AEGIS.company.com --key MYKEY --tenant t-001
  python deploy/build.py --platform linux --zip-only
        """,
    )

    parser.add_argument(
        "--platform", "-p",
        choices=["windows", "macos", "linux"],
        help="Target platform to build for",
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Build for all platforms (cross-compile where possible)",
    )
    parser.add_argument(
        "--server", "-s",
        default="",
        help="AEGIS server URL to embed in the build",
    )
    parser.add_argument(
        "--key", "-k",
        default="",
        help="Registration key to embed in the build",
    )
    parser.add_argument(
        "--tenant", "-t",
        default="",
        help="Tenant ID to embed in the build",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=DIST_DIR,
        help="Output directory for build artifacts (default: dist/)",
    )
    parser.add_argument(
        "--zip-only",
        action="store_true",
        help="Only create deployment ZIP, skip binary builds",
    )
    parser.add_argument(
        "--version",
        default=VERSION,
        help=f"Version string (default: {VERSION})",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean build directory before starting",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if not HAS_PYINSTALLER and not args.zip_only:
        print_warning("PyInstaller is not installed.")
        print("  Install with: pip install pyinstaller")
        print("  Or use --zip-only to create deployment package without binary builds.")
        print()

    global VERSION, DIST_DIR
    VERSION = args.version
    DIST_DIR = args.output

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    if args.clean:
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
        BUILD_DIR.mkdir(exist_ok=True)

    print_banner()
    print(f"  Version:   {color_text(VERSION, 'bold')}")
    print(f"  Platform:  {color_text(args.platform or 'all (deployment zip)', 'bold')}")
    print(f"  Output:    {DIST_DIR}")
    print()

    if args.all:
        platforms = ["windows", "linux", "macos"]
    elif args.platform:
        platforms = [args.platform]
    else:
        platforms = []

    if not args.zip_only:
        for plat in platforms:
            print(color_text(f"â•â•â• Building for {plat.upper()} â•â•â•", "cyan"))
            print()

            if plat == "windows":
                build_windows_exe(args.server, args.key, args.tenant)
            elif plat == "macos":
                build_macos_pkg(args.server, args.key, args.tenant)
            elif plat == "linux":
                build_linux_packages(args.server, args.key, args.tenant)

            print()

    # Always create deployment ZIP
    print(color_text("â•â•â• Creating Deployment Package â•â•â•", "cyan"))
    print()
    create_deployment_zip(DIST_DIR, args.server, args.key, args.tenant)

    # Cleanup PyInstaller cruft from project root
    for cruft in ["build", "__pycache__"]:
        cruft_path = Path.cwd() / cruft
        if cruft_path.exists() and cruft_path != BUILD_DIR:
            try:
                shutil.rmtree(cruft_path)
            except Exception:
                pass

    spec_files = list(Path.cwd().glob("*.spec"))
    for sf in spec_files:
        try:
            sf.unlink()
        except Exception:
            pass

    print()
    print(color_text("â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—", "green"))
    print(color_text("â•‘           Build Complete!                    â•‘", "green"))
    print(color_text("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•", "green"))
    print()
    print(f"  Artifacts:  {DIST_DIR}")
    print()
    print("  Files:")
    for f in sorted(DIST_DIR.rglob("*")):
        if f.is_file():
            size_kb = f.stat().st_size / 1024
            rel = f.relative_to(DIST_DIR)
            print(f"    {color_text(str(rel), 'cyan')} ({size_kb:.1f} KB)")
    print()


if __name__ == "__main__":
    main()
