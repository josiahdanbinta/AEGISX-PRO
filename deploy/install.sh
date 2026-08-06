#!/bin/bash
# AEGISX Agent Enrollment Script - Linux/macOS
# Usage: curl -sSL https://your-aegisx-server.com/deploy/install.sh | bash -s -- --server https://your-server.com --key YOUR_REGISTRATION_KEY --tenant YOUR_TENANT_ID

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SERVER_URL=""
REGISTRATION_KEY=""
TENANT_ID=""
INSTALL_DIR="/opt/aegisx-agent"
DATA_DIR="/var/lib/aegisx-agent"
LOG_DIR="/var/log/aegisx"
AGENT_PORT=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server) SERVER_URL="$2"; shift 2 ;;
        --key) REGISTRATION_KEY="$2"; shift 2 ;;
        --tenant) TENANT_ID="$2"; shift 2 ;;
        --dir) INSTALL_DIR="$2"; shift 2 ;;
        --port) AGENT_PORT="$2"; shift 2 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# Validate
if [ -z "$SERVER_URL" ] || [ -z "$REGISTRATION_KEY" ] || [ -z "$TENANT_ID" ]; then
    echo -e "${RED}ERROR: --server, --key, and --tenant are required${NC}"
    echo "Usage: $0 --server https://aegisx.company.com --key YOUR_KEY --tenant YOUR_TENANT_ID"
    exit 1
fi

echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     AEGISX Agent Enrollment - Linux/macOS    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  OS_TYPE="linux" ;;
    Darwin) OS_TYPE="macos" ;;
    *)      echo -e "${RED}Unsupported OS: $OS${NC}"; exit 1 ;;
esac

echo -e "${BLUE}[1/6]${NC} Detecting system..."
echo -e "  OS:      ${BOLD}$OS_TYPE${NC}"
echo -e "  Arch:    $(uname -m)"
echo -e "  Host:    $(hostname)"
echo ""

# Check Python
echo -e "${BLUE}[2/6]${NC} Checking prerequisites..."
if command -v python3 &> /dev/null; then
    PYTHON=python3
elif command -v python &> /dev/null; then
    PYTHON=python
else
    echo -e "${RED}Python 3.8+ is required. Installing...${NC}"
    if [ "$OS_TYPE" = "linux" ]; then
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3 python3-pip
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y python3 python3-pip
        fi
    elif [ "$OS_TYPE" = "macos" ]; then
        if command -v brew &> /dev/null; then
            brew install python3
        else
            echo -e "${RED}Please install Python 3.8+ from https://python.org${NC}"
            exit 1
        fi
    fi
    PYTHON=python3
fi
echo -e "  ${GREEN}✓${NC} Python: $($PYTHON --version)"
echo ""

# Create directories
echo -e "${BLUE}[3/6]${NC} Creating directories..."
sudo mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
sudo chown -R $(whoami) "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
echo -e "  ${GREEN}✓${NC} Install: $INSTALL_DIR"
echo -e "  ${GREEN}✓${NC} Data:    $DATA_DIR"
echo -e "  ${GREEN}✓${NC} Logs:    $LOG_DIR"
echo ""

# Download agent
echo -e "${BLUE}[4/6]${NC} Downloading agent..."
AGENT_URL="${SERVER_URL}/api/v1/agent/download"
curl -sSL -o "$INSTALL_DIR/agent.tar.gz" "$AGENT_URL" -H "X-Registration-Key: $REGISTRATION_KEY" -H "X-Tenant-ID: $TENANT_ID"
tar -xzf "$INSTALL_DIR/agent.tar.gz" -C "$INSTALL_DIR"
echo -e "  ${GREEN}✓${NC} Agent downloaded to $INSTALL_DIR"
echo ""

# Install Python dependencies
echo -e "${BLUE}[5/6]${NC} Installing dependencies..."
cd "$INSTALL_DIR"
$PYTHON -m venv venv
source venv/bin/activate
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1
echo -e "  ${GREEN}✓${NC} Dependencies installed"
echo ""

# Configure agent
echo -e "${BLUE}[6/6]${NC} Configuring agent..."
cat > "$INSTALL_DIR/config.yaml" << EOF
server_url: "${SERVER_URL}"
registration_key: "${REGISTRATION_KEY}"
tenant_id: "${TENANT_ID}"
data_dir: "${DATA_DIR}"
log_dir: "${LOG_DIR}"
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
  ransomware: true

communication:
  reconnect_base_delay: 5
  reconnect_max_delay: 300
  reconnect_max_attempts: 0
  batch_size: 100
  compress_data: true

logs:
  sources:
    linux:
      - "/var/log/syslog"
      - "/var/log/auth.log"
    macos:
      - "/var/log/system.log"
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
EOF
echo -e "  ${GREEN}✓${NC} Configuration saved"
echo ""

# Create service (Linux only)
if [ "$OS_TYPE" = "linux" ]; then
    sudo tee /etc/systemd/system/aegisx-agent.service > /dev/null << EOF
[Unit]
Description=AEGISX Security Agent
After=network.target
Documentation=https://aegisx.com/docs

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python -m agent.agent
Restart=always
RestartSec=10
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent-error.log
Environment="AEGISX_SERVER_URL=${SERVER_URL}"
Environment="AEGISX_REGISTRATION_KEY=${REGISTRATION_KEY}"
Environment="AEGISX_TENANT_ID=${TENANT_ID}"

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable aegisx-agent
    sudo systemctl start aegisx-agent
    echo -e "  ${GREEN}✓${NC} Systemd service installed and started"
elif [ "$OS_TYPE" = "macos" ]; then
    # LaunchAgent for macOS
    PLIST_DIR="$HOME/Library/LaunchAgents"
    mkdir -p "$PLIST_DIR"
    cat > "$PLIST_DIR/com.aegisx.agent.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegisx.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/venv/bin/python</string>
        <string>-m</string>
        <string>agent.agent</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/agent-error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>AEGISX_SERVER_URL</key>
        <string>${SERVER_URL}</string>
        <key>AEGISX_REGISTRATION_KEY</key>
        <string>${REGISTRATION_KEY}</string>
        <key>AEGISX_TENANT_ID</key>
        <string>${TENANT_ID}</string>
    </dict>
</dict>
</plist>
EOF
    launchctl load "$PLIST_DIR/com.aegisx.agent.plist"
    echo -e "  ${GREEN}✓${NC} LaunchAgent installed and started"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     AEGISX Agent Enrolled Successfully!      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Server:  ${BOLD}${SERVER_URL}${NC}"
echo -e "  Tenant:  ${TENANT_ID}"
echo -e "  Status:  ${GREEN}Running${NC}"
echo -e "  Logs:    ${LOG_DIR}/agent.log"
echo ""
echo -e "To check status: ${CYAN}sudo systemctl status aegisx-agent${NC}"
echo -e "To view logs:    ${CYAN}tail -f ${LOG_DIR}/agent.log${NC}"
