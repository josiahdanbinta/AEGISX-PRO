#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# AEGISX Agent Enrollment Script (Linux / macOS)
# 
# One-command agent deployment:
#   curl -sSL http://YOUR_SERVER:8000/deploy/install.sh | bash -s -- \
#     --server http://YOUR_SERVER:8000 \
#     --key YOUR_REGISTRATION_KEY \
#     --tenant YOUR_TENANT_ID
# ═══════════════════════════════════════════════════════════════
set -e

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Parameters ────────────────────────────────────────────────
SERVER_URL=""
REGISTRATION_KEY=""
TENANT_ID=""
INSTALL_DIR="/opt/aegisx-agent"
AGENT_VERSION="1.1.0"

while [[ $# -gt 0 ]]; do
    case $1 in
        --server) SERVER_URL="$2"; shift 2 ;;
        --key)    REGISTRATION_KEY="$2"; shift 2 ;;
        --tenant) TENANT_ID="$2"; shift 2 ;;
        --dir)    INSTALL_DIR="$2"; shift 2 ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

if [ -z "$SERVER_URL" ] || [ -z "$REGISTRATION_KEY" ] || [ -z "$TENANT_ID" ]; then
    echo -e "${RED}ERROR: --server, --key, and --tenant are required${NC}"
    echo "Usage: $0 --server http://192.168.1.100:8000 --key YOUR_KEY --tenant YOUR_TENANT_ID"
    exit 1
fi

echo ""
echo -e "${CYAN}  ┌──────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}  │        AEGISX Agent Enrollment (Linux/macOS)    │${NC}"
echo -e "${CYAN}  └──────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "  Server:  ${BOLD}${SERVER_URL}${NC}"
echo -e "  Tenant:  ${TENANT_ID}"
echo ""

# ── Step 1: Detect system ─────────────────────────────────────
echo -e "${BLUE}[1/7]${NC} Detecting system..."
OS="$(uname -s)"
case "$OS" in
    Linux)  OS_TYPE="linux" ;;
    Darwin) OS_TYPE="macos" ;;
    *)      echo -e "${RED}Unsupported OS: $OS${NC}"; exit 1 ;;
esac

HOSTNAME=$(hostname)
ARCH=$(uname -m)
# Get primary IP
if command -v ip &>/dev/null; then
    SYSIP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
elif command -v ifconfig &>/dev/null; then
    SYSIP=$(ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1)
else
    SYSIP="unknown"
fi

echo -e "  OS:       ${OS_TYPE}"
echo -e "  Hostname: ${HOSTNAME}"
echo -e "  IP:       ${SYSIP}"
echo ""

# ── Step 2: Check/Install Python ──────────────────────────────
echo -e "${BLUE}[2/7]${NC} Checking Python..."
PYTHON=""
if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
fi

if [ -z "$PYTHON" ]; then
    echo -e "  ${RED}Python 3.8+ required. Installing...${NC}"
    if [ "$OS_TYPE" = "linux" ]; then
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq && sudo apt-get install -y -qq python3 python3-pip python3-venv
        elif command -v yum &>/dev/null; then
            sudo yum install -y python3 python3-pip
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y python3 python3-pip
        fi
    elif [ "$OS_TYPE" = "macos" ]; then
        if command -v brew &>/dev/null; then brew install python3; fi
    fi
    PYTHON=python3
fi

PYVER=$($PYTHON --version 2>&1)
echo -e "  ${GREEN}✓${NC} ${PYVER}"
echo ""

# ── Step 3: Create directories ────────────────────────────────
echo -e "${BLUE}[3/7]${NC} Creating directories..."
sudo mkdir -p "$INSTALL_DIR" /var/lib/aegisx-agent /var/log/aegisx-agent 2>/dev/null || mkdir -p "$INSTALL_DIR" ~/aegisx-agent-data ~/aegisx-agent-logs
echo -e "  ${GREEN}✓${NC} Install dir: $INSTALL_DIR"
echo ""

# ── Step 4: Download agent ────────────────────────────────────
echo -e "${BLUE}[4/7]${NC} Downloading agent v${AGENT_VERSION}..."
DOWNLOAD_URL="${SERVER_URL}/api/v1/agent/download"

if command -v curl &>/dev/null; then
    curl -sSL --fail -o "${INSTALL_DIR}/agent.tar.gz" "$DOWNLOAD_URL" || {
        echo -e "  ${RED}Failed to download agent from ${DOWNLOAD_URL}${NC}"
        echo -e "  ${BLUE}Trying alternative: copying from local path...${NC}"
        # Fallback: try to copy from current directory if this script is run locally
        if [ -f "agent/agent.py" ]; then
            echo -e "  Found local agent source. Copying..."
            cp -r agent/* "$INSTALL_DIR/"
        else
            echo -e "${RED}Cannot find agent source. Please ensure the server is running and accessible.${NC}"
            exit 1
        fi
    }
    if [ -f "${INSTALL_DIR}/agent.tar.gz" ]; then
        tar -xzf "${INSTALL_DIR}/agent.tar.gz" -C "$INSTALL_DIR" 2>/dev/null
        rm -f "${INSTALL_DIR}/agent.tar.gz"
    fi
elif command -v wget &>/dev/null; then
    wget -q -O "${INSTALL_DIR}/agent.tar.gz" "$DOWNLOAD_URL" || echo "wget download failed"
    if [ -f "${INSTALL_DIR}/agent.tar.gz" ]; then
        tar -xzf "${INSTALL_DIR}/agent.tar.gz" -C "$INSTALL_DIR" 2>/dev/null
        rm -f "${INSTALL_DIR}/agent.tar.gz"
    fi
fi

echo -e "  ${GREEN}✓${NC} Agent downloaded"
echo ""

# ── Step 5: Install dependencies ──────────────────────────────
echo -e "${BLUE}[5/7]${NC} Installing Python dependencies..."
cd "$INSTALL_DIR"
$PYTHON -m venv venv 2>/dev/null || $PYTHON -m virtualenv venv 2>/dev/null || true
source venv/bin/activate 2>/dev/null || true
pip install --upgrade pip --quiet 2>/dev/null || true

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt --quiet 2>/dev/null || {
        # Manual install if requirements.txt has issues
        pip install psutil aiohttp pyyaml pydantic websocket-client --quiet
    }
else
    pip install psutil aiohttp pyyaml pydantic websocket-client --quiet
fi
echo -e "  ${GREEN}✓${NC} Dependencies installed"
echo ""

# ── Step 6: Configure agent ───────────────────────────────────
echo -e "${BLUE}[6/7]${NC} Configuring agent..."
cat > "$INSTALL_DIR/config.yaml" << EOF
# AEGISX Agent Configuration
server_url: "${SERVER_URL}"
registration_key: "${REGISTRATION_KEY}"
tenant_id: "${TENANT_ID}"
agent_name: "${HOSTNAME}"
data_dir: "/var/lib/aegisx-agent"
log_dir: "/var/log/aegisx-agent"
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
EOF
echo -e "  ${GREEN}✓${NC} Configuration saved"
echo ""

# ── Step 7: Register & Start ──────────────────────────────────
echo -e "${BLUE}[7/7]${NC} Registering agent with server..."
if [ -f "agent.py" ]; then
    # Try to register via REST API
    REGISTER_RESPONSE=$(curl -s -X POST "${SERVER_URL}/api/v1/agent/register" \
        -H "Content-Type: application/json" \
        -d "{
            \"hostname\": \"${HOSTNAME}\",
            \"platform\": \"${OS_TYPE}\",
            \"platform_version\": \"$(uname -r)\",
            \"ip_address\": \"${SYSIP}\",
            \"agent_version\": \"${AGENT_VERSION}\",
            \"registration_key\": \"${REGISTRATION_KEY}\",
            \"tenant_id\": \"${TENANT_ID}\",
            \"capabilities\": [\"system\", \"processes\", \"services\", \"software\", \"hardware\", \"ransomware\"]
        }" 2>/dev/null)

    if echo "$REGISTER_RESPONSE" | grep -q "agent_id"; then
        AGENT_ID=$(echo "$REGISTER_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id','unknown'))" 2>/dev/null || echo "registered")
        echo -e "  ${GREEN}✓${NC} Agent registered: ${AGENT_ID}"
    else
        echo -e "  ${BLUE}○${NC} Agent will register on first start"
    fi
fi

# Install as service
if [ "$OS_TYPE" = "linux" ]; then
    sudo tee /etc/systemd/system/aegisx-agent.service > /dev/null << EOFUNIT
[Unit]
Description=AEGISX Security Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOFUNIT
    sudo systemctl daemon-reload
    sudo systemctl enable aegisx-agent
    sudo systemctl start aegisx-agent
    echo -e "  ${GREEN}✓${NC} Systemd service installed and started"
elif [ "$OS_TYPE" = "macos" ]; then
    PLIST="$HOME/Library/LaunchAgents/com.aegisx.agent.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$PLIST" << EOFPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.aegisx.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/venv/bin/python</string>
        <string>${INSTALL_DIR}/agent.py</string>
    </array>
    <key>WorkingDirectory</key><string>${INSTALL_DIR}</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>
EOFPLIST
    launchctl load "$PLIST" 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} LaunchAgent installed"
else
    # Manual start in background
    nohup $PYTHON "$INSTALL_DIR/agent.py" > /var/log/aegisx-agent.log 2>&1 &
    echo -e "  ${GREEN}✓${NC} Agent started in background (PID: $!)"
fi

echo ""
echo -e "${GREEN}  ┌──────────────────────────────────────────────────┐${NC}"
echo -e "${GREEN}  │     AEGISX Agent Enrolled Successfully!          │${NC}"
echo -e "${GREEN}  └──────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "  Server:      ${BOLD}${SERVER_URL}${NC}"
echo -e "  Tenant:      ${TENANT_ID}"
echo -e "  Hostname:    ${HOSTNAME}"
echo -e "  IP:          ${SYSIP}"
echo -e "  Status:      ${GREEN}Running${NC}"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "  Status:  sudo systemctl status aegisx-agent"
echo -e "  Logs:    sudo tail -f /var/log/aegisx-agent/agent.log"
echo -e "  Restart: sudo systemctl restart aegisx-agent"
echo ""
