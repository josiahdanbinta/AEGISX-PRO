#!/bin/bash
# ═══════════════════════════════════════════════════════════
# AEGISX Platform Startup Script (Linux/macOS)
# Auto-detects system IP and launches all services
# ═══════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${CYAN}  ╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}  ║          AEGISX Enterprise Security Platform            ║${NC}"
echo -e "${CYAN}  ╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Detect system IP
if command -v ip &> /dev/null; then
    SYSIP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
elif command -v ifconfig &> /dev/null; then
    SYSIP=$(ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1)
elif [[ "$OSTYPE" == "darwin"* ]]; then
    SYSIP=$(ifconfig en0 | grep 'inet ' | awk '{print $2}' | head -1)
fi

if [ -z "$SYSIP" ]; then
    SYSIP="localhost"
fi

echo -e "  System IP Detected: ${BOLD}${SYSIP}${NC}"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "  ${RED}[ERROR] Docker is not installed.${NC}"
    echo "  Install from: https://docs.docker.com/engine/install/"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "  ${RED}[ERROR] Docker daemon is not running.${NC}"
    echo "  Start Docker and try again."
    exit 1
fi

echo -e "  ${GREEN}[1/4]${NC} Creating backend/.env from template (if needed)..."
if [ ! -f "backend/.env" ]; then
    cp .env.example backend/.env
    echo "          Created: backend/.env -- EDIT THIS FILE with your secrets"
else
    echo "          Already exists: backend/.env"
fi

echo ""
echo -e "  ${GREEN}[2/4]${NC} Building Docker images..."
docker-compose build --quiet

echo ""
echo -e "  ${GREEN}[3/4]${NC} Starting AEGISX services..."
docker-compose up -d

echo ""
echo -e "  ${GREEN}[4/4]${NC} Waiting for services to be ready..."
echo "          (this may take 30-60 seconds on first run)"

while ! docker inspect aegisx-backend --format='{{.State.Health.Status}}' 2>/dev/null | grep -q 'healthy'; do
    echo -n "."
    sleep 2
done

echo ""
echo ""
echo -e "${GREEN}  ╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}  ║              AEGISX IS NOW RUNNING                      ║${NC}"
echo -e "${GREEN}  ╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Access the platform at:"
echo ""
echo -e "    Dashboard  : ${BOLD}http://${SYSIP}:80${NC}"
echo -e "    API Docs   : ${BOLD}http://${SYSIP}:80/docs${NC}"
echo -e "    API Health : ${BOLD}http://${SYSIP}:80/health${NC}"
echo ""
echo -e "    Backend API: ${BOLD}http://${SYSIP}:8000${NC}"
echo "    Frontend   : http://${SYSIP}:3000"
echo ""
echo "  Agent Enrollment:"
echo -e "    Linux/macOS: curl -sSL http://${SYSIP}:8000/deploy/install.sh | bash -s -- --server http://${SYSIP}:8000 --key YOUR_KEY --tenant YOUR_TENANT"
echo -e "    Windows PS : Invoke-WebRequest -Uri http://${SYSIP}:8000/deploy/install.ps1 -OutFile install.ps1; .\install.ps1 -Server http://${SYSIP}:8000 -Key YOUR_KEY -Tenant YOUR_TENANT"
echo ""
echo -e "  ${BOLD}Opening dashboard in browser...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "http://${SYSIP}:80"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open "http://${SYSIP}:80" &>/dev/null || true
fi
