#!/bin/bash
# ================================================================
# AEGIS v2.0 - Quick Customer Demo (Docker-based)
# Creates an isolated demo for a customer in 60 seconds.
# No Kubernetes required. Just Docker + Docker Compose.
#
# Usage: bash deploy/demo-docker.sh acme-corp
# ================================================================
set -e

CUSTOMER="${1:-demo}"
DEMO_DIR="/opt/aegis-demos/${CUSTOMER}"

echo "=== AEGIS v2.0 - Customer Demo ==="
echo "Customer: $CUSTOMER"
echo ""

# Create isolated demo directory
mkdir -p "$DEMO_DIR/data" "$DEMO_DIR/logs"
cp docker-compose.yml "$DEMO_DIR/"
cp docker-compose.prod.yml "$DEMO_DIR/"
cp -r docker/ "$DEMO_DIR/"

# Generate secrets
SECRET_KEY=$(openssl rand -base64 32)
JWT_KEY=$(openssl rand -base64 32)
DB_PASS=$(openssl rand -base64 16)
ADMIN_PASS=$(openssl rand -base64 12)

# Generate license key
cd "$(dirname "$0")/.."
LICENSE=$(python3 backend/app/core/license_key.py "$CUSTOMER" "demo@joshwarescybertech.com" --trial 2>/dev/null | grep "Trial" | awk '{print $NF}')

cat > "$DEMO_DIR/.env" <<EOF
APP_NAME=AEGIS
APP_VERSION=2.0.0
APP_ENV=demo
DEBUG=false
SECRET_KEY=$SECRET_KEY
JWT_SECRET_KEY=$JWT_KEY
AGENT_REGISTRATION_KEY=$(openssl rand -base64 16)
POSTGRES_USER=aegis
POSTGRES_PASSWORD=$DB_PASS
POSTGRES_DB=aegis
OPENSEARCH_PASSWORD=$DB_PASS
MINIO_ROOT_PASSWORD=$(openssl rand -base64 16)
CLICKHOUSE_PASSWORD=$(openssl rand -base64 16)
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 12)
AEGIS_ADMIN_EMAIL=demo@joshwarescybertech.com
AEGIS_ADMIN_PASSWORD=$ADMIN_PASS
LICENSE_KEY=$LICENSE
FEATURE_SOAR=true
FEATURE_THREAT_INTEL=true
FEATURE_COMPLIANCE=true
FEATURE_VULNERABILITY=true
FEATURE_KAFKA=false
FEATURE_CLICKHOUSE=false
FEATURE_UEBA=false
FEATURE_AI=false
FEATURE_SLACK_BOT=false
AI_ENABLED=false
EOF

cd "$DEMO_DIR"
docker compose up -d

echo ""
echo "============================================"
echo " Demo Ready - $CUSTOMER"
echo "============================================"
echo " URL:      http://$(hostname -I | awk '{print $1}'):5174"
echo " Admin:    demo@joshwarescybertech.com"
echo " Password: $ADMIN_PASS"
echo " License:  $LICENSE"
echo " Expires:  14 days"
echo ""
echo " Stop:     cd $DEMO_DIR && docker compose down"
echo " Clean:    rm -rf $DEMO_DIR"
echo "============================================"
