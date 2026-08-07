#!/bin/bash
# ================================================================
# AEGIS v2.0 — Customer Demo Provisioning Script
# Creates an isolated demo environment for a single customer.
# Usage: bash deploy/demo-provision.sh <customer-name>
# ================================================================
set -e

CUSTOMER_NAME="${1:-demo-customer}"
CUSTOMER_SLUG=$(echo "$CUSTOMER_NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-')
NAMESPACE="aegis-demo-${CUSTOMER_SLUG}"
ADMIN_PASSWORD=$(openssl rand -base64 12)
DB_PASSWORD=$(openssl rand -base64 16)
DEMO_PORT=$((8000 + RANDOM % 1000))

echo "============================================"
echo " AEGIS v2.0 - Demo Provisioning"
echo "============================================"
echo " Customer:  $CUSTOMER_NAME"
echo " Namespace: $NAMESPACE"
echo " Port:      $DEMO_PORT"
echo "============================================"
echo ""

# Generate license key
cd "$(dirname "$0")/.."
LICENSE_KEY=$(python3 backend/app/core/license_key.py "$CUSTOMER_NAME" "demo@${CUSTOMER_SLUG}.demo" --trial 2>/dev/null | grep "Trial license" | cut -d' ' -f4)

echo "License: $LICENSE_KEY"
echo ""

# Create namespace
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Create secrets
kubectl create secret generic aegis-secrets \
    --namespace "$NAMESPACE" \
    --from-literal=POSTGRES_PASSWORD="$DB_PASSWORD" \
    --from-literal=REDIS_PASSWORD="" \
    --from-literal=SECRET_KEY="$(openssl rand -base64 32)" \
    --from-literal=JWT_SECRET_KEY="$(openssl rand -base64 32)" \
    --from-literal=AGENT_REGISTRATION_KEY="$(openssl rand -base64 16)" \
    --from-literal=MINIO_ROOT_PASSWORD="$(openssl rand -base64 16)" \
    --from-literal=CLICKHOUSE_PASSWORD="$(openssl rand -base64 16)" \
    --from-literal=GRAFANA_ADMIN_PASSWORD="$(openssl rand -base64 12)" \
    --from-literal=OPENSEARCH_ADMIN_PASSWORD="$(openssl rand -base64 16)" \
    --dry-run=client -o yaml | kubectl apply -f -

# Deploy with Helm (single replica, minimal resources for demo)
helm upgrade --install aegis ./kubernetes/helm/aegis \
    --namespace "$NAMESPACE" \
    --values kubernetes/helm/aegis/values-dev.yaml \
    --set global.environment=demo \
    --set config.appName="AEGIS - $CUSTOMER_NAME Demo" \
    --set config.appEnv=demo \
    --set config.corsOrigins="*" \
    --set backend.replicaCount=1 \
    --set frontend.replicaCount=1 \
    --set postgresql.replicaCount=1 \
    --set redis.replicaCount=1 \
    --set opensearch.replicaCount=1 \
    --set kafka.enabled=false \
    --set timescaledb.enabled=false \
    --set clickhouse.enabled=false \
    --set minio.enabled=false \
    --set flink.enabled=false \
    --set prometheus.enabled=false \
    --set grafana.enabled=false \
    --set jaeger.enabled=false \
    --set argocd.enabled=false \
    --set backend.resources.requests.cpu=250m \
    --set backend.resources.requests.memory=256Mi \
    --timeout 5m --wait

# Expose via NodePort
kubectl expose deployment aegis-frontend \
    --namespace "$NAMESPACE" \
    --type=NodePort \
    --port=80 \
    --name=aegis-frontend-external \
    --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "============================================"
echo " Demo Ready!"
echo "============================================"
echo " Customer:  $CUSTOMER_NAME"
echo " Namespace: $NAMESPACE"
echo " URL:       http://<server-ip>:$DEMO_PORT"
echo " Admin:     admin@$CUSTOMER_SLUG.demo"
echo " Password:  $ADMIN_PASSWORD"
echo " License:   $LICENSE_KEY"
echo " Expires:   14 days"
echo "============================================"
