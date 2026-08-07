#!/bin/bash
# ================================================================
# AEGISX PRO — Kubernetes Deploy Script
# Deploys the full stack to Kubernetes with Helm.
# Usage:
#   1. Set required env vars (see .env.production)
#   2. bash deploy/k8s-deploy.sh [namespace] [environment]
# ================================================================
set -euo pipefail

NAMESPACE="${1:-aegisx}"
ENVIRONMENT="${2:-production}"
RELEASE="aegisx"
VALUES_FILE="kubernetes/helm/aegisx/values-${ENVIRONMENT}.yaml"

echo "=== AEGISX PRO Kubernetes Deploy ==="
echo "Namespace:    $NAMESPACE"
echo "Environment:  $ENVIRONMENT"
echo "Release:      $RELEASE"
echo ""

# ── Prerequisites check ───────────────────────────
command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found"; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "ERROR: helm not found"; exit 1; }
kubectl cluster-info >/dev/null 2>&1 || { echo "ERROR: cannot connect to cluster"; exit 1; }

# ── Create namespace ──────────────────────────────
if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    echo "Creating namespace: $NAMESPACE"
    kubectl create namespace "$NAMESPACE"
fi

# ── Generate secure secrets if not set ────────────
generate_secret() { python3 -c "import secrets; print(secrets.token_urlsafe(32))"; }

if [ -z "${POSTGRES_PASSWORD:-}" ]; then
    POSTGRES_PASSWORD=$(generate_secret)
    echo "Generated POSTGRES_PASSWORD"
fi
if [ -z "${REDIS_PASSWORD:-}" ]; then
    REDIS_PASSWORD=$(generate_secret)
    echo "Generated REDIS_PASSWORD"
fi
if [ -z "${SECRET_KEY:-}" ]; then
    SECRET_KEY=$(generate_secret)
    echo "Generated SECRET_KEY"
fi
if [ -z "${JWT_SECRET_KEY:-}" ]; then
    JWT_SECRET_KEY=$(generate_secret)
    echo "Generated JWT_SECRET_KEY"
fi
if [ -z "${AGENT_REGISTRATION_KEY:-}" ]; then
    AGENT_REGISTRATION_KEY=$(generate_secret)
    echo "Generated AGENT_REGISTRATION_KEY"
fi

# ── Create secrets ────────────────────────────────
echo ""
echo "Creating secrets in $NAMESPACE..."

kubectl create secret generic aegisx-secrets \
    --namespace "$NAMESPACE" \
    --from-literal=SECRET_KEY="${SECRET_KEY:-change-me-in-production}" \
    --from-literal=JWT_SECRET_KEY="${JWT_SECRET_KEY:-change-me-jwt-secret}" \
    --from-literal=POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-change-me-postgres}" \
    --from-literal=REDIS_PASSWORD="${REDIS_PASSWORD:-}" \
    --from-literal=AGENT_REGISTRATION_KEY="${AGENT_REGISTRATION_KEY:-change-me-agent-key}" \
    --from-literal=TIMESCALEDB_PASSWORD="${POSTGRES_PASSWORD:-change-me-postgres}" \
    --from-literal=MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-change-me-minio}" \
    --from-literal=CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-change-me-clickhouse}" \
    --from-literal=GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-change-me-grafana}" \
    --from-literal=OPENSEARCH_ADMIN_PASSWORD="${OPENSEARCH_PASSWORD:-change-me-opensearch}" \
    --from-literal=OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
    --from-literal=RABBITMQ_PASSWORD="${RABBITMQ_PASSWORD:-}" \
    --from-literal=RABBITMQ_ERLANG_COOKIE="$(generate_secret)" \
    --dry-run=client -o yaml | kubectl apply -f -

# ── Deploy with Helm ────────────────────────────
echo ""
echo "Deploying AEGISX with Helm..."

helm upgrade --install "$RELEASE" \
    ./kubernetes/helm/aegisx \
    --namespace "$NAMESPACE" \
    --values "$VALUES_FILE" \
    --set global.environment="$ENVIRONMENT" \
    --set config.appEnv="$ENVIRONMENT" \
    --timeout 15m \
    --wait \
    --wait-for-jobs

# ── Wait for pods ────────────────────────────────
echo ""
echo "Waiting for all pods to be ready..."
kubectl wait --namespace "$NAMESPACE" \
    --for=condition=ready pod \
    --selector=app.kubernetes.io/instance="$RELEASE" \
    --timeout=10m 2>/dev/null || true

# ── Show status ───────────────────────────────────
echo ""
echo "=== Deployment Complete ==="
echo ""
kubectl get pods --namespace "$NAMESPACE" -o wide
echo ""
kubectl get svc --namespace "$NAMESPACE"
echo ""
echo "Access URLs:"
echo "  Frontend:  https://aegisx.example.com"
echo "  API:       https://aegisx.example.com/api"
echo "  Grafana:   https://aegisx.example.com/grafana"
echo "  Jaeger:    https://aegisx.example.com/jaeger"
echo ""
echo "Health check:"
echo "  kubectl port-forward -n $NAMESPACE svc/aegisx-backend 8000:8000"
echo "  curl http://localhost:8000/health"
echo ""
echo "Get admin password:"
echo "  kubectl get secret -n $NAMESPACE aegisx-secrets -o jsonpath='{.data.SECRET_KEY}' | base64 -d"
