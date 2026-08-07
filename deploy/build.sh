#!/bin/bash
# ================================================================
# AEGISX PRO — Docker Build & Push Script
# Builds and pushes all images to container registry.
# Usage: bash deploy/build.sh <registry> <tag>
# Example: bash deploy/build.sh ghcr.io/org main
# ================================================================
set -euo pipefail

REGISTRY="${1:-ghcr.io/org/aegisx}"
TAG="${2:-$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')}"

echo "=== AEGISX PRO Build ==="
echo "Registry: $REGISTRY"
echo "Tag:      $TAG"
echo ""

# ── Backend ───────────────────────────────────────
echo "[1/4] Building backend..."
docker build \
  --platform linux/amd64 \
  --target production \
  -t "$REGISTRY-backend:$TAG" \
  -t "$REGISTRY-backend:latest" \
  -f backend/Dockerfile \
  backend/

# ── Frontend ──────────────────────────────────────
echo "[2/4] Building frontend..."
docker build \
  --platform linux/amd64 \
  --target production \
  -t "$REGISTRY-frontend:$TAG" \
  -t "$REGISTRY-frontend:latest" \
  -f frontend/Dockerfile \
  frontend/

# ── Stream Processor (uses backend image) ─────────
echo "[3/4] Tagging stream processor..."
docker tag "$REGISTRY-backend:$TAG" "$REGISTRY-stream-processor:$TAG"
docker tag "$REGISTRY-backend:$TAG" "$REGISTRY-stream-processor:latest"

# ── Celery Worker (uses backend image) ────────────
echo "[4/4] Tagging celery..."
docker tag "$REGISTRY-backend:$TAG" "$REGISTRY-celery-worker:$TAG"
docker tag "$REGISTRY-backend:$TAG" "$REGISTRY-celery-worker:latest"

echo ""
echo "=== Build Complete ==="
echo ""
echo "Push with:"
echo "  docker push $REGISTRY-backend:$TAG"
echo "  docker push $REGISTRY-backend:latest"
echo "  docker push $REGISTRY-frontend:$TAG"
echo "  docker push $REGISTRY-frontend:latest"
echo "  docker push $REGISTRY-stream-processor:$TAG"
echo "  docker push $REGISTRY-celery-worker:$TAG"
echo ""
echo "Or push all:"
echo "  docker push -a $REGISTRY-backend"
echo "  docker push -a $REGISTRY-frontend"
