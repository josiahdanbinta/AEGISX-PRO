# AEGIS â€” Deployment Runbook

## Architecture Overview

```
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                     â”‚  NGINX   â”‚ TLS 1.3 + mTLS
                     â”‚  :80/443 â”‚
                     â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜
            â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
       â”Œâ”€â”€â”€â”€â–¼â”€â”€â”€â”€â”   â”Œâ”€â”€â”€â”€â–¼â”€â”€â”€â”€â”   â”Œâ”€â”€â”€â”€â–¼â”€â”€â”€â”€â”
       â”‚ Frontendâ”‚   â”‚ Backend â”‚   â”‚ Grafana â”‚
       â”‚ React   â”‚   â”‚ FastAPI â”‚   â”‚ :3000   â”‚
       â”‚ :5174   â”‚   â”‚ :8000   â”‚   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
       â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜   â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”˜
                          â”‚
    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
    â”‚                     â”‚                     â”‚
â”Œâ”€â”€â”€â–¼â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â–¼â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â–¼â”€â”€â”€â”
â”‚Kafka  â”‚ â”‚Redis  â”‚ â”‚Timescaleâ”‚ â”‚ClickHseâ”‚ â”‚MinIO â”‚
â”‚3-node â”‚ â”‚Cache  â”‚ â”‚DB PG15  â”‚ â”‚Analytx â”‚ â”‚Evidncâ”‚
â””â”€â”€â”€â”¬â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”˜
    â”‚
â”Œâ”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚Stream Proc   â”‚ â”‚Celery    â”‚ â”‚Flink   â”‚
â”‚(Normalize)   â”‚ â”‚Worker x4 â”‚ â”‚Jobs x5 â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â””â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Hardware Requirements

| Environment | CPU | RAM | Disk | Nodes |
|-------------|-----|-----|------|-------|
| **Development** | 8 cores | 16 GB | 100 GB SSD | 1 |
| **Staging** | 16 cores | 32 GB | 500 GB SSD | 3 |
| **Production** | 32+ cores | 64+ GB | 1 TB NVMe SSD | 6+ |

## Pre-Deployment Checklist

- [ ] All 8 REQUIRED secrets generated (64+ char, cryptographically random)
- [ ] TLS certificates generated: `bash docker/nginx/generate-mtls-certs.sh certs/`
- [ ] DNS configured for `AEGIS.example.com` â†’ load balancer IP
- [ ] SMTP relay configured (for password reset emails)
- [ ] Container registry access configured (ghcr.io or private)
- [ ] Slack app created (if using Slack bot)
- [ ] OpenAI API key (if using AI features)
- [ ] Kubernetes cluster >= 1.28 with:
  - [ ] Ingress controller (nginx-ingress)
  - [ ] cert-manager (for TLS auto-renewal)
  - [ ] Storage class for PV provisioning

## Option A: Docker Compose (single node)

```bash
# 1. Set secrets
cp .env.production .env
# Edit .env â€” replace all REQUIRED values

# 2. Generate TLS certs (optional)
bash docker/nginx/generate-mtls-certs.sh certs/

# 3. Build images
docker compose -f docker-compose.prod.yml build

# 4. Start
docker compose -f docker-compose.prod.yml up -d

# 5. Verify
curl http://localhost:8001/health

# 6. Initialize database
docker compose -f docker-compose.prod.yml exec backend python -c "
from app.core.database import engine, Base
from app.models import *
import asyncio
async def init():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
asyncio.run(init())
print('Database initialized')
"

# 7. Default login
# Email: admin@AEGIS.com
# Password: set via AEGIS_ADMIN_PASSWORD env var
```

## Option B: Kubernetes (multi-node)

```bash
# 1. Set secrets
export POSTGRES_PASSWORD="$(openssl rand -base64 32)"
export REDIS_PASSWORD="$(openssl rand -base64 32)"
export SECRET_KEY="$(openssl rand -base64 48)"
export JWT_SECRET_KEY="$(openssl rand -base64 48)"
export AGENT_REGISTRATION_KEY="$(openssl rand -base64 24)"
export MINIO_ROOT_PASSWORD="$(openssl rand -base64 32)"
export CLICKHOUSE_PASSWORD="$(openssl rand -base64 32)"
export GRAFANA_ADMIN_PASSWORD="$(openssl rand -base64 24)"
export OPENSEARCH_PASSWORD="$(openssl rand -base64 32)"

# 2. Deploy
bash deploy/k8s-deploy.sh AEGISduction

# 3. Verify all pods running
kubectl get pods -n AEGIS -w
# Should see: backend-xxx, kafka-0/1/2, timescaledb-0, clickhouse-0, minio-0, prometheus-0, grafana-xxx, jaeger-xxx

# 4. Port forward for local access
kubectl port-forward -n AEGIS svc/AEGIS-backend 8000:8000
kubectl port-forward -n AEGIS svc/AEGIS-grafana 3000:3000
kubectl port-forward -n AEGIS svc/AEGIS-jaeger-query 16686:16686

# 5. Health check
curl http://localhost:8000/health/live
curl http://localhost:8000/metrics  # Prometheus metrics
```

## Post-Deployment

1. **Change default admin password:**
   ```bash
   curl -X POST https://AEGIS.example.com/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@AEGIS.com","password":"Admin123!@#"}'
   # Use the JWT to call change-password endpoint
   ```

2. **Enable MFA for all admin accounts:**
   ```
   POST /api/v1/auth/mfa/setup â†’ scan QR â†’ POST /api/v1/auth/mfa/enable
   ```

3. **Configure threat intel feeds:**
   ```
   POST /api/v1/threat-intel/feeds â†’ add MISP, OpenCTI, VirusTotal keys
   ```

4. **Deploy agents to endpoints:**
   Navigate to `/deploy` in the web UI for OS-specific commands.

5. **Import detection rules:**
   ```bash
   # Mount Sigma/Falco rules via ConfigMap or copy to /etc/AEGIS/rules/
   kubectl create configmap AEGIS-rules --from-file=rules/ -n AEGIS
   ```

## Health Monitoring

| Service | Health Endpoint | Metrics |
|---------|----------------|---------|
| Backend | `/health/live` | `/metrics` |
| TimescaleDB | `pg_isready` | â€” |
| Redis | `redis-cli ping` | `/metrics` |
| Kafka | `kafka-broker-api-versions` | JMX |
| ClickHouse | `SELECT 1` | `/metrics` |
| MinIO | `/minio/health/live` | `/minio/v2/metrics/cluster` |
| Prometheus | `/-/healthy` | built-in |

## Rollback

```bash
# Docker
docker compose -f docker-compose.prod.yml down
docker compose -f docker-compose.prod.yml up -d  # restarts with same volumes

# Kubernetes
helm rollback AEGIS -n AEGIS
kubectl rollout undo deployment/AEGIS-backend -n AEGIS
```

## Disaster Recovery

1. **TimescaleDB:** WAL archives in `/backups/`. Restore with `pg_restore`.
2. **ClickHouse:** Backup tables with `clickhouse-client -q "SELECT * FROM {table}" > backup.tsv`.
3. **MinIO:** `mc mirror` to secondary cluster. Versioning protects against accidental deletion.
4. **Full backup script:** `POST /api/v1/backup/full` triggers all backup jobs.
