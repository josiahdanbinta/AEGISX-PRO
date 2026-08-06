# AEGISX Deployment Guide

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Disk | 20 GB free | 100+ GB SSD |
| OS | Windows 10+ / Linux (Ubuntu 20.04+) / macOS 12+ |

### Required Software

- **Docker** 24.0+ and **Docker Compose** v2.x
- **Python** 3.11+ (for local dev and agent)
- **Node.js** 18+ and npm 9+ (for frontend dev)
- **Git** 2.40+

### Ports Used

| Service | Port | Purpose |
|---------|------|---------|
| Nginx | 80, 443 | Reverse proxy / SSL |
| Backend API | 8000 | FastAPI application |
| Frontend Dev | 3000 | Vite dev server |
| PostgreSQL | 5432 | Database |
| Redis | 6379 | Cache / broker |
| OpenSearch | 9200, 9600 | Search engine |
| RabbitMQ | 5672, 15672 | Message broker / management UI |

---

## Docker Compose Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/aegisx.git
cd aegisx
```

### 2. Configure Environment

Copy the example environment file and customize values:

```bash
cp .env.example backend/.env
```

Edit `backend/.env` with your configuration:

```ini
# Application
APP_NAME=AEGISX
APP_VERSION=1.0.0
APP_ENV=development
DEBUG=false
SECRET_KEY=your-64-char-random-secret-key-here-change-me

# Database
POSTGRES_USER=aegisx
POSTGRES_PASSWORD=your-secure-db-password
POSTGRES_DB=aegisx

# JWT Authentication
JWT_SECRET_KEY=your-strong-jwt-secret-key-change-me
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Agent Registration
AGENT_REGISTRATION_KEY=your-agent-secret-key-change-me
```

### 3. Start the Stack

```bash
docker compose up -d
```

This starts all services:
- PostgreSQL 15
- Redis 7
- OpenSearch 2.x
- RabbitMQ 3.12
- Backend API (FastAPI on port 8000)
- Frontend (Vite dev server on port 3000)
- Celery Worker + Celery Beat
- Nginx reverse proxy (port 80)

### 4. Initialize the Database

```bash
docker compose exec backend alembic upgrade head
```

### 5. Verify Installation

```bash
# Health check
curl http://localhost/health/

# API documentation
open http://localhost/docs

# Frontend dashboard
open http://localhost:3000
```

---

## Environment Variables Configuration

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Application master secret | 64-char random string |
| `JWT_SECRET_KEY` | JWT signing key | 32-char random string |
| `POSTGRES_PASSWORD` | Database password | `secure-password` |

### Database Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_HOST` | `localhost` | Database hostname |
| `POSTGRES_PORT` | `5432` | Database port |
| `POSTGRES_USER` | `aegisx` | Database user |
| `POSTGRES_PASSWORD` | `aegisx` | Database password |
| `POSTGRES_DB` | `aegisx` | Database name |
| `DATABASE_POOL_SIZE` | `20` | Connection pool size |
| `DATABASE_MAX_OVERFLOW` | `40` | Max overflow connections |

### Redis Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `localhost` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | (none) | Redis password |
| `REDIS_DB` | `0` | Redis database number |

### AI / LLM Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_ENABLED` | `true` | Enable AI features |
| `AI_PROVIDER` | `openai` | AI provider (openai / azure) |
| `AI_MODEL` | `gpt-4` | Model name |
| `OPENAI_API_KEY` | (none) | OpenAI API key |
| `AZURE_OPENAI_KEY` | (none) | Azure OpenAI key |
| `AZURE_OPENAI_ENDPOINT` | (none) | Azure endpoint URL |

### Threat Intelligence Integrations

| Variable | Description |
|----------|-------------|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |
| `SHODAN_API_KEY` | Shodan API key |
| `MISP_URL` | MISP instance URL |
| `MISP_API_KEY` | MISP API key |
| `OPENCTI_URL` | OpenCTI instance URL |
| `OPENCTI_API_KEY` | OpenCTI API key |

### Password Policy

| Variable | Default | Description |
|----------|---------|-------------|
| `PASSWORD_MIN_LENGTH` | `12` | Minimum password length |
| `PASSWORD_REQUIRE_UPPERCASE` | `true` | Require uppercase |
| `PASSWORD_REQUIRE_LOWERCASE` | `true` | Require lowercase |
| `PASSWORD_REQUIRE_DIGITS` | `true` | Require digits |
| `PASSWORD_REQUIRE_SPECIAL` | `true` | Require special chars |
| `PASSWORD_LOCKOUT_ATTEMPTS` | `5` | Max failed attempts |
| `PASSWORD_LOCKOUT_MINUTES` | `15` | Lockout duration |

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.27+ cluster
- `kubectl` configured for your cluster
- `kustomize` (built into `kubectl apply -k`)
- Ingress controller (nginx-ingress, Traefik, etc.)
- PersistentVolume provisioner for stateful services

### Directory Structure

```
kubernetes/
├── base/
│   ├── deployments.yaml     # Backend, Celery worker, Celery beat
│   ├── kustomization.yaml   # Base kustomization
│   └── services.yaml        # ClusterIP services
└── overlays/
    ├── dev/                 # Development overlay
    │   ├── kustomization.yaml
    │   └── patches/
    └── prod/                # Production overlay
        ├── kustomization.yaml
        └── patches/
```

### Quick Deploy

```bash
# Development
kubectl apply -k kubernetes/overlays/dev/

# Production
kubectl apply -k kubernetes/overlays/prod/
```

### External Services

For production Kubernetes, use managed services instead of in-cluster databases:

- **PostgreSQL:** AWS RDS / Azure Database for PostgreSQL / Cloud SQL
- **Redis:** AWS ElastiCache / Azure Cache for Redis / Memorystore
- **OpenSearch:** AWS OpenSearch Service / Azure AI Search
- **RabbitMQ:** AWS MQ / Azure Service Bus

Update environment variables to point to the managed services.

### Production Checklist

- [ ] Set all secrets in Kubernetes Secrets or external vault (HashiCorp Vault, AWS Secrets Manager)
- [ ] Enable TLS via cert-manager with Let's Encrypt
- [ ] Configure NetworkPolicy to restrict pod communication
- [ ] Set resource limits and requests on all deployments
- [ ] Enable HorizontalPodAutoscaler for backend (min 3, max 10)
- [ ] Configure PodDisruptionBudget for high availability
- [ ] Set up liveness, readiness, and startup probes
- [ ] Enable audit logging to external syslog/OpenSearch
- [ ] Configure node affinity and anti-affinity for resilience
- [ ] Enable Prometheus metrics scraping for monitoring
- [ ] Set `APP_ENV=production` and `DEBUG=false`

---

## Agent Deployment

The AEGISX agent collects telemetry from endpoints and sends it to the backend API.

### Installation

#### Windows

```powershell
# Via PowerShell installer
.\deploy\install.ps1 -ServerUrl "https://your-aegisx-server.com" -RegistrationKey "your-agent-key"
```

#### Linux

```bash
# Via bash installer
chmod +x deploy/install.sh
sudo ./deploy/install.sh --server-url "https://your-aegisx-server.com" --registration-key "your-agent-key"
```

#### macOS

```bash
# Same as Linux installer
chmod +x deploy/install.sh
sudo ./deploy/install.sh --server-url "https://your-aegisx-server.com" --registration-key "your-agent-key"
```

### Manual Setup

```bash
# Install dependencies
cd agent
pip install -r requirements.txt

# Configure
cp config.yaml.example config.yaml
# Edit config.yaml with your server URL and registration key

# Run agent
python agent.py --config config.yaml
```

### Agent Configuration (`agent/config.yaml`)

```yaml
server:
  url: https://your-aegisx-server.com
  registration_key: your-agent-key

agent:
  name: my-workstation
  heartbeat_interval: 60
  log_level: info

collection:
  processes: true
  network: true
  filesystem: true
  logs: true
  registry: true       # Windows only

monitoring:
  realtime: true
  file_integrity: true
  anomaly_detection: false
```

### Verification

Check the agent status in the AEGISX dashboard under **Assets → Agents**. Online agents show with a green status indicator. If an agent goes offline for more than 300 seconds (configurable via `AGENT_STALE_TIMEOUT`), it will be marked as offline.

---

## Getting System IP/Port Info for Dashboard

### Docker Compose (Local)

Access the dashboard at:

- **Frontend:** `http://localhost:3000`
- **API (direct):** `http://localhost:8000`
- **API (via Nginx):** `http://localhost/api/v1`
- **API Docs:** `http://localhost/docs`

### Finding Your IP on Windows

```powershell
# Get local IP address
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object IPAddress, InterfaceAlias

# Or simply:
ipconfig
```

### Finding Your IP on Linux/macOS

```bash
# Get local IP address
ip addr show | grep "inet " | grep -v 127.0.0.1
# or
ifconfig | grep "inet " | grep -v 127.0.0.1

# macOS
ifconfig en0 | grep "inet " | awk '{print $2}'
```

### Accessing from Other Machines

If backend and frontend are bound to `0.0.0.0`, you can access the dashboard from other machines on the network using the host machine's IP address:

```
http://<HOST-IP>:80/          # Dashboard via Nginx
http://<HOST-IP>:3000/        # Frontend dev server
http://<HOST-IP>:8000/        # Backend API directly
```

For production, always use a proper domain with TLS enabled via Nginx or a cloud load balancer.

---

## Troubleshooting

### Backend Won't Start

```bash
# Check logs
docker compose logs backend

# Common issues:
# 1. Database not ready - wait for postgres healthcheck
# 2. Port conflict - check if port 8000 is in use
# 3. Missing .env file - ensure backend/.env exists

# Verify database connectivity
docker compose exec postgres pg_isready -U aegisx
```

### Agent Won't Connect

```bash
# Verify agent configuration
cat agent/config.yaml

# Test API reachability
curl https://your-server.com/health/

# Check agent registration key matches backend config
grep AGENT_REGISTRATION_KEY backend/.env

# Check agent logs
tail -f agent/logs/agent.log
```

### Database Migration Issues

```bash
# View current migration state
docker compose exec backend alembic current

# View pending migrations
docker compose exec backend alembic history

# Generate new migration
docker compose exec backend alembic revision --autogenerate -m "description"

# Apply all pending migrations
docker compose exec backend alembic upgrade head
```

### Resetting the Environment

```bash
# Stop and remove everything
docker compose down -v

# Remove volumes (WARNING: deletes all data)
docker volume rm aegisx-postgres-data aegisx-redis-data aegisx-opensearch-data aegisx-rabbitmq-data

# Start fresh
docker compose up -d
docker compose exec backend alembic upgrade head
```
