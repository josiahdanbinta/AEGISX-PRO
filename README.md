# AEGISX — Enterprise Cybersecurity Operations Platform

**AI-Powered SIEM + SOAR + XDR + Vulnerability Management + Compliance — All in One.**

[![Version](https://img.shields.io/badge/version-1.0.0-blue)]()
[![Tests](https://img.shields.io/badge/tests-530+-green)]()
[![API](https://img.shields.io/badge/endpoints-330+-blue)]()
[![Stubs](https://img.shields.io/badge/unimplemented-0-success)]()

---

## Quick Start (Docker)

```bash
git clone https://github.com/josiahdanbinta/AEGISX-PRO.git
cd AEGISX-PRO
cp .env.example backend/.env
docker-compose up -d
docker-compose exec backend python setup.py
```

Open **http://localhost:8080** — Login: `admin@aegisx.com` / `Admin123!@#`

---

## Table of Contents

1. [Installation](#installation)
   - [Docker (Recommended)](#docker-recommended)
   - [Native Windows](#native-windows)
   - [Native Linux](#native-linux)
   - [Native macOS](#native-macos)
2. [Kubernetes Deployment](#kubernetes-deployment)
3. [Agent Deployment](#agent-deployment)
4. [Platform Overview](#platform-overview)
5. [API Reference](#api-reference)
6. [Architecture](#architecture)
7. [Testing](#testing)
8. [Security](#security)

---

## Installation

### Docker (Recommended)

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/)

```bash
# 1. Clone
git clone https://github.com/josiahdanbinta/AEGISX-PRO.git
cd AEGISX-PRO

# 2. Configure
cp .env.example backend/.env
# Edit backend/.env and set SECRET_KEY + JWT_SECRET_KEY + AGENT_REGISTRATION_KEY

# 3. Start all services (PostgreSQL, Redis, OpenSearch, RabbitMQ, Backend, Celery, Frontend, Nginx)
docker-compose up -d

# 4. Initialize database (creates tenant, admin user, roles)
docker-compose exec backend python setup.py
```

**Access the platform:**

| Service | URL |
|---|---|
| Dashboard | http://localhost:8080 |
| API Docs | http://localhost:8080/docs |
| API Health | http://localhost:8001/health |
| Redis Insight | http://localhost:8001/api/v1/health/ready |

**Startup script (auto-detects your IP):**
```bash
# Windows
.\start.bat

# Linux / macOS
chmod +x start.sh && ./start.sh
```

---

### Native Windows

**Prerequisites:** [PostgreSQL 17](https://www.enterprisedb.com/downloads/postgresql-postgresql-downloads), Python 3.12+

```powershell
# 1. Install PostgreSQL
#    - Run installer as Administrator
#    - Set superuser password: aegisx
#    - Port: 5432

# 2. Create database
cd C:\Path\To\AEGISX-PRO
& "C:\Program Files\PostgreSQL\17\bin\createdb.exe" -U postgres aegisx
& "C:\Program Files\PostgreSQL\17\bin\psql.exe" -U postgres -c "CREATE USER aegisx WITH PASSWORD 'aegisx' SUPERUSER;"

# 3. Install backend dependencies
cd backend
pip install -r requirements.txt

# 4. Configure
cp ..\.env.example .env
# Edit .env — set SECRET_KEY, JWT_SECRET_KEY, AGENT_REGISTRATION_KEY
# Ensure POSTGRES_HOST=localhost, POSTGRES_PORT=5432

# 5. Initialize database
python setup.py

# 6. Start backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload

# 7. Start frontend (new terminal)
cd ..\frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

Open **http://192.168.2.34:5173** — Login: `admin@aegisx.com` / `Admin123!@#`

---

### Native Linux

**Prerequisites:** PostgreSQL 15+, Python 3.12+, Redis (optional)

```bash
# 1. Install PostgreSQL
sudo apt update
sudo apt install -y postgresql postgresql-client python3 python3-pip python3-venv

# 2. Create database
sudo -u postgres createdb aegisx
sudo -u postgres psql -c "CREATE USER aegisx WITH PASSWORD 'aegisx' SUPERUSER;"

# 3. Clone and setup
git clone https://github.com/josiahdanbinta/AEGISX-PRO.git
cd AEGISX-PRO/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env
# Edit .env with your keys

# 4. Initialize
python setup.py

# 5. Start
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

---

### Native macOS

```bash
# 1. Install PostgreSQL
brew install postgresql@17
brew services start postgresql@17
createdb aegisx
psql -c "CREATE USER aegisx WITH PASSWORD 'aegisx' SUPERUSER;"

# 2. Clone and setup (same as Linux above)
git clone https://github.com/josiahdanbinta/AEGISX-PRO.git
cd AEGISX-PRO/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env

# 3. Initialize and start
python setup.py
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

---

## Kubernetes Deployment

```bash
# Deploy with Helm
helm install aegisx ./kubernetes/helm/aegisx \
  --namespace aegisx --create-namespace \
  -f ./kubernetes/helm/aegisx/values-prod.yaml

# Development
helm install aegisx-dev ./kubernetes/helm/aegisx \
  --namespace aegisx-dev --create-namespace \
  -f ./kubernetes/helm/aegisx/values-dev.yaml
```

**Post-install:**
```bash
kubectl exec -it deployment/aegisx-backend -n aegisx -- python setup.py
```

---

## Agent Deployment

Deploy the AEGISX agent to monitor endpoints (Windows, Linux, macOS).

### One-Command Enrollment

**Windows (PowerShell):**
```powershell
.\deploy\install.ps1 -Server http://YOUR_SERVER:8001 -Key YOUR_REG_KEY -Tenant YOUR_TENANT_ID
```

**Windows (CMD):**
```cmd
deploy\install.cmd http://YOUR_SERVER:8001 YOUR_REG_KEY YOUR_TENANT_ID
```

**Linux / macOS:**
```bash
curl -sSL http://YOUR_SERVER:8001/deploy/install.sh | bash -s -- \
  --server http://YOUR_SERVER:8001 \
  --key YOUR_REG_KEY \
  --tenant YOUR_TENANT_ID
```

### What the Agent Does
- Collects hardware inventory (CPU, RAM, disks, BIOS, TPM, Secure Boot, serial numbers)
- Collects software inventory (installed apps, versions, certificates, browser extensions)
- Detects outdated applications with fix recommendations and download links
- Detects outdated/vulnerable services (SSH, Apache, Nginx, MySQL, Redis, etc.)
- Monitors running processes and services with risk assessment
- Detects ransomware activity (file extensions, ransom notes, shadow copy deletion)
- Real-time system metrics (CPU, memory, disk, network)

### Get Registration Key (Admin)
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://YOUR_SERVER:8001/api/v1/agent/registration-key
```

---

## Platform Overview

### Backend (21 API Routers — 330+ Endpoints)

| Router | Endpoints | Description |
|---|---|---|
| `auth` | 18 | Login, MFA, password reset, API keys, WebAuthn |
| `sso` | 12 | SAML, OIDC, LDAP, Microsoft Entra ID |
| `tenants` | 9 | Multi-tenant management (super admin) |
| `users` | 17 | User CRUD, roles, departments, sessions |
| `assets` | 25 | Asset management, discovery, monitoring |
| `incidents` | 30 | Full lifecycle, timeline, evidence, MITRE |
| `detection` | 25 | Sigma/YARA/IOC rules, alerts, anomaly detection |
| `soar` | 25 | Playbook CRUD, execution, integrations, 26 actions |
| `threat_intel` | 20 | 26 actors, 15 campaigns, 50 MITRE techniques |
| `vulnerabilities` | 30 | Scans, CVEs, misconfigurations, remediation |
| `compliance` | 22 | PCI DSS, SOC 2, ISO 27001, NIST, HIPAA, GDPR |
| `dashboards` | 22 | Executive, SOC, threat, asset, compliance dashboards |
| `reports` | 23 | PDF/CSV generation, scheduling, templates |
| `notifications` | 21 | Email, SMS, Slack, Teams, Discord, Telegram |
| `search` | 18 | Global search, natural language, suggestions |
| `audit` | 19 | Logs, exports, retention, sessions, analytics |
| `ai` | 12 | Summarization, root cause, recommendations, Q&A |
| `agent` | 7 | Registration, heartbeat, data push, commands |
| `websocket` | 4 | Live dashboard, alerts, agent channel |
| `health` | 3 | Liveness, readiness, health |

### Frontend (13 Pages)

| Page | Features |
|---|---|
| Executive Dashboard | Live KPIs, threat map, severity charts, AI insights |
| SOC Dashboard | Real-time alerts, analyst workload, SLA tracking |
| Assets | Full inventory, hardware/software details, tags |
| Asset Detail | 7 tabs: Overview, Hardware, Software, Services, Vulns, Alerts, Ransomware |
| Incidents | Lifecycle management, timeline, evidence, MITRE |
| Alerts | Triage, bulk actions, severity filters |
| Threat Intel | 5 tabs: Indicators, Feeds, Actors, Campaigns, MITRE |
| Vulnerabilities | CVE tracking, scans, exploitation status |
| Compliance | Framework assessments, control tracking, evidence |
| SOAR Playbooks | CRUD, templates, executions, integrations |
| Reports | Generate, schedule, templates, download |
| Users | Admin management, roles, departments |
| Settings | Profile, MFA, API keys, notifications |

### Desktop Agent (7 Collectors)

| Collector | Data |
|---|---|
| System | CPU, memory, disks, network, battery, uptime |
| Hardware | Motherboard, BIOS, RAM, GPU, USB, TPM, Secure Boot |
| Software | Installed apps, versions, certificates, extensions |
| Services | Running services with risk flags (crypto miners, outdated) |
| Processes | Running processes with port mapping, suspicious detection |
| Logs | System logs with real-time tail |
| Ransomware | File extension monitoring, ransom note detection, behavior analysis |

---

## API Reference

- **Interactive:** http://localhost:8001/docs (Swagger UI)
- **Standalone:** http://localhost:8001/redoc
- **Markdown:** [docs/api/api-reference.md](docs/api/api-reference.md)
- **Generate from code:** `cd docs/api && python generate_api_docs.py`

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AEGISX Platform                      │
├─────────────────────────────────────────────────────────┤
│  Frontend (React 18 + TS)   │   Backend (FastAPI)       │
│  TailwindCSS + Framer Motion│   Python 3.12 + async     │
│  13 pages, dark/light theme │   21 routers, 330+ routes │
├─────────────────────────────┼───────────────────────────┤
│  Celery Workers             │   Desktop Agent           │
│  8 queues, scheduled tasks  │   7 collectors, 3 OS      │
├─────────────────────────────┴───────────────────────────┤
│              Infrastructure                             │
│  PostgreSQL │ Redis │ OpenSearch │ RabbitMQ │ Nginx     │
│  Docker Compose │ Kubernetes │ Helm                    │
└─────────────────────────────────────────────────────────┘
```

---

## Testing

**530+ tests across backend, frontend, and agent.**

```bash
# Backend (448 tests)
cd backend
pytest tests/ -v                     # All tests
pytest tests/unit/ -v                # Unit tests (models, security, config, deps)
pytest tests/integration/ -v         # Integration tests (API endpoints)
pytest tests/security/ -v            # Security tests
pytest tests/performance/ -v -m performance  # Load/performance tests

# Frontend (39 tests)
cd frontend
npm test                             # Vitest runner
npm run test:coverage                # With coverage

# Agent (39 tests)
cd agent
pytest tests/ -v
```

---

## Security

| Feature | Implementation |
|---|---|
| Password Hashing | bcrypt (12 rounds) |
| JWT Tokens | HS256, jti, expiry, refresh rotation |
| MFA | TOTP + backup codes |
| Passkeys | WebAuthn |
| SSO | SAML 2.0, OIDC, LDAP/AD, Microsoft Entra ID |
| API Keys | SHA-256 hashing, scopes, expiration |
| Encryption | Fernet symmetric |
| RBAC | 12 roles with permission-based access |
| Multi-Tenant | Row-level isolation (TenantMixin on all models) |
| Audit Trail | Every mutation logged with user, IP, resource |
| Rate Limiting | Per-IP, per-endpoint configurable |
| Security Headers | CSP, HSTS, X-Frame-Options, XSS protection |
| SQL Injection | Parameterized queries (SQLAlchemy ORM) |
| CSRF | Token-based (JWT in Authorization header) |

---

## Environment Variables

See [.env.example](.env.example) for all 152 configurable options. Key variables:

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | App encryption key (64+ chars) |
| `JWT_SECRET_KEY` | Yes | JWT signing key (64+ chars) |
| `AGENT_REGISTRATION_KEY` | Yes | Agent enrollment key |
| `POSTGRES_HOST` | Yes | PostgreSQL host |
| `POSTGRES_PASSWORD` | Yes | PostgreSQL password |
| `AI_ENABLED` | No | Enable AI features (requires OpenAI key) |
| `OPENAI_API_KEY` | No | OpenAI API key for AI features |

---

## Project Stats

| Metric | Count |
|---|---|
| Total Files | 241 |
| API Routers | 21 |
| API Endpoints | 330+ |
| Database Models | 30 |
| Frontend Pages | 13 |
| UI Components | 18 |
| Agent Collectors | 7 |
| Test Methods | 530+ |
| Docker Services | 9 |
| Helm Templates | 28 |
| Unimplemented Stubs | 0 |

---

## License

Proprietary. Contact sales@aegisx.com.

---

**Built for fintech. Ready for enterprise.**
