# AEGISX — Enterprise Cybersecurity Operations Platform

[![CI/CD](https://github.com/org/aegisx/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/org/aegisx/actions)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/org/aegisx/releases)
[![License](https://img.shields.io/badge/license-Proprietary-red)](LICENSE)

**AI-Powered SIEM + SOAR + XDR + Vulnerability Management + Compliance — All in One Platform.**

AEGISX combines security information and event management (SIEM), security orchestration automation and response (SOAR), extended detection and response (XDR), vulnerability management, asset management, threat intelligence, compliance management, and incident response into a single, scalable, cloud-native platform designed for enterprise SOCs, MSSPs, and fintech organizations.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AEGISX Platform                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │ Frontend │  │ Backend  │  │  Celery  │  │   Agent    │ │
│  │ React+TS │  │ FastAPI  │  │ Workers  │  │ Python 3   │ │
│  │ Tailwind │  │ Python   │  │          │  │ Win/Lin/Mac│ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘ │
│       │              │              │              │         │
│  ┌────┴──────────────┴──────────────┴──────────────┴──────┐ │
│  │              Infrastructure & Data Layer                │ │
│  │  PostgreSQL │ Redis │ OpenSearch │ RabbitMQ │ Nginx    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start (Docker)

```bash
# Clone the repository
git clone https://github.com/your-org/aegisx.git
cd aegisx

# Copy environment template
cp .env.example backend/.env

# Start all services
docker-compose up -d

# Initialize database
docker-compose exec backend alembic upgrade head

# Access the platform
# Dashboard: http://localhost:3000
# API Docs:  http://localhost:8000/docs
# Health:    http://localhost:8000/health
```

### Kubernetes Deployment

```bash
# Deploy with Helm
helm install aegisx ./kubernetes/helm/aegisx \
  --namespace aegisx --create-namespace \
  -f ./kubernetes/helm/aegisx/values.yaml

# Development environment
helm install aegisx-dev ./kubernetes/helm/aegisx \
  --namespace aegisx-dev --create-namespace \
  -f ./kubernetes/helm/aegisx/values-dev.yaml

# Production environment (6+ backend replicas, HPA, TLS)
helm install aegisx-prod ./kubernetes/helm/aegisx \
  --namespace aegisx-prod --create-namespace \
  -f ./kubernetes/helm/aegisx/values-prod.yaml \
  --set secrets.secretKey=$(openssl rand -hex 32) \
  --set secrets.jwtSecretKey=$(openssl rand -hex 32)
```

### Agent Deployment

```bash
# Linux / macOS
curl -sSL https://your-server.com/deploy/install.sh | bash -s -- \
  --server https://aegisx.company.com \
  --key YOUR_REGISTRATION_KEY \
  --tenant YOUR_TENANT_ID

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://your-server.com/deploy/install.ps1" -OutFile install.ps1
.\install.ps1 -Server "https://aegisx.company.com" -Key "YOUR_KEY" -Tenant "YOUR_TENANT"

# Docker
docker run -d --name aegisx-agent --restart always \
  -e AEGISX_SERVER=https://aegisx.company.com \
  -e AEGISX_KEY=YOUR_KEY \
  -e AEGISX_TENANT=YOUR_TENANT \
  ghcr.io/org/aegisx-agent:latest
```

---

## Features

### Security Operations
- **Real-time Asset Monitoring** — Windows, Linux, macOS, cloud, containers, network devices
- **Advanced Detection Engine** — Sigma, YARA, IOC matching, behavioral analytics, anomaly detection
- **Incident Management** — Full lifecycle with timeline, evidence, MITRE ATT&CK mapping, AI-powered root cause analysis
- **SOAR Playbooks** — Visual playbook builder with 26 built-in actions, templates, and approval workflows

### Compliance & Risk
- **PCI DSS v4.0** — 12 requirements, 60+ controls with automated assessments
- **SOC 2** — All 5 trust service criteria with evidence collection
- **ISO 27001:2022** — 14 domains, 40+ controls
- **NIST CSF 2.0** — Govern, Identify, Protect, Detect, Respond, Recover
- **HIPAA, GDPR, CIS Controls v8** — Built-in frameworks

### AI-Powered
- Incident summarization and root cause analysis
- Alert explanation and false positive classification
- Playbook recommendations
- Vulnerability fix suggestions
- Natural language Q&A over security data
- Automated report generation

### Enterprise Features
- **Multi-Tenant Architecture** — Row-level isolation, per-tenant quotas
- **SSO Integration** — SAML 2.0, OIDC, LDAP/Active Directory, Microsoft Entra ID
- **MFA & Passkeys** — TOTP, backup codes, WebAuthn
- **RBAC** — 12 granular roles with permission-based access control
- **Full Audit Trail** — Every action logged with CSV export and retention policies
- **API-First Design** — REST + WebSocket + GraphQL, OpenAPI documentation

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy 2.0 (async), Celery |
| **Frontend** | React 18, TypeScript, TailwindCSS, Framer Motion, Recharts |
| **Database** | PostgreSQL 15 (asyncpg), Alembic migrations |
| **Cache** | Redis 7 |
| **Search** | OpenSearch 2.14 (full-text search + log analytics) |
| **Queue** | RabbitMQ 3.12 / Celery |
| **Agent** | Python 3 (cross-platform), psutil, asyncio, WebSocket |
| **Infrastructure** | Docker, Docker Compose, Kubernetes (Helm), Nginx |
| **CI/CD** | GitHub Actions (lint, test, build, security scan) |
| **Security** | bcrypt (12 rounds), JWT HS256, Fernet encryption, HMAC, TLS 1.3 |

---

## Project Structure

```
aegisx/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── api/v1/         # 21 API routers (330+ endpoints)
│   │   ├── core/           # Config, DB, security, cache, celery
│   │   ├── models/         # 30 SQLAlchemy models
│   │   ├── services/       # Business logic services
│   │   ├── middleware/     # Auth, rate limiting, tenant isolation
│   │   ├── tasks/          # Celery tasks (8 modules)
│   │   ├── ai/             # AI/LLM services
│   │   └── plugins/        # Detection, SOAR, threat intel plugins
│   ├── tests/              # 448 test methods (unit + integration + performance)
│   └── alembic/            # Database migrations
├── frontend/               # React + TypeScript frontend
│   ├── src/
│   │   ├── pages/          # 13 pages (dashboard, incidents, alerts, etc.)
│   │   ├── components/     # 18 UI components (dual light/dark theme)
│   │   ├── stores/         # Zustand state management
│   │   ├── services/       # API client with auto-refresh
│   │   └── contexts/       # Auth + Theme providers
│   └── tests/              # 39 Vitest tests
├── agent/                  # Cross-platform desktop agent
│   ├── core/collectors/   # 7 collectors (system, hardware, software, etc.)
│   └── tests/              # 39 agent tests
├── deploy/                 # Agent deployment scripts
├── kubernetes/             # K8s manifests + Helm charts
├── docker/                 # Nginx configuration
├── docs/                   # Architecture, deployment, API reference
└── docker-compose.yml      # 9-service orchestration
```

---

## API Reference

Full API documentation is available:
- **Interactive**: `http://localhost:8000/docs` (Swagger UI)
- **Standalone**: `http://localhost:8000/redoc` (ReDoc)
- **PDF/Markdown**: [docs/api/api-reference.md](docs/api/api-reference.md)

Generate updated docs:
```bash
cd docs/api
python generate_api_docs.py --format both
```

---

## Testing

```bash
# Backend tests (448 methods)
cd backend
pytest tests/ -v

# Specific test categories
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/security/ -v
pytest tests/performance/ -v -m performance

# Frontend tests (39 methods)
cd frontend
npm test

# Agent tests (39 methods)
cd agent
pytest tests/ -v

# All tests (526 methods total)
# Run from project root
(cd backend && pytest tests/ -v) && (cd frontend && npm test) && (cd agent && pytest tests/ -v)
```

---

## Environment Variables

See [.env.example](.env.example) for all configuration options. Key variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | App encryption key | Required |
| `JWT_SECRET_KEY` | JWT signing key | Required |
| `POSTGRES_HOST` | PostgreSQL host | localhost |
| `REDIS_HOST` | Redis host | localhost |
| `AI_ENABLED` | Enable AI features | false |
| `AGENT_REGISTRATION_KEY` | Agent enrollment key | Required |

---

## Security

- **Zero Trust Architecture** — All endpoints authenticated, tenant-isolated
- **Encryption** — bcrypt for passwords, Fernet for data at rest, TLS 1.3 in transit
- **MFA** — TOTP + backup codes + WebAuthn passkeys
- **RBAC + ABAC** — 12 granular roles with permission checking
- **Audit Trail** — Every mutation logged with user, IP, and resource tracking
- **Rate Limiting** — Configurable per-endpoint rate limits
- **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture Guide](docs/architecture/README.md) | System design, data flow, component breakdown |
| [Deployment Guide](docs/deployment/README.md) | Docker, Kubernetes, agent deployment instructions |
| [API Reference](docs/api/api-reference.md) | Complete API documentation (370+ endpoints) |
| [Helm Charts](kubernetes/helm/aegisx/) | Production Kubernetes deployment |

---

## License

Proprietary. All rights reserved. Contact sales@aegisx.com for licensing.

---

**Built for fintech. Ready for enterprise.**
