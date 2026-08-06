# AEGISX Architecture

## System Overview

AEGISX is an enterprise cybersecurity operations platform combining SIEM, SOAR, XDR, Vulnerability Management, Asset Management, Threat Intelligence, Compliance, and Incident Response into a unified multi-tenant platform.

```
┌──────────────────────────────────────────────────────────────────────┐
│                         AEGISX PLATFORM                              │
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐                │
│  │   Frontend   │  │   Backend   │  │    Agents     │               │
│  │  (React+Vite)│  │  (FastAPI)  │  │  (Win/Lin/Mac)│               │
│  └──────┬───────┘  └──────┬──────┘  └──────┬────────┘               │
│         │                 │                 │                        │
│         └──────────┬──────┴─────────────────┘                        │
│                    │                                                 │
│  ┌─────────────────┴──────────────────────────────┐                 │
│  │              NGINX Reverse Proxy                │                 │
│  └─────────────────┬──────────────────────────────┘                 │
│                    │                                                 │
│     ┌──────────────┼──────────────┬──────────────────┐              │
│     │              │              │                  │              │
│  ┌──▼───┐   ┌──────▼─────┐  ┌────▼────┐   ┌───────▼──────┐        │
│  │ API  │   │   Celery   │  │  Redis  │   │  PostgreSQL  │        │
│  │Svcs  │   │  Workers   │  │         │   │     15       │        │
│  └──────┘   └────────────┘  └─────────┘   └──────────────┘        │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐          │
│  │  OpenSearch  │  │   RabbitMQ   │  │ External APIs    │          │
│  │ (Log Index)  │  │  (Msg Bus)   │  │ (VT, MISP, CTI) │          │
│  └──────────────┘  └──────────────┘  └──────────────────┘          │
└──────────────────────────────────────────────────────────────────────┘
```

## Component Breakdown

### Backend (FastAPI + Python)

The backend is an async Python application built on FastAPI with SQLAlchemy 2.0 for database operations.

**Core Modules:**

| Module | Path | Purpose |
|--------|------|---------|
| API Routes | `app/api/v1/` | REST endpoints for all platform features |
| Core | `app/core/` | Configuration, security, database, caching, Celery |
| Models | `app/models/` | SQLAlchemy ORM models for all entities |
| Middleware | `app/middleware/` | CORS, tenant context, rate limiting, security headers |
| AI Services | `app/ai/` | AI-powered analysis, summarization, recommendations |
| Plugins | `app/plugins/` | Extensible integration framework |
| Tasks | `app/tasks/` | Background Celery tasks for async operations |

**API Structure (v1):**

| Prefix | Module | Description |
|--------|--------|-------------|
| `/auth` | `auth.py` | Login, MFA, WebAuthn, password management, API keys |
| `/tenants` | `tenants.py` | Tenant CRUD, usage tracking, audit logs |
| `/users` | `users.py` | User, role, department management |
| `/assets` | `assets.py` | Asset inventory, groups, discovery, agents, monitoring |
| `/incidents` | `incidents.py` | Incident lifecycle, timeline, notes, evidence, MITRE, playbooks |
| `/detection` | `detection.py` | Detection rules (Sigma, YARA, Suricata), alerts, IOCs, UEBA |
| `/vulnerabilities` | `vulnerabilities.py` | Vulnerability scans, CVE database, misconfigurations |
| `/compliance` | `compliance.py` | PCI DSS, SOC 2, ISO 27001, NIST CSF, HIPAA, GDPR frameworks |
| `/reports` | `reports.py` | Report generation, scheduling, statistical dashboards |
| `/ai` | `ai.py` | Incident summarization, root cause analysis, alert explanation |
| `/sso` | `sso.py` | SAML 2.0, OIDC, LDAP/AD, Microsoft Entra ID |
| `/soar` | `soar.py` | SOAR playbooks, workflow automation |
| `/threat-intel` | `threat_intel.py` | Threat feeds, indicators, intelligence sources |
| `/search` | `search.py` | Global search across all resources |
| `/audit` | `audit.py` | Audit log querying and compliance evidence |
| `/notifications` | `notifications.py` | Alert channels, user preferences |
| `/dashboards` | `dashboards.py` | Aggregated dashboard data |
| `/ws` | `websocket.py` | Real-time WebSocket event streaming |

### Frontend (React + TypeScript + Vite)

The frontend is a single-page application (SPA) built with React, TypeScript, Tailwind CSS, and Recharts for data visualization.

**Key libraries:** `react-router-dom`, `zustand` (state management), `lucide-react` (icons), `react-hot-toast` (notifications).

### Agent (Python)

Cross-platform lightweight agent deployed to endpoints for real-time monitoring.

| Component | Purpose |
|-----------|---------|
| `core/collector.py` | Data collection engine |
| `core/communication.py` | Secure communication with backend |
| `core/discovery/` | Asset and network discovery |
| `core/monitors/` | Process, file, network monitors |
| `platforms/windows/` | Windows-specific integrations (Event Log, WMI, Registry) |
| `platforms/linux/` | Linux-specific integrations (syslog, auditd, proc) |
| `platforms/macos/` | macOS-specific integrations |

### Infrastructure

| Service | Technology | Role |
|---------|-----------|------|
| API Gateway | Nginx | Reverse proxy, SSL termination, static file serving |
| Database | PostgreSQL 15 | Primary relational data store |
| Cache | Redis 7 | Rate limiting, session cache, Celery broker |
| Message Queue | RabbitMQ 3.12 | Event bus for async task distribution |
| Search/Logs | OpenSearch 2.x | Log indexing, full-text search, analytics |
| Task Worker | Celery | Background jobs (detection, scanning, reporting) |

## Data Flow

### Agent → Backend Flow

1. Agents register with the backend using a registration key
2. Agents send heartbeats every 60 seconds via HTTPS
3. Collected telemetry (events, logs, metrics) is batched and pushed to the API
4. Backend persists data in PostgreSQL and indexes in OpenSearch
5. Detection engine processes events against active detection rules
6. Alerts are generated when detection rules match

### API Request Flow

1. Client sends request through Nginx to FastAPI backend
2. Tenant context middleware extracts `X-Tenant-ID` header
3. Authentication validates JWT or API key
4. Authorization checks role-based permissions
5. Rate limiting middleware validates request quotas
6. Request handlers process the operation
7. Audit logs are created for state-changing operations
8. Response returns with security headers and correlation ID

## Multi-Tenant Architecture

AEGISX implements **row-level tenant isolation** (`TENANT_ISOLATION_MODE: "row"`) with support for schema-level and database-level isolation in production deployments.

**Key principles:**

- Every resource row carries a `tenant_id` foreign key to the `tenants` table
- All queries are scoped to the current tenant via `X-Tenant-ID` header
- JWT tokens embed `tenant_id` to prevent cross-tenant access
- Super admins can navigate across tenants; all other roles are tenant-bound
- Resource quotas are enforced per tenant (assets, users, storage)
- Audit logs capture all tenant operations for compliance

## Security Architecture

### Authentication

- **Primary:** JWT access + refresh token pair (HS256)
- **MFA:** TOTP (Time-based One-Time Password) with backup codes
- **WebAuthn:** FIDO2/Passkey support for passwordless authentication
- **API Keys:** SHA-256 hashed keys for service-to-service auth
- **SSO:** SAML 2.0, OIDC, LDAP/AD, Microsoft Entra ID integration

### Authorization (RBAC)

| Role | Access Level |
|------|-------------|
| `super_admin` | Platform-wide, cross-tenant access |
| `tenant_admin` | Full tenant administration |
| `soc_manager` | SOC operations management |
| `soc_analyst_l1/l2/l3` | Tiered analyst access |
| `incident_responder` | Incident response operations |
| `threat_hunter` | Threat hunting and detection engineering |
| `compliance_officer` | Compliance assessment and auditing |
| `auditor` | Read-only audit access |

### Network Security

- CORS with configurable origins
- Trusted host middleware
- Security headers (HSTS, CSP, X-Frame-Options, XSS protection)
- Rate limiting (10 req/min for auth, 100 req/min for API)
- Request correlation IDs for traceability

### Cryptographic Security

- Password hashing: bcrypt with 12 rounds
- JWT signing: HS256
- API key hashing: SHA-256
- Data encryption: Fernet (symmetric) via `cryptography` library
- HMAC signatures for webhook verification
- Secure token generation via `secrets` module

## Deployment Options

### Docker Compose (Development)

Single-host deployment with all services containerized. See `docker-compose.yml` for the full service stack including PostgreSQL, Redis, OpenSearch, RabbitMQ, backend, frontend, Celery workers, and Nginx.

### Kubernetes (Production)

The `kubernetes/` directory contains Kustomize-based deployment manifests:

- `kubernetes/base/` — Core deployments and configurations
- `kubernetes/overlays/dev/` — Development overlay
- `kubernetes/overlays/prod/` — Production overlay

Key Kubernetes considerations:
- Horizontal Pod Autoscaling for API and Celery workers
- PersistentVolumeClaims for databases
- Secrets management via Kubernetes Secrets or external vault
- Ingress for TLS termination
- Network policies for inter-service communication
- Resource limits and requests on all pods

### Supported Topologies

1. **All-in-One:** All services on a single host (Docker Compose)
2. **Distributed:** Services split across multiple hosts/VMs
3. **Kubernetes:** Full cloud-native deployment
4. **Hybrid:** Backend in cloud, agents on-premises
