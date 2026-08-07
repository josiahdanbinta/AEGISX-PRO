# AEGISX PRO — Unified Security Operations Platform

<p align="center">
  <img src="https://img.shields.io/badge/license-AGPL%20v3-blue" alt="License">
  <img src="https://img.shields.io/badge/python-3.12-blue" alt="Python">
  <img src="https://img.shields.io/badge/typescript-5.x-3178c6" alt="TypeScript">
  <img src="https://img.shields.io/badge/docker-ready-2496ed" alt="Docker">
  <img src="https://img.shields.io/badge/kubernetes-ready-326ce5" alt="Kubernetes">
</p>

> **One platform. $0 open source. All 6 security tools unified.**

AEGISX PRO replaces Splunk ($150K), CrowdStrike ($60K), Palo Alto XSOAR ($100K), Tenable ($40K), ThreatConnect ($50K), and Wazuh — all in one open-core platform.

---

## What It Replaces

| Instead of buying... | You get... |
|----------------------|------------|
| Splunk Enterprise Security → | **SIEM** — Log ingestion, correlation, alerting |
| CrowdStrike Falcon → | **XDR/EDR** — Endpoint agents, osquery, falco rules |
| Palo Alto XSOAR → | **SOAR** — 14-action playbook builder, auto-remediation |
| Tenable / Rapid7 → | **Vulnerability Mgmt** — CVE tracking, remediation fixes |
| ThreatConnect / Anomali → | **Threat Intel** — MISP, OpenCTI, VirusTotal, Shodan |
| Wazuh → | **Asset Inventory + Compliance** — ISO 27001, PCI DSS, NIST |

**Estimated savings: $400K+/year** for a mid-market SOC team.

---

## Quick Start

```bash
# Clone
git clone https://github.com/josiahdanbinta/AEGISX-PRO.git
cd AEGISX-PRO
docker compose up -d

# Set secrets
cp .env.example .env  # Edit all REQUIRED values

# Launch (Community Edition)
docker compose up -d

# Access
# Frontend:  http://localhost:5174
# API Docs:  http://localhost:8001/docs
# Grafana:   http://localhost:3000
# Default login: admin@aegisx.com / Admin123!@#
```

---

## Editions

| Feature | Community (Free) | Enterprise |
|---------|:---:|:---:|
| SIEM + Log Ingestion | Yes | Yes |
| XDR Agent + Osquery | Yes | Yes |
| SOAR Playbooks (5) | Yes | Unlimited |
| Vulnerability Mgmt | Yes | Yes |
| Threat Intel (basic) | Yes | MISP/OpenCTI/VT/Shodan |
| Compliance Mgmt | Yes | Yes |
| Multi-Tenant (3 tenants) | Yes | Unlimited |
| RBAC (5 roles) | Yes | 12 roles + custom |
| AI Auto-Remediation | No | Yes |
| Slack/Teams Bot | No | Yes |
| SOC Chat with AI | No | Yes |
| SSO (SAML/OIDC) | No | Yes |
| White-Label / MSSP | No | Yes |
| 24/7 Support SLA | Community | Enterprise |
| **License** | AGPL v3 | Commercial |
| **Price** | **Free** | Contact us |

---

## Architecture

```
Agent → Kafka(3-node) → Flink/Stream Processor → Sigma+Falco Rules
                            ↓                            ↓
                     ClickHouse Analytics    UEBA Anomaly → Alert
                            ↓                    ↓            ↓
                     TimescaleDB (hot)    Auto-Contain   AI Remediation
                            ↓                    ↓            ↓
                     MinIO (evidence)     Smart Notify   Slack Bot
                            ↓
                     Grafana Dashboards ← Prometheus Metrics
                            ↓
                     React SPA (SOC Workbench + Threat Hunting + Chat)
```

---

## Enterprise Features (Licensed)

To unlock Enterprise features, set in your `.env`:

```bash
FEATURE_AI_REMEDIATION=true
FEATURE_SLACK_BOT=true
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
# Contact enterprise@aegisx.com for license key
```

---

## Deployment Channels

| Channel | Best For |
|---------|----------|
| **GitHub** | Self-hosted Community Edition |
| **Docker Compose** | Single-node POC / Lab |
| **Kubernetes (Helm)** | Production multi-node |
| **AWS Marketplace** | AWS-native deployment |
| **Azure Marketplace** | Azure-native deployment |
| **MSSP White-Label** | Managed Security Service Providers |

---

## For MSSPs (White-Label)

```bash
# Deploy with your brand
helm install aegisx ./kubernetes/helm/aegisx \
  --set config.appName="YourBrand SOC" \
  --set config.corsOrigins="https://yourbrand.com" \
  --set global.imageRegistry=your-registry.io \
  --namespace yourbrand-soc
```

Multi-tenant isolation modes: `row` | `schema` | `database` — each client gets isolated data.

---

## Contributing

AGPL v3. Community contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Community Edition: **GNU AGPL v3** — [LICENSE](LICENSE)
Enterprise Edition: **Commercial License** — [Contact us](mailto:enterprise@aegisx.com)

---

**Built by [Josiah Danbinta](https://github.com/josiahdanbinta)** | **enterprise@aegisx.com**
