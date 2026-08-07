# 🛡️ AEGIS - Unified Security Operations Platform

> 💰 One platform. Open source. All 6 security tools unified.

AEGIS replaces Splunk, CrowdStrike, Palo Alto XSOAR, Tenable, ThreatConnect, and Wazuh in one open-core platform.

---

## 📊 What It Replaces

| Instead of buying... | You get... |
|----------------------|------------|
| Splunk Enterprise Security | SIEM - Log ingestion, correlation, alerting |
| CrowdStrike Falcon | XDR/EDR - Endpoint agents, osquery, falco rules |
| Palo Alto XSOAR | SOAR - 14-action playbook builder, auto-remediation |
| Tenable / Rapid7 | Vulnerability Management - CVE tracking, remediation |
| ThreatConnect / Anomali | Threat Intel - MISP, OpenCTI, VirusTotal, Shodan |
| Wazuh | Asset Inventory + Compliance - ISO 27001, PCI DSS, NIST |

💸 Estimated annual savings: $400K+ for a mid-market SOC team.

---

## 🚀 Quick Start

```bash
git clone https://github.com/josiahdanbinta/AEGIS.git
cd AEGIS
cp .env.example .env
# Edit .env with your secure values
docker compose up -d
```

🔗 Access:
- Frontend: http://localhost:5174
- API Docs: http://localhost:8001/docs
- Grafana: http://localhost:3000
- Default login: admin@joshwarescybertech.com / Admin123!@#

---

## 📦 Editions

| Feature | Community (Free) | Enterprise |
|---------|:---:|:---:|
| SIEM + Log Ingestion | ✅ | ✅ |
| XDR Agent + Osquery | ✅ | ✅ |
| SOAR Playbooks | 5 active | Unlimited |
| Vulnerability Management | ✅ | ✅ |
| Threat Intelligence | Basic | MISP + OpenCTI + VT + Shodan |
| Compliance Management | ✅ | ✅ |
| Multi-Tenant | 3 tenants | Unlimited |
| RBAC | 5 roles | 12 roles + custom |
| AI Auto-Remediation | ❌ | ✅ |
| Slack/Teams Bot | ❌ | ✅ |
| SOC Chat with AI | ❌ | ✅ |
| SSO (SAML/OIDC) | ❌ | ✅ |
| White-Label / MSSP | ❌ | ✅ |
| Support | Community | 24/7 SLA |
| License | AGPL v3 | Commercial |
| Price | Free | Contact us |

---

## 🏗️ Architecture

```
Agent -> Kafka (3-node) -> Flink Stream Processor -> Sigma + Falco Rules
                                |                           |
                         ClickHouse Analytics      UEBA Anomaly -> Alert
                                |                    |              |
                         TimescaleDB (hot)    Auto-Contain    AI Remediation
                                |                    |              |
                         MinIO (evidence)     Smart Notify     Slack Bot
                                |
                    Grafana Dashboards <- Prometheus Metrics
                                |
                    React SPA (SOC Workbench + Threat Hunting + Chat)
```

---

## 🔐 Enterprise Features

To unlock Enterprise features, set in your .env:

```bash
FEATURE_AI_REMEDIATION=true
FEATURE_SLACK_BOT=true
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
# Contact sales@joshwarescybertech.com for license key
```

---

## ☁️ Deployment Channels

| Channel | Best For |
|---------|----------|
| GitHub | Self-hosted Community Edition |
| Docker Compose | Single-node POC or Lab |
| Kubernetes (Helm) | Production multi-node |
| AWS Marketplace | AWS-native deployment |
| Azure Marketplace | Azure-native deployment |
| MSSP White-Label | Managed Security Service Providers |

---

## 🏢 For MSSPs (White-Label)

```bash
helm install aegis ./kubernetes/helm/aegis \
  --set config.appName="YourBrand SOC" \
  --set config.corsOrigins="https://yourbrand.com" \
  --set global.imageRegistry=your-registry.io \
  --namespace yourbrand-soc
```

Multi-tenant isolation modes: row | schema | database. Each client gets isolated data.

---

## 🤝 Contributing

AGPL v3. Community contributions welcome.

## 📜 License

- Community Edition: GNU AGPL v3 (LICENSE)
- Enterprise Edition: Commercial License (contact sales@joshwarescybertech.com)

---

Built by Josiah Danbinta | joshwarescybertech.com
