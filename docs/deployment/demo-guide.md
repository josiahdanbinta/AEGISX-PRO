# AEGIS v2.0 - How to Demo & Sell

## Your Domain: joshwarescybertech.com

### Quick Setup for Your Domain

Point your domain's DNS to your server IP:
```
joshwarescybertech.com   A   <your-server-ip>
demo.joshwarescybertech.com   A   <your-server-ip>
```

Then update nginx config with your domain. Customers see `demo.joshwarescybertech.com` instead of an IP.

---

## How to Generate License Keys

```bash
# Trial key (14 days, full features)
python backend/app/core/license_key.py "ACME Corp" "soc@acme.com" --trial

# Paid license (1 year, 10 tenants, 500 endpoints)
python backend/app/core/license_key.py "ACME Corp" "soc@acme.com" --tenants 10 --endpoints 500 --days 365

# Output: AEGIS-a1b2c3d4e5f6g7h8-<base64payload>
```

The key is cryptographically signed. Customers paste it into their .env:
```bash
LICENSE_KEY=AEGIS-a1b2c3d4e5f6g7h8-<payload>
```

---

## Demo Playbook (15 minutes)

### Minute 1-3: The Problem
- "Your team uses 5-6 separate tools costing $400K+/year"
- "AEGIS replaces all of them in one platform"

### Minute 3-6: Live Dashboard
- Show the Agent Dashboard with hardware/software inventory
- Show the Real-Time Alert Dashboard (live WebSocket)
- Deploy an agent live with a one-liner command

### Minute 6-9: Detection & Response
- Show a detection rule firing in real-time
- Walk through the auto-containment flow (isolate endpoint)
- Show the AI remediation suggestions

### Minute 9-12: Threat Hunting & SOAR
- Open the Threat Hunting page, run a pre-built query
- Show the SOAR Playbook Builder (drag-drop 14 actions)
- Execute a playbook live

### Minute 12-15: Enterprise Features & Close
- Multi-tenant isolation (each SOC team separate)
- White-label capability (your company's logo on the UI)
- Pricing: $49/endpoint/month Professional, $99 Enterprise
- "You save 70% vs buying Splunk + CrowdStrike + XSOAR separately"

---

## Running a Customer Demo

### Option 1: Quick Docker Demo (local server)
```bash
bash deploy/demo-docker.sh acme-corp
# Output: URL, admin password, license key
# Share the URL with the customer
```

### Option 2: Kubernetes Demo (production-grade)
```bash
bash deploy/demo-provision.sh acme-corp
# Creates an isolated namespace with full isolation
```

### Option 3: SaaS Trial (multi-tenant)
- Customer signs up via your website
- Auto-provisioned as a tenant in your AEGIS instance
- Trial license auto-applied for 14 days

---

## What to Send Customers

After the demo, send this email:

```
Subject: Your AEGIS Trial - joshwarescybertech.com

Hi [Name],

Your AEGIS trial is ready:

URL:      https://[customer].demo.joshwarescybertech.com
Username: admin@[customer].demo
Password: [generated-password]
License:  [license-key]
Expires:  14 days

Quick start:
1. Login and go to Agents > Deploy Agent
2. Copy the enrollment command
3. Run it on any Windows/Linux/Mac endpoint
4. The agent appears in the dashboard with full inventory

Need help? Reply to this email.

Best,
Josiah Danbinta
joshwarescybertech.com
```

---

## Pricing to Quote

| Tier | Price | Best For |
|------|-------|----------|
| Professional | $49/endpoint/month | 50-500 endpoints |
| Enterprise | $99/endpoint/month | Unlimited, white-label, SSO |
| MSSP | Custom | Reselling to their customers |
