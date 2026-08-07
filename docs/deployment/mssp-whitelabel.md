# AEGIS â€” White-Label Configuration for MSSPs

Managed Security Service Providers can rebrand and resell AEGIS to their customers.

## Quick White-Label

```bash
helm install AEGIS ./kubernetes/helm/AEGIS \
  --namespace yourbrand-soc \
  --set config.appName="YourBrand SOC" \
  --set config.corsOrigins="https://soc.yourbrand.com" \
  --set global.imageRegistry="registry.yourbrand.com" \
  --set ingress.hosts[0].host="soc.yourbrand.com" \
  --set ingress.tls[0].hosts[0]="soc.yourbrand.com"
```

## Custom Branding

| Setting | Purpose |
|---------|---------|
| `config.appName` | Platform name shown in UI header and emails |
| `config.corsOrigins` | Customer-facing domain |
| `global.imageRegistry` | Your private container registry |
| `ingress.hosts` | Custom domain for each customer |
| `ingress.tls` | TLS certificates via cert-manager |

## Per-Customer Tenant Isolation

```bash
# Row-level (shared DB, filtered by tenant_id)
helm install customer-acme ./kubernetes/helm/AEGIS \
  --set config.tenantIsolationMode=row \
  --set config.appName="ACME Corp SOC"

# Schema-level (each customer gets their own DB schema)
helm install customer-acme ./kubernetes/helm/AEGIS \
  --set config.tenantIsolationMode=schema \
  --set config.appName="ACME Corp SOC"

# Database-level (fully isolated â€” recommended for regulated industries)
helm install customer-acme ./kubernetes/helm/AEGIS \
  --set config.tenantIsolationMode=database \
  --set timescaledb.postgresDb=acme_AEGIS \
  --set config.appName="ACME Corp SOC"
```

## Automated Customer Provisioning

```python
# Python script to provision a new tenant
import requests
import uuid

API_URL = "https://yourbrand-soc.com/api/v1"
API_KEY = "your-admin-api-key"

def provision_customer(company_name, admin_email, admin_password):
    # Create tenant
    tenant_id = str(uuid.uuid4())
    resp = requests.post(
        f"{API_URL}/tenants",
        json={
            "name": company_name.lower().replace(" ", "-"),
            "display_name": company_name,
            "subscription_tier": "enterprise",
            "quota_endpoints": 500,
            "quota_users": 50,
            "quota_storage_gb": 1000,
        },
        headers={"X-API-Key": API_KEY}
    )

    # Create admin user
    resp = requests.post(
        f"{API_URL}/users",
        json={
            "email": admin_email,
            "password": admin_password,
            "full_name": f"{company_name} Admin",
            "roles": ["tenant_admin", "soc_manager"],
            "tenant_id": tenant_id,
        },
        headers={"X-API-Key": API_KEY, "X-Tenant-ID": tenant_id}
    )

    return {"tenant_id": tenant_id, "admin_email": admin_email}

# Usage
provision_customer("ACME Corp", "soc@acme.com", "SecurePass123!")
```

## Usage Billing (Per-Tenant Metering)

```bash
# Get per-tenant usage stats
curl -H "X-API-Key: <key>" https://yourbrand-soc.com/api/v1/tenants/{tenant_id}/usage

# Response:
{
  "endpoint_count": 234,
  "event_volume_24h": 1245000,
  "storage_used_gb": 42.3,
  "alerts_24h": 87,
  "active_users": 12
}
```

## Reseller Portal

The Admin panel at `/admin/tenants` provides a self-service dashboard for:
- Creating/deleting tenant organizations
- Setting endpoint and storage quotas
- Viewing per-customer usage and billing
- Suspending/reactivating tenants
- Managing customer admin accounts
