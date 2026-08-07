"""
AEGISX - API v1 Router
Safe imports — individual router failures don't crash the app.
"""
from fastapi import APIRouter

api_router = APIRouter()

_routers = [
    ("auth", "/auth", "Authentication"),
    ("tenants", "/tenants", "Tenants"),
    ("users", "/users", "Users"),
    ("assets", "/assets", "Assets"),
    ("incidents", "/incidents", "Incidents"),
    ("detection", "/detection", "Detection"),
    ("soar", "/soar", "SOAR"),
    ("threat_intel", "/threat-intel", "Threat Intelligence"),
    ("vulnerabilities", "/vulnerabilities", "Vulnerabilities"),
    ("dashboards", "/dashboards", "Dashboards"),
    ("compliance", "/compliance", "Compliance"),
    ("reports", "/reports", "Reports"),
    ("notifications", "/notifications", "Notifications"),
    ("search", "/search", "Search"),
    ("audit", "/audit", "Audit"),
    ("ai", "/ai", "AI"),
    ("sso", "/sso", "SSO"),
    ("websocket", "", "WebSocket"),
    ("agent", "/agent", "Agent"),
    ("ingestion", "/ingestion", "Ingestion"),
]

for name, prefix, tag in _routers:
    try:
        mod = __import__(f"app.api.v1.{name}", fromlist=["router"])
        api_router.include_router(mod.router, prefix=prefix, tags=[tag])
        if prefix and not prefix.endswith('/'):
            api_router.include_router(mod.router, prefix=prefix + '/', tags=[tag])
    except Exception as e:
        print(f"  ⚠ Router '{name}' failed to load: {e} — skipping")
