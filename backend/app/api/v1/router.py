"""
AEGISX - API v1 Router
Central router that includes all v1 endpoint routers
"""
from fastapi import APIRouter

from app.api.v1.auth import router as auth_router
from app.api.v1.tenants import router as tenants_router
from app.api.v1.users import router as users_router
from app.api.v1.assets import router as assets_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.detection import router as detection_router
from app.api.v1.soar import router as soar_router
from app.api.v1.threat_intel import router as threat_intel_router
from app.api.v1.vulnerabilities import router as vulnerabilities_router
from app.api.v1.dashboards import router as dashboards_router
from app.api.v1.compliance import router as compliance_router
from app.api.v1.reports import router as reports_router
from app.api.v1.notifications import router as notifications_router
from app.api.v1.search import router as search_router
from app.api.v1.audit import router as audit_router
from app.api.v1.ai import router as ai_router
from app.api.v1.sso import router as sso_router
from app.api.v1.websocket import router as websocket_router
from app.api.v1.agent import router as agent_router

api_router = APIRouter()

api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_router.include_router(tenants_router, prefix="/tenants", tags=["Tenants"])
api_router.include_router(users_router, prefix="/users", tags=["Users"])
api_router.include_router(assets_router, prefix="/assets", tags=["Assets"])
api_router.include_router(incidents_router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(detection_router, prefix="/detection", tags=["Detection"])
api_router.include_router(soar_router, prefix="/soar", tags=["SOAR"])
api_router.include_router(threat_intel_router, prefix="/threat-intel", tags=["Threat Intelligence"])
api_router.include_router(vulnerabilities_router, prefix="/vulnerabilities", tags=["Vulnerabilities"])
api_router.include_router(dashboards_router, prefix="/dashboards", tags=["Dashboards"])
api_router.include_router(compliance_router, prefix="/compliance", tags=["Compliance"])
api_router.include_router(reports_router, prefix="/reports", tags=["Reports"])
api_router.include_router(notifications_router, prefix="/notifications", tags=["Notifications"])
api_router.include_router(search_router, prefix="/search", tags=["Search"])
api_router.include_router(audit_router, prefix="/audit", tags=["Audit"])
api_router.include_router(ai_router, prefix="/ai", tags=["AI"])
api_router.include_router(sso_router, prefix="/sso", tags=["SSO"])
api_router.include_router(websocket_router, prefix="", tags=["WebSocket"])
api_router.include_router(agent_router, prefix="/agent", tags=["Agent"])
