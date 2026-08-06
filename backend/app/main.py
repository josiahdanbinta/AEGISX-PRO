"""
AEGISX - Main FastAPI Application Entry Point
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi

from app.core.config import settings
from app.core.database import close_db_connection
from app.core.exception_handlers import setup_exception_handlers
from app.middleware import setup_middleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup — auto-initialize database if empty."""
    print("AEGISX starting up...")
    
    # Auto-setup: create tables and admin user if database is empty
    try:
        from app.core.database import async_session_factory, engine
        from sqlalchemy import select, text
        from app.models.tenant import Tenant
        from app.models.base import Base
        
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        async with async_session_factory() as db:
            result = await db.execute(select(Tenant).limit(1))
            if not result.scalar_one_or_none():
                import uuid
                from app.core.security import hash_password
                from app.models.user import User, Role
                
                tenant_id = uuid.uuid4()
                db.add(Tenant(id=tenant_id, name="default", display_name="AEGISX Enterprise",
                              subscription_tier="enterprise", status="active",
                              quota_assets=10000, quota_users=1000, quota_storage_gb=500))
                await db.flush()
                
                admin = User(id=uuid.uuid4(), tenant_id=tenant_id, username="admin",
                             email="admin@aegisx.com", hashed_password=hash_password("Admin123!@#"),
                             full_name="Super Admin", roles=[{"role_name": "super_admin"}],
                             status="active", must_change_password=True)
                db.add(admin)
                
                roles_data = [
                    ("tenant_admin", "Tenant Administrator", ["users:*","roles:*","departments:*","audit:read"]),
                    ("soc_manager", "SOC Manager", ["incidents:*","alerts:*","detection:*","soar:*"]),
                    ("soc_analyst_l2", "SOC Analyst L2", ["incidents:*","alerts:*","detection:read"]),
                    ("soc_analyst_l1", "SOC Analyst L1", ["incidents:read","alerts:acknowledge"]),
                    ("threat_hunter", "Threat Hunter", ["threat_intel:*","detection:*"]),
                    ("incident_responder", "Incident Responder", ["incidents:*","soar:execute"]),
                    ("compliance_officer", "Compliance Officer", ["compliance:*","vulnerabilities:*"]),
                    ("auditor", "Auditor", ["audit:read","reports:read"]),
                ]
                for name, display, perms in roles_data:
                    db.add(Role(tenant_id=tenant_id, name=name, display_name=display, is_system=True, permissions=perms))
                
                await db.commit()
                print(f"\n{'='*60}")
                print(f"  AEGISX Auto-Setup Complete!")
                print(f"  Tenant ID: {tenant_id}")
                print(f"  Login: admin@aegisx.com / Admin123!@#")
                print(f"{'='*60}\n")
    except Exception as e:
        print(f"Auto-setup skipped (DB not available): {e}")

    yield
    print("AEGISX shutting down...")


def create_application() -> FastAPI:
    """Factory function to create the FastAPI application."""

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.APP_VERSION,
        description="""
## AEGISX - Enterprise Cybersecurity Operations Platform

A comprehensive, AI-powered cybersecurity platform combining SIEM, SOAR, XDR,
Vulnerability Management, Asset Management, Threat Intelligence, Compliance,
and Incident Response.

### Features
- **Multi-Tenant Architecture** with complete tenant isolation
- **Real-Time Asset Monitoring** across Windows, Linux, macOS, cloud, and network
- **Advanced Detection Engine** (Signature, Anomaly, Behavioral)
- **AI-Powered Analysis** for incident triage and investigation
- **SOAR Playbooks** with visual workflow builder
- **Threat Intelligence** integration with MISP, OpenCTI, VirusTotal
- **Compliance Management** for ISO 27001, NIST, PCI DSS, HIPAA, GDPR
- **Zero Trust Security** with RBAC, ABAC, MFA, and WebAuthn
        """,
        docs_url=None,
        redoc_url=None,
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
        lifespan=lifespan,
        contact={
            "name": "AEGISX Security Team",
            "email": "security@aegisx.com",
        },
        license_info={
            "name": "Proprietary",
            "url": "https://aegisx.com/license",
        },
    )

    setup_middleware(app)
    setup_exception_handlers(app)

    # ── API Routes ───────────────────────────────────────────────
    from app.api.v1.router import api_router
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # ── Health Check ─────────────────────────────────────────────
    from app.api.v1.health import router as health_router
    app.include_router(health_router, prefix="/health", tags=["Health"])

    # ── Root endpoint for Railway health check ────────────────────
    @app.get("/")
    async def root():
        return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}

    # ── Documentation Routes ─────────────────────────────────────
    @app.get("/docs", include_in_schema=False)
    async def swagger_ui_html():
        return get_swagger_ui_html(
            openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
            title=f"{settings.PROJECT_NAME} - API Documentation",
            swagger_favicon_url="/static/favicon.ico",
        )

    @app.get("/redoc", include_in_schema=False)
    async def redoc_html():
        return get_redoc_html(
            openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
            title=f"{settings.PROJECT_NAME} - API Reference",
            redoc_favicon_url="/static/favicon.ico",
        )

    # ── Custom OpenAPI Schema ────────────────────────────────────
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        openapi_schema = get_openapi(
            title=settings.PROJECT_NAME,
            version=settings.APP_VERSION,
            description=app.description,
            routes=app.routes,
        )
        openapi_schema["info"]["x-logo"] = {"url": "/static/logo.png"}
        openapi_schema["servers"] = [
            {"url": "/", "description": f"{settings.APP_ENV} server"},
        ]
        # Security schemes
        openapi_schema["components"]["securitySchemes"] = {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Enter your JWT access token",
            },
            "tenantHeader": {
                "type": "apiKey",
                "in": "header",
                "name": "X-Tenant-ID",
                "description": "Tenant identifier for multi-tenant isolation",
            },
            "apiKey": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "API Key for service-to-service authentication",
            },
        }
        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi

    return app


app = create_application()
