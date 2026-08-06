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
    """Startup — discover PostgreSQL on Railway and auto-initialize."""
    import os, socket, asyncio
    from app.core.config import settings
    
    # Try to find Railway PostgreSQL
    db_url = settings.DATABASE_URL or ""
    if "localhost" in db_url or "aegisx:aegisx@" in db_url:
        # Try Railway internal PostgreSQL hosts
        candidate_hosts = [
            "postgres.railway.internal",
            "monorail.proxy.rlwy.net",
            os.environ.get("PGHOST", ""),
            os.environ.get("POSTGRES_HOST", ""),
        ]

        # Also try all environment variables that might contain a PostgreSQL URL
        for env_key in ["DATABASE_URL", "DATABASE_PUBLIC_URL"]:
            env_val = os.environ.get(env_key, "")
            if env_val and ("postgres" in env_val):
                candidate = env_val.replace("postgres://", "postgresql+asyncpg://").replace("postgresql://", "postgresql+asyncpg://")
                try:
                    import asyncpg
                    conn = await asyncpg.connect(candidate)
                    await conn.close()
                    settings.DATABASE_URL = candidate
                    print(f"✓ Found PostgreSQL via {env_key}")
                    break
                except Exception:
                    continue
        
        for host in candidate_hosts:
            if not host: continue
            try:
                # Test DNS resolution
                socket.gethostbyname(host)
                # Build URL with Railway's default credentials
                pg_user = os.environ.get("PGUSER", "postgres")
                pg_pass = os.environ.get("PGPASSWORD", "")
                pg_db = os.environ.get("PGDATABASE", "railway")
                pg_port = os.environ.get("PGPORT", "5432")
                candidate = f"postgresql+asyncpg://{pg_user}:{pg_pass}@{host}:{pg_port}/{pg_db}"
                
                # Test connection
                import asyncpg
                conn = await asyncpg.connect(candidate)
                await conn.close()
                
                settings.DATABASE_URL = candidate
                print(f"✓ Found PostgreSQL at {host}")
                break
            except Exception:
                continue
    
    print(f"AEGISX starting... DB: {'connected' if 'railway' in settings.DATABASE_URL else 'fallback'}")
    
    # Auto-setup if database is reachable
    try:
        from app.core.database import async_session_factory, engine
        from sqlalchemy import select
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
                
                tid = uuid.uuid4()
                db.add(Tenant(id=tid, name="default", display_name="AEGISX", subscription_tier="enterprise", status="active", quota_assets=10000, quota_users=1000))
                await db.flush()
                db.add(User(id=uuid.uuid4(), tenant_id=tid, username="admin", email="admin@aegisx.com", hashed_password=hash_password("Admin123!@#"), full_name="Super Admin", roles=[{"role_name":"super_admin"}], status="active"))
                for name, disp, p in [("tenant_admin","Tenant Admin",["users:*"]),("soc_manager","SOC Manager",["incidents:*"]),("soc_analyst_l1","SOC Analyst L1",["incidents:read"]),("compliance_officer","Compliance Officer",["compliance:*"])]:
                    db.add(Role(tenant_id=tid, name=name, display_name=disp, is_system=True, permissions=p))
                await db.commit()
                print(f"\n  SETUP COMPLETE — Login: admin@aegisx.com / Admin123!@#\n")
    except Exception as e:
        print(f"Auto-setup: {e}")

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

    @app.get("/debug")
    async def debug():
        """Debug endpoint — shows configuration state."""
        url = settings.DATABASE_URL or "NOT SET"
        masked = url.replace("://", "://****:****@") if "://" in url else url
        return {
            "database_url": masked,
            "database_url_raw_type": url.split("://")[0] if "://" in url else "none",
            "redis_url": settings.REDIS_URL or "NOT SET",
            "port": settings.PORT,
        }

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
