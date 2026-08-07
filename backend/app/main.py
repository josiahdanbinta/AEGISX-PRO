"""
AEGIS - Main FastAPI Application Entry Point
"""
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Depends
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi

from app.core.config import settings
from app.core.database import close_db_connection
from app.core.exception_handlers import setup_exception_handlers
from app.middleware import setup_middleware
from app.api.deps import get_current_user
from app.services.metrics import setup_metrics, METRICS


async def _publish_dashboard_stats():
    """Background task: publish aggregate dashboard stats every 10 seconds."""
    import asyncio
    import uuid
    from sqlalchemy import select, func

    while True:
        try:
            await asyncio.sleep(10)
            from app.core.database import async_session_factory
            from app.models import Alert, Asset, Incident, Agent
            from app.services.event_bus import event_bus

            async with async_session_factory() as db:
                alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
                incidents = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
                assets = (await db.execute(select(func.count(Asset.id)))).scalar() or 0
                agents = (await db.execute(
                    select(func.count(Agent.id)).where(Agent.status == "online")
                )).scalar() or 0
                open_incidents = (await db.execute(
                    select(func.count(Incident.id)).where(
                        Incident.status.notin_(["closed", "resolved"])
                    )
                )).scalar() or 0
                await event_bus.dashboard_update({
                    "incidents_total": incidents,
                    "incidents_open": open_incidents,
                    "alerts_total": alerts,
                    "assets_total": assets,
                    "agents_online": agents,
                })
        except asyncio.CancelledError:
            break
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup â€” auto-initialize database, services, metrics, and telemetry."""
    import os
    
    # DUMP: Print all env vars containing PG, POSTGRES, DATABASE, RAILWAY
    for k, v in sorted(os.environ.items()):
        if any(x in k.upper() for x in ["PG", "POSTGRES", "DATABASE", "RAILWAY", "REDIS"]):
            v2 = v[:3] + "***" + v[-3:] if len(v) > 10 else v
            print(f"ENV|{k}={v2}")
    
    print(f"AEGIS starting... DB: {settings.DATABASE_URL and settings.DATABASE_URL[:30]}...")

    setup_metrics(app)

    # License validation
    if settings.LICENSE_KEY:
        try:
            from app.core.license_key import validate_license
            result = validate_license(settings.LICENSE_KEY)
            if result["valid"]:
                settings.LICENSE_VALID = True
                settings.LICENSE_CUSTOMER = result["customer"]
                settings.LICENSE_EXPIRES = result["expires_at"]
                settings.LICENSE_MAX_TENANTS = result["max_tenants"]
                settings.LICENSE_MAX_ENDPOINTS = result["max_endpoints"]
                settings.EDITION = "enterprise"
                settings.FEATURE_AI_REMEDIATION = True
                settings.FEATURE_SLACK_BOT = True
                days = (result["expires_at"] - __import__('time').time()) // 86400
                print(f"LICENSE: {result['customer']} (Enterprise, {days} days remaining)")
            else:
                print(f"LICENSE: INVALID - {result.get('error', 'unknown error')}")
        except Exception as e:
            print(f"LICENSE: Error validating - {e}")
    else:
        print(f"LICENSE: Community Edition (free)")
        settings.EDITION = "community"

    if settings.TRACING_ENABLED:
        try:
            from app.services.tracing import setup_tracing
            setup_tracing()
            print("Jaeger tracing enabled")
        except Exception as e:
            print(f"Tracing setup skipped: {e}")

    # â”€â”€ Kafka â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if settings.FEATURE_KAFKA:
        try:
            from app.services.kafka_messaging import kafka_service
            await kafka_service.initialize()
            print("Kafka service initialized")
        except Exception as e:
            print(f"Kafka init skipped: {e}")

    # â”€â”€ MinIO â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        from app.services.minio_service import minio_service
        await minio_service.ensure_buckets()
        print("MinIO service initialized")
    except Exception as e:
        print(f"MinIO init skipped: {e}")

    # â”€â”€ ClickHouse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if settings.FEATURE_CLICKHOUSE:
        try:
            from app.services.clickhouse_service import clickhouse_service
            await clickhouse_service.initialize()
            print("ClickHouse service initialized")
        except Exception as e:
            print(f"ClickHouse init skipped: {e}")

    # â”€â”€ TimescaleDB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        from app.services.timescale_service import initialize_timescaledb
        await initialize_timescaledb()
        print("TimescaleDB service initialized")
    except Exception as e:
        print(f"TimescaleDB init skipped: {e}")

    # â”€â”€ TimescaleDB Event Writer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        from app.services.timescale_persistence import tsdb_writer
        await tsdb_writer.start()
        print("TimescaleDB event writer started")
    except Exception as e:
        print(f"TSDB writer start skipped: {e}")

    # â”€â”€ Dashboard Stats Publisher (background task) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _dash_task = asyncio.create_task(_publish_dashboard_stats())
    app.state.dashboard_task = _dash_task

    # â”€â”€ Database auto-setup (create tables, seed admin) â”€â”€â”€â”€â”€â”€â”€
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
                import uuid as _uuid
                from app.core.security import hash_password
                from app.models.user import User, Role

                admin_email = os.getenv("AEGIS_ADMIN_EMAIL", "admin@AEGIS.com")
                admin_password = os.getenv("AEGIS_ADMIN_PASSWORD", "Admin123!@#")

                tid = _uuid.uuid4()
                db.add(Tenant(id=tid, name="default", display_name="AEGIS", subscription_tier="enterprise", status="active", quota_assets=10000, quota_users=1000))
                await db.flush()
                db.add(User(id=_uuid.uuid4(), tenant_id=tid, username="admin", email=admin_email, hashed_password=hash_password(admin_password), full_name="Super Admin", roles=[{"role_name":"super_admin"}], status="active"))
                for name, disp, p in [("tenant_admin","Tenant Admin",["users:*"]),("soc_manager","SOC Manager",["incidents:*"]),("soc_analyst_l1","Analyst L1",["incidents:read"]),("compliance_officer","Compliance",["compliance:*"])]:
                    db.add(Role(tenant_id=tid, name=name, display_name=disp, is_system=True, permissions=p))
                await db.commit()
                if settings.APP_ENV == "development":
                    print(f"SETUP COMPLETE â€” Login: {admin_email}")
    except Exception as e:
        print(f"DB setup skipped: {e}")

    yield

    # â”€â”€ Shutdown â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print("AEGIS shutting down...")
    if hasattr(app.state, "dashboard_task"):
        app.state.dashboard_task.cancel()
    try:
        from app.services.kafka_messaging import kafka_service
        kafka_service.flush()
    except Exception:
        pass
    try:
        from app.services.clickhouse_service import clickhouse_service
        await clickhouse_service.close()
    except Exception:
        pass
    try:
        from app.services.timescale_persistence import tsdb_writer
        await tsdb_writer.stop()
    except Exception:
        pass
    await close_db_connection()


def create_application() -> FastAPI:
    """Factory function to create the FastAPI application."""

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.APP_VERSION,
        description="""
## AEGIS - Enterprise Cybersecurity Operations Platform

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
            "name": "AEGIS Security Team",
            "email": "security@AEGIS.com",
        },
        license_info={
            "name": "Proprietary",
            "url": "https://AEGIS.com/license",
        },
    )

    setup_middleware(app)
    setup_exception_handlers(app)

    # â”€â”€ API Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    from app.api.v1.router import api_router
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    # â”€â”€ Prometheus Metrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics():
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        from fastapi.responses import Response
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # â”€â”€ Health Check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    from app.api.v1.health import router as health_router
    app.include_router(health_router, prefix="/health", tags=["Health"])

    # â”€â”€ Root endpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @app.get("/")
    async def root():
        return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION, "edition": settings.EDITION}

    @app.get("/license")
    async def license_info():
        return {
            "edition": settings.EDITION,
            "customer": settings.LICENSE_CUSTOMER,
            "valid": settings.LICENSE_VALID,
            "expires_at": settings.LICENSE_EXPIRES,
            "max_tenants": settings.LICENSE_MAX_TENANTS,
            "max_endpoints": settings.LICENSE_MAX_ENDPOINTS,
            "features": {
                "ai_remediation": settings.FEATURE_AI_REMEDIATION,
                "slack_bot": settings.FEATURE_SLACK_BOT,
                "kafka": settings.FEATURE_KAFKA,
                "ueba": settings.FEATURE_UEBA,
            }
        }

    @app.get("/debug", include_in_schema=False)
    async def debug(current_user: dict = Depends(get_current_user)):
        """Debug endpoint â€” shows configuration state. Requires authentication."""
        from app.core.config import settings as s
        url = s.DATABASE_URL or "NOT SET"
        masked = url.split("://")[0] + "://****" if "://" in url else url
        return {
            "database_url": masked,
            "redis_url": settings.REDIS_URL or "NOT SET",
            "kafka_brokers": settings.KAFKA_BOOTSTRAP_SERVERS,
            "minio_endpoint": settings.MINIO_ENDPOINT,
            "clickhouse_host": settings.CLICKHOUSE_HOST,
            "jaeger_host": settings.JAEGER_HOST,
            "features": {
                "kafka": settings.FEATURE_KAFKA,
                "clickhouse": settings.FEATURE_CLICKHOUSE,
                "ueba": settings.FEATURE_UEBA,
                "ai": settings.FEATURE_AI,
                "tracing": settings.TRACING_ENABLED,
            },
            "port": settings.PORT,
        }

    # â”€â”€ Documentation Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # â”€â”€ Custom OpenAPI Schema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
