"""
AEGISX - Main FastAPI Application Entry Point
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles

from app.core.cache import init_cache, close_cache
from app.core.config import settings
from app.core.database import check_db_connection, close_db_connection
from app.core.exception_handlers import setup_exception_handlers
from app.middleware import setup_middleware


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle management."""
    try:
        await init_cache()
        db_ok = await check_db_connection()
        if not db_ok:
            print("WARNING: Database connection failed on startup")
    except Exception as e:
        print(f"WARNING: Service initialization error: {e}")

    yield

    try:
        await close_cache()
        await close_db_connection()
    except Exception as e:
        print(f"ERROR during shutdown: {e}")


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
