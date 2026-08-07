"""
AEGIS - Health Check Endpoints
"""
from fastapi import APIRouter, status
from pydantic import BaseModel, Field
from typing import Optional, Dict

from app.core.config import settings

router = APIRouter()


class HealthCheck(BaseModel):
    status: str = "healthy"
    app: str = settings.APP_NAME
    version: str = settings.APP_VERSION
    environment: str = settings.APP_ENV


class ServiceStatus(BaseModel):
    status: str
    message: Optional[str] = None


class ReadinessCheck(BaseModel):
    status: str
    database: ServiceStatus
    cache: ServiceStatus
    search: ServiceStatus
    kafka: ServiceStatus = Field(default_factory=lambda: ServiceStatus(status="disabled"))
    timescaledb: ServiceStatus = Field(default_factory=lambda: ServiceStatus(status="disabled"))
    minio: ServiceStatus = Field(default_factory=lambda: ServiceStatus(status="disabled"))
    clickhouse: ServiceStatus = Field(default_factory=lambda: ServiceStatus(status="disabled"))
    version: str = settings.APP_VERSION


@router.get(
    "/",
    response_model=HealthCheck,
    summary="Health Check",
    description="Basic health check endpoint",
)
async def health_check():
    return HealthCheck()


@router.get(
    "/ready",
    response_model=ReadinessCheck,
    summary="Readiness Check",
    description="Full readiness probe including database, cache, search, and infrastructure services",
)
async def readiness_check():
    from app.core.database import check_db_connection
    from app.core.cache import redis_client

    services = {}

    # â”€â”€ Database â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        if await check_db_connection():
            services["database"] = ServiceStatus(status="ok")
        else:
            services["database"] = ServiceStatus(status="unavailable", message="Connection failed")
    except Exception as e:
        services["database"] = ServiceStatus(status="unavailable", message=str(e)[:200])

    # â”€â”€ Redis Cache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        if redis_client:
            await redis_client.ping()
            services["cache"] = ServiceStatus(status="ok")
        else:
            services["cache"] = ServiceStatus(status="unavailable", message="Client not initialized")
    except Exception as e:
        services["cache"] = ServiceStatus(status="unavailable", message=str(e)[:200])

    # â”€â”€ OpenSearch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        from app.services.opensearch import get_search_service
        search = get_search_service()
        if search and search.client:
            search.client.info()
            services["search"] = ServiceStatus(status="ok")
        else:
            services["search"] = ServiceStatus(status="unavailable")
    except Exception as e:
        services["search"] = ServiceStatus(status="degraded", message=str(e)[:200])

    # â”€â”€ Kafka â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if settings.FEATURE_KAFKA:
        try:
            from app.services.kafka_messaging import kafka_service
            if kafka_service._admin_client:
                kafka_service._admin_client.list_topics(timeout=5)
                services["kafka"] = ServiceStatus(status="ok")
            else:
                services["kafka"] = ServiceStatus(status="unavailable", message="Not initialized")
        except Exception as e:
            services["kafka"] = ServiceStatus(status="degraded", message=str(e)[:200])
    else:
        services["kafka"] = ServiceStatus(status="disabled")

    # â”€â”€ TimescaleDB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        from app.core.database import async_session_factory
        from sqlalchemy import text
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"))
            services["timescaledb"] = ServiceStatus(status="ok")
    except Exception:
        services["timescaledb"] = ServiceStatus(status="disabled", message="TimescaleDB extension not available")

    # â”€â”€ MinIO â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        from app.services.minio_service import minio_service
        client = minio_service._get_client()
        if client:
            import asyncio
            found = await asyncio.get_event_loop().run_in_executor(None, client.bucket_exists, "AEGIS-evidence")
            services["minio"] = ServiceStatus(status="ok")
        else:
            services["minio"] = ServiceStatus(status="unavailable", message="Client not initialized")
    except Exception as e:
        services["minio"] = ServiceStatus(status="degraded", message=str(e)[:200])

    # â”€â”€ ClickHouse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if settings.FEATURE_CLICKHOUSE:
        try:
            from app.services.clickhouse_service import clickhouse_service
            await clickhouse_service._query("SELECT 1")
            services["clickhouse"] = ServiceStatus(status="ok")
        except Exception as e:
            services["clickhouse"] = ServiceStatus(status="degraded", message=str(e)[:200])
    else:
        services["clickhouse"] = ServiceStatus(status="disabled")

    # â”€â”€ Overall status â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    critical = ["database", "cache"]
    overall = "healthy"
    for name, svc in services.items():
        if name in critical and svc.status != "ok":
            overall = "unhealthy"
            break
        elif svc.status not in ("ok", "disabled"):
            overall = "degraded"

    return ReadinessCheck(status=overall, version=settings.APP_VERSION, **services)


@router.get(
    "/live",
    response_model=dict,
    summary="Liveness Check",
    description="Kubernetes liveness probe",
)
async def liveness_check():
    return {"status": "alive"}
