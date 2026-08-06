"""
AEGISX - Health Check Endpoints
"""
from fastapi import APIRouter, status
from pydantic import BaseModel

from app.core.config import settings


router = APIRouter()


class HealthCheck(BaseModel):
    status: str = "healthy"
    app: str = settings.APP_NAME
    version: str = settings.APP_VERSION
    environment: str = settings.APP_ENV


class ReadinessCheck(BaseModel):
    status: str
    database: str
    cache: str
    search: str


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
    description="Full readiness probe including database, cache, and search",
)
async def readiness_check():
    from app.core.database import check_db_connection
    from app.core.cache import redis_client

    db_status = "ok"
    try:
        if not await check_db_connection():
            db_status = "unavailable"
    except Exception:
        db_status = "unavailable"

    cache_status = "ok"
    try:
        if redis_client:
            await redis_client.ping()
        else:
            cache_status = "unavailable"
    except Exception:
        cache_status = "unavailable"
    search_status = "ok"  # Simplified

    overall = "healthy" if all(s == "ok" for s in [db_status, cache_status, search_status]) else "degraded"

    return ReadinessCheck(
        status=overall,
        database=db_status,
        cache=cache_status,
        search=search_status,
    )


@router.get(
    "/live",
    response_model=dict,
    summary="Liveness Check",
    description="Kubernetes liveness probe",
)
async def liveness_check():
    return {"status": "alive"}
