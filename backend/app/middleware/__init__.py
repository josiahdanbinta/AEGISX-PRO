"""
AEGISX - Middleware Stack
Security, rate limiting, tenant isolation, audit logging, CORS
"""
import time
import uuid
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
try:
    from starlette.middleware.sessions import SessionMiddleware
    HAS_SESSION_MIDDLEWARE = True
except ImportError:
    SessionMiddleware = None
    HAS_SESSION_MIDDLEWARE = False
from starlette.types import ASGIApp

from app.core.cache import rate_limit_check
from app.core.config import settings


class TenantContextMiddleware(BaseHTTPMiddleware):
    """Extract and validate tenant context from request headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        tenant_id = request.headers.get("X-Tenant-ID")
        if tenant_id:
            try:
                uuid.UUID(tenant_id)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid X-Tenant-ID format"},
                )
            request.state.tenant_id = tenant_id

        request.state.correlation_id = str(uuid.uuid4())
        request.state.request_start = time.time()

        response = await call_next(request)

        response.headers["X-Correlation-ID"] = request.state.correlation_id
        response.headers["X-Response-Time"] = f"{(time.time() - request.state.request_start):.4f}s"

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Global rate limiting middleware."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self._enabled = settings.RATE_LIMIT_ENABLED

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not self._enabled:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        if path.startswith(f"{settings.API_V1_PREFIX}/auth"):
            max_req, window = 10, 60
            key = f"rl:auth:{client_ip}"
        else:
            parts = [p for p in path.split("/") if p]
            max_req, window = 100, 60
            key = f"rl:{client_ip}:{':'.join(parts[:3])}"

        allowed, remaining = await rate_limit_check(key, max_req, window)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please try again later.",
                    "retry_after": window,
                },
                headers={"Retry-After": str(window)},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Limit"] = str(max_req)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if settings.APP_ENV == "development":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self' ws: wss:;"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self' ws: wss:;"
            )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

        return response


def setup_middleware(app: FastAPI) -> None:
    """Configure all middleware for the FastAPI application."""

    cors_origins = [str(origin) for origin in settings.BACKEND_CORS_ORIGINS]
    if not cors_origins and settings.APP_ENV == "production":
        cors_origins = []
    elif not cors_origins:
        cors_origins = ["http://localhost:3000", "http://localhost:5173", "http://localhost:5174", "http://localhost:8080"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True if cors_origins else False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Tenant-ID",
            "X-Correlation-ID",
            "X-Request-ID",
            "Accept",
            "Origin",
            "X-API-Key",
        ],
        expose_headers=[
            "X-Correlation-ID",
            "X-Response-Time",
            "X-RateLimit-Remaining",
            "X-RateLimit-Limit",
        ],
        max_age=600,
    )

    trusted_hosts_env = getattr(settings, 'TRUSTED_HOSTS', None)
    if trusted_hosts_env:
        import json as _json
        try:
            trusted_hosts = _json.loads(trusted_hosts_env) if isinstance(trusted_hosts_env, str) else trusted_hosts_env
        except (_json.JSONDecodeError, TypeError):
            trusted_hosts = [trusted_hosts_env]
        if trusted_hosts:
            app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)

    from app.middleware.request_logging import RequestLoggingMiddleware
    from app.middleware.metrics_middleware import PrometheusHTTPMiddleware

    app.add_middleware(PrometheusHTTPMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(TenantContextMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
