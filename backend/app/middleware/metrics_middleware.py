"""
AEGIS - Prometheus HTTP Metrics Middleware
Auto-instruments all HTTP requests for count and duration tracking.
"""
import time
import re

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.services.metrics import METRICS

SKIP_PATHS = re.compile(r"/(metrics|health|docs|redoc|openapi\.json|debug)$")


class PrometheusHTTPMiddleware(BaseHTTPMiddleware):
    """Auto-instrument HTTP request counts and latencies via Prometheus metrics."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if SKIP_PATHS.search(request.url.path):
            return await call_next(request)

        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        handler = request.url.path
        method = request.method
        status_code = response.status_code

        try:
            counter = METRICS.get("http_requests_total")
            if counter:
                counter.labels(method=method, handler=handler, status=str(status_code)).inc()
        except Exception:
            pass

        try:
            histogram = METRICS.get("http_request_duration_seconds")
            if histogram:
                histogram.labels(method=method, handler=handler).observe(duration)
        except Exception:
            pass

        try:
            from app.services.metrics import METRICS as m
            gauge = m.get("AEGIS_db_connections_active")
            if gauge:
                from app.core.database import engine
                if engine and engine.pool:
                    gauge.set(engine.pool.size() - engine.pool.overflow())
        except Exception:
            pass

        return response
