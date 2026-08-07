"""
AEGIS - Request Logging Middleware
Logs every API request to the immutable audit trail with body capture.
"""
import time
import json
import logging
from typing import Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import settings

logger = logging.getLogger("AEGIS.request")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every API request with metadata to audit trail."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.time()
        correlation_id = getattr(request.state, "correlation_id", None)
        tenant_id = getattr(request.state, "tenant_id", None)

        body: Optional[bytes] = None
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body = await request.body()
            except Exception:
                body = None

        response = await call_next(request)

        duration_ms = (time.time() - start) * 1000
        status_code = response.status_code

        log_entry = {
            "correlation_id": str(correlation_id) if correlation_id else None,
            "tenant_id": str(tenant_id) if tenant_id else None,
            "method": request.method,
            "path": request.url.path,
            "query_string": str(request.url.query) if request.url.query else None,
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent", ""),
            "status_code": status_code,
            "duration_ms": round(duration_ms, 2),
            "response_size": int(response.headers.get("content-length", 0)) or 0,
        }

        if body and len(body) <= 65536:
            try:
                log_entry["request_body"] = body.decode("utf-8", errors="replace")[:4096]
            except Exception:
                log_entry["request_body"] = f"[binary {len(body)} bytes]"

        logger.info(json.dumps(log_entry, default=str))

        try:
            from app.core.database import async_session_factory
            from app.models.audit import AuditLog
            if async_session_factory and status_code >= 400:
                async with async_session_factory() as db:
                    audit = AuditLog(
                        user_id=None,
                        action=f"{request.method} {request.url.path}",
                        resource_type="api_request",
                        resource_id=str(correlation_id),
                        details=log_entry,
                        ip_address=log_entry["client_ip"],
                        user_agent=log_entry["user_agent"],
                        correlation_id=str(correlation_id) if correlation_id else None,
                        success=status_code < 400,
                    )
                    db.add(audit)
                    await db.commit()
        except Exception:
            pass

        return response
