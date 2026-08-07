"""
Integration tests for AEGIS WebSocket endpoint registration verification.
"""
import uuid

import pytest_asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest_asyncio.fixture(autouse=True)
def _patch_lifespan(monkeypatch):
    original = app.router.lifespan_context
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def safe_lifespan(app):
        try:
            async with original(app) as state:
                yield state
        except Exception:
            yield

    monkeypatch.setattr(app.router, "lifespan_context", safe_lifespan)


@pytest.fixture
def auth_headers():
    from app.core.security import create_access_token
    token = create_access_token(
        subject=str(uuid.uuid4()),
        tenant_id=str(uuid.uuid4()),
        roles=["super_admin"],
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": str(uuid.uuid4()),
    }


class TestWebSocketEndpointRegistration:
    """Verify that WebSocket endpoints are registered in the application router."""

    def test_websocket_routes_are_registered(self):
        ws_routes = []
        for route in app.routes:
            if hasattr(route, "methods") and "WEBSOCKET" in route.methods:
                ws_routes.append(route.path)
            elif hasattr(route, "method") and route.method == "WEBSOCKET":
                ws_routes.append(route.path)

        expected_paths = [
            "/api/v1/live/dashboard",
            "/api/v1/live/alerts",
            "/api/v1/live/agent/{agent_id}",
            "/api/v1/live/incidents/{incident_id}",
        ]
        for expected in expected_paths:
            assert expected in ws_routes, f"Expected WebSocket route {expected} not found"

    def test_websocket_route_count(self):
        ws_routes = []
        for route in app.routes:
            if hasattr(route, "methods") and "WEBSOCKET" in route.methods:
                ws_routes.append(route.path)
            elif hasattr(route, "method") and route.method == "WEBSOCKET":
                ws_routes.append(route.path)

        assert len(ws_routes) >= 4, f"Expected at least 4 WebSocket routes, found {len(ws_routes)}"

    def test_websocket_live_dashboard_route(self):
        found = False
        for route in app.routes:
            path = route.path if hasattr(route, "path") else getattr(route, "path", "")
            if "live/dashboard" in path and (
                (hasattr(route, "methods") and "WEBSOCKET" in route.methods) or
                (hasattr(route, "method") and route.method == "WEBSOCKET")
            ):
                found = True
                break
        assert found, "WebSocket live/dashboard route not registered"

    def test_websocket_live_alerts_route(self):
        found = False
        for route in app.routes:
            path = route.path if hasattr(route, "path") else getattr(route, "path", "")
            if "live/alerts" in path and (
                (hasattr(route, "methods") and "WEBSOCKET" in route.methods) or
                (hasattr(route, "method") and route.method == "WEBSOCKET")
            ):
                found = True
                break
        assert found, "WebSocket live/alerts route not registered"

    def test_websocket_connection_manager_exists(self):
        from app.api.v1.websocket import ConnectionManager
        assert ConnectionManager is not None
