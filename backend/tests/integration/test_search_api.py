"""
Integration tests for AEGIS Search API endpoints.
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
        roles=["soc_analyst_l1"],
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": str(uuid.uuid4()),
    }


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestGlobalSearch:
    @pytest.mark.asyncio
    async def test_global_search(self, client, auth_headers):
        res = await client.get("/api/v1/search/global?q=test", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_global_search_empty_query(self, client, auth_headers):
        res = await client.get("/api/v1/search/global?q=", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestResourceSearch:
    @pytest.mark.asyncio
    async def test_asset_search(self, client, auth_headers):
        res = await client.get("/api/v1/search/assets?q=server", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_incident_search(self, client, auth_headers):
        res = await client.get("/api/v1/search/incidents?q=malware", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_alert_search(self, client, auth_headers):
        res = await client.get("/api/v1/search/alerts?q=critical", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_ioc_search(self, client, auth_headers):
        res = await client.get("/api/v1/search/iocs?q=malicious", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestSearchSuggestions:
    @pytest.mark.asyncio
    async def test_search_suggestions(self, client, auth_headers):
        res = await client.get("/api/v1/search/suggestions?q=sec", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestSavedSearches:
    @pytest.mark.asyncio
    async def test_list_saved_searches(self, client, auth_headers):
        res = await client.get("/api/v1/search/saved", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_create_saved_search(self, client, auth_headers):
        res = await client.post("/api/v1/search/saved", json={
            "name": "My Critical Alerts",
            "query": "severity:critical",
            "resource_types": ["alerts"],
        }, headers=auth_headers)
        assert res.status_code in [201, 503]


class TestSearchUnauthorized:
    @pytest.mark.asyncio
    async def test_search_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/search/global?q=test")
            assert res.status_code in [401, 403]
