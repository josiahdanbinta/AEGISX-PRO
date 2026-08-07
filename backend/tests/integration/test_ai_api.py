"""
Integration tests for AEGIS AI API endpoints.
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


class TestAIHealth:
    @pytest.mark.asyncio
    async def test_health_check(self, client, auth_headers):
        res = await client.get("/api/v1/ai/health", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert "enabled" in data
        assert "model" in data
        assert "provider" in data


class TestAISummarize:
    @pytest.mark.asyncio
    async def test_summarize_incident(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/ai/incidents/{fake_id}/summarize", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestAIExplain:
    @pytest.mark.asyncio
    async def test_explain_alert(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/ai/alerts/{fake_id}/explain", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestAIClassify:
    @pytest.mark.asyncio
    async def test_classify_alert(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/ai/alerts/{fake_id}/classify", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestAIPrioritize:
    @pytest.mark.asyncio
    async def test_prioritize_incidents(self, client, auth_headers):
        res = await client.post("/api/v1/ai/incidents/prioritize", json={
            "incident_ids": [str(uuid.uuid4()), str(uuid.uuid4())],
        }, headers=auth_headers)
        assert res.status_code in [200, 503]


class TestAIAsk:
    @pytest.mark.asyncio
    async def test_ask_ai(self, client, auth_headers):
        res = await client.post("/api/v1/ai/ask", json={
            "question": "What is the current security posture?",
        }, headers=auth_headers)
        assert res.status_code in [200, 503]


class TestAIInsights:
    @pytest.mark.asyncio
    async def test_get_insights(self, client, auth_headers):
        res = await client.get("/api/v1/ai/insights", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestAIReport:
    @pytest.mark.asyncio
    async def test_generate_ai_report(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/ai/incidents/{fake_id}/report", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestAIUnauthorized:
    @pytest.mark.asyncio
    async def test_ai_health_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/ai/health")
            assert res.status_code in [401, 403]
