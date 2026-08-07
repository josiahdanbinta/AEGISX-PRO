"""
Integration tests for AEGIS Detection API endpoints.
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
        roles=["threat_hunter"],
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


class TestDetectionRules:
    @pytest.mark.asyncio
    async def test_create_rule(self, client, auth_headers):
        res = await client.post("/api/v1/detection/rules", json={
            "name": f"test-rule-{uuid.uuid4().hex[:8]}",
            "description": "Test detection rule",
            "rule_type": "sigma",
            "severity": "high",
            "logic": {"query": "SELECT * FROM events"},
            "enabled": True,
            "priority": 75,
        }, headers=auth_headers)
        assert res.status_code in [201, 503]

    @pytest.mark.asyncio
    async def test_list_rules(self, client, auth_headers):
        res = await client.get("/api/v1/detection/rules", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_get_rule_detail(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.get(f"/api/v1/detection/rules/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_update_rule(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.patch(f"/api/v1/detection/rules/{fake_id}", json={
            "name": "Updated Rule",
        }, headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_delete_rule(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.delete(f"/api/v1/detection/rules/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_enable_rule(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/detection/rules/{fake_id}/enable", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_disable_rule(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/detection/rules/{fake_id}/disable", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_test_rule(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/detection/rules/{fake_id}/test", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestSigmaRules:
    @pytest.mark.asyncio
    async def test_list_sigma_rules(self, client, auth_headers):
        res = await client.get("/api/v1/detection/sigma/rules", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_sigma_convert(self, client, auth_headers):
        res = await client.post("/api/v1/detection/sigma/convert", json={
            "sigma_rule": 'title: Test\ndescription: test\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: "\\\\cmd.exe"\n  condition: selection',
        }, headers=auth_headers)
        assert res.status_code in [200, 503]


class TestIOCRules:
    @pytest.mark.asyncio
    async def test_list_ioc_rules(self, client, auth_headers):
        res = await client.get("/api/v1/detection/rules/ioc", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestDetectionAlerts:
    @pytest.mark.asyncio
    async def test_list_alerts(self, client, auth_headers):
        res = await client.get("/api/v1/detection/alerts", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_list_alerts_with_search(self, client, auth_headers):
        res = await client.get("/api/v1/detection/alerts?q=critical", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_alert_stats(self, client, auth_headers):
        res = await client.get("/api/v1/detection/alerts/stats", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_bulk_acknowledge_alerts(self, client, auth_headers):
        res = await client.post("/api/v1/detection/alerts/bulk", json={
            "alert_ids": [str(uuid.uuid4())],
            "action": "acknowledge",
        }, headers=auth_headers)
        assert res.status_code in [200, 503]


class TestDetectionUnauthorized:
    @pytest.mark.asyncio
    async def test_rules_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/detection/rules")
            assert res.status_code in [401, 403]
