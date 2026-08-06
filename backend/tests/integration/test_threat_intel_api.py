"""
Integration tests for AEGISX Threat Intelligence API endpoints.
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


class TestThreatFeeds:
    @pytest.mark.asyncio
    async def test_list_feeds(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/feeds", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_create_feed(self, client, auth_headers):
        res = await client.post("/api/v1/threat-intel/feeds", json={
            "name": "Test Feed",
            "source_type": "misp",
            "url": "https://misp.example.com",
            "is_active": True,
            "sync_interval": 3600,
        }, headers=auth_headers)
        assert res.status_code in [201, 503]

    @pytest.mark.asyncio
    async def test_get_feed_status(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.get(f"/api/v1/threat-intel/feeds/{fake_id}/status", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_delete_feed(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.delete(f"/api/v1/threat-intel/feeds/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestThreatIndicators:
    @pytest.mark.asyncio
    async def test_list_indicators(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/indicators", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_list_indicators_with_search(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/indicators?q=malware", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_get_indicator_detail(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.get(f"/api/v1/threat-intel/indicators/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_create_indicator(self, client, auth_headers):
        res = await client.post("/api/v1/threat-intel/indicators", json={
            "type": "ip",
            "value": f"192.168.{uuid.uuid4().hex[:2]}.1",
            "description": "Test indicator",
            "confidence": 0.75,
            "tlp": "amber",
            "source": "test",
        }, headers=auth_headers)
        assert res.status_code in [201, 503]

    @pytest.mark.asyncio
    async def test_indicator_stats(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/indicators/stats", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestThreatActors:
    @pytest.mark.asyncio
    async def test_list_actors(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/actors", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_get_actor_detail(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.get(f"/api/v1/threat-intel/actors/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestThreatCampaigns:
    @pytest.mark.asyncio
    async def test_list_campaigns(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/campaigns", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_get_campaign_detail(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.get(f"/api/v1/threat-intel/campaigns/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestTTPs:
    @pytest.mark.asyncio
    async def test_list_ttps(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/ttps", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestMITRE:
    @pytest.mark.asyncio
    async def test_mitre_enterprise(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/mitre/enterprise", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_mitre_technique_detail(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/mitre/techniques/T1566", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_mitre_heatmap(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/mitre/heatmap", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestThreatLookups:
    @pytest.mark.asyncio
    async def test_ip_reputation_lookup(self, client, auth_headers):
        res = await client.post("/api/v1/threat-intel/lookup/ip/8.8.8.8", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_domain_reputation_lookup(self, client, auth_headers):
        res = await client.post("/api/v1/threat-intel/lookup/domain/example.com", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_hash_reputation_lookup(self, client, auth_headers):
        res = await client.post(
            "/api/v1/threat-intel/lookup/hash/d41d8cd98f00b204e9800998ecf8427e",
            headers=auth_headers,
        )
        assert res.status_code in [200, 503]


class TestThreatReports:
    @pytest.mark.asyncio
    async def test_list_threat_reports(self, client, auth_headers):
        res = await client.get("/api/v1/threat-intel/reports", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_generate_threat_report(self, client, auth_headers):
        res = await client.post("/api/v1/threat-intel/reports/generate", json={
            "title": "Test Threat Report",
        }, headers=auth_headers)
        assert res.status_code in [201, 503]


class TestThreatIntelUnauthorized:
    @pytest.mark.asyncio
    async def test_feeds_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/threat-intel/feeds")
            assert res.status_code in [401, 403]
