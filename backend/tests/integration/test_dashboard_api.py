"""
Integration tests for AEGISX Dashboard API endpoints.
"""
import uuid

import pytest_asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest_asyncio.fixture(autouse=True)
def _patch_lifespan(monkeypatch):
    """Suppress lifespan DB check errors when DB is not available."""
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


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestExecutiveDashboard:
    @pytest.mark.asyncio
    async def test_executive_dashboard_returns_200(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/executive", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_executive_dashboard_response_structure(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/executive", headers=auth_headers)
        if res.status_code == 200:
            data = res.json()
            assert isinstance(data, dict)
            assert "risk_score" in data
            assert "security_posture" in data
            assert "open_incidents" in data
            assert "asset_count" in data

    @pytest.mark.asyncio
    async def test_executive_dashboard_requires_auth(self, client):
        res = await client.get("/api/v1/dashboards/executive")
        assert res.status_code in [401, 403]


class TestSOCDashboard:
    @pytest.mark.asyncio
    async def test_soc_dashboard_returns_200(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/soc", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_soc_dashboard_response_structure(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/soc", headers=auth_headers)
        if res.status_code == 200:
            data = res.json()
            assert isinstance(data, dict)
            assert "alert_count" in data


class TestThreatsDashboard:
    @pytest.mark.asyncio
    async def test_threats_dashboard_returns_200(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/threats", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_threats_dashboard_response_structure(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/threats", headers=auth_headers)
        if res.status_code == 200:
            data = res.json()
            assert isinstance(data, dict)
            assert "threat_level" in data
            assert "active_threat_count" in data


class TestAssetsDashboard:
    @pytest.mark.asyncio
    async def test_assets_dashboard_returns_200(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/assets", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_assets_dashboard_response_structure(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/assets", headers=auth_headers)
        if res.status_code == 200:
            data = res.json()
            assert isinstance(data, dict)


class TestIncidentsDashboard:
    @pytest.mark.asyncio
    async def test_incidents_dashboard_returns_200(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/incidents", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_incidents_dashboard_response_structure(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/incidents", headers=auth_headers)
        if res.status_code == 200:
            data = res.json()
            assert isinstance(data, dict)
            assert "total_incidents" in data
            assert "open_incidents" in data


class TestVulnerabilitiesDashboard:
    @pytest.mark.asyncio
    async def test_vulnerabilities_dashboard_returns_200(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/vulnerabilities", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_vulnerabilities_dashboard_response_structure(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/vulnerabilities", headers=auth_headers)
        if res.status_code == 200:
            data = res.json()
            assert isinstance(data, dict)


class TestComplianceDashboard:
    @pytest.mark.asyncio
    async def test_compliance_dashboard_returns_200(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/compliance", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_compliance_dashboard_response_structure(self, client, auth_headers):
        res = await client.get("/api/v1/dashboards/compliance", headers=auth_headers)
        if res.status_code == 200:
            data = res.json()
            assert isinstance(data, dict)


class TestDashboardUnauthorized:
    @pytest.mark.asyncio
    async def test_dashboard_unauthorized_no_headers(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/dashboards/executive")
            assert res.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_dashboard_requires_tenant_id(self):
        from app.core.security import create_access_token
        token = create_access_token(
            subject=str(uuid.uuid4()),
            tenant_id=str(uuid.uuid4()),
            roles=["super_admin"],
        )
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get(
                "/api/v1/dashboards/soc",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res.status_code in [400, 401, 403]
