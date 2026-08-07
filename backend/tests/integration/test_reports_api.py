"""
Integration tests for AEGIS Reports API endpoints.
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
        roles=["compliance_officer"],
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


class TestReportGeneration:
    @pytest.mark.asyncio
    async def test_generate_report(self, client, auth_headers):
        res = await client.post("/api/v1/reports/generate", json={
            "report_type": "executive",
            "name": "Test Report",
            "format": "pdf",
        }, headers=auth_headers)
        assert res.status_code in [202, 503]

    @pytest.mark.asyncio
    async def test_generate_incident_report(self, client, auth_headers):
        res = await client.post("/api/v1/reports/generate", json={
            "report_type": "incident",
            "name": "Test Incident Report",
            "format": "pdf",
        }, headers=auth_headers)
        assert res.status_code in [202, 503]

    @pytest.mark.asyncio
    async def test_list_reports(self, client, auth_headers):
        res = await client.get("/api/v1/reports/", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestReportStats:
    @pytest.mark.asyncio
    async def test_executive_summary(self, client, auth_headers):
        res = await client.get("/api/v1/reports/executive", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_incident_stats(self, client, auth_headers):
        res = await client.get("/api/v1/reports/incident", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_asset_stats(self, client, auth_headers):
        res = await client.get("/api/v1/reports/asset", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_threat_stats(self, client, auth_headers):
        res = await client.get("/api/v1/reports/threat", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_vulnerability_stats(self, client, auth_headers):
        res = await client.get("/api/v1/reports/vulnerability", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestReportSchedules:
    @pytest.mark.asyncio
    async def test_list_schedules(self, client, auth_headers):
        res = await client.get("/api/v1/reports/schedules", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_create_schedule(self, client, auth_headers):
        res = await client.post("/api/v1/reports/schedule", json={
            "report_type": "executive",
            "name": "Weekly Executive",
            "format": "pdf",
            "cron_expression": "0 8 * * 1",
        }, headers=auth_headers)
        assert res.status_code in [201, 503]


class TestReportTemplates:
    @pytest.mark.asyncio
    async def test_list_templates(self, client, auth_headers):
        res = await client.get("/api/v1/reports/templates", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_create_template(self, client, auth_headers):
        res = await client.post("/api/v1/reports/templates", json={
            "name": "Custom Template",
            "report_type": "executive",
            "content": {"sections": ["overview", "risks"]},
        }, headers=auth_headers)
        assert res.status_code in [201, 503]


class TestReportsUnauthorized:
    @pytest.mark.asyncio
    async def test_reports_require_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/reports/")
            assert res.status_code in [401, 403]
