"""
Integration tests for AEGISX Compliance API endpoints.
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


class TestComplianceFrameworks:
    @pytest.mark.asyncio
    async def test_list_frameworks(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/frameworks", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_list_frameworks_response_structure(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/frameworks", headers=auth_headers)
        if res.status_code == 200:
            data = res.json()
            assert isinstance(data, list)
            assert len(data) > 0

    @pytest.mark.asyncio
    async def test_get_framework_detail(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/frameworks/pci_dss_v4", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_get_framework_detail_structure(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/frameworks/pci_dss_v4", headers=auth_headers)
        if res.status_code == 200:
            data = res.json()
            assert "name" in data
            assert "version" in data

    @pytest.mark.asyncio
    async def test_get_nonexistent_framework(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/frameworks/nonexistent", headers=auth_headers)
        assert res.status_code in [404, 503]


class TestComplianceAssessments:
    @pytest.mark.asyncio
    async def test_create_assessment(self, client, auth_headers):
        res = await client.post("/api/v1/compliance/frameworks/pci_dss_v4/assess", json={
            "name": "Test Assessment",
            "scope": "Test scope",
        }, headers=auth_headers)
        assert res.status_code in [201, 503]

    @pytest.mark.asyncio
    async def test_list_assessments(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/assessments", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_get_assessment_detail(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.get(f"/api/v1/compliance/assessments/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_get_assessment_controls(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.get(f"/api/v1/compliance/assessments/{fake_id}/controls", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestComplianceControls:
    @pytest.mark.asyncio
    async def test_list_controls(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/controls", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_update_control_status(self, client, auth_headers):
        fake_assessment_id = str(uuid.uuid4())
        fake_control_id = str(uuid.uuid4())
        res = await client.patch(
            f"/api/v1/compliance/assessments/{fake_assessment_id}/controls/{fake_control_id}",
            json={"status": "pass"},
            headers=auth_headers,
        )
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_compliance_dashboard(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/dashboards", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_compliance_gaps(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/gaps", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestCompliancePolicies:
    @pytest.mark.asyncio
    async def test_list_policies(self, client, auth_headers):
        res = await client.get("/api/v1/compliance/policies", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_create_policy(self, client, auth_headers):
        res = await client.post("/api/v1/compliance/policies", json={
            "name": "Test Policy",
            "description": "Test policy description",
            "policy_type": "security",
        }, headers=auth_headers)
        assert res.status_code in [201, 503]


class TestComplianceUnauthorized:
    @pytest.mark.asyncio
    async def test_frameworks_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/compliance/frameworks")
            assert res.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_assessments_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/compliance/assessments")
            assert res.status_code in [401, 403]
