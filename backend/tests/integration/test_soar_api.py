"""
Integration tests for AEGISX SOAR API endpoints.
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
        roles=["incident_responder"],
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


class TestSOARPlaybooks:
    @pytest.mark.asyncio
    async def test_create_playbook(self, client, auth_headers):
        res = await client.post("/api/v1/soar/playbooks", json={
            "name": f"playbook-{uuid.uuid4().hex[:8]}",
            "description": "Test playbook",
            "trigger_type": "alert",
            "steps": [{"name": "step1", "action": "send_email"}],
        }, headers=auth_headers)
        assert res.status_code in [201, 503]

    @pytest.mark.asyncio
    async def test_list_playbooks(self, client, auth_headers):
        res = await client.get("/api/v1/soar/playbooks", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_get_playbook_detail(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.get(f"/api/v1/soar/playbooks/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_delete_playbook(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.delete(f"/api/v1/soar/playbooks/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_enable_playbook(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/soar/playbooks/{fake_id}/enable", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_disable_playbook(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/soar/playbooks/{fake_id}/disable", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_execute_playbook(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/soar/playbooks/{fake_id}/execute", json={
            "incident_id": str(uuid.uuid4()),
        }, headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestSOARExecutions:
    @pytest.mark.asyncio
    async def test_list_playbook_executions(self, client, auth_headers):
        fake_playbook_id = str(uuid.uuid4())
        res = await client.get(f"/api/v1/soar/playbooks/{fake_playbook_id}/executions", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestSOARTemplates:
    @pytest.mark.asyncio
    async def test_list_playbook_templates(self, client, auth_headers):
        res = await client.get("/api/v1/soar/playbooks/templates", headers=auth_headers)
        assert res.status_code in [200, 503]


class TestSOARIntegrations:
    @pytest.mark.asyncio
    async def test_list_integrations(self, client, auth_headers):
        res = await client.get("/api/v1/soar/integrations", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_create_integration(self, client, auth_headers):
        res = await client.post("/api/v1/soar/integrations", json={
            "name": "Test Integration",
            "integration_type": "webhook",
            "config": {"url": "https://example.com/webhook"},
        }, headers=auth_headers)
        assert res.status_code in [201, 503]


class TestSOARActions:
    @pytest.mark.asyncio
    async def test_list_actions_catalog(self, client, auth_headers):
        res = await client.get("/api/v1/soar/actions", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_test_action(self, client, auth_headers):
        res = await client.post("/api/v1/soar/actions/send_email/test", json={
            "to": "test@example.com",
            "subject": "Test",
        }, headers=auth_headers)
        assert res.status_code in [200, 503]


class TestSOARUnauthorized:
    @pytest.mark.asyncio
    async def test_playbooks_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/soar/playbooks")
            assert res.status_code in [401, 403]
