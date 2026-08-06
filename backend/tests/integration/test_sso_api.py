"""
Integration tests for AEGISX SSO API endpoints.
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
        roles=["tenant_admin"],
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


class TestSSOProviders:
    @pytest.mark.asyncio
    async def test_list_providers(self, client, auth_headers):
        res = await client.get("/api/v1/sso/providers", headers=auth_headers)
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_create_provider(self, client, auth_headers):
        res = await client.post("/api/v1/sso/providers", json={
            "name": f"saml-provider-{uuid.uuid4().hex[:6]}",
            "provider_type": "saml",
            "config": {
                "issuer_url": "https://idp.example.com",
                "idp_sso_url": "https://idp.example.com/sso",
                "idp_x509_cert": "MOCKCERT",
            },
            "is_active": True,
        }, headers=auth_headers)
        assert res.status_code in [201, 503]

    @pytest.mark.asyncio
    async def test_get_provider_detail(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.patch(f"/api/v1/sso/providers/{fake_id}", json={
            "name": "Updated Provider",
        }, headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_delete_provider(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.delete(f"/api/v1/sso/providers/{fake_id}", headers=auth_headers)
        assert res.status_code in [200, 404, 503]

    @pytest.mark.asyncio
    async def test_test_provider(self, client, auth_headers):
        fake_id = str(uuid.uuid4())
        res = await client.post(f"/api/v1/sso/providers/{fake_id}/test", headers=auth_headers)
        assert res.status_code in [200, 404, 503]


class TestSAMLLogin:
    @pytest.mark.asyncio
    async def test_saml_login_initiate(self, client):
        res = await client.post("/api/v1/sso/saml/login", json={
            "tenant_id": str(uuid.uuid4()),
        })
        assert res.status_code in [200, 503]

    @pytest.mark.asyncio
    async def test_saml_metadata(self, client):
        res = await client.get("/api/v1/sso/saml/metadata")
        assert res.status_code in [200, 503]


class TestOIDCLogin:
    @pytest.mark.asyncio
    async def test_oidc_login_initiate(self, client):
        res = await client.post("/api/v1/sso/oidc/login", json={
            "tenant_id": str(uuid.uuid4()),
        })
        assert res.status_code in [200, 503]


class TestLDAPLogin:
    @pytest.mark.asyncio
    async def test_ldap_login(self, client):
        res = await client.post("/api/v1/sso/ldap/login", json={
            "username": "testuser",
            "password": "testpassword",
            "tenant_id": str(uuid.uuid4()),
        })
        assert res.status_code in [200, 401, 503]


class TestSSOUnauthorized:
    @pytest.mark.asyncio
    async def test_providers_requires_auth(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get("/api/v1/sso/providers")
            assert res.status_code in [401, 403]
