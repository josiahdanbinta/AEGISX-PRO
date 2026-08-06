import uuid

import pytest
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials

from app.api.deps import (
    get_tenant_id,
    require_tenant,
    get_current_user_token,
    get_current_user,
    PermissionChecker,
    RequireSuperAdmin,
    RequireTenantAdmin,
    RequireSOCAnalyst,
    RequireIncidentResponder,
    RequireThreatHunter,
    RequireAuditor,
    RequireComplianceOfficer,
    RequireSOCManager,
    PaginationParams,
)


class TestTenantDeps:
    @pytest.mark.asyncio
    async def test_get_tenant_id_valid(self):
        tid = str(uuid.uuid4())
        mock_request = Request(scope={"type": "http", "headers": []})
        result = await get_tenant_id(request=mock_request, x_tenant_id=tid)
        assert result == tid

    @pytest.mark.asyncio
    async def test_get_tenant_id_invalid_uuid(self):
        mock_request = Request(scope={"type": "http", "headers": []})
        result = await get_tenant_id(request=mock_request, x_tenant_id="not-a-uuid")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_tenant_id_missing(self):
        mock_request = Request(scope={"type": "http", "headers": []})
        result = await get_tenant_id(request=mock_request, x_tenant_id=None)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_tenant_id_from_request_state(self):
        tid = str(uuid.uuid4())
        mock_request = Request(scope={
            "type": "http",
            "headers": [],
            "state": {"tenant_id": tid},
        })
        mock_request.state.tenant_id = tid
        result = await get_tenant_id(request=mock_request, x_tenant_id=None)
        assert result == tid

    @pytest.mark.asyncio
    async def test_require_tenant_valid(self):
        tid = str(uuid.uuid4())
        result = require_tenant(tenant_id=tid)
        assert result == tid

    @pytest.mark.asyncio
    async def test_require_tenant_missing(self):
        with pytest.raises(HTTPException) as exc:
            require_tenant(tenant_id=None)
        assert exc.value.status_code == 400
        assert "X-Tenant-ID" in exc.value.detail


class TestAuthDeps:
    def _make_credentials(self, token: str):
        return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    @pytest.mark.asyncio
    async def test_get_current_user_token_no_auth(self):
        with pytest.raises(HTTPException) as exc:
            await get_current_user_token(credentials=None, x_api_key=None)
        assert exc.value.status_code == 401
        assert "Authentication required" in exc.value.detail

    @pytest.mark.asyncio
    async def test_get_current_user_token_invalid(self):
        with pytest.raises(HTTPException) as exc:
            await get_current_user_token(
                credentials=self._make_credentials("invalid.token.here"),
                x_api_key=None,
            )
        assert exc.value.status_code == 401
        assert "Invalid or expired" in exc.value.detail

    @pytest.mark.asyncio
    async def test_get_current_user_token_expired(self):
        from app.core.security import create_access_token
        from datetime import timedelta

        token = create_access_token(
            subject="test-user",
            tenant_id=str(uuid.uuid4()),
            roles=["soc_analyst_l1"],
            expires_delta=timedelta(seconds=-1),
        )
        with pytest.raises(HTTPException) as exc:
            await get_current_user_token(
                credentials=self._make_credentials(token),
                x_api_key=None,
            )
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_get_current_user_token_valid(self):
        from app.core.security import create_access_token

        uid = str(uuid.uuid4())
        token = create_access_token(
            subject=uid,
            tenant_id=str(uuid.uuid4()),
            roles=["soc_analyst_l1"],
        )
        payload = await get_current_user_token(
            credentials=self._make_credentials(token),
            x_api_key=None,
        )
        assert payload["sub"] == uid
        assert "soc_analyst_l1" in payload["roles"]
        assert payload["type"] == "access"

    @pytest.mark.asyncio
    async def test_get_current_user_token_wrong_type(self):
        from app.core.security import create_refresh_token

        token = create_refresh_token(
            subject="test-user",
            tenant_id=str(uuid.uuid4()),
        )
        with pytest.raises(HTTPException) as exc:
            await get_current_user_token(
                credentials=self._make_credentials(token),
                x_api_key=None,
            )
        assert exc.value.status_code == 401
        assert "Invalid token type" in exc.value.detail

    @pytest.mark.asyncio
    async def test_get_current_user_token_api_key(self):
        payload = await get_current_user_token(
            credentials=None,
            x_api_key="test-api-key-value",
        )
        assert payload["sub"] == "api_key"
        assert payload["type"] == "api_key"

    @pytest.mark.asyncio
    async def test_get_current_user_valid(self):
        from app.core.security import create_access_token

        uid = str(uuid.uuid4())
        tid = str(uuid.uuid4())
        token = create_access_token(
            subject=uid,
            tenant_id=tid,
            roles=["soc_analyst_l1"],
        )
        payload = await get_current_user_token(
            credentials=self._make_credentials(token),
            x_api_key=None,
        )
        user = await get_current_user(payload=payload, tenant_id=tid)
        assert user["user_id"] == uid
        assert user["tenant_id"] == tid
        assert "soc_analyst_l1" in user["roles"]

    @pytest.mark.asyncio
    async def test_get_current_user_with_header_tenant(self):
        from app.core.security import create_access_token

        uid = str(uuid.uuid4())
        tid = str(uuid.uuid4())
        token = create_access_token(
            subject=uid,
            tenant_id=tid,
            roles=["soc_analyst_l1"],
        )
        payload = await get_current_user_token(
            credentials=self._make_credentials(token),
            x_api_key=None,
        )
        user = await get_current_user(payload=payload, tenant_id=None)
        assert user["user_id"] == uid
        assert user["tenant_id"] == tid
        assert "soc_analyst_l1" in user["roles"]


class TestPermissionChecker:
    @pytest.mark.asyncio
    async def test_require_super_admin_allows(self):
        checker = PermissionChecker(required_roles=["super_admin"])
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["super_admin"],
        }
        result = await checker(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_require_super_admin_denies(self):
        checker = PermissionChecker(required_roles=["super_admin"])
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["soc_analyst_l1"],
        }
        with pytest.raises(HTTPException) as exc:
            await checker(current_user=user)
        assert exc.value.status_code == 403
        assert "super_admin" in exc.value.detail

    @pytest.mark.asyncio
    async def test_require_tenant_admin(self):
        checker = PermissionChecker(required_roles=["tenant_admin"])
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["tenant_admin"],
        }
        result = await checker(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_require_tenant_admin_denies(self):
        checker = PermissionChecker(required_roles=["tenant_admin"])
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["soc_analyst_l1"],
        }
        with pytest.raises(HTTPException) as exc:
            await checker(current_user=user)
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_require_soc_analyst(self):
        checker = PermissionChecker(required_roles=["soc_analyst_l1"])
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["soc_analyst_l1"],
        }
        result = await checker(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_require_soc_analyst_denies(self):
        checker = PermissionChecker(required_roles=["soc_analyst_l1"])
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["guest"],
        }
        with pytest.raises(HTTPException) as exc:
            await checker(current_user=user)
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_super_admin_bypasses_all_checks(self):
        checker = PermissionChecker(required_roles=["tenant_admin", "soc_manager"])
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["super_admin"],
        }
        result = await checker(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_require_all_roles_fails_when_missing_one(self):
        checker = PermissionChecker(
            required_roles=["soc_manager", "incident_responder"],
            require_all=True,
        )
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["soc_manager"],
        }
        with pytest.raises(HTTPException) as exc:
            await checker(current_user=user)
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_require_any_roles_succeeds_with_one(self):
        checker = PermissionChecker(
            required_roles=["soc_manager", "incident_responder"],
            require_all=False,
        )
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["soc_manager"],
        }
        result = await checker(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_require_any_roles_fails_with_none(self):
        checker = PermissionChecker(
            required_roles=["soc_manager", "incident_responder"],
            require_all=False,
        )
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["guest"],
        }
        with pytest.raises(HTTPException) as exc:
            await checker(current_user=user)
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_predefined_require_super_admin(self):
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["super_admin"],
        }
        result = await RequireSuperAdmin(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_predefined_require_tenant_admin_with_super_admin(self):
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["super_admin"],
        }
        result = await RequireTenantAdmin(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_predefined_require_soc_analyst(self):
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["soc_analyst_l1"],
        }
        result = await RequireSOCAnalyst(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_predefined_require_incident_responder(self):
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["incident_responder"],
        }
        result = await RequireIncidentResponder(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_predefined_require_threat_hunter(self):
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["threat_hunter"],
        }
        result = await RequireThreatHunter(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_predefined_require_auditor(self):
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["auditor"],
        }
        result = await RequireAuditor(current_user=user)
        assert result == user

    @pytest.mark.asyncio
    async def test_predefined_require_compliance_officer(self):
        user = {
            "user_id": "test-user",
            "tenant_id": str(uuid.uuid4()),
            "roles": ["compliance_officer"],
        }
        result = await RequireComplianceOfficer(current_user=user)
        assert result == user


class TestPaginationParams:
    def test_default_values(self):
        params = PaginationParams()
        assert params.page == 1
        assert params.page_size == 50
        assert params.offset == 0
        assert params.sort_by is None
        assert params.sort_order == "desc"

    def test_custom_values(self):
        params = PaginationParams(page=3, page_size=100, sort_by="name", sort_order="asc")
        assert params.page == 3
        assert params.page_size == 100
        assert params.offset == 200
        assert params.sort_by == "name"
        assert params.sort_order == "asc"

    def test_page_min_1(self):
        params = PaginationParams(page=0, page_size=50)
        assert params.page == 1
        params = PaginationParams(page=-5, page_size=50)
        assert params.page == 1

    def test_page_size_max_200(self):
        params = PaginationParams(page=1, page_size=500)
        assert params.page_size == 200
        params = PaginationParams(page=1, page_size=300)
        assert params.page_size == 200

    def test_page_size_min_1(self):
        params = PaginationParams(page=1, page_size=0)
        assert params.page_size == 1
        params = PaginationParams(page=1, page_size=-10)
        assert params.page_size == 1

    def test_offset_calculation(self):
        params = PaginationParams(page=1, page_size=20)
        assert params.offset == 0
        params = PaginationParams(page=5, page_size=20)
        assert params.offset == 80
        params = PaginationParams(page=10, page_size=100)
        assert params.offset == 900

    def test_sort_order_invalid_defaults_to_desc(self):
        params = PaginationParams(sort_order="invalid")
        assert params.sort_order == "desc"

    def test_to_dict(self):
        params = PaginationParams(page=2, page_size=25, sort_by="created_at")
        d = params.to_dict()
        assert d["page"] == 2
        assert d["page_size"] == 25
        assert d["offset"] == 25
        assert d["sort_by"] == "created_at"
        assert d["sort_order"] == "desc"
