"""
AEGISX - API Dependencies
Authentication, authorization, tenant isolation, and common dependencies
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordBearer,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.security import decode_token

bearer_scheme = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login", auto_error=False)


# ── Tenant Context ───────────────────────────────────────────────

async def get_tenant_id(
    request: Request,
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> Optional[str]:
    """Extract tenant ID from header or request state."""
    tenant_id = x_tenant_id or getattr(request.state, "tenant_id", None)
    if tenant_id:
        try:
            uuid.UUID(tenant_id)
            return tenant_id
        except ValueError:
            pass
    return None


def require_tenant(
    tenant_id: Optional[str] = Depends(get_tenant_id),
) -> str:
    """Require a valid tenant ID for multi-tenant endpoints."""
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Tenant-ID header is required",
        )
    return tenant_id


# ── Authentication ──────────────────────────────────────────────

async def get_current_user_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Validate JWT or API key and return payload."""
    if x_api_key:
        from app.models import ApiKey
        from app.core.security import hash_api_key
        from sqlalchemy import select
        hashed = hash_api_key(x_api_key)
        result = await db.execute(
            select(ApiKey).where(
                ApiKey.key_hash == hashed,
                ApiKey.is_active == True,
            )
        )
        api_key_record = result.scalar_one_or_none()
        if not api_key_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
        if api_key_record.expires_at and api_key_record.expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
            )
        return {
            "sub": str(api_key_record.user_id),
            "type": "api_key",
            "tenant_id": str(api_key_record.tenant_id) if api_key_record.tenant_id else None,
            "roles": api_key_record.scopes or ["api"],
        }

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_type = payload.get("type")
    if token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload.get("jti")
    if jti and token_type == "access":
        from app.models import BlacklistedToken
        from sqlalchemy import select as _select
        result = await db.execute(
            _select(BlacklistedToken).where(BlacklistedToken.token_jti == jti)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return payload


async def get_current_user(
    payload: dict = Depends(get_current_user_token),
    tenant_id: Optional[str] = Depends(get_tenant_id),
) -> dict:
    """Return current authenticated user info."""
    token_tenant = payload.get("tenant_id")

    # Cross-tenant access check (super admins may have no tenant_id in token)
    if tenant_id and token_tenant and tenant_id != token_tenant:
        if "super_admin" not in payload.get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant access denied",
            )

    return {
        "user_id": payload.get("sub"),
        "tenant_id": tenant_id or token_tenant,
        "roles": payload.get("roles", []),
        "token_jti": payload.get("jti"),
    }


# ── Authorization ───────────────────────────────────────────────

class PermissionChecker:
    """Role and permission-based access control checker."""

    def __init__(
        self,
        required_roles: Optional[List[str]] = None,
        required_permissions: Optional[List[str]] = None,
        require_all: bool = True,
    ):
        self.required_roles = required_roles or []
        self.required_permissions = required_permissions or []
        self.require_all = require_all

    async def __call__(
        self,
        current_user: dict = Depends(get_current_user),
    ) -> dict:
        user_roles = current_user.get("roles", [])

        if "super_admin" in user_roles:
            return current_user

        if self.required_roles:
            if self.require_all:
                if not all(r in user_roles for r in self.required_roles):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Requires roles: {', '.join(self.required_roles)}",
                    )
            else:
                if not any(r in user_roles for r in self.required_roles):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Requires at least one role: {', '.join(self.required_roles)}",
                    )

        if self.required_permissions:
            # Permissions would be checked against DB role-permission mappings
            # For now, role-based check suffices as stub
            if not any(r in user_roles for r in self.required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions",
                )

        return current_user


# ── Common permission checkers ──────────────────────────────────

RequireSuperAdmin = PermissionChecker(required_roles=["super_admin"])
RequireTenantAdmin = PermissionChecker(required_roles=["super_admin", "tenant_admin"])
RequireSOCManager = PermissionChecker(required_roles=["super_admin", "tenant_admin", "soc_manager"])
RequireSOCAnalyst = PermissionChecker(required_roles=["super_admin", "tenant_admin", "soc_manager", "soc_analyst_l1", "soc_analyst_l2", "soc_analyst_l3"])
RequireIncidentResponder = PermissionChecker(required_roles=["super_admin", "tenant_admin", "soc_manager", "incident_responder"])
RequireThreatHunter = PermissionChecker(required_roles=["super_admin", "tenant_admin", "soc_manager", "threat_hunter"])
RequireAuditor = PermissionChecker(required_roles=["super_admin", "tenant_admin", "auditor", "compliance_officer"])
RequireComplianceOfficer = PermissionChecker(required_roles=["super_admin", "tenant_admin", "compliance_officer"])


# ── Pagination ──────────────────────────────────────────────────

class PaginationParams:
    def __init__(
        self,
        page: int = 1,
        page_size: int = 50,
        sort_by: Optional[str] = None,
        sort_order: str = "desc",
    ):
        self.page = max(1, page)
        self.page_size = min(max(1, page_size), 200)
        self.sort_by = sort_by
        self.sort_order = sort_order if sort_order in ("asc", "desc") else "desc"
        self.offset = (self.page - 1) * self.page_size

    def to_dict(self) -> dict:
        return {
            "page": self.page,
            "page_size": self.page_size,
            "offset": self.offset,
            "sort_by": self.sort_by,
            "sort_order": self.sort_order,
        }
