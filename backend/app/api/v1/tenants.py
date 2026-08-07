"""
AEGIS - Tenant Management Endpoints (Super Admin)
"""
import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func, or_, and_, desc

from app.core.database import get_db
from app.models import Tenant, User, AuditLog

from app.api.deps import (
    PaginationParams,
    RequireSuperAdmin,
    get_current_user,
    require_tenant,
)

router = APIRouter()


async def _audit(
    db,
    *,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID,
    tenant_id: uuid.UUID,
    user_id: Optional[uuid.UUID] = None,
    details: Optional[dict] = None,
    severity: str = "info",
):
    entry = AuditLog(
        tenant_id=tenant_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        severity=severity,
    )
    db.add(entry)


# â”€â”€ Pydantic Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TenantCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Unique tenant identifier slug")
    display_name: Optional[str] = Field(None, max_length=255)
    domain: Optional[str] = Field(None, max_length=255)
    subscription_tier: str = Field("free", pattern=r"^(free|starter|professional|enterprise)$")
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = Field(None, max_length=50)
    quota_assets: int = Field(1000, ge=0)
    quota_users: int = Field(50, ge=0)
    quota_storage_gb: int = Field(10, ge=0)
    address: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class TenantUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    display_name: Optional[str] = Field(None, max_length=255)
    domain: Optional[str] = Field(None, max_length=255)
    subscription_tier: Optional[str] = Field(None, pattern=r"^(free|starter|professional|enterprise)$")
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = Field(None, max_length=50)
    quota_assets: Optional[int] = Field(None, ge=0)
    quota_users: Optional[int] = Field(None, ge=0)
    quota_storage_gb: Optional[int] = Field(None, ge=0)
    status: Optional[str] = Field(None, pattern=r"^(active|suspended|inactive|trial)$")
    settings: Optional[Dict[str, Any]] = None
    address: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


class TenantResponse(BaseModel):
    id: str
    name: str
    display_name: Optional[str] = None
    domain: Optional[str] = None
    subscription_tier: str
    status: str
    settings: Optional[Dict[str, Any]] = None
    quota_assets: int
    quota_users: int
    quota_storage_gb: int
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    address: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TenantUsageResponse(BaseModel):
    tenant_id: str
    tenant_name: str
    assets: Dict[str, int] = Field(default_factory=dict)
    users: Dict[str, int] = Field(default_factory=dict)
    storage: Dict[str, float] = Field(default_factory=dict)
    incidents: Dict[str, int] = Field(default_factory=dict)
    api_calls: Dict[str, int] = Field(default_factory=dict)


class TenantListResponse(BaseModel):
    items: List[TenantResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class TenantAuditLogEntry(BaseModel):
    id: str
    tenant_id: str
    action: str
    resource: str
    actor_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TenantAuditLogResponse(BaseModel):
    items: List[TenantAuditLogEntry]
    total: int
    page: int
    page_size: int
    total_pages: int


# â”€â”€ Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Tenant",
    dependencies=[Depends(RequireSuperAdmin)],
)
async def create_tenant(
    payload: TenantCreate,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_db),
):
    existing = (await db.execute(select(Tenant).where(Tenant.name == payload.name))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Tenant name already exists")

    t = Tenant(
        name=payload.name,
        display_name=payload.display_name,
        domain=payload.domain,
        subscription_tier=payload.subscription_tier,
        contact_email=payload.contact_email,
        contact_phone=payload.contact_phone,
        quota_assets=payload.quota_assets,
        quota_users=payload.quota_users,
        quota_storage_gb=payload.quota_storage_gb,
        address=payload.address,
        meta_data=payload.metadata,
    )
    db.add(t)
    await db.flush()

    await _audit(
        db,
        action="tenant.created",
        resource_type="tenant",
        resource_id=t.id,
        tenant_id=t.id,
        user_id=uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None,
        details={"name": payload.name},
    )

    return TenantResponse.model_validate(t)


@router.get(
    "/",
    response_model=TenantListResponse,
    summary="List All Tenants",
    dependencies=[Depends(RequireSuperAdmin)],
)
async def list_tenants(
    current_user: dict = Depends(get_current_user),
    pagination: PaginationParams = Depends(),
    search: Optional[str] = Query(None, description="Search by name or domain"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by tenant status"),
    tier_filter: Optional[str] = Query(None, alias="tier", description="Filter by subscription tier"),
    db = Depends(get_db),
):
    conditions = [Tenant.status != "deleted"]

    if status_filter:
        conditions.append(Tenant.status == status_filter)
    if tier_filter:
        conditions.append(Tenant.subscription_tier == tier_filter)
    if search:
        conditions.append(or_(Tenant.name.ilike(f"%{search}%"), Tenant.domain.ilike(f"%{search}%")))

    where_clause = and_(*conditions)

    count_q = select(func.count()).select_from(Tenant).where(where_clause)
    total = (await db.execute(count_q)).scalar()

    query = select(Tenant).where(where_clause).order_by(desc(Tenant.created_at)).offset(pagination.offset).limit(pagination.page_size)
    result = await db.execute(query)
    items = result.scalars().all()

    return TenantListResponse(
        items=[
            TenantResponse(
                id=str(row.id),
                name=row.name,
                display_name=row.display_name,
                domain=row.domain,
                subscription_tier=row.subscription_tier,
                status=row.status,
                settings=row.settings,
                quota_assets=row.quota_assets,
                quota_users=row.quota_users,
                quota_storage_gb=row.quota_storage_gb,
                contact_email=row.contact_email,
                contact_phone=row.contact_phone,
                address=row.address,
                metadata=row.meta_data,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in items
        ],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=max(1, math.ceil(total / pagination.page_size)) if total else 1,
    )


@router.get(
    "/{tenant_id}",
    response_model=TenantResponse,
    summary="Get Tenant Details",
    dependencies=[Depends(RequireSuperAdmin)],
)
async def get_tenant(
    tenant_id: str,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_db),
):
    t = (await db.execute(select(Tenant).where(Tenant.id == uuid.UUID(tenant_id)))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantResponse(
        id=str(t.id), name=t.name, display_name=t.display_name, domain=t.domain,
        subscription_tier=t.subscription_tier, status=t.status, settings=t.settings,
        quota_assets=t.quota_assets, quota_users=t.quota_users,
        quota_storage_gb=t.quota_storage_gb, contact_email=t.contact_email,
        contact_phone=t.contact_phone, address=t.address, metadata=t.meta_data,
        created_at=t.created_at, updated_at=t.updated_at,
    )


@router.patch(
    "/{tenant_id}",
    response_model=TenantResponse,
    summary="Update Tenant",
    dependencies=[Depends(RequireSuperAdmin)],
)
async def update_tenant(
    tenant_id: str,
    payload: TenantUpdate,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_db),
):
    t = (await db.execute(select(Tenant).where(Tenant.id == uuid.UUID(tenant_id)))).scalar_one_or_none()
    if not t or t.status == "deleted":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    update_data = payload.model_dump(exclude_unset=True)
    changed = []
    for field, value in update_data.items():
        if hasattr(t, field) and field != "metadata":
            setattr(t, field, value)
        elif field == "metadata":
            setattr(t, "meta_data", value)
        changed.append(field)

    await _audit(
        db,
        action="tenant.updated",
        resource_type="tenant",
        resource_id=t.id,
        tenant_id=t.id,
        user_id=uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None,
        details={"changed_fields": changed},
    )

    return TenantResponse.model_validate(t)


@router.delete(
    "/{tenant_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft Delete Tenant",
    dependencies=[Depends(RequireSuperAdmin)],
)
async def delete_tenant(
    tenant_id: str,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_db),
):
    t = (await db.execute(select(Tenant).where(Tenant.id == uuid.UUID(tenant_id)))).scalar_one_or_none()
    if not t or t.status == "deleted":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    t.status = "deleted"

    await _audit(
        db,
        action="tenant.deleted",
        resource_type="tenant",
        resource_id=t.id,
        tenant_id=t.id,
        user_id=uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None,
        severity="warning",
    )


@router.post(
    "/{tenant_id}/suspend",
    response_model=TenantResponse,
    summary="Suspend Tenant",
    dependencies=[Depends(RequireSuperAdmin)],
)
async def suspend_tenant(
    tenant_id: str,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_db),
):
    t = (await db.execute(select(Tenant).where(Tenant.id == uuid.UUID(tenant_id)))).scalar_one_or_none()
    if not t or t.status == "deleted":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    t.status = "suspended"

    await _audit(
        db,
        action="tenant.suspended",
        resource_type="tenant",
        resource_id=t.id,
        tenant_id=t.id,
        user_id=uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None,
        severity="warning",
    )

    return TenantResponse.model_validate(t)


@router.post(
    "/{tenant_id}/activate",
    response_model=TenantResponse,
    summary="Activate Tenant",
    dependencies=[Depends(RequireSuperAdmin)],
)
async def activate_tenant(
    tenant_id: str,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_db),
):
    t = (await db.execute(select(Tenant).where(Tenant.id == uuid.UUID(tenant_id)))).scalar_one_or_none()
    if not t or t.status == "deleted":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    t.status = "active"

    await _audit(
        db,
        action="tenant.activated",
        resource_type="tenant",
        resource_id=t.id,
        tenant_id=t.id,
        user_id=uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None,
    )

    return TenantResponse.model_validate(t)


@router.get(
    "/{tenant_id}/usage",
    response_model=TenantUsageResponse,
    summary="Get Tenant Resource Usage",
    dependencies=[Depends(RequireSuperAdmin)],
)
async def get_tenant_usage(
    tenant_id: str,
    current_user: dict = Depends(get_current_user),
    db = Depends(get_db),
):
    t = (await db.execute(select(Tenant).where(Tenant.id == uuid.UUID(tenant_id)))).scalar_one_or_none()
    if not t or t.status == "deleted":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    tid = uuid.UUID(tenant_id)
    user_count = (await db.execute(
        select(func.count()).select_from(User).where(User.tenant_id == tid, User.is_deleted == False)
    )).scalar()

    return TenantUsageResponse(
        tenant_id=str(t.id),
        tenant_name=t.name,
        assets={"current": 0, "quota": t.quota_assets},
        users={"current": user_count, "quota": t.quota_users},
        storage={"current": 0.0, "quota": float(t.quota_storage_gb)},
        incidents={"current": 0},
        api_calls={"today": 0, "this_month": 0},
    )


@router.get(
    "/{tenant_id}/audit-logs",
    response_model=TenantAuditLogResponse,
    summary="Get Tenant Audit Logs",
    dependencies=[Depends(RequireSuperAdmin)],
)
async def get_tenant_audit_logs(
    tenant_id: str,
    current_user: dict = Depends(get_current_user),
    pagination: PaginationParams = Depends(),
    action_filter: Optional[str] = Query(None, alias="action", description="Filter by action type"),
    resource_filter: Optional[str] = Query(None, alias="resource", description="Filter by resource"),
    from_date: Optional[datetime] = Query(None, description="Filter logs from this date"),
    to_date: Optional[datetime] = Query(None, description="Filter logs up to this date"),
    db = Depends(get_db),
):
    t = (await db.execute(select(Tenant).where(Tenant.id == uuid.UUID(tenant_id)))).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    tid = uuid.UUID(tenant_id)
    conditions = [AuditLog.tenant_id == tid]

    if action_filter:
        conditions.append(AuditLog.action == action_filter)
    if resource_filter:
        conditions.append(AuditLog.resource_type == resource_filter)
    if from_date:
        conditions.append(AuditLog.created_at >= from_date)
    if to_date:
        conditions.append(AuditLog.created_at <= to_date)

    where_clause = and_(*conditions)

    count_q = select(func.count()).select_from(AuditLog).where(where_clause)
    total = (await db.execute(count_q)).scalar()

    query = select(AuditLog).where(where_clause).order_by(desc(AuditLog.created_at)).offset(pagination.offset).limit(pagination.page_size)
    result = await db.execute(query)
    rows = result.scalars().all()

    entries = []
    for row in rows:
        entries.append(TenantAuditLogEntry(
            id=str(row.id),
            tenant_id=str(row.tenant_id),
            action=row.action,
            resource=row.resource_type,
            actor_id=str(row.user_id) if row.user_id else None,
            details=row.details,
            ip_address=row.ip_address,
            created_at=row.created_at,
        ))

    return TenantAuditLogResponse(
        items=entries,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=max(1, math.ceil(total / pagination.page_size)) if total else 1,
    )
