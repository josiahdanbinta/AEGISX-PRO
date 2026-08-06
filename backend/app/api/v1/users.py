"""
AEGISX - User, Role, and Department Management Endpoints (Tenant Admin)
"""
import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func, or_, and_, desc
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import hash_password
from app.models import User, Role, Department, UserRole, AuditLog, RefreshToken, Tenant

from app.api.deps import (
    PaginationParams,
    RequireSOCManager,
    RequireTenantAdmin,
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


def _build_dept_tree(departments) -> list:
    dept_map = {}
    roots = []
    for d in departments:
        node = {
            "id": str(d.id),
            "tenant_id": str(d.tenant_id) if d.tenant_id else None,
            "name": d.name,
            "parent_department_id": str(d.parent_department_id) if d.parent_department_id else None,
            "description": d.description,
            "manager_id": str(d.manager_id) if d.manager_id else None,
            "children": [],
            "created_at": d.created_at.isoformat() if d.created_at else None,
            "updated_at": d.updated_at.isoformat() if d.updated_at else None,
        }
        dept_map[str(d.id)] = node

    for d in departments:
        node = dept_map[str(d.id)]
        pid = str(d.parent_department_id) if d.parent_department_id else None
        if pid and pid in dept_map:
            dept_map[pid]["children"].append(node)
        else:
            roots.append(node)

    return roots


# ── User Models ───────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=255)
    roles: List[str] = Field(default_factory=list, description="Role names to assign")
    department_id: Optional[str] = Field(None, description="Department UUID")
    password: str = Field(..., min_length=8, max_length=128)


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=255)
    roles: Optional[List[str]] = None
    department_id: Optional[str] = None
    title: Optional[str] = Field(None, max_length=255)
    phone: Optional[str] = Field(None, max_length=50)
    status: Optional[str] = Field(None, pattern=r"^(active|suspended|inactive|locked)$")
    must_change_password: Optional[bool] = None
    mfa_enabled: Optional[bool] = None


class UserResponse(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    username: str
    email: str
    full_name: Optional[str] = None
    phone: Optional[str] = None
    department_id: Optional[str] = None
    title: Optional[str] = None
    roles: Optional[list] = None
    status: str
    mfa_enabled: bool
    last_login_at: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    failed_login_attempts: int
    locked_until: Optional[datetime] = None
    must_change_password: bool
    password_changed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    items: List[UserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class UserSessionResponse(BaseModel):
    session_id: str
    user_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_active: bool


class UserSessionListResponse(BaseModel):
    items: List[UserSessionResponse]
    total: int


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=128)
    force_change: bool = Field(False, description="Require password change on next login")


class ResetPasswordResponse(BaseModel):
    message: str


# ── Role Models ───────────────────────────────────────────────────

class RoleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    display_name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    permissions: Optional[List[str]] = None
    is_system: bool = False


class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=150)
    display_name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    permissions: Optional[List[str]] = None


class RoleResponse(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    name: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[list] = None
    is_system: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Department Models ─────────────────────────────────────────────

class DepartmentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    parent_department_id: Optional[str] = Field(None, description="Parent department UUID for hierarchy")
    description: Optional[str] = None
    manager_id: Optional[str] = Field(None, description="Department manager user UUID")


class DepartmentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    parent_department_id: Optional[str] = None
    description: Optional[str] = None
    manager_id: Optional[str] = None


class DepartmentResponse(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    name: str
    parent_department_id: Optional[str] = None
    description: Optional[str] = None
    manager_id: Optional[str] = None
    children: Optional[List["DepartmentResponse"]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── User Endpoints ────────────────────────────────────────────────

@router.post(
    "/",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create User",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def create_user(
    payload: UserCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)

    # Quota enforcement
    tenant = (await db.execute(select(Tenant).where(Tenant.id == tid))).scalar_one_or_none()
    if tenant:
        user_count = (await db.execute(
            select(func.count(User.id)).where(User.tenant_id == tid, User.is_deleted == False)
        )).scalar() or 0
        if user_count >= tenant.quota_users:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"User quota exceeded ({tenant.quota_users}). Contact your administrator to upgrade.",
            )

    existing = (await db.execute(
        select(User).where(User.tenant_id == tid, User.email == payload.email, User.is_deleted == False)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists in this tenant")

    username = payload.email.split("@")[0]
    hashed = hash_password(payload.password)

    u = User(
        tenant_id=tid,
        email=payload.email,
        username=username,
        full_name=payload.full_name,
        hashed_password=hashed,
        department_id=uuid.UUID(payload.department_id) if payload.department_id else None,
    )
    db.add(u)
    await db.flush()

    if payload.roles:
        for role_name in payload.roles:
            role = (await db.execute(
                select(Role).where(Role.name == role_name, Role.tenant_id == tid)
            )).scalar_one_or_none()
            if role:
                user_role = UserRole(user_id=u.id, role_id=role.id, assigned_by=uuid.UUID(current_user["user_id"]))
                db.add(user_role)

    await _audit(
        db,
        action="user.created",
        resource_type="user",
        resource_id=u.id,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"email": payload.email, "roles": payload.roles},
    )

    return UserResponse(
        id=str(u.id),
        tenant_id=str(u.tenant_id),
        username=u.username,
        email=u.email,
        full_name=u.full_name,
        department_id=str(u.department_id) if u.department_id else None,
        roles=payload.roles,
        status=u.status,
        mfa_enabled=u.mfa_enabled,
        failed_login_attempts=u.failed_login_attempts,
        must_change_password=u.must_change_password,
        created_at=u.created_at,
        updated_at=u.updated_at,
    )


@router.get(
    "/",
    response_model=UserListResponse,
    summary="List Users",
    dependencies=[Depends(RequireSOCManager)],
)
async def list_users(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    pagination: PaginationParams = Depends(),
    search: Optional[str] = Query(None, description="Search by name or email"),
    role_filter: Optional[str] = Query(None, alias="role", description="Filter by role"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by user status"),
    department_filter: Optional[str] = Query(None, alias="department_id", description="Filter by department"),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    conditions = [User.tenant_id == tid, User.is_deleted == False]

    if status_filter:
        conditions.append(User.status == status_filter)
    if department_filter:
        conditions.append(User.department_id == uuid.UUID(department_filter))
    if search:
        conditions.append(or_(User.full_name.ilike(f"%{search}%"), User.email.ilike(f"%{search}%")))
    if role_filter:
        role_user_ids = (
            select(UserRole.user_id)
            .join(Role, Role.id == UserRole.role_id)
            .where(Role.name == role_filter, Role.tenant_id == tid)
        )
        conditions.append(User.id.in_(role_user_ids))

    where_clause = and_(*conditions)

    count_q = select(func.count()).select_from(User).where(where_clause)
    total = (await db.execute(count_q)).scalar()

    query = (
        select(User)
        .options(selectinload(User.user_roles).selectinload(UserRole.role))
        .where(where_clause)
        .order_by(desc(User.created_at))
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    result = await db.execute(query)
    users = result.scalars().all()

    items = []
    for u in users:
        role_names = [ur.role.name for ur in u.user_roles if ur.role] if u.user_roles else []
        items.append(UserResponse(
            id=str(u.id),
            tenant_id=str(u.tenant_id),
            username=u.username,
            email=u.email,
            full_name=u.full_name,
            phone=u.phone,
            department_id=str(u.department_id) if u.department_id else None,
            title=u.title,
            roles=role_names,
            status=u.status,
            mfa_enabled=u.mfa_enabled,
            last_login_at=u.last_login_at,
            last_login_ip=u.last_login_ip,
            failed_login_attempts=u.failed_login_attempts,
            locked_until=u.locked_until,
            must_change_password=u.must_change_password,
            password_changed_at=u.password_changed_at,
            created_at=u.created_at,
            updated_at=u.updated_at,
        ))

    return UserListResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=max(1, math.ceil(total / pagination.page_size)) if total else 1,
    )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get User Details",
    dependencies=[Depends(RequireSOCManager)],
)
async def get_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(user_id)

    u = (await db.execute(
        select(User)
        .options(selectinload(User.user_roles).selectinload(UserRole.role), selectinload(User.department))
        .where(User.id == uid, User.tenant_id == tid, User.is_deleted == False)
    )).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    role_names = [ur.role.name for ur in u.user_roles if ur.role] if u.user_roles else []

    return UserResponse(
        id=str(u.id),
        tenant_id=str(u.tenant_id),
        username=u.username,
        email=u.email,
        full_name=u.full_name,
        phone=u.phone,
        department_id=str(u.department_id) if u.department_id else None,
        title=u.title,
        roles=role_names,
        status=u.status,
        mfa_enabled=u.mfa_enabled,
        last_login_at=u.last_login_at,
        last_login_ip=u.last_login_ip,
        failed_login_attempts=u.failed_login_attempts,
        locked_until=u.locked_until,
        must_change_password=u.must_change_password,
        password_changed_at=u.password_changed_at,
        created_at=u.created_at,
        updated_at=u.updated_at,
    )


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update User",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(user_id)

    u = (await db.execute(
        select(User)
        .options(selectinload(User.user_roles).selectinload(UserRole.role))
        .where(User.id == uid, User.tenant_id == tid, User.is_deleted == False)
    )).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    update_data = payload.model_dump(exclude_unset=True)
    changed = []

    if "full_name" in update_data:
        u.full_name = update_data["full_name"]
        changed.append("full_name")
    if "department_id" in update_data:
        u.department_id = uuid.UUID(update_data["department_id"]) if update_data["department_id"] else None
        changed.append("department_id")
    if "title" in update_data:
        u.title = update_data["title"]
        changed.append("title")
    if "phone" in update_data:
        u.phone = update_data["phone"]
        changed.append("phone")
    if "status" in update_data:
        u.status = update_data["status"]
        changed.append("status")
    if "must_change_password" in update_data:
        u.must_change_password = update_data["must_change_password"]
        changed.append("must_change_password")
    if "mfa_enabled" in update_data:
        u.mfa_enabled = update_data["mfa_enabled"]
        changed.append("mfa_enabled")

    if "roles" in update_data:
        requested_roles = update_data["roles"] or []
        actor_id = uuid.UUID(current_user["user_id"])

        if uid == actor_id:
            current_role_names = {ur.role.name for ur in u.user_roles if ur.role}
            if "tenant_admin" in current_role_names and "tenant_admin" not in requested_roles:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot demote yourself")

        for ur in u.user_roles:
            await db.delete(ur)

        for role_name in requested_roles:
            role = (await db.execute(
                select(Role).where(Role.name == role_name, Role.tenant_id == tid)
            )).scalar_one_or_none()
            if role:
                db.add(UserRole(user_id=uid, role_id=role.id, assigned_by=actor_id))

        changed.append("roles")

    await _audit(
        db,
        action="user.updated",
        resource_type="user",
        resource_id=uid,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"changed_fields": changed},
    )

    role_names = [ur.role.name for ur in u.user_roles if ur.role] if u.user_roles else []
    if "roles" in update_data:
        role_names = update_data["roles"] or []

    return UserResponse(
        id=str(u.id),
        tenant_id=str(u.tenant_id),
        username=u.username,
        email=u.email,
        full_name=u.full_name,
        phone=u.phone,
        department_id=str(u.department_id) if u.department_id else None,
        title=u.title,
        roles=role_names,
        status=u.status,
        mfa_enabled=u.mfa_enabled,
        last_login_at=u.last_login_at,
        last_login_ip=u.last_login_ip,
        failed_login_attempts=u.failed_login_attempts,
        locked_until=u.locked_until,
        must_change_password=u.must_change_password,
        password_changed_at=u.password_changed_at,
        created_at=u.created_at,
        updated_at=u.updated_at,
    )


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Soft Delete User",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def delete_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(user_id)

    if str(uid) == current_user.get("user_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot delete yourself")

    u = (await db.execute(
        select(User).where(User.id == uid, User.tenant_id == tid, User.is_deleted == False)
    )).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    u.is_deleted = True
    u.status = "inactive"

    await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == uid, RefreshToken.is_revoked == False)
    )
    tokens = (await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == uid, RefreshToken.is_revoked == False)
    )).scalars().all()
    for token in tokens:
        token.is_revoked = True

    await _audit(
        db,
        action="user.deleted",
        resource_type="user",
        resource_id=uid,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        severity="warning",
    )


@router.post(
    "/{user_id}/suspend",
    response_model=UserResponse,
    summary="Suspend User",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def suspend_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(user_id)

    if str(uid) == current_user.get("user_id"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot suspend yourself")

    u = (await db.execute(
        select(User).options(selectinload(User.user_roles).selectinload(UserRole.role))
        .where(User.id == uid, User.tenant_id == tid, User.is_deleted == False)
    )).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    u.status = "suspended"

    tokens = (await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == uid, RefreshToken.is_revoked == False)
    )).scalars().all()
    for token in tokens:
        token.is_revoked = True

    await _audit(
        db,
        action="user.suspended",
        resource_type="user",
        resource_id=uid,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        severity="warning",
    )

    role_names = [ur.role.name for ur in u.user_roles if ur.role] if u.user_roles else []
    return UserResponse(
        id=str(u.id), tenant_id=str(u.tenant_id), username=u.username, email=u.email,
        full_name=u.full_name, phone=u.phone,
        department_id=str(u.department_id) if u.department_id else None,
        title=u.title, roles=role_names, status=u.status, mfa_enabled=u.mfa_enabled,
        last_login_at=u.last_login_at, last_login_ip=u.last_login_ip,
        failed_login_attempts=u.failed_login_attempts, locked_until=u.locked_until,
        must_change_password=u.must_change_password, password_changed_at=u.password_changed_at,
        created_at=u.created_at, updated_at=u.updated_at,
    )


@router.post(
    "/{user_id}/activate",
    response_model=UserResponse,
    summary="Activate User",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def activate_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(user_id)

    u = (await db.execute(
        select(User).options(selectinload(User.user_roles).selectinload(UserRole.role))
        .where(User.id == uid, User.tenant_id == tid, User.is_deleted == False)
    )).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    u.status = "active"
    u.locked_until = None
    u.failed_login_attempts = 0

    await _audit(
        db,
        action="user.activated",
        resource_type="user",
        resource_id=uid,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
    )

    role_names = [ur.role.name for ur in u.user_roles if ur.role] if u.user_roles else []
    return UserResponse(
        id=str(u.id), tenant_id=str(u.tenant_id), username=u.username, email=u.email,
        full_name=u.full_name, phone=u.phone,
        department_id=str(u.department_id) if u.department_id else None,
        title=u.title, roles=role_names, status=u.status, mfa_enabled=u.mfa_enabled,
        last_login_at=u.last_login_at, last_login_ip=u.last_login_ip,
        failed_login_attempts=u.failed_login_attempts, locked_until=u.locked_until,
        must_change_password=u.must_change_password, password_changed_at=u.password_changed_at,
        created_at=u.created_at, updated_at=u.updated_at,
    )


@router.post(
    "/{user_id}/unlock",
    response_model=UserResponse,
    summary="Unlock User Account",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def unlock_user(
    user_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(user_id)

    u = (await db.execute(
        select(User).options(selectinload(User.user_roles).selectinload(UserRole.role))
        .where(User.id == uid, User.tenant_id == tid, User.is_deleted == False)
    )).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    u.locked_until = None
    u.failed_login_attempts = 0
    u.status = "active"

    await _audit(
        db,
        action="user.unlocked",
        resource_type="user",
        resource_id=uid,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
    )

    role_names = [ur.role.name for ur in u.user_roles if ur.role] if u.user_roles else []
    return UserResponse(
        id=str(u.id), tenant_id=str(u.tenant_id), username=u.username, email=u.email,
        full_name=u.full_name, phone=u.phone,
        department_id=str(u.department_id) if u.department_id else None,
        title=u.title, roles=role_names, status=u.status, mfa_enabled=u.mfa_enabled,
        last_login_at=u.last_login_at, last_login_ip=u.last_login_ip,
        failed_login_attempts=u.failed_login_attempts, locked_until=u.locked_until,
        must_change_password=u.must_change_password, password_changed_at=u.password_changed_at,
        created_at=u.created_at, updated_at=u.updated_at,
    )


@router.post(
    "/{user_id}/reset-password",
    response_model=ResetPasswordResponse,
    summary="Admin Reset User Password",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def reset_user_password(
    user_id: str,
    payload: ResetPasswordRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(user_id)

    u = (await db.execute(
        select(User).where(User.id == uid, User.tenant_id == tid, User.is_deleted == False)
    )).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    u.hashed_password = hash_password(payload.new_password)
    u.password_changed_at = datetime.now(timezone.utc)
    if payload.force_change:
        u.must_change_password = True

    tokens = (await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == uid, RefreshToken.is_revoked == False)
    )).scalars().all()
    for token in tokens:
        token.is_revoked = True

    await _audit(
        db,
        action="user.password_reset",
        resource_type="user",
        resource_id=uid,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"force_change": payload.force_change},
        severity="warning",
    )

    return ResetPasswordResponse(message="Password has been reset successfully")


@router.get(
    "/{user_id}/sessions",
    response_model=UserSessionListResponse,
    summary="List User Active Sessions",
    dependencies=[Depends(RequireSOCManager)],
)
async def list_user_sessions(
    user_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(user_id)

    u = (await db.execute(
        select(User).where(User.id == uid, User.tenant_id == tid, User.is_deleted == False)
    )).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    now = datetime.now(timezone.utc)
    tokens = (await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == uid,
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > now,
        ).order_by(desc(RefreshToken.created_at))
    )).scalars().all()

    items = [
        UserSessionResponse(
            session_id=str(t.id),
            user_id=str(t.user_id),
            created_at=t.created_at,
            expires_at=t.expires_at,
            is_active=True,
        )
        for t in tokens
    ]

    return UserSessionListResponse(items=items, total=len(items))


@router.delete(
    "/{user_id}/sessions",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke All User Sessions",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def revoke_user_sessions(
    user_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(user_id)

    u = (await db.execute(
        select(User).where(User.id == uid, User.tenant_id == tid, User.is_deleted == False)
    )).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    tokens = (await db.execute(
        select(RefreshToken).where(RefreshToken.user_id == uid, RefreshToken.is_revoked == False)
    )).scalars().all()
    for token in tokens:
        token.is_revoked = True

    await _audit(
        db,
        action="user.sessions_revoked",
        resource_type="user",
        resource_id=uid,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"revoked_count": len(tokens)},
        severity="warning",
    )


# ── Role Endpoints ────────────────────────────────────────────────

@router.get(
    "/roles",
    response_model=List[RoleResponse],
    summary="List All Roles",
    dependencies=[Depends(RequireSOCManager)],
)
async def list_roles(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    roles = (await db.execute(
        select(Role).where(Role.tenant_id == tid).order_by(Role.name)
    )).scalars().all()

    return [
        RoleResponse(
            id=str(r.id),
            tenant_id=str(r.tenant_id),
            name=r.name,
            display_name=r.display_name,
            description=r.description,
            permissions=r.permissions,
            is_system=r.is_system,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in roles
    ]


@router.post(
    "/roles",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Role",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def create_role(
    payload: RoleCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)

    existing = (await db.execute(
        select(Role).where(Role.name == payload.name, Role.tenant_id == tid)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Role name already exists in this tenant")

    r = Role(
        tenant_id=tid,
        name=payload.name,
        display_name=payload.display_name,
        description=payload.description,
        permissions=payload.permissions,
        is_system=payload.is_system,
    )
    db.add(r)
    await db.flush()

    await _audit(
        db,
        action="role.created",
        resource_type="role",
        resource_id=r.id,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"name": payload.name},
    )

    return RoleResponse(
        id=str(r.id), tenant_id=str(r.tenant_id), name=r.name,
        display_name=r.display_name, description=r.description,
        permissions=r.permissions, is_system=r.is_system,
        created_at=r.created_at, updated_at=r.updated_at,
    )


@router.patch(
    "/roles/{role_id}",
    response_model=RoleResponse,
    summary="Update Role",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def update_role(
    role_id: str,
    payload: RoleUpdate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    rid = uuid.UUID(role_id)

    r = (await db.execute(
        select(Role).where(Role.id == rid, Role.tenant_id == tid)
    )).scalar_one_or_none()

    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    if r.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify system roles")

    update_data = payload.model_dump(exclude_unset=True)
    changed = []
    for field, value in update_data.items():
        if hasattr(r, field):
            setattr(r, field, value)
        changed.append(field)

    await _audit(
        db,
        action="role.updated",
        resource_type="role",
        resource_id=rid,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"changed_fields": changed},
    )

    return RoleResponse(
        id=str(r.id), tenant_id=str(r.tenant_id), name=r.name,
        display_name=r.display_name, description=r.description,
        permissions=r.permissions, is_system=r.is_system,
        created_at=r.created_at, updated_at=r.updated_at,
    )


@router.delete(
    "/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Role",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def delete_role(
    role_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    rid = uuid.UUID(role_id)

    r = (await db.execute(
        select(Role).where(Role.id == rid, Role.tenant_id == tid)
    )).scalar_one_or_none()

    if not r:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    if r.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot delete system roles")

    await db.delete(r)

    await _audit(
        db,
        action="role.deleted",
        resource_type="role",
        resource_id=rid,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"name": r.name},
        severity="warning",
    )


# ── Department Endpoints ──────────────────────────────────────────

@router.get(
    "/departments",
    response_model=List[DepartmentResponse],
    summary="List Departments (Hierarchical)",
    dependencies=[Depends(RequireSOCManager)],
)
async def list_departments(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    departments = (await db.execute(
        select(Department).where(Department.tenant_id == tid).order_by(Department.name)
    )).scalars().all()

    tree = _build_dept_tree(departments)
    return [DepartmentResponse(**node) for node in tree]


@router.post(
    "/departments",
    response_model=DepartmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Department",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def create_department(
    payload: DepartmentCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)

    if payload.parent_department_id:
        parent = (await db.execute(
            select(Department).where(Department.id == uuid.UUID(payload.parent_department_id), Department.tenant_id == tid)
        )).scalar_one_or_none()
        if not parent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent department not found")

    if payload.manager_id:
        manager = (await db.execute(
            select(User).where(User.id == uuid.UUID(payload.manager_id), User.tenant_id == tid, User.is_deleted == False)
        )).scalar_one_or_none()
        if not manager:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Manager user not found")

    d = Department(
        tenant_id=tid,
        name=payload.name,
        parent_department_id=uuid.UUID(payload.parent_department_id) if payload.parent_department_id else None,
        description=payload.description,
        manager_id=uuid.UUID(payload.manager_id) if payload.manager_id else None,
    )
    db.add(d)
    await db.flush()

    await _audit(
        db,
        action="department.created",
        resource_type="department",
        resource_id=d.id,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"name": payload.name},
    )

    return DepartmentResponse(
        id=str(d.id), tenant_id=str(d.tenant_id), name=d.name,
        parent_department_id=str(d.parent_department_id) if d.parent_department_id else None,
        description=d.description,
        manager_id=str(d.manager_id) if d.manager_id else None,
        created_at=d.created_at, updated_at=d.updated_at,
    )


@router.patch(
    "/departments/{dept_id}",
    response_model=DepartmentResponse,
    summary="Update Department",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def update_department(
    dept_id: str,
    payload: DepartmentUpdate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    did = uuid.UUID(dept_id)

    d = (await db.execute(
        select(Department).where(Department.id == did, Department.tenant_id == tid)
    )).scalar_one_or_none()

    if not d:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Department not found")

    update_data = payload.model_dump(exclude_unset=True)
    changed = []

    if "name" in update_data:
        d.name = update_data["name"]
        changed.append("name")
    if "description" in update_data:
        d.description = update_data["description"]
        changed.append("description")

    new_parent_id = None
    if "parent_department_id" in update_data:
        new_parent_id = uuid.UUID(update_data["parent_department_id"]) if update_data["parent_department_id"] else None
        if new_parent_id and new_parent_id == did:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Department cannot be its own parent")
        if new_parent_id:
            parent = (await db.execute(
                select(Department).where(Department.id == new_parent_id, Department.tenant_id == tid)
            )).scalar_one_or_none()
            if not parent:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent department not found")
        d.parent_department_id = new_parent_id
        changed.append("parent_department_id")

    if "manager_id" in update_data:
        new_manager = uuid.UUID(update_data["manager_id"]) if update_data["manager_id"] else None
        if new_manager:
            manager = (await db.execute(
                select(User).where(User.id == new_manager, User.tenant_id == tid, User.is_deleted == False)
            )).scalar_one_or_none()
            if not manager:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Manager user not found")
        d.manager_id = new_manager
        changed.append("manager_id")

    await _audit(
        db,
        action="department.updated",
        resource_type="department",
        resource_id=did,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"changed_fields": changed},
    )

    return DepartmentResponse(
        id=str(d.id), tenant_id=str(d.tenant_id), name=d.name,
        parent_department_id=str(d.parent_department_id) if d.parent_department_id else None,
        description=d.description,
        manager_id=str(d.manager_id) if d.manager_id else None,
        created_at=d.created_at, updated_at=d.updated_at,
    )


@router.delete(
    "/departments/{dept_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Department",
    dependencies=[Depends(RequireTenantAdmin)],
)
async def delete_department(
    dept_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    did = uuid.UUID(dept_id)

    d = (await db.execute(
        select(Department).where(Department.id == did, Department.tenant_id == tid)
    )).scalar_one_or_none()

    if not d:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Department not found")

    user_count = (await db.execute(
        select(func.count()).select_from(User).where(
            User.department_id == did, User.tenant_id == tid, User.is_deleted == False
        )
    )).scalar()
    if user_count > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot delete department with {user_count} active users. Reassign users first.",
        )

    child_count = (await db.execute(
        select(func.count()).select_from(Department).where(Department.parent_department_id == did, Department.tenant_id == tid)
    )).scalar()
    if child_count > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot delete department with {child_count} child departments. Delete or reassign children first.",
        )

    await db.delete(d)

    await _audit(
        db,
        action="department.deleted",
        resource_type="department",
        resource_id=did,
        tenant_id=tid,
        user_id=uuid.UUID(current_user["user_id"]),
        details={"name": d.name},
        severity="warning",
    )
