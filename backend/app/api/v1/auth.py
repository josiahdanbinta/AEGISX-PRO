"""
AEGIS - Authentication API Router
Login, MFA, password management, API keys, WebAuthn
"""
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_user,
    require_tenant,
    RequireTenantAdmin,
)
from app.core.config import settings
from app.core.database import get_db
from app.models.audit import AuditLog
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    create_reset_token,
    decode_token,
    generate_api_key,
    hash_api_key,
    validate_password_strength,
    generate_secure_token,
)
from app.models import (
    User,
    RefreshToken,
    PasswordResetToken,
    BlacklistedToken,
    ApiKey,
)

router = APIRouter()

# â”€â”€ Request / Response Models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_id: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    requires_mfa: bool = False
    mfa_session_token: Optional[str] = None

class RefreshRequest(BaseModel):
    refresh_token: str

class MFAVerifyRequest(BaseModel):
    session_token: str
    code: str

class MFASetupResponse(BaseModel):
    secret: str
    qr_code_uri: str
    backup_codes: List[str]

class MFAEnableRequest(BaseModel):
    code: str

class MFADisableRequest(BaseModel):
    password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetApproveRequest(BaseModel):
    reason: Optional[str] = None

class PasswordResetExecute(BaseModel):
    new_password: str
    confirm_password: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

class ApiKeyCreateRequest(BaseModel):
    name: str
    scopes: List[str] = ["api"]
    expires_in_days: Optional[int] = 365

class ApiKeyResponse(BaseModel):
    id: str
    name: str
    api_key: Optional[str] = None
    prefix: str
    scopes: List[str]
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

class UserProfileResponse(BaseModel):
    id: str
    email: str
    full_name: str
    roles: List[str]
    department: Optional[str] = None
    mfa_enabled: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime

class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None
    preferences: Optional[dict] = None

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None


# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _roles_to_str_list(roles: Optional[list]) -> List[str]:
    if not roles:
        return []
    return [r["role_name"] for r in roles if isinstance(r, dict) and "role_name" in r]


def _generate_qr_code_uri(secret: str, email: str, issuer: str = "AEGIS") -> str:
    try:
        import pyotp
        return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)
    except ImportError:
        return f"otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}"


def _generate_backup_codes(count: int = 8) -> List[str]:
    return [generate_secure_token(10) for _ in range(count)]


async def _audit_auth(db: AsyncSession, user, action: str, success: bool = True,
                       details: Optional[dict] = None, ip: Optional[str] = None):
    try:
        db.add(AuditLog(
            tenant_id=user.tenant_id if hasattr(user, 'tenant_id') else None,
            user_id=user.id if hasattr(user, 'id') else None,
            action=f"auth.{action}",
            resource_type="auth",
            details=details or {},
            ip_address=ip,
            status="success" if success else "failure",
            severity="info",
        ))
        await db.flush()
    except Exception:
        pass


# â”€â”€ Login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="User Login",
    description="Authenticate with email/password and receive JWT tokens. Returns MFA challenge if enabled.",
)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    query = select(User).where(User.email == request.email, User.is_deleted == False)
    if request.tenant_id:
        try:
            tid = uuid.UUID(request.tenant_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid tenant_id format")
        query = query.where(User.tenant_id == tid)

    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if user.status == "suspended":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account suspended",
        )

    if user.status == "locked" or (
        user.locked_until and user.locked_until > datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account locked",
        )

    if user.status == "inactive":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account inactive",
        )

    if not verify_password(request.password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.PASSWORD_LOCKOUT_ATTEMPTS:
            user.status = "locked"
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=settings.PASSWORD_LOCKOUT_MINUTES)
        await db.flush()
        await _audit_auth(db, user, "login_failed", success=False, details={"reason": "bad_password"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    user.failed_login_attempts = 0
    user.last_login_at = datetime.now(timezone.utc)
    user.locked_until = None

    if user.status == "locked":
        user.status = "active"

    tenant_id_str = str(user.tenant_id)
    user_id_str = str(user.id)
    roles = _roles_to_str_list(user.roles)

    if user.mfa_enabled:
        session_token = generate_secure_token(32)
        db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hashlib.sha256(session_token.encode()).hexdigest(),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                is_used=False,
            )
        )
        await db.flush()
        return TokenResponse(
            access_token="",
            refresh_token="",
            expires_in=0,
            requires_mfa=True,
            mfa_session_token=session_token,
        )

    access_token = create_access_token(
        subject=user_id_str,
        tenant_id=tenant_id_str,
        roles=roles,
    )

    refresh_token_str = create_refresh_token(
        subject=user_id_str,
        tenant_id=tenant_id_str,
    )

    refresh_payload = decode_token(refresh_token_str)
    if refresh_payload:
        db.add(
            RefreshToken(
                tenant_id=user.tenant_id,
                user_id=user.id,
                token_jti=refresh_payload["jti"],
                token_hash=hashlib.sha256(refresh_token_str.encode()).hexdigest(),
                expires_at=datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc),
            )
        )
        await db.flush()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        requires_mfa=False,
    )


# â”€â”€ Token Refresh â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh Access Token",
    description="Exchange a valid refresh token for a new access/refresh token pair.",
)
async def refresh_token(
    request: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    payload = decode_token(request.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    jti = payload.get("jti")
    bl_result = await db.execute(
        select(BlacklistedToken).where(BlacklistedToken.token_jti == jti)
    )
    if bl_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
        )

    token_hash_val = hashlib.sha256(request.refresh_token.encode()).hexdigest()
    rt_result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash_val,
            RefreshToken.is_revoked == False,
        )
    )
    rt = rt_result.scalar_one_or_none()

    if not rt:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        )

    rt.is_revoked = True

    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    roles = payload.get("roles", [])

    expired_user = await db.execute(
        select(User).where(User.id == uuid.UUID(user_id), User.is_deleted == False)
    )
    db_user = expired_user.scalar_one_or_none()
    if not db_user or db_user.status not in ("active",):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is not active",
        )

    access_token = create_access_token(subject=user_id, tenant_id=tenant_id, roles=roles)
    new_refresh_token = create_refresh_token(subject=user_id, tenant_id=tenant_id)

    new_payload = decode_token(new_refresh_token)
    if new_payload:
        db.add(
            RefreshToken(
                tenant_id=uuid.UUID(tenant_id),
                user_id=uuid.UUID(user_id),
                token_jti=new_payload["jti"],
                token_hash=hashlib.sha256(new_refresh_token.encode()).hexdigest(),
                expires_at=datetime.fromtimestamp(new_payload["exp"], tz=timezone.utc),
            )
        )
        await db.flush()

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# â”€â”€ Logout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout",
    description="Invalidate current session token.",
)
async def logout(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    jti = current_user.get("token_jti")
    if jti:
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )
        db.add(
            BlacklistedToken(
                token_jti=jti,
                expires_at=expires_at,
            )
        )
        user_id = current_user.get("user_id")
        if user_id:
            await db.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.user_id == uuid.UUID(user_id),
                    RefreshToken.is_revoked == False,
                )
                .values(is_revoked=True)
            )
        await db.flush()

    await _audit_auth(db, current_user, "logout")
    return MessageResponse(message="Logged out successfully")


# â”€â”€ MFA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/mfa/verify",
    response_model=TokenResponse,
    summary="Verify MFA",
    description="Verify MFA code (TOTP or backup code) and complete login.",
)
async def verify_mfa(
    request: MFAVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    session_hash = hashlib.sha256(request.session_token.encode()).hexdigest()
    prt_result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == session_hash,
            PasswordResetToken.is_used == False,
            PasswordResetToken.expires_at > datetime.now(timezone.utc),
        )
    )
    prt = prt_result.scalar_one_or_none()

    if not prt:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA session token",
        )

    prt.is_used = True

    user_result = await db.execute(
        select(User).where(User.id == prt.user_id, User.is_deleted == False)
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    verified = False

    if user.mfa_secret:
        try:
            import pyotp
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(request.code, valid_window=1):
                verified = True
        except (ImportError, Exception):
            pass

    if not verified and user.mfa_backup_codes:
        codes = user.mfa_backup_codes if isinstance(user.mfa_backup_codes, list) else []
        if request.code in codes:
            codes.remove(request.code)
            user.mfa_backup_codes = codes
            verified = True

    if not verified:
        await db.flush()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

    user.last_login_at = datetime.now(timezone.utc)
    await db.flush()

    user_id_str = str(user.id)
    tenant_id_str = str(user.tenant_id)
    roles = _roles_to_str_list(user.roles)

    access_token = create_access_token(
        subject=user_id_str,
        tenant_id=tenant_id_str,
        roles=roles,
    )

    refresh_token_str = create_refresh_token(
        subject=user_id_str,
        tenant_id=tenant_id_str,
    )

    refresh_payload = decode_token(refresh_token_str)
    if refresh_payload:
        db.add(
            RefreshToken(
                tenant_id=user.tenant_id,
                user_id=user.id,
                token_jti=refresh_payload["jti"],
                token_hash=hashlib.sha256(refresh_token_str.encode()).hexdigest(),
                expires_at=datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc),
            )
        )
        await db.flush()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        requires_mfa=False,
    )


@router.post(
    "/mfa/setup",
    response_model=MFASetupResponse,
    summary="Setup MFA",
    description="Initialize MFA setup, returns secret and QR code URI.",
)
async def setup_mfa(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(current_user["user_id"]),
            User.is_deleted == False,
        )
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    try:
        import pyotp
        secret = pyotp.random_base32()
    except ImportError:
        secret = generate_secure_token(16)

    backup_codes = _generate_backup_codes()

    user.mfa_secret = secret
    user.mfa_backup_codes = backup_codes
    await db.flush()

    qr_code_uri = _generate_qr_code_uri(secret, user.email)

    return MFASetupResponse(
        secret=secret,
        qr_code_uri=qr_code_uri,
        backup_codes=backup_codes,
    )


@router.post(
    "/mfa/enable",
    response_model=MessageResponse,
    summary="Enable MFA",
    description="Confirm MFA setup and enable it for the account.",
)
async def enable_mfa(
    request: MFAEnableRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(current_user["user_id"]),
            User.is_deleted == False,
        )
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup has not been initialized",
        )

    verified = False

    try:
        import pyotp
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(request.code, valid_window=1):
            verified = True
    except (ImportError, Exception):
        pass

    if not verified and user.mfa_backup_codes:
        codes = user.mfa_backup_codes if isinstance(user.mfa_backup_codes, list) else []
        if request.code in codes:
            verified = True

    if not verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    user.mfa_enabled = True
    await db.flush()

    return MessageResponse(message="MFA has been enabled successfully")


@router.post(
    "/mfa/disable",
    response_model=MessageResponse,
    summary="Disable MFA",
    description="Disable MFA for the account (requires password confirmation).",
)
async def disable_mfa(
    request: MFADisableRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(current_user["user_id"]),
            User.is_deleted == False,
        )
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password",
        )

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_backup_codes = None
    await db.flush()

    await _audit_auth(db, current_user, "mfa_disabled")
    return MessageResponse(message="MFA has been disabled successfully")


# â”€â”€ Password Reset â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/password/reset-request",
    response_model=MessageResponse,
    summary="Request Password Reset",
    description="Submit a password reset request. Requires admin approval.",
)
async def request_password_reset(
    request: PasswordResetRequest,
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    user_result = await db.execute(
        select(User).where(
            User.email == request.email,
            User.tenant_id == tid,
            User.is_deleted == False,
        )
    )
    user = user_result.scalar_one_or_none()

    if not user:
        return MessageResponse(
            message="If the email exists in this tenant, a password reset request has been submitted",
            detail="A tenant administrator must approve this request before the reset can proceed.",
        )

    reset_token = create_reset_token(str(user.id), str(user.tenant_id))
    token_hash = hashlib.sha256(reset_token.encode()).hexdigest()

    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.JWT_RESET_TOKEN_EXPIRE_HOURS),
            is_used=False,
            requested_by=user.id,
        )
    )
    await db.flush()

    try:
        from app.services.reset_email import send_reset_email
        await send_reset_email(
            to_email=request.email,
            reset_token=reset_token,
            reset_url="https://AEGIS.local/reset-password",
            username=user.full_name or user.username,
        )
    except Exception:
        pass

    return MessageResponse(
        message="Password reset request submitted",
        detail="A tenant administrator must approve this request before the reset can proceed.",
        request_id=str(prt.id),  # type: ignore
    )


@router.get(
    "/password/reset-requests",
    summary="List Pending Reset Requests",
    description="Super admin or tenant admin lists pending password reset requests.",
)
async def list_reset_requests(
    current_user: dict = Depends(RequireTenantAdmin),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.is_used == False,
        ).join(User, User.id == PasswordResetToken.user_id).where(
            User.tenant_id == tid,
        ).order_by(desc(PasswordResetToken.created_at)).limit(50)
    )
    tokens = result.scalars().all()

    requests = []
    for t in tokens:
        user_result = await db.execute(select(User).where(User.id == t.user_id))
        user = user_result.scalar_one_or_none()
        requests.append({
            "request_id": str(t.id),
            "user_email": user.email if user else "unknown",
            "user_name": user.full_name if user else "unknown",
            "requested_at": t.created_at.isoformat() if t.created_at else None,
            "expires_at": t.expires_at.isoformat() if t.expires_at else None,
            "approved_at": t.approved_at.isoformat() if t.approved_at else None,
            "status": "approved" if t.approved_at else "pending",
            "is_expired": t.expires_at < datetime.now(timezone.utc) if t.expires_at else False,
        })

    return {"total": len(requests), "requests": requests}


@router.post(
    "/password/reset-reject/{request_id}",
    response_model=MessageResponse,
    summary="Reject Password Reset",
    description="Super admin or tenant admin rejects a password reset request.",
)
async def reject_password_reset(
    request_id: str,
    current_user: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    try:
        prt_id = uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request ID")

    prt_result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.id == prt_id,
            PasswordResetToken.is_used == False,
        )
    )
    prt = prt_result.scalar_one_or_none()
    if not prt:
        raise HTTPException(status_code=404, detail="Reset request not found")

    prt.is_used = True
    await db.flush()

    await _audit_auth(db, current_user, "password_reset_rejected",
                       details={"request_id": str(prt_id), "user_id": str(prt.user_id)})

    return MessageResponse(
        message="Password reset request rejected",
        detail="The reset request has been denied.",
    )


@router.post(
    "/password/reset-approve/{request_id}",
    response_model=MessageResponse,
    summary="Approve Password Reset",
    description="Tenant admin approves a password reset request.",
)
async def approve_password_reset(
    request_id: str,
    body: PasswordResetApproveRequest,
    current_user: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    try:
        prt_id = uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request ID format",
        )

    prt_result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.id == prt_id,
            PasswordResetToken.is_used == False,
        )
    )
    prt = prt_result.scalar_one_or_none()

    if not prt:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Password reset request not found",
        )

    if prt.approved_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request has already been approved",
        )

    if prt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset request has expired",
        )

    user_result = await db.execute(
        select(User).where(User.id == prt.user_id, User.is_deleted == False)
    )
    prt_user = user_result.scalar_one_or_none()

    if not prt_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    admin_user = current_user["user_id"]
    admin_tid = uuid.UUID(current_user["tenant_id"]) if current_user.get("tenant_id") else None

    if admin_tid and prt_user.tenant_id != admin_tid:
        if "super_admin" not in current_user.get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cross-tenant access denied",
            )

    prt.approved_at = datetime.now(timezone.utc)

    new_reset_token = create_reset_token(str(prt_user.id), str(prt_user.tenant_id))
    new_token_hash = hashlib.sha256(new_reset_token.encode()).hexdigest()

    prt.token_hash = new_token_hash
    prt.expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_RESET_TOKEN_EXPIRE_HOURS)
    prt.requested_by = uuid.UUID(admin_user) if admin_user else prt.requested_by
    await db.flush()

    return MessageResponse(
        message="Password reset approved",
        detail=f"The user has been notified with the reset instructions. Reset token valid for {settings.JWT_RESET_TOKEN_EXPIRE_HOURS} hours.",
    )


@router.post(
    "/password/reset/{token}",
    response_model=MessageResponse,
    summary="Execute Password Reset",
    description="Reset password using the approved reset token.",
)
async def reset_password(
    token: str,
    request: PasswordResetExecute,
    db: AsyncSession = Depends(get_db),
):
    if request.new_password != request.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )

    valid, error = validate_password_strength(request.new_password)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error,
        )

    payload = decode_token(token)
    if not payload or payload.get("type") != "reset":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    token_hash_val = hashlib.sha256(token.encode()).hexdigest()
    prt_result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash_val,
            PasswordResetToken.is_used == False,
            PasswordResetToken.approved_at != None,
            PasswordResetToken.expires_at > datetime.now(timezone.utc),
        )
    )
    prt = prt_result.scalar_one_or_none()

    if not prt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used reset token",
        )

    user_id = payload.get("sub")
    user_result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(user_id),
            User.is_deleted == False,
        )
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    user.hashed_password = hash_password(request.new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.must_change_password = False
    user.failed_login_attempts = 0
    user.locked_until = None
    if user.status == "locked":
        user.status = "active"

    prt.is_used = True

    await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.user_id == user.id,
            RefreshToken.is_revoked == False,
        )
        .values(is_revoked=True)
    )
    await db.flush()

    return MessageResponse(message="Password has been reset successfully")


# â”€â”€ Change Password â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/password/change",
    response_model=MessageResponse,
    summary="Change Password",
    description="Change your own password (requires current password).",
)
async def change_password(
    request: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if request.new_password != request.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )

    valid, error = validate_password_strength(request.new_password)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error,
        )

    user_result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(current_user["user_id"]),
            User.is_deleted == False,
        )
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not verify_password(request.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    user.hashed_password = hash_password(request.new_password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.must_change_password = False

    await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.user_id == user.id,
            RefreshToken.is_revoked == False,
        )
        .values(is_revoked=True)
    )
    await db.flush()

    await _audit_auth(db, current_user, "password_changed")
    return MessageResponse(message="Password changed successfully")


# â”€â”€ WebAuthn / Passkeys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/webauthn/register",
    response_model=dict,
    summary="Register Passkey",
    description="Start WebAuthn/passkey registration.",
)
async def webauthn_register(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(current_user["user_id"]),
            User.is_deleted == False,
        )
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    challenge = generate_secure_token(32)
    user.preferences = user.preferences or {}
    user.preferences["webauthn_challenge"] = challenge
    user.preferences["webauthn_challenge_expires"] = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat()
    await db.flush()

    existing_credentials = user.webauthn_credentials or []

    return {
        "challenge": challenge,
        "rp": {
            "name": settings.APP_NAME,
            "id": getattr(settings, "APP_DOMAIN", "localhost"),
        },
        "user": {
            "id": str(user.id),
            "name": user.email,
            "displayName": user.full_name or user.username,
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
        ],
        "timeout": 60000,
        "attestation": "none",
        "excludeCredentials": [
            {"type": "public-key", "id": cred.get("credential_id", "")}
            for cred in existing_credentials
        ],
    }


@router.post(
    "/webauthn/verify",
    response_model=MessageResponse,
    summary="Verify Passkey",
    description="Verify and complete WebAuthn passkey registration.",
)
async def webauthn_verify(
    request: dict,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(current_user["user_id"]),
            User.is_deleted == False,
        )
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    preferences = user.preferences or {}
    stored_challenge = preferences.get("webauthn_challenge")
    challenge_expires = preferences.get("webauthn_challenge_expires")

    if not stored_challenge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No WebAuthn registration in progress",
        )

    if challenge_expires and datetime.now(timezone.utc) > datetime.fromisoformat(challenge_expires):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="WebAuthn registration challenge expired",
        )

    credential_id = request.get("id", "")
    public_key = request.get("response", {}).get("attestationObject", "")

    if not credential_id or not public_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid WebAuthn attestation response",
        )

    credentials = user.webauthn_credentials or []
    existing_ids = {c.get("credential_id") for c in credentials if isinstance(c, dict)}
    if credential_id in existing_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential already registered",
        )

    credential = {
        "credential_id": credential_id,
        "public_key": public_key if isinstance(public_key, str) else "",
        "name": request.get("name", user.email),
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "last_used_at": None,
        "transports": request.get("response", {}).get("transports", []),
    }
    credentials.append(credential)
    user.webauthn_credentials = credentials

    preferences.pop("webauthn_challenge", None)
    preferences.pop("webauthn_challenge_expires", None)
    user.preferences = preferences

    await db.flush()

    return MessageResponse(
        message="Passkey registered successfully",
        detail=f"Credential ID: {credential_id[:12]}...",
    )


# â”€â”€ API Keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/api-key/generate",
    response_model=ApiKeyResponse,
    summary="Generate API Key",
    description="Create a new API key for programmatic access.",
)
async def generate_api_key_endpoint(
    request: ApiKeyCreateRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    raw_key = generate_api_key()
    key_hash_val = hash_api_key(raw_key)
    prefix = raw_key[:12] + "..."

    user_id = uuid.UUID(current_user["user_id"])
    user_result = await db.execute(
        select(User).where(User.id == user_id, User.is_deleted == False)
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    expires_at = None
    if request.expires_in_days and request.expires_in_days > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(days=request.expires_in_days)

    api_key_entry = ApiKey(
        tenant_id=user.tenant_id,
        user_id=user.id,
        name=request.name,
        key_hash=key_hash_val,
        prefix=prefix,
        scopes=request.scopes,
        expires_at=expires_at,
        is_active=True,
    )
    db.add(api_key_entry)
    await db.flush()

    return ApiKeyResponse(
        id=str(api_key_entry.id),
        name=api_key_entry.name,
        api_key=raw_key,
        prefix=prefix,
        scopes=request.scopes,
        expires_at=expires_at,
        created_at=api_key_entry.created_at,
    )


@router.get(
    "/api-key/list",
    response_model=List[ApiKeyResponse],
    summary="List API Keys",
    description="List all API keys for the current user.",
)
async def list_api_keys(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = uuid.UUID(current_user["user_id"])
    result = await db.execute(
        select(ApiKey)
        .where(
            ApiKey.user_id == user_id,
            ApiKey.is_active == True,
        )
        .order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()

    return [
        ApiKeyResponse(
            id=str(k.id),
            name=k.name,
            api_key=None,
            prefix=k.prefix,
            scopes=k.scopes or [],
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
            created_at=k.created_at,
        )
        for k in keys
    ]


@router.delete(
    "/api-key/{key_id}",
    response_model=MessageResponse,
    summary="Revoke API Key",
    description="Revoke and delete an API key.",
)
async def revoke_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        kid = uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid key ID format",
        )

    user_id = uuid.UUID(current_user["user_id"])
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == kid,
            ApiKey.user_id == user_id,
        )
    )
    api_key_entry = result.scalar_one_or_none()

    if not api_key_entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    api_key_entry.is_active = False
    await db.flush()

    await _audit_auth(db, current_user, "api_key_revoked", details={"key_id": str(key_id)})
    return MessageResponse(message="API key revoked")


# â”€â”€ User Profile â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get(
    "/me",
    response_model=UserProfileResponse,
    summary="Get Current User",
    description="Return the authenticated user's profile.",
)
async def get_me(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = uuid.UUID(current_user["user_id"])
    result = await db.execute(
        select(User).where(User.id == user_id, User.is_deleted == False)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    dept_name = None
    if user.department_id and user.department:
        dept_name = user.department.name

    return UserProfileResponse(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name or user.username,
        roles=_roles_to_str_list(user.roles),
        department=dept_name,
        mfa_enabled=user.mfa_enabled,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


@router.patch(
    "/me",
    response_model=UserProfileResponse,
    summary="Update Profile",
    description="Update your own profile information.",
)
async def update_me(
    update: UserProfileUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = uuid.UUID(current_user["user_id"])
    result = await db.execute(
        select(User).where(User.id == user_id, User.is_deleted == False)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if update.full_name is not None:
        user.full_name = update.full_name

    if update.phone is not None:
        user.phone = update.phone

    if update.preferences is not None:
        existing = user.preferences or {}
        existing.update(update.preferences)
        user.preferences = existing

    await db.flush()

    dept_name = None
    if user.department_id and user.department:
        dept_name = user.department.name

    return UserProfileResponse(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name or user.username,
        roles=_roles_to_str_list(user.roles),
        department=dept_name,
        mfa_enabled=user.mfa_enabled,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )
