"""
AEGISX - Notifications API Router
Preferences, channels, templates, ad-hoc sending, history, integrations
"""
import logging
import smtplib
import uuid
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models import (
    NotificationChannel,
    NotificationHistory,
    NotificationPreference,
    NotificationTemplate,
    AuditLog,
)
from app.api.deps import (
    get_current_user,
    require_tenant,
    RequireTenantAdmin,
    RequireSOCManager,
    RequireSOCAnalyst,
)

router = APIRouter()


# ════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════

class NotificationChannelEnum(str, Enum):
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"
    MOBILE_PUSH = "mobile_push"

class NotificationType(str, Enum):
    ALERT = "alert"
    INCIDENT = "incident"
    COMPLIANCE = "compliance"
    REPORT = "report"
    SYSTEM = "system"
    REMINDER = "reminder"

class NotificationPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ChannelStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"

class TemplateCategory(str, Enum):
    ALERT = "alert"
    INCIDENT = "incident"
    REPORT = "report"
    REMINDER = "reminder"
    COMPLIANCE = "compliance"
    SYSTEM = "system"

class IntegrationProvider(str, Enum):
    SMTP = "smtp"
    TWILIO = "twilio"
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"
    FIREBASE = "firebase"


# ════════════════════════════════════════════════════════════════════
# Common Response Models
# ════════════════════════════════════════════════════════════════════

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


# ════════════════════════════════════════════════════════════════════
# Preference Models
# ════════════════════════════════════════════════════════════════════

class NotificationPreferencesRead(BaseModel):
    user_id: str
    channels: List[NotificationChannelEnum]
    notification_types: List[NotificationType]
    digest_enabled: bool
    digest_frequency: Optional[str] = None
    quiet_hours_start: Optional[str] = None
    quiet_hours_end: Optional[str] = None
    quiet_hours_timezone: Optional[str] = None

class NotificationPreferencesUpdate(BaseModel):
    channels: Optional[List[NotificationChannelEnum]] = None
    notification_types: Optional[List[NotificationType]] = None
    digest_enabled: Optional[bool] = None
    digest_frequency: Optional[str] = None
    quiet_hours_start: Optional[str] = None
    quiet_hours_end: Optional[str] = None
    quiet_hours_timezone: Optional[str] = None


# ════════════════════════════════════════════════════════════════════
# Channel Models
# ════════════════════════════════════════════════════════════════════

class ChannelConfigRead(BaseModel):
    id: str
    tenant_id: str
    channel_type: NotificationChannelEnum
    name: str
    status: ChannelStatus
    config: Dict[str, Any]
    last_test_at: Optional[datetime] = None
    last_test_result: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None

class ChannelConfigCreate(BaseModel):
    channel_type: NotificationChannelEnum
    name: str = Field(..., min_length=1, max_length=255)
    config: Dict[str, Any]

class ChannelConfigUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[Dict[str, Any]] = None
    status: Optional[ChannelStatus] = None

class TestChannelResponse(BaseModel):
    channel_id: str
    success: bool
    message: str
    detail: Optional[str] = None
    tested_at: datetime


# ════════════════════════════════════════════════════════════════════
# History Models
# ════════════════════════════════════════════════════════════════════

class NotificationHistoryEntry(BaseModel):
    id: str
    tenant_id: str
    notification_type: NotificationType
    channel: NotificationChannelEnum
    priority: NotificationPriority
    recipient: str
    subject: Optional[str] = None
    body: Optional[str] = None
    status: str
    sent_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    error: Optional[str] = None
    template_id: Optional[str] = None
    created_by: Optional[str] = None


# ════════════════════════════════════════════════════════════════════
# Template Models
# ════════════════════════════════════════════════════════════════════

class TemplateResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    category: TemplateCategory
    subject: str
    body_html: Optional[str] = None
    body_text: Optional[str] = None
    variables: List[str]
    channels: List[NotificationChannelEnum]
    enabled: bool
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None

class TemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    category: TemplateCategory
    subject: str = Field(..., min_length=1, max_length=500)
    body_html: Optional[str] = None
    body_text: Optional[str] = None
    variables: List[str] = Field(default_factory=list)
    channels: List[NotificationChannelEnum] = Field(default_factory=list)
    enabled: bool = True

class TemplateUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    category: Optional[TemplateCategory] = None
    subject: Optional[str] = Field(None, min_length=1, max_length=500)
    body_html: Optional[str] = None
    body_text: Optional[str] = None
    variables: Optional[List[str]] = None
    channels: Optional[List[NotificationChannelEnum]] = None
    enabled: Optional[bool] = None


# ════════════════════════════════════════════════════════════════════
# Send Notification Model
# ════════════════════════════════════════════════════════════════════

class SendNotificationRequest(BaseModel):
    recipients: List[str] = Field(..., min_length=1)
    channel: NotificationChannelEnum
    notification_type: NotificationType
    priority: NotificationPriority = NotificationPriority.MEDIUM
    subject: Optional[str] = Field(None, max_length=500)
    body: str = Field(..., min_length=1)
    body_html: Optional[str] = None
    template_id: Optional[str] = None
    template_variables: Optional[Dict[str, Any]] = None
    attachments: Optional[List[Dict[str, str]]] = None

class SendNotificationResponse(BaseModel):
    notification_id: str
    status: str
    recipients_processed: int
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    sent_at: datetime


# ════════════════════════════════════════════════════════════════════
# Integration Models
# ════════════════════════════════════════════════════════════════════

class IntegrationResponse(BaseModel):
    id: str
    tenant_id: str
    provider: IntegrationProvider
    name: str
    is_configured: bool
    status: ChannelStatus
    config_summary: Dict[str, Any]
    last_verified_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

class EmailIntegrationConfig(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    host: str = Field(..., min_length=1)
    port: int = Field(default=587, ge=1, le=65535)
    use_tls: bool = True
    username: Optional[str] = None
    password: Optional[str] = None
    from_email: str = Field(..., description="Sender email address")
    reply_to: Optional[str] = None
    max_retries: int = Field(default=3, ge=0, le=10)
    timeout_seconds: int = Field(default=30, ge=5, le=120)

class SMSIntegrationConfig(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    account_sid: str = Field(..., min_length=1)
    auth_token: str = Field(..., min_length=1)
    from_number: str = Field(..., min_length=3)
    messaging_service_sid: Optional[str] = None
    status_callback_url: Optional[str] = None

class SlackIntegrationConfig(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    bot_token: str = Field(..., min_length=1)
    signing_secret: Optional[str] = None
    default_channel: str = Field(..., min_length=1)
    app_token: Optional[str] = None

class TeamsIntegrationConfig(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    webhook_url: str = Field(..., min_length=1)
    tenant_id: Optional[str] = None
    app_id: Optional[str] = None
    app_secret: Optional[str] = None

class DiscordIntegrationConfig(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    webhook_url: str = Field(..., min_length=1)
    bot_token: Optional[str] = None
    default_channel_id: Optional[str] = None

class TelegramIntegrationConfig(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    bot_token: str = Field(..., min_length=1)
    default_chat_id: Optional[str] = None
    proxy_url: Optional[str] = None

class WebhookIntegrationConfig(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    url: str = Field(..., min_length=1)
    method: str = Field(default="POST")
    headers: Dict[str, str] = Field(default_factory=dict)
    auth_header: Optional[str] = None
    auth_header_value: Optional[str] = None
    payload_template: Optional[Dict[str, Any]] = None
    retry_count: int = Field(default=3, ge=0, le=10)
    verify_ssl: bool = True

class MobilePushIntegrationConfig(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    project_id: str = Field(..., min_length=1)
    server_key: str = Field(..., min_length=1)
    app_id: Optional[str] = None
    fcm_endpoint: str = Field(default="https://fcm.googleapis.com/fcm/send")
    priority: str = Field(default="high")


def _pref_to_response(pref: NotificationPreference) -> NotificationPreferencesRead:
    channels = [NotificationChannelEnum(c) for c in (pref.enabled_channels or ["email"])]
    return NotificationPreferencesRead(
        user_id=str(pref.user_id),
        channels=channels,
        notification_types=[e for e in NotificationType],
        digest_enabled=pref.daily_digest if pref.daily_digest is not None else False,
        digest_frequency=None,
        quiet_hours_start=pref.quiet_hours_start,
        quiet_hours_end=pref.quiet_hours_end,
        quiet_hours_timezone="UTC",
    )


def _channel_to_response(ch: NotificationChannel) -> ChannelConfigRead:
    return ChannelConfigRead(
        id=str(ch.id),
        tenant_id=str(ch.tenant_id),
        channel_type=NotificationChannelEnum(ch.channel_type),
        name=ch.name,
        status=ChannelStatus.ACTIVE if ch.is_active else ChannelStatus.INACTIVE,
        config=ch.config or {},
        last_test_at=ch.last_tested_at,
        last_test_result=None,
        created_at=ch.created_at,
        updated_at=ch.updated_at,
        created_by=None,
    )


# ════════════════════════════════════════════════════════════════════
# PREFERENCE ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@router.get("/", response_model=NotificationPreferencesRead)
async def get_preferences(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    user_uuid = uuid.UUID(current_user["user_id"])

    stmt = select(NotificationPreference).where(
        NotificationPreference.tenant_id == tenant_uuid,
        NotificationPreference.user_id == user_uuid,
    )
    result = await db.execute(stmt)
    pref = result.scalars().first()

    if not pref:
        pref = NotificationPreference(
            tenant_id=tenant_uuid,
            user_id=user_uuid,
            enabled_channels=["email"],
            alert_severity_filter="high",
            incident_updates=True,
            report_ready=True,
            daily_digest=False,
        )
        db.add(pref)
        await db.flush()
        await db.refresh(pref)

    return _pref_to_response(pref)


@router.patch("/", response_model=NotificationPreferencesRead)
async def update_preferences(
    body: NotificationPreferencesUpdate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    user_uuid = uuid.UUID(current_user["user_id"])

    stmt = select(NotificationPreference).where(
        NotificationPreference.tenant_id == tenant_uuid,
        NotificationPreference.user_id == user_uuid,
    )
    result = await db.execute(stmt)
    pref = result.scalars().first()

    if not pref:
        pref = NotificationPreference(
            tenant_id=tenant_uuid,
            user_id=user_uuid,
            enabled_channels=["email"],
            alert_severity_filter="high",
            incident_updates=True,
            report_ready=True,
            daily_digest=False,
        )
        db.add(pref)

    if body.channels is not None:
        pref.enabled_channels = [c.value for c in body.channels]
    if body.digest_enabled is not None:
        pref.daily_digest = body.digest_enabled
    if body.quiet_hours_start is not None:
        pref.quiet_hours_start = body.quiet_hours_start
    if body.quiet_hours_end is not None:
        pref.quiet_hours_end = body.quiet_hours_end
    pref.updated_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(pref)
    return _pref_to_response(pref)


# ════════════════════════════════════════════════════════════════════
# CHANNEL ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@router.get("/channels", response_model=List[ChannelConfigRead])
async def list_channels(
    channel_type: Optional[NotificationChannelEnum] = Query(None),
    status_filter: Optional[ChannelStatus] = Query(None, alias="status"),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [NotificationChannel.tenant_id == tenant_uuid]

    if channel_type:
        conditions.append(NotificationChannel.channel_type == channel_type.value)
    if status_filter:
        if status_filter == ChannelStatus.ACTIVE:
            conditions.append(NotificationChannel.is_active == True)
        elif status_filter == ChannelStatus.INACTIVE:
            conditions.append(NotificationChannel.is_active == False)

    stmt = select(NotificationChannel).where(and_(*conditions)).order_by(NotificationChannel.created_at.desc())
    result = await db.execute(stmt)
    channels = result.scalars().all()

    return [_channel_to_response(ch) for ch in channels]


@router.post("/channels", response_model=ChannelConfigRead, status_code=status.HTTP_201_CREATED)
async def create_channel(
    body: ChannelConfigCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)

    existing = await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.tenant_id == tenant_uuid,
            NotificationChannel.name == body.name,
        )
    )
    if existing.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Channel with name '{body.name}' already exists",
        )

    channel = NotificationChannel(
        tenant_id=tenant_uuid,
        name=body.name,
        channel_type=body.channel_type.value,
        config=body.config,
        is_active=True,
    )
    db.add(channel)
    await db.flush()
    await db.refresh(channel)
    return _channel_to_response(channel)


@router.patch("/channels/{channel_id}", response_model=ChannelConfigRead)
async def update_channel(
    channel_id: str,
    body: ChannelConfigUpdate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    channel_uuid = uuid.UUID(channel_id)

    stmt = select(NotificationChannel).where(
        NotificationChannel.id == channel_uuid,
        NotificationChannel.tenant_id == tenant_uuid,
    )
    result = await db.execute(stmt)
    channel = result.scalars().first()

    if not channel:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Channel not found")

    if body.name is not None:
        existing = await db.execute(
            select(NotificationChannel).where(
                NotificationChannel.tenant_id == tenant_uuid,
                NotificationChannel.name == body.name,
                NotificationChannel.id != channel_uuid,
            )
        )
        if existing.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Channel with name '{body.name}' already exists",
            )
        channel.name = body.name

    if body.config is not None:
        channel.config = body.config
    if body.status is not None:
        channel.is_active = body.status == ChannelStatus.ACTIVE

    channel.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(channel)
    return _channel_to_response(channel)


@router.delete("/channels/{channel_id}", response_model=MessageResponse)
async def delete_channel(
    channel_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    channel_uuid = uuid.UUID(channel_id)

    stmt = select(NotificationChannel).where(
        NotificationChannel.id == channel_uuid,
        NotificationChannel.tenant_id == tenant_uuid,
    )
    result = await db.execute(stmt)
    channel = result.scalars().first()

    if not channel:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Channel not found")

    await db.delete(channel)
    await db.flush()
    return MessageResponse(message="Channel deleted successfully", detail=f"Deleted channel '{channel.name}'")


@router.post("/channels/{channel_id}/test", response_model=TestChannelResponse)
async def test_channel(
    channel_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    channel_uuid = uuid.UUID(channel_id)

    stmt = select(NotificationChannel).where(
        NotificationChannel.id == channel_uuid,
        NotificationChannel.tenant_id == tenant_uuid,
    )
    result = await db.execute(stmt)
    channel = result.scalars().first()

    if not channel:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Channel not found")

    now = datetime.now(timezone.utc)
    channel.last_tested_at = now
    channel.updated_at = now

    test_entry = NotificationHistory(
        tenant_id=tenant_uuid,
        channel_type=channel.channel_type,
        recipient="test@aegisx.local",
        subject="Test Notification",
        content="This is a test notification from the AEGISX platform.",
        status="sent",
        triggered_by="test",
    )
    db.add(test_entry)
    await db.flush()

    return TestChannelResponse(
        channel_id=str(channel.id),
        success=True,
        message="Test notification sent successfully",
        tested_at=now,
    )


# ════════════════════════════════════════════════════════════════════
# HISTORY ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@router.get("/history", response_model=PaginatedResponse)
async def get_notification_history(
    notification_type: Optional[NotificationType] = Query(None),
    channel: Optional[NotificationChannelEnum] = Query(None),
    priority: Optional[NotificationPriority] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    recipient: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [NotificationHistory.tenant_id == tenant_uuid]

    if channel:
        conditions.append(NotificationHistory.channel_type == channel.value)
    if status_filter:
        conditions.append(NotificationHistory.status == status_filter)
    if recipient:
        conditions.append(NotificationHistory.recipient.ilike(f"%{recipient}%"))
    if date_from:
        conditions.append(NotificationHistory.created_at >= date_from)
    if date_to:
        conditions.append(NotificationHistory.created_at <= date_to)

    count_stmt = select(func.count()).select_from(NotificationHistory).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        select(NotificationHistory)
        .where(and_(*conditions))
        .order_by(desc(NotificationHistory.created_at))
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    entries = result.scalars().all()

    items = []
    for h in entries:
        items.append(NotificationHistoryEntry(
            id=str(h.id),
            tenant_id=str(h.tenant_id),
            notification_type=NotificationType.SYSTEM,
            channel=NotificationChannelEnum(h.channel_type) if h.channel_type in [e.value for e in NotificationChannelEnum] else NotificationChannelEnum.EMAIL,
            priority=NotificationPriority.MEDIUM,
            recipient=h.recipient,
            subject=h.subject,
            body=h.content,
            status=h.status,
            sent_at=h.created_at,
            delivered_at=None,
            error=h.error_message,
            template_id=str(h.template_id) if h.template_id else None,
            created_by=h.triggered_by,
        ))

    total_pages = max(1, (total + page_size - 1) // page_size)
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# TEMPLATE ENDPOINTS
# ════════════════════════════════════════════════════════════════════


def _template_to_response(t: NotificationTemplate) -> TemplateResponse:
    return TemplateResponse(
        id=str(t.id),
        tenant_id=str(t.tenant_id),
        name=t.name,
        category=TemplateCategory(t.category) if t.category in [e.value for e in TemplateCategory] else TemplateCategory.SYSTEM,
        subject=t.subject,
        body_html=t.body_html,
        body_text=t.body_text,
        variables=t.variables or [],
        channels=[NotificationChannelEnum(ch) for ch in (t.channels or ["email"]) if ch in [e.value for e in NotificationChannelEnum]],
        enabled=t.enabled,
        created_at=t.created_at,
        updated_at=t.updated_at,
        created_by=str(t.created_by) if t.created_by else None,
    )


_HARDCODED_TEMPLATES = [
    TemplateResponse(
        id="tmpl-001",
        tenant_id="system",
        name="Incident Created",
        category=TemplateCategory.INCIDENT,
        subject="New Incident: {{incident_title}}",
        body_html="<p>An incident has been created: <strong>{{incident_title}}</strong></p>",
        body_text="An incident has been created: {{incident_title}}",
        variables=["incident_title", "incident_severity", "incident_assignee"],
        channels=list(NotificationChannelEnum),
        enabled=True,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    ),
    TemplateResponse(
        id="tmpl-002",
        tenant_id="system",
        name="Alert Fired",
        category=TemplateCategory.ALERT,
        subject="Alert: {{alert_name}}",
        body_html="<p>Alert fired: <strong>{{alert_name}}</strong> - Severity: {{alert_severity}}</p>",
        body_text="Alert fired: {{alert_name}} - Severity: {{alert_severity}}",
        variables=["alert_name", "alert_severity", "alert_source"],
        channels=list(NotificationChannelEnum),
        enabled=True,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    ),
    TemplateResponse(
        id="tmpl-003",
        tenant_id="system",
        name="Report Ready",
        category=TemplateCategory.REPORT,
        subject="Report Generated: {{report_name}}",
        body_html="<p>Your report <strong>{{report_name}}</strong> is ready for download.</p>",
        body_text="Your report {{report_name}} is ready for download.",
        variables=["report_name", "report_type", "download_url"],
        channels=[NotificationChannelEnum.EMAIL],
        enabled=True,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    ),
]


@router.get("/templates", response_model=List[TemplateResponse])
async def list_templates(
    category: Optional[TemplateCategory] = Query(None),
    channel: Optional[NotificationChannelEnum] = Query(None),
    enabled: Optional[bool] = Query(None),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)

    conditions = [
        or_(
            NotificationTemplate.tenant_id == tid,
            NotificationTemplate.is_system == True,
        )
    ]
    if category:
        conditions.append(NotificationTemplate.category == category.value)
    if enabled is not None:
        conditions.append(NotificationTemplate.enabled == enabled)

    result = await db.execute(
        select(NotificationTemplate).where(and_(*conditions)).order_by(desc(NotificationTemplate.created_at))
    )
    db_templates = result.scalars().all()

    templates = []
    for t in db_templates:
        tpl = _template_to_response(t)
        if channel and channel not in tpl.channels:
            continue
        templates.append(tpl)

    if not db_templates:
        templates = list(_HARDCODED_TEMPLATES)
        if category:
            templates = [t for t in templates if t.category == category]
        if channel:
            templates = [t for t in templates if channel in t.channels]
        if enabled is not None:
            templates = [t for t in templates if t.enabled == enabled]

    return templates


@router.post("/templates", response_model=TemplateResponse, status_code=status.HTTP_201_CREATED)
async def create_template(
    body: TemplateCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    t = NotificationTemplate(
        tenant_id=tid,
        name=body.name,
        category=body.category.value,
        subject=body.subject,
        body_html=body.body_html,
        body_text=body.body_text,
        variables=body.variables,
        channels=[ch.value for ch in body.channels] if body.channels else ["email"],
        enabled=body.enabled,
        is_system=False,
        created_by=uid,
    )
    db.add(t)
    await db.flush()

    await db.execute(
        AuditLog.__table__.insert().values(
            id=uuid.uuid4(),
            tenant_id=tid,
            user_id=uid,
            action="template.created",
            resource_type="notification_template",
            resource_id=t.id,
            details={"name": body.name, "category": body.category.value if body.category else None},
            status="success",
            severity="info",
        )
    )
    await db.flush()
    return _template_to_response(t)


@router.patch("/templates/{template_id}", response_model=TemplateResponse)
async def update_template(
    template_id: str,
    body: TemplateUpdate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    t = (await db.execute(
        select(NotificationTemplate).where(
            NotificationTemplate.id == uuid.UUID(template_id),
            NotificationTemplate.tenant_id == tid,
            NotificationTemplate.is_system == False,
        )
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")

    update_data = body.model_dump(exclude_unset=True)
    if "name" in update_data and update_data["name"] is not None:
        t.name = update_data["name"]
    if "category" in update_data and update_data["category"] is not None:
        t.category = update_data["category"].value
    if "subject" in update_data and update_data["subject"] is not None:
        t.subject = update_data["subject"]
    if "body_html" in update_data:
        t.body_html = update_data["body_html"]
    if "body_text" in update_data:
        t.body_text = update_data["body_text"]
    if "variables" in update_data and update_data["variables"] is not None:
        t.variables = update_data["variables"]
    if "channels" in update_data and update_data["channels"] is not None:
        t.channels = [ch.value for ch in update_data["channels"]]
    if "enabled" in update_data and update_data["enabled"] is not None:
        t.enabled = update_data["enabled"]

    await db.execute(
        AuditLog.__table__.insert().values(
            id=uuid.uuid4(),
            tenant_id=tid,
            user_id=uid,
            action="template.updated",
            resource_type="notification_template",
            resource_id=t.id,
            details={"updated_fields": list(update_data.keys())},
            status="success",
            severity="info",
        )
    )
    await db.flush()
    await db.refresh(t)
    return _template_to_response(t)


@router.delete("/templates/{template_id}", response_model=MessageResponse)
async def delete_template(
    template_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"]) if current_user.get("user_id") else None

    t = (await db.execute(
        select(NotificationTemplate).where(
            NotificationTemplate.id == uuid.UUID(template_id),
            NotificationTemplate.tenant_id == tid,
            NotificationTemplate.is_system == False,
        )
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")

    name = t.name
    await db.delete(t)

    await db.execute(
        AuditLog.__table__.insert().values(
            id=uuid.uuid4(),
            tenant_id=tid,
            user_id=uid,
            action="template.deleted",
            resource_type="notification_template",
            resource_id=uuid.UUID(template_id),
            details={"name": name},
            status="success",
            severity="info",
        )
    )
    await db.flush()
    return MessageResponse(message="Template deleted successfully", detail=f"Template '{name}' removed")


# ════════════════════════════════════════════════════════════════════
# EMAIL DELIVERY
# ════════════════════════════════════════════════════════════════════

logger = logging.getLogger(__name__)


def send_email_notification(
    recipient: str,
    subject: str,
    body: str,
    body_html: Optional[str] = None,
    smtp_host: Optional[str] = None,
    smtp_port: Optional[int] = None,
    smtp_user: Optional[str] = None,
    smtp_password: Optional[str] = None,
    smtp_from: Optional[str] = None,
    use_tls: bool = True,
) -> tuple[bool, Optional[str]]:
    host = smtp_host or settings.SMTP_HOST
    port = smtp_port or settings.SMTP_PORT
    user = smtp_user or settings.SMTP_USER
    password = smtp_password or settings.SMTP_PASSWORD
    from_addr = smtp_from or settings.SMTP_FROM
    tls = use_tls if use_tls is not None else settings.SMTP_TLS

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = recipient
        msg.attach(MIMEText(body, "plain", "utf-8"))
        if body_html:
            msg.attach(MIMEText(body_html, "html", "utf-8"))

        if tls:
            server = smtplib.SMTP(host, port, timeout=30)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP(host, port, timeout=30)

        if user and password:
            server.login(user, password)

        server.sendmail(from_addr, [recipient], msg.as_string())
        server.quit()
        return True, None
    except Exception as e:
        logger.error(f"Failed to send email to {recipient}: {e}")
        return False, str(e)


# ════════════════════════════════════════════════════════════════════
# SEND ENDPOINT
# ════════════════════════════════════════════════════════════════════

@router.post("/send", response_model=SendNotificationResponse, status_code=status.HTTP_202_ACCEPTED)
async def send_notification(
    body: SendNotificationRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    now = datetime.now(timezone.utc)
    errors: List[Dict[str, Any]] = []

    for recipient in body.recipients:
        entry = NotificationHistory(
            tenant_id=tenant_uuid,
            channel_type=body.channel.value,
            recipient=recipient,
            subject=body.subject or "Notification",
            content=body.body,
            status="pending",
            template_id=uuid.UUID(body.template_id) if body.template_id else None,
            triggered_by=current_user["user_id"],
        )
        db.add(entry)

        if body.channel == NotificationChannelEnum.EMAIL:
            success, error = send_email_notification(
                recipient=recipient,
                subject=body.subject or "Notification",
                body=body.body,
                body_html=body.body_html,
            )
            if success:
                entry.status = "sent"
            else:
                entry.status = "failed"
                entry.error_message = error
                errors.append({"recipient": recipient, "error": error})

    await db.flush()

    return SendNotificationResponse(
        notification_id=str(uuid.uuid4()),
        status="queued",
        recipients_processed=len(body.recipients),
        errors=errors,
        sent_at=now,
    )


# ════════════════════════════════════════════════════════════════════
# INTEGRATION ENDPOINTS
# ════════════════════════════════════════════════════════════════════

PROVIDER_TO_CHANNEL_TYPE = {
    IntegrationProvider.SMTP: "email",
    IntegrationProvider.TWILIO: "sms",
    IntegrationProvider.SLACK: "slack",
    IntegrationProvider.TEAMS: "teams",
    IntegrationProvider.DISCORD: "discord",
    IntegrationProvider.TELEGRAM: "telegram",
    IntegrationProvider.WEBHOOK: "webhook",
    IntegrationProvider.FIREBASE: "mobile_push",
}


def _config_summary(provider: IntegrationProvider, config: Dict[str, Any]) -> Dict[str, Any]:
    redacted = {}
    sensitive_keys = {"password", "auth_token", "bot_token", "signing_secret", "app_secret",
                      "server_key", "auth_header_value", "account_sid", "api_key"}
    for key, value in config.items():
        if key in sensitive_keys:
            redacted[key] = "***redacted***"
        else:
            redacted[key] = value
    return redacted


async def _upsert_integration(
    db: AsyncSession,
    tenant_uuid: uuid.UUID,
    provider: IntegrationProvider,
    display_name: str,
    config: Dict[str, Any],
) -> IntegrationResponse:
    channel_type = PROVIDER_TO_CHANNEL_TYPE[provider]

    stmt = select(NotificationChannel).where(
        NotificationChannel.tenant_id == tenant_uuid,
        NotificationChannel.channel_type == channel_type,
    )
    result = await db.execute(stmt)
    channel = result.scalars().first()

    now = datetime.now(timezone.utc)

    if channel:
        channel.name = display_name
        channel.config = config
        channel.updated_at = now
    else:
        channel = NotificationChannel(
            tenant_id=tenant_uuid,
            name=display_name,
            channel_type=channel_type,
            config=config,
            is_active=True,
        )
        db.add(channel)

    await db.flush()
    await db.refresh(channel)

    return IntegrationResponse(
        id=str(channel.id),
        tenant_id=str(channel.tenant_id),
        provider=provider,
        name=channel.name,
        is_configured=True,
        status=ChannelStatus.ACTIVE if channel.is_active else ChannelStatus.INACTIVE,
        config_summary=_config_summary(provider, channel.config or {}),
        last_verified_at=channel.last_tested_at,
        created_at=channel.created_at,
        updated_at=channel.updated_at,
    )


@router.get("/integrations", response_model=List[IntegrationResponse])
async def list_integrations(
    provider: Optional[IntegrationProvider] = Query(None),
    is_configured: Optional[bool] = Query(None),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)

    stmt = select(NotificationChannel).where(NotificationChannel.tenant_id == tenant_uuid)
    if provider:
        channel_type = PROVIDER_TO_CHANNEL_TYPE.get(provider)
        if channel_type:
            stmt = stmt.where(NotificationChannel.channel_type == channel_type)
        else:
            return []
    if is_configured is not None:
        stmt = stmt.where(NotificationChannel.is_active == is_configured)

    result = await db.execute(stmt)
    channels = result.scalars().all()

    integrations = []
    for ch in channels:
        prov = next((p for p, ct in PROVIDER_TO_CHANNEL_TYPE.items() if ct == ch.channel_type), None)
        if prov:
            integrations.append(IntegrationResponse(
                id=str(ch.id),
                tenant_id=str(ch.tenant_id),
                provider=prov,
                name=ch.name,
                is_configured=True,
                status=ChannelStatus.ACTIVE if ch.is_active else ChannelStatus.INACTIVE,
                config_summary=_config_summary(prov, ch.config or {}),
                last_verified_at=ch.last_tested_at,
                created_at=ch.created_at,
                updated_at=ch.updated_at,
            ))
    return integrations


@router.post("/integrations/email", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def configure_email_integration(
    body: EmailIntegrationConfig,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return await _upsert_integration(
        db, uuid.UUID(tenant_id), IntegrationProvider.SMTP,
        body.display_name, body.model_dump(),
    )


@router.post("/integrations/sms", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def configure_sms_integration(
    body: SMSIntegrationConfig,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return await _upsert_integration(
        db, uuid.UUID(tenant_id), IntegrationProvider.TWILIO,
        body.display_name, body.model_dump(),
    )


@router.post("/integrations/slack", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def configure_slack_integration(
    body: SlackIntegrationConfig,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return await _upsert_integration(
        db, uuid.UUID(tenant_id), IntegrationProvider.SLACK,
        body.display_name, body.model_dump(),
    )


@router.post("/integrations/teams", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def configure_teams_integration(
    body: TeamsIntegrationConfig,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return await _upsert_integration(
        db, uuid.UUID(tenant_id), IntegrationProvider.TEAMS,
        body.display_name, body.model_dump(),
    )


@router.post("/integrations/discord", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def configure_discord_integration(
    body: DiscordIntegrationConfig,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return await _upsert_integration(
        db, uuid.UUID(tenant_id), IntegrationProvider.DISCORD,
        body.display_name, body.model_dump(),
    )


@router.post("/integrations/telegram", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def configure_telegram_integration(
    body: TelegramIntegrationConfig,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return await _upsert_integration(
        db, uuid.UUID(tenant_id), IntegrationProvider.TELEGRAM,
        body.display_name, body.model_dump(),
    )


@router.post("/integrations/webhook", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def configure_webhook_integration(
    body: WebhookIntegrationConfig,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return await _upsert_integration(
        db, uuid.UUID(tenant_id), IntegrationProvider.WEBHOOK,
        body.display_name, body.model_dump(),
    )


@router.post("/integrations/mobile-push", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def configure_mobile_push_integration(
    body: MobilePushIntegrationConfig,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return await _upsert_integration(
        db, uuid.UUID(tenant_id), IntegrationProvider.FIREBASE,
        body.display_name, body.model_dump(),
    )
