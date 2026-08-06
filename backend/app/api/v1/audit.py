"""
AEGISX - Audit API Router
Audit logs, statistics, exports, retention, sessions, API usage, summaries, anomaly detection
"""
import csv
import io
import math
import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, desc, cast, Date, String, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import AuditLog, RefreshToken
from app.api.deps import (
    get_current_user,
    require_tenant,
    RequireTenantAdmin,
    RequireSOCManager,
    RequireAuditor,
)

router = APIRouter()

_export_store: dict = {}
_retention_config: dict = {"retention_days": 90, "critical_event_retention_days": 365}

# ════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════

class AuditAction(str, Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    EXPORT = "export"
    IMPORT = "import"
    EXECUTE = "execute"
    GRANT = "grant"
    REVOKE = "revoke"
    CONFIGURE = "configure"
    PURGE = "purge"

class AuditSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class ExportFormat(str, Enum):
    CSV = "csv"
    JSON = "json"
    PDF = "pdf"

class ExportStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"

class SessionStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


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
# Audit Log Models
# ════════════════════════════════════════════════════════════════════

class AuditLogEntry(BaseModel):
    id: str
    tenant_id: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    action: AuditAction
    resource_type: str
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    severity: AuditSeverity
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    changes: Optional[Dict[str, Any]] = None
    details: Optional[str] = None
    status_code: Optional[int] = None
    duration_ms: Optional[float] = None
    timestamp: datetime
    tags: List[str] = Field(default_factory=list)

class AuditLogDetail(BaseModel):
    id: str
    tenant_id: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    user_roles: List[str] = Field(default_factory=list)
    action: AuditAction
    resource_type: str
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    severity: AuditSeverity
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    request_headers: Optional[Dict[str, Any]] = None
    request_body: Optional[Any] = None
    response_status_code: Optional[int] = None
    response_body: Optional[Any] = None
    changes_before: Optional[Dict[str, Any]] = None
    changes_after: Optional[Dict[str, Any]] = None
    changes_diff: Optional[Dict[str, Any]] = None
    details: Optional[str] = None
    duration_ms: Optional[float] = None
    session_id: Optional[str] = None
    trace_id: Optional[str] = None
    timestamp: datetime
    tags: List[str] = Field(default_factory=list)


# ════════════════════════════════════════════════════════════════════
# Audit Statistics Models
# ════════════════════════════════════════════════════════════════════

class AuditStatsEntry(BaseModel):
    label: str
    count: int
    percentage: Optional[float] = None

class AuditTimeSeries(BaseModel):
    period: str
    timestamp: datetime
    count: int

class AuditStats(BaseModel):
    total_events: int
    date_range: Dict[str, datetime]
    by_action: List[AuditStatsEntry]
    by_user: List[AuditStatsEntry] = Field(default_factory=list)
    by_resource_type: List[AuditStatsEntry] = Field(default_factory=list)
    by_severity: List[AuditStatsEntry] = Field(default_factory=list)
    time_series: List[AuditTimeSeries] = Field(default_factory=list)
    top_ip_addresses: List[AuditStatsEntry] = Field(default_factory=list)
    unique_users: int = 0


# ════════════════════════════════════════════════════════════════════
# Export Models
# ════════════════════════════════════════════════════════════════════

class ExportRequest(BaseModel):
    format: ExportFormat = ExportFormat.CSV
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    user_id: Optional[str] = None
    action: Optional[List[AuditAction]] = None
    resource_type: Optional[str] = None
    severity: Optional[AuditSeverity] = None
    fields: Optional[List[str]] = Field(None, description="Specific fields to include in export")

class ExportBulkRequest(BaseModel):
    format: ExportFormat = ExportFormat.CSV
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    user_id: Optional[str] = None
    action: Optional[List[AuditAction]] = None
    resource_type: Optional[str] = None
    severity: Optional[AuditSeverity] = None
    fields: Optional[List[str]] = None
    notify_on_completion: bool = False
    notification_channel: Optional[str] = None

class ExportStatusResponse(BaseModel):
    id: str
    tenant_id: str
    format: ExportFormat
    status: ExportStatus
    filters: Dict[str, Any]
    total_records: Optional[int] = None
    file_size_bytes: Optional[int] = None
    created_by: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    download_url: Optional[str] = None
    error: Optional[str] = None


# ════════════════════════════════════════════════════════════════════
# Retention Models
# ════════════════════════════════════════════════════════════════════

class RetentionConfig(BaseModel):
    tenant_id: str
    retention_days: int = Field(default=365, ge=30, le=2555)
    archive_enabled: bool = False
    archive_storage: Optional[str] = None
    auto_purge_enabled: bool = False
    purge_schedule: Optional[str] = None
    critical_event_retention_days: Optional[int] = Field(None, ge=365, le=7300)
    last_purge_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class RetentionUpdate(BaseModel):
    retention_days: Optional[int] = Field(None, ge=30, le=2555)
    archive_enabled: Optional[bool] = None
    archive_storage: Optional[str] = None
    auto_purge_enabled: Optional[bool] = None
    purge_schedule: Optional[str] = None
    critical_event_retention_days: Optional[int] = Field(None, ge=365, le=7300)

class PurgeRequest(BaseModel):
    before_date: Optional[datetime] = None
    action_types: Optional[List[AuditAction]] = None
    dry_run: bool = True
    confirm: bool = False

class PurgeResponse(BaseModel):
    dry_run: bool
    total_records_eligible: int
    records_purged: Optional[int] = None
    storage_freed_bytes: Optional[int] = None
    duration_ms: float
    errors: List[Dict[str, Any]] = Field(default_factory=list)


# ════════════════════════════════════════════════════════════════════
# Session & API Usage Models
# ════════════════════════════════════════════════════════════════════

class ActiveSession(BaseModel):
    session_id: str
    user_id: str
    username: str
    tenant_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    login_at: datetime
    last_activity_at: datetime
    expires_at: Optional[datetime] = None
    status: SessionStatus
    device_info: Optional[Dict[str, Any]] = None

class ApiUsageEntry(BaseModel):
    endpoint: str
    method: str
    request_count: int
    avg_response_time_ms: Optional[float] = None
    error_count: int = 0
    error_rate: Optional[float] = None

class UserApiUsage(BaseModel):
    user_id: str
    username: str
    request_count: int
    avg_response_time_ms: Optional[float] = None
    endpoints_used: int
    error_count: int = 0

class ApiUsageStats(BaseModel):
    period: Dict[str, datetime]
    total_requests: int
    total_errors: int
    overall_error_rate: Optional[float] = None
    avg_response_time_ms: Optional[float] = None
    by_endpoint: List[ApiUsageEntry] = Field(default_factory=list)
    by_user: List[UserApiUsage] = Field(default_factory=list)


# ════════════════════════════════════════════════════════════════════
# Summary & Anomaly Models
# ════════════════════════════════════════════════════════════════════

class DailySummary(BaseModel):
    date: str
    total_events: int
    unique_users: int
    by_action: Dict[str, int]
    by_severity: Dict[str, int]
    top_users: List[Dict[str, Any]] = Field(default_factory=list)
    top_resources: List[Dict[str, Any]] = Field(default_factory=list)
    notable_events: List[Dict[str, Any]] = Field(default_factory=list)

class WeeklySummary(BaseModel):
    week_start: str
    week_end: str
    total_events: int
    unique_users: int
    daily_breakdown: List[DailySummary] = Field(default_factory=list)
    by_action: Dict[str, int]
    by_severity: Dict[str, int]
    comparison_previous_week: Optional[Dict[str, Any]] = None

class AuditAnomaly(BaseModel):
    id: str
    anomaly_type: str
    severity: AuditSeverity
    description: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    resource_type: Optional[str] = None
    detected_at: datetime
    baseline: Optional[Dict[str, Any]] = None
    observed: Optional[Dict[str, Any]] = None
    deviation_factor: Optional[float] = None
    recommendation: Optional[str] = None

class AnomalyDetectionResponse(BaseModel):
    detected_at: datetime
    anomalies: List[AuditAnomaly]
    total_events_analyzed: int
    analysis_period: Dict[str, datetime]
    baseline_period: Optional[Dict[str, datetime]] = None


def _is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except (ValueError, AttributeError):
        return False


def _log_to_entry(log: AuditLog) -> AuditLogEntry:
    details_str = None
    if log.details and isinstance(log.details, dict):
        details_str = log.details.get("description", str(log.details)) if isinstance(log.details, dict) else None

    request_method = None
    request_path = None
    if log.details and isinstance(log.details, dict):
        request_method = log.details.get("method")
        request_path = log.details.get("path")

    return AuditLogEntry(
        id=str(log.id),
        tenant_id=str(log.tenant_id),
        user_id=str(log.user_id) if log.user_id else None,
        username=None,
        action=AuditAction(log.action) if log.action in [e.value for e in AuditAction] else AuditAction.READ,
        resource_type=log.resource_type,
        resource_id=str(log.resource_id) if log.resource_id else None,
        resource_name=None,
        severity=AuditSeverity(log.severity) if log.severity in [e.value for e in AuditSeverity] else AuditSeverity.INFO,
        ip_address=log.ip_address,
        user_agent=log.user_agent,
        request_method=request_method,
        request_path=request_path,
        changes=log.details if isinstance(log.details, dict) else None,
        details=details_str,
        status_code=None,
        duration_ms=None,
        timestamp=log.created_at,
        tags=[],
    )


# ════════════════════════════════════════════════════════════════════
# AUDIT LOGS
# ════════════════════════════════════════════════════════════════════

@router.get("/logs", response_model=PaginatedResponse)
async def list_audit_logs(
    user_id: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    action: Optional[AuditAction] = Query(None),
    resource_type: Optional[str] = Query(None),
    resource_id: Optional[str] = Query(None),
    severity: Optional[AuditSeverity] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    ip_address: Optional[str] = Query(None),
    status_code: Optional[int] = Query(None),
    search: Optional[str] = Query(None, description="Full-text search in details, resource_name"),
    sort_by: Optional[str] = Query("timestamp", description="Sort field"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [AuditLog.tenant_id == tenant_uuid]

    if user_id and _is_valid_uuid(user_id):
        conditions.append(AuditLog.user_id == uuid.UUID(user_id))
    if action:
        conditions.append(AuditLog.action == action.value)
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if resource_id and _is_valid_uuid(resource_id):
        conditions.append(AuditLog.resource_id == uuid.UUID(resource_id))
    if severity:
        conditions.append(AuditLog.severity == severity.value)
    if date_from:
        conditions.append(AuditLog.created_at >= date_from)
    if date_to:
        conditions.append(AuditLog.created_at <= date_to)
    if ip_address:
        conditions.append(AuditLog.ip_address.ilike(f"%{ip_address}%"))
    if status_code is not None:
        conditions.append(AuditLog.status == ("success" if status_code < 400 else "error"))
    if search:
        conditions.append(
            or_(
                AuditLog.details.cast(String).ilike(f"%{search}%"),
                AuditLog.resource_type.ilike(f"%{search}%"),
            )
        )

    count_stmt = select(func.count()).select_from(AuditLog).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    sort_col = AuditLog.created_at
    order_fn = desc(sort_col) if sort_order == "desc" else sort_col.asc()
    offset = (page - 1) * page_size

    stmt = (
        select(AuditLog)
        .where(and_(*conditions))
        .order_by(order_fn)
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()

    items = [_log_to_entry(log) for log in logs]
    total_pages = max(1, math.ceil(total / page_size))

    return PaginatedResponse(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


@router.get("/logs/{log_id}", response_model=AuditLogDetail)
async def get_audit_log_entry(
    log_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    log_uuid = uuid.UUID(log_id)

    stmt = select(AuditLog).where(
        AuditLog.id == log_uuid,
        AuditLog.tenant_id == tenant_uuid,
    )
    result = await db.execute(stmt)
    log = result.scalars().first()

    if not log:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit log entry not found")

    details_dict = log.details if isinstance(log.details, dict) else {}

    return AuditLogDetail(
        id=str(log.id),
        tenant_id=str(log.tenant_id),
        user_id=str(log.user_id) if log.user_id else None,
        username=None,
        user_roles=[],
        action=AuditAction(log.action) if log.action in [e.value for e in AuditAction] else AuditAction.READ,
        resource_type=log.resource_type,
        resource_id=str(log.resource_id) if log.resource_id else None,
        resource_name=None,
        severity=AuditSeverity(log.severity) if log.severity in [e.value for e in AuditSeverity] else AuditSeverity.INFO,
        ip_address=log.ip_address,
        user_agent=log.user_agent,
        request_method=details_dict.get("method"),
        request_path=details_dict.get("path"),
        request_headers=details_dict,
        request_body=details_dict.get("request_body"),
        response_status_code=details_dict.get("status_code"),
        response_body=details_dict.get("response_body"),
        changes_before=details_dict.get("before"),
        changes_after=details_dict.get("after"),
        changes_diff=details_dict.get("diff"),
        details=details_dict.get("description"),
        duration_ms=details_dict.get("duration_ms"),
        session_id=None,
        trace_id=None,
        timestamp=log.created_at,
        tags=[],
    )


# ════════════════════════════════════════════════════════════════════
# AUDIT STATISTICS
# ════════════════════════════════════════════════════════════════════

@router.get("/stats", response_model=AuditStats)
async def get_audit_stats(
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    granularity: Optional[str] = Query("hour", description="Time series granularity: hour, day, week"),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    base_conditions = [AuditLog.tenant_id == tenant_uuid]

    if date_from:
        base_conditions.append(AuditLog.created_at >= date_from)
    if date_to:
        base_conditions.append(AuditLog.created_at <= date_to)

    now = datetime.now(timezone.utc)
    range_start = date_from or (now - timedelta(days=7))
    range_end = date_to or now

    # Total events
    total_stmt = select(func.count()).select_from(AuditLog).where(and_(*base_conditions))
    total_result = await db.execute(total_stmt)
    total_events = total_result.scalar() or 0

    # By action
    by_action_stmt = (
        select(AuditLog.action, func.count().label("count"))
        .where(and_(*base_conditions))
        .group_by(AuditLog.action)
        .order_by(desc("count"))
    )
    action_results = await db.execute(by_action_stmt)
    by_action = []
    for row in action_results:
        count = row[1]
        by_action.append(AuditStatsEntry(
            label=row[0],
            count=count,
            percentage=round((count / total_events * 100), 1) if total_events > 0 else 0.0,
        ))

    # By user
    by_user_stmt = (
        select(AuditLog.user_id, func.count().label("count"))
        .where(and_(*base_conditions))
        .group_by(AuditLog.user_id)
        .order_by(desc("count"))
        .limit(10)
    )
    user_results = await db.execute(by_user_stmt)
    by_user = []
    for row in user_results:
        count = row[1]
        by_user.append(AuditStatsEntry(
            label=str(row[0]) if row[0] else "system",
            count=count,
            percentage=round((count / total_events * 100), 1) if total_events > 0 else 0.0,
        ))

    # By resource type
    by_resource_stmt = (
        select(AuditLog.resource_type, func.count().label("count"))
        .where(and_(*base_conditions))
        .group_by(AuditLog.resource_type)
        .order_by(desc("count"))
    )
    resource_results = await db.execute(by_resource_stmt)
    by_resource_type = []
    for row in resource_results:
        count = row[1]
        by_resource_type.append(AuditStatsEntry(
            label=row[0],
            count=count,
            percentage=round((count / total_events * 100), 1) if total_events > 0 else 0.0,
        ))

    # By severity
    by_severity_stmt = (
        select(AuditLog.severity, func.count().label("count"))
        .where(and_(*base_conditions))
        .group_by(AuditLog.severity)
        .order_by(desc("count"))
    )
    severity_results = await db.execute(by_severity_stmt)
    by_severity = []
    for row in severity_results:
        count = row[1]
        by_severity.append(AuditStatsEntry(
            label=row[0],
            count=count,
            percentage=round((count / total_events * 100), 1) if total_events > 0 else 0.0,
        ))

    # Time series
    time_format = "YYYY-MM-DD HH24"
    if granularity == "day":
        time_format = "YYYY-MM-DD"
    elif granularity == "week":
        time_format = "IYYY-IW"

    ts_stmt = (
        select(
            func.to_char(AuditLog.created_at, time_format).label("period"),
            func.min(AuditLog.created_at).label("timestamp"),
            func.count().label("count"),
        )
        .where(and_(*base_conditions))
        .group_by("period")
        .order_by("period")
    )
    ts_results = await db.execute(ts_stmt)
    time_series = []
    for row in ts_results:
        time_series.append(AuditTimeSeries(
            period=row[0],
            timestamp=row[1],
            count=row[2],
        ))

    # Top IP addresses
    ip_stmt = (
        select(AuditLog.ip_address, func.count().label("count"))
        .where(and_(AuditLog.ip_address != None, *base_conditions))
        .group_by(AuditLog.ip_address)
        .order_by(desc("count"))
        .limit(10)
    )
    ip_results = await db.execute(ip_stmt)
    top_ip_addresses = []
    for row in ip_results:
        count = row[1]
        top_ip_addresses.append(AuditStatsEntry(
            label=row[0] or "unknown",
            count=count,
            percentage=round((count / total_events * 100), 1) if total_events > 0 else 0.0,
        ))

    # Unique users
    unique_stmt = (
        select(func.count(func.distinct(AuditLog.user_id)))
        .where(and_(AuditLog.user_id != None, *base_conditions))
    )
    unique_result = await db.execute(unique_stmt)
    unique_users = unique_result.scalar() or 0

    return AuditStats(
        total_events=total_events,
        date_range={"from": range_start, "to": range_end},
        by_action=by_action,
        by_user=by_user,
        by_resource_type=by_resource_type,
        by_severity=by_severity,
        time_series=time_series,
        top_ip_addresses=top_ip_addresses,
        unique_users=unique_users,
    )


# ════════════════════════════════════════════════════════════════════
# USER AUDIT LOGS
# ════════════════════════════════════════════════════════════════════

@router.get("/users/{user_id}", response_model=PaginatedResponse)
async def get_user_audit_log(
    user_id: str,
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    action: Optional[AuditAction] = Query(None),
    resource_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    if not _is_valid_uuid(user_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user_id format")

    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [
        AuditLog.tenant_id == tenant_uuid,
        AuditLog.user_id == uuid.UUID(user_id),
    ]

    if action:
        conditions.append(AuditLog.action == action.value)
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if date_from:
        conditions.append(AuditLog.created_at >= date_from)
    if date_to:
        conditions.append(AuditLog.created_at <= date_to)

    count_stmt = select(func.count()).select_from(AuditLog).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        select(AuditLog)
        .where(and_(*conditions))
        .order_by(desc(AuditLog.created_at))
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()

    items = [_log_to_entry(log) for log in logs]
    total_pages = max(1, math.ceil(total / page_size))

    return PaginatedResponse(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# RESOURCE AUDIT TRAIL
# ════════════════════════════════════════════════════════════════════

@router.get("/resources/{resource_type}/{resource_id}", response_model=PaginatedResponse)
async def get_resource_audit_trail(
    resource_type: str,
    resource_id: str,
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    action: Optional[AuditAction] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    if not _is_valid_uuid(resource_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid resource_id format")

    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [
        AuditLog.tenant_id == tenant_uuid,
        AuditLog.resource_type == resource_type,
        AuditLog.resource_id == uuid.UUID(resource_id),
    ]

    if action:
        conditions.append(AuditLog.action == action.value)
    if date_from:
        conditions.append(AuditLog.created_at >= date_from)
    if date_to:
        conditions.append(AuditLog.created_at <= date_to)

    count_stmt = select(func.count()).select_from(AuditLog).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        select(AuditLog)
        .where(and_(*conditions))
        .order_by(desc(AuditLog.created_at))
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()

    items = [_log_to_entry(log) for log in logs]
    total_pages = max(1, math.ceil(total / page_size))

    return PaginatedResponse(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# EXPORT ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@router.get("/export")
async def export_audit_logs(
    format: ExportFormat = Query(ExportFormat.CSV),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    user_id: Optional[str] = Query(None),
    action: Optional[List[AuditAction]] = Query(None),
    resource_type: Optional[str] = Query(None),
    severity: Optional[AuditSeverity] = Query(None),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [AuditLog.tenant_id == tenant_uuid]

    if user_id and _is_valid_uuid(user_id):
        conditions.append(AuditLog.user_id == uuid.UUID(user_id))
    if action:
        conditions.append(AuditLog.action.in_([a.value for a in action]))
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if severity:
        conditions.append(AuditLog.severity == severity.value)
    if date_from:
        conditions.append(AuditLog.created_at >= date_from)
    if date_to:
        conditions.append(AuditLog.created_at <= date_to)

    stmt = (
        select(AuditLog)
        .where(and_(*conditions))
        .order_by(AuditLog.created_at.desc())
        .limit(10000)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()
    items = [_log_to_entry(log) for log in logs]

    if format == ExportFormat.CSV:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "tenant_id", "user_id", "action", "resource_type", "resource_id", "status", "severity", "ip_address", "created_at"])
        for entry in items:
            status_str = entry.details.get("status") if isinstance(entry.details, dict) else ""
            writer.writerow([
                entry.id, entry.tenant_id, entry.user_id or "", entry.action.value,
                entry.resource_type, entry.resource_id or "", status_str,
                entry.severity.value, entry.ip_address or "",
                entry.timestamp.isoformat() if entry.timestamp else "",
            ])
        csv_content = output.getvalue()
        return StreamingResponse(
            iter([csv_content]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_export.csv"},
        )

    return [entry.model_dump() for entry in items]


@router.post("/export/bulk", response_model=ExportStatusResponse, status_code=status.HTTP_202_ACCEPTED)
async def schedule_bulk_export(
    body: ExportBulkRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    export_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    tenant_uuid = uuid.UUID(tenant_id)

    conditions = [AuditLog.tenant_id == tenant_uuid]
    if body.user_id and _is_valid_uuid(body.user_id):
        conditions.append(AuditLog.user_id == uuid.UUID(body.user_id))
    if body.action:
        conditions.append(AuditLog.action.in_([a.value for a in body.action]))
    if body.resource_type:
        conditions.append(AuditLog.resource_type == body.resource_type)
    if body.severity:
        conditions.append(AuditLog.severity == body.severity.value)
    if body.date_from:
        conditions.append(AuditLog.created_at >= body.date_from)
    if body.date_to:
        conditions.append(AuditLog.created_at <= body.date_to)

    stmt = (
        select(AuditLog)
        .where(and_(*conditions))
        .order_by(AuditLog.created_at.desc())
        .limit(10000)
    )
    result = await db.execute(stmt)
    logs = result.scalars().all()
    items = [_log_to_entry(log) for log in logs]

    _export_store[export_id] = {
        "id": export_id,
        "tenant_id": tenant_id,
        "format": body.format.value,
        "status": ExportStatus.COMPLETED.value,
        "filters": body.model_dump(exclude={"format", "notify_on_completion", "notification_channel"}),
        "total_records": len(items),
        "file_size_bytes": len(str([item.model_dump() for item in items])) * 2,
        "created_by": current_user.get("sub") or current_user.get("user_id"),
        "created_at": now,
        "completed_at": now,
        "expires_at": now + timedelta(hours=24),
        "download_url": f"/api/v1/audit/exports/{export_id}/download",
        "error": None,
        "data": [item.model_dump() for item in items],
    }

    return ExportStatusResponse(
        id=export_id,
        tenant_id=tenant_id,
        format=body.format,
        status=ExportStatus.COMPLETED,
        filters=body.model_dump(exclude={"format", "notify_on_completion", "notification_channel"}),
        total_records=len(items),
        file_size_bytes=len(str([item.model_dump() for item in items])) * 2,
        created_by=current_user.get("sub") or current_user.get("user_id"),
        created_at=now,
        completed_at=now,
        expires_at=now + timedelta(hours=24),
        download_url=f"/api/v1/audit/exports/{export_id}/download",
    )


@router.get("/exports/{export_id}", response_model=ExportStatusResponse)
async def get_export_status(
    export_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    export = _export_store.get(export_id)
    if not export:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Export not found",
        )
    if export.get("tenant_id") != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this export",
        )
    return ExportStatusResponse(
        id=export["id"],
        tenant_id=export["tenant_id"],
        format=ExportFormat(export["format"]),
        status=ExportStatus(export["status"]),
        filters=export["filters"],
        total_records=export["total_records"],
        file_size_bytes=export["file_size_bytes"],
        created_by=export["created_by"],
        created_at=export["created_at"],
        completed_at=export["completed_at"],
        expires_at=export["expires_at"],
        download_url=export["download_url"],
        error=export["error"],
    )


@router.get("/exports/{export_id}/download")
async def download_export(
    export_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    export = _export_store.get(export_id)
    if not export:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Export not found",
        )
    if export.get("tenant_id") != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this export",
        )
    return export["data"]


# ════════════════════════════════════════════════════════════════════
# RETENTION ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@router.get("/retention", response_model=RetentionConfig)
async def get_retention_config(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    return RetentionConfig(
        tenant_id=tenant_id,
        retention_days=_retention_config.get("retention_days", 90),
        archive_enabled=False,
        archive_storage=None,
        auto_purge_enabled=False,
        purge_schedule=None,
        critical_event_retention_days=_retention_config.get("critical_event_retention_days", 365),
        last_purge_at=None,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


@router.patch("/retention", response_model=RetentionConfig)
async def update_retention_policy(
    body: RetentionUpdate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    if body.retention_days is not None:
        _retention_config["retention_days"] = body.retention_days
    if body.critical_event_retention_days is not None:
        _retention_config["critical_event_retention_days"] = body.critical_event_retention_days

    return RetentionConfig(
        tenant_id=tenant_id,
        retention_days=_retention_config.get("retention_days", 90),
        archive_enabled=body.archive_enabled if body.archive_enabled is not None else False,
        archive_storage=body.archive_storage,
        auto_purge_enabled=body.auto_purge_enabled if body.auto_purge_enabled is not None else False,
        purge_schedule=body.purge_schedule,
        critical_event_retention_days=_retention_config.get("critical_event_retention_days", 365),
        last_purge_at=None,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


# ════════════════════════════════════════════════════════════════════
# PURGE ENDPOINT
# ════════════════════════════════════════════════════════════════════

@router.post("/purge", response_model=PurgeResponse)
async def purge_old_logs(
    body: PurgeRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    cutoff_date = body.before_date or (datetime.now(timezone.utc) - timedelta(days=90))

    conditions = [
        AuditLog.tenant_id == tenant_uuid,
        AuditLog.created_at < cutoff_date,
    ]
    if body.action_types:
        conditions.append(AuditLog.action.in_([a.value for a in body.action_types]))

    count_stmt = select(func.count()).select_from(AuditLog).where(and_(*conditions))
    count_result = await db.execute(count_stmt)
    eligible_count = count_result.scalar() or 0

    if body.dry_run:
        return PurgeResponse(
            dry_run=True,
            total_records_eligible=eligible_count,
            records_purged=None,
            storage_freed_bytes=None,
            duration_ms=0.0,
        )

    if not body.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Set confirm=True to actually purge logs",
        )

    start_time = datetime.now(timezone.utc)
    delete_stmt = AuditLog.__table__.delete().where(and_(*conditions))
    result = await db.execute(delete_stmt)
    await db.flush()

    duration = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
    records_purged = result.rowcount

    return PurgeResponse(
        dry_run=False,
        total_records_eligible=eligible_count,
        records_purged=records_purged,
        storage_freed_bytes=records_purged * 2048 if records_purged else 0,
        duration_ms=duration,
    )


# ════════════════════════════════════════════════════════════════════
# SESSION ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@router.get("/sessions", response_model=List[ActiveSession])
async def list_active_sessions(
    user_id: Optional[str] = Query(None),
    session_status: Optional[SessionStatus] = Query(SessionStatus.ACTIVE, alias="status"),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    now = datetime.now(timezone.utc)
    conditions = [
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > now,
        RefreshToken.tenant_id == tenant_uuid,
    ]

    if user_id and _is_valid_uuid(user_id):
        conditions.append(RefreshToken.user_id == uuid.UUID(user_id))

    if session_status == SessionStatus.REVOKED:
        conditions = [
            RefreshToken.is_revoked == True,
            RefreshToken.tenant_id == tenant_uuid,
        ]
        if user_id and _is_valid_uuid(user_id):
            conditions.append(RefreshToken.user_id == uuid.UUID(user_id))
    elif session_status == SessionStatus.EXPIRED:
        conditions = [
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at <= now,
            RefreshToken.tenant_id == tenant_uuid,
        ]
        if user_id and _is_valid_uuid(user_id):
            conditions.append(RefreshToken.user_id == uuid.UUID(user_id))

    stmt = select(RefreshToken).where(and_(*conditions)).order_by(desc(RefreshToken.created_at)).limit(100)
    result = await db.execute(stmt)
    tokens = result.scalars().all()

    sessions = []
    for token in tokens:
        is_expired = token.expires_at <= now
        status_val = SessionStatus.REVOKED if token.is_revoked else (SessionStatus.EXPIRED if is_expired else SessionStatus.ACTIVE)
        sessions.append(ActiveSession(
            session_id=str(token.id),
            user_id=str(token.user_id),
            username="unknown",
            tenant_id=str(token.tenant_id),
            ip_address=None,
            user_agent=None,
            login_at=token.created_at,
            last_activity_at=token.updated_at,
            expires_at=token.expires_at,
            status=status_val,
            device_info=None,
        ))

    return sessions


@router.post("/sessions/{session_id}/revoke", response_model=MessageResponse)
async def revoke_session(
    session_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireTenantAdmin),
    db: AsyncSession = Depends(get_db),
):
    if not _is_valid_uuid(session_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid session_id format")

    tenant_uuid = uuid.UUID(tenant_id)
    session_uuid = uuid.UUID(session_id)

    stmt = select(RefreshToken).where(
        RefreshToken.id == session_uuid,
        RefreshToken.tenant_id == tenant_uuid,
    )
    result = await db.execute(stmt)
    token = result.scalars().first()

    if not token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    token.is_revoked = True
    token.updated_at = datetime.now(timezone.utc)
    await db.flush()

    return MessageResponse(message="Session revoked successfully", detail=f"Session {session_id} has been revoked")


# ════════════════════════════════════════════════════════════════════
# API USAGE ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@router.get("/api-usage", response_model=ApiUsageStats)
async def get_api_usage(
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    user_id: Optional[str] = Query(None),
    endpoint: Optional[str] = Query(None),
    method: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [
        AuditLog.tenant_id == tenant_uuid,
        AuditLog.resource_type == "api",
    ]

    if date_from:
        conditions.append(AuditLog.created_at >= date_from)
    if date_to:
        conditions.append(AuditLog.created_at <= date_to)
    if user_id and _is_valid_uuid(user_id):
        conditions.append(AuditLog.user_id == uuid.UUID(user_id))

    now = datetime.now(timezone.utc)
    range_start = date_from or (now - timedelta(days=7))
    range_end = date_to or now

    total_stmt = select(func.count()).select_from(AuditLog).where(and_(*conditions))
    total_result = await db.execute(total_stmt)
    total_requests = total_result.scalar() or 0

    error_conditions = list(conditions)
    error_conditions.append(AuditLog.status == "error")
    error_stmt = select(func.count()).select_from(AuditLog).where(and_(*error_conditions))
    error_result = await db.execute(error_stmt)
    total_errors = error_result.scalar() or 0

    overall_error_rate = round((total_errors / total_requests * 100), 2) if total_requests > 0 else 0.0

    by_endpoint_stmt = (
        select(
            AuditLog.resource_type,
            func.count().label("request_count"),
            func.count().filter(AuditLog.status == "error").label("error_count"),
        )
        .where(and_(*conditions))
        .group_by(AuditLog.resource_type)
        .order_by(desc("request_count"))
        .limit(20)
    )
    endpoint_results = await db.execute(by_endpoint_stmt)
    by_endpoint = []
    for row in endpoint_results:
        count = row[1]
        err_count = row[2] or 0
        by_endpoint.append(ApiUsageEntry(
            endpoint=row[0] or "unknown",
            method="UNKNOWN",
            request_count=count,
            avg_response_time_ms=None,
            error_count=err_count,
            error_rate=round((err_count / count * 100), 2) if count > 0 else 0.0,
        ))

    by_user_stmt = (
        select(
            AuditLog.user_id,
            func.count().label("request_count"),
            func.count(func.distinct(AuditLog.resource_type)).label("endpoints_used"),
            func.count().filter(AuditLog.status == "error").label("error_count"),
        )
        .where(and_(AuditLog.user_id != None, *conditions))
        .group_by(AuditLog.user_id)
        .order_by(desc("request_count"))
        .limit(20)
    )
    user_results = await db.execute(by_user_stmt)
    by_user = []
    for row in user_results:
        by_user.append(UserApiUsage(
            user_id=str(row[0]) if row[0] else "unknown",
            username="unknown",
            request_count=row[1],
            avg_response_time_ms=None,
            endpoints_used=row[2] or 0,
            error_count=row[3] or 0,
        ))

    return ApiUsageStats(
        period={"from": range_start, "to": range_end},
        total_requests=total_requests,
        total_errors=total_errors,
        overall_error_rate=overall_error_rate,
        avg_response_time_ms=None,
        by_endpoint=by_endpoint,
        by_user=by_user,
    )


# ════════════════════════════════════════════════════════════════════
# SUMMARY ENDPOINTS
# ════════════════════════════════════════════════════════════════════

@router.get("/summary/daily", response_model=List[DailySummary])
async def get_daily_summary(
    date: Optional[str] = Query(None, description="Specific date in YYYY-MM-DD format, defaults to today"),
    days: int = Query(7, ge=1, le=30, description="Number of past days to include"),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    end_date = datetime.now(timezone.utc)
    if date:
        try:
            end_date = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format, use YYYY-MM-DD")

    start_date = end_date - timedelta(days=days)

    daily_stmt = (
        select(
            cast(AuditLog.created_at, Date).label("date"),
            func.count().label("count"),
            func.count(func.distinct(AuditLog.user_id)).label("unique_users"),
        )
        .where(
            AuditLog.tenant_id == tenant_uuid,
            AuditLog.created_at >= start_date,
            AuditLog.created_at <= end_date,
        )
        .group_by("date")
        .order_by("date")
    )
    daily_results = await db.execute(daily_stmt)

    summaries = []
    for row in daily_results:
        day_str = row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0])
        summaries.append(DailySummary(
            date=day_str,
            total_events=row[1] or 0,
            unique_users=row[2] or 0,
            by_action={},
            by_severity={},
            top_users=[],
            top_resources=[],
            notable_events=[],
        ))

    return summaries


@router.get("/summary/weekly", response_model=List[WeeklySummary])
async def get_weekly_summary(
    week_start: Optional[str] = Query(None, description="Week start date YYYY-MM-DD, defaults to current week"),
    weeks: int = Query(4, ge=1, le=12, description="Number of past weeks to include"),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    now = datetime.now(timezone.utc)
    end_date = now
    if week_start:
        try:
            end_date = datetime.strptime(week_start, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=6)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid date format, use YYYY-MM-DD")

    start_date = end_date - timedelta(weeks=weeks)

    weekly_stmt = (
        select(
            func.date_trunc("week", AuditLog.created_at).label("week"),
            func.count().label("count"),
            func.count(func.distinct(AuditLog.user_id)).label("unique_users"),
        )
        .where(
            AuditLog.tenant_id == tenant_uuid,
            AuditLog.created_at >= start_date,
            AuditLog.created_at <= end_date,
        )
        .group_by("week")
        .order_by("week")
    )
    weekly_results = await db.execute(weekly_stmt)

    summaries = []
    for row in weekly_results:
        week_dt = row[0]
        week_end_dt = week_dt + timedelta(days=6)
        summaries.append(WeeklySummary(
            week_start=week_dt.strftime("%Y-%m-%d") if hasattr(week_dt, "strftime") else str(week_dt),
            week_end=week_end_dt.strftime("%Y-%m-%d") if hasattr(week_end_dt, "strftime") else str(week_end_dt),
            total_events=row[1] or 0,
            unique_users=row[2] or 0,
            daily_breakdown=[],
            by_action={},
            by_severity={},
            comparison_previous_week=None,
        ))

    return summaries


# ════════════════════════════════════════════════════════════════════
# ANOMALY DETECTION
# ════════════════════════════════════════════════════════════════════

@router.get("/anomalies", response_model=AnomalyDetectionResponse)
async def detect_audit_anomalies(
    lookback_hours: int = Query(24, ge=1, le=168, description="Hours to analyze for anomalies"),
    baseline_hours: int = Query(168, ge=24, le=720, description="Hours used for baseline comparison"),
    sensitivity: str = Query("medium", description="Detection sensitivity: low, medium, high"),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireAuditor),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    tenant_uuid = uuid.UUID(tenant_id)
    analysis_start = now - timedelta(hours=lookback_hours)
    baseline_start = now - timedelta(hours=baseline_hours + lookback_hours)
    baseline_end = analysis_start

    multiplier_map = {"low": 3.0, "medium": 2.0, "high": 1.5}
    std_multiplier = multiplier_map.get(sensitivity, 2.0)

    hourly_stmt = (
        select(
            func.date_trunc("hour", AuditLog.created_at).label("hour"),
            func.count().label("count"),
            func.count(func.distinct(AuditLog.user_id)).label("unique_users"),
            func.count(func.distinct(AuditLog.action)).label("unique_actions"),
        )
        .where(
            AuditLog.tenant_id == tenant_uuid,
            AuditLog.created_at >= baseline_start,
            AuditLog.created_at <= now,
        )
        .group_by("hour")
        .order_by("hour")
    )
    hourly_results = await db.execute(hourly_stmt)
    hourly_data = []
    for row in hourly_results:
        hourly_data.append({
            "hour": row[0],
            "count": row[1] or 0,
            "unique_users": row[2] or 0,
            "unique_actions": row[3] or 0,
        })

    baseline_entries = [h for h in hourly_data if h["hour"] >= baseline_start and h["hour"] < baseline_end]
    analysis_entries = [h for h in hourly_data if h["hour"] >= analysis_start]

    total_events_analyzed = sum(h["count"] for h in analysis_entries)

    baseline_counts = [h["count"] for h in baseline_entries]
    if not baseline_counts:
        base_mean = 0.0
        base_std = 1.0
    else:
        base_mean = sum(baseline_counts) / len(baseline_counts)
        variance = sum((x - base_mean) ** 2 for x in baseline_counts) / len(baseline_counts)
        base_std = variance ** 0.5

    # Also calculate user count baseline
    baseline_users = [h["unique_users"] for h in baseline_entries]
    if baseline_users:
        user_mean = sum(baseline_users) / len(baseline_users)
        user_var = sum((x - user_mean) ** 2 for x in baseline_users) / len(baseline_users)
        user_std = user_var ** 0.5
    else:
        user_mean = 0.0
        user_std = 1.0

    threshold = base_mean + (std_multiplier * base_std)
    user_threshold = user_mean + (std_multiplier * user_std)

    anomalies: List[AuditAnomaly] = []
    for entry in analysis_entries:
        hour_count = entry["count"]
        hour_users = entry["unique_users"]
        hour = entry["hour"]

        if hour_count > threshold and hour_count > 5:
            deviation = (hour_count - base_mean) / base_std if base_std > 0 else 0.0
            sev = AuditSeverity.CRITICAL if deviation > 4 else (AuditSeverity.HIGH if deviation > 3 else (AuditSeverity.WARNING if deviation > 2 else AuditSeverity.INFO))

            anomalies.append(AuditAnomaly(
                id=str(uuid.uuid4()),
                anomaly_type="high_activity",
                severity=sev,
                description=f"Unusually high audit activity detected at {hour}: {hour_count} events (baseline mean: {base_mean:.1f}, std: {base_std:.1f})",
                user_id=None,
                username=None,
                resource_type="audit_log",
                detected_at=now,
                baseline={"mean_hourly_events": round(base_mean, 2), "std": round(base_std, 2)},
                observed={"hourly_events": hour_count, "hour": hour.isoformat() if hasattr(hour, "isoformat") else str(hour)},
                deviation_factor=round(deviation, 2),
                recommendation="Investigate the spike in audit activity. Check for potential automated scripts, bulk operations, or unauthorized access.",
            ))

        if hour_users > user_threshold and hour_users > 3:
            deviation = (hour_users - user_mean) / user_std if user_std > 0 else 0.0
            anomalies.append(AuditAnomaly(
                id=str(uuid.uuid4()),
                anomaly_type="unusual_user_volume",
                severity=AuditSeverity.WARNING,
                description=f"Unusually high number of unique users ({hour_users}) generating audit activity at {hour}",
                user_id=None,
                username=None,
                resource_type="audit_log",
                detected_at=now,
                baseline={"mean_unique_users": round(user_mean, 2), "std": round(user_std, 2)},
                observed={"unique_users": hour_users, "hour": hour.isoformat() if hasattr(hour, "isoformat") else str(hour)},
                deviation_factor=round(deviation, 2),
                recommendation="Review the diversity of users active during this period for possible credential sharing or lateral movement.",
            ))

    anomalies.sort(key=lambda a: a.deviation_factor or 0, reverse=True)

    return AnomalyDetectionResponse(
        detected_at=now,
        anomalies=anomalies[:50],
        total_events_analyzed=total_events_analyzed,
        analysis_period={"from": analysis_start, "to": now},
        baseline_period={"from": baseline_start, "to": baseline_end},
    )
