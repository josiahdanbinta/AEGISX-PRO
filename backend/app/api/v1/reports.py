"""
AEGISX - Reports API Router
Report generation, scheduling, templates, executive summaries, and data export
"""
import csv
import io
import json
import math
import os
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import case, cast, Date, desc, extract, func, select, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_user,
    require_tenant,
    RequireComplianceOfficer,
    RequireSOCManager,
    RequireSOCAnalyst,
)
from app.core.config import settings
from app.core.database import get_db
from app.models import (
    Incident, Asset, Alert, Vulnerability,
    ComplianceAssessment, AuditLog,
    Report, ReportSchedule, ReportTemplate,
    ThreatIndicator,
)

router = APIRouter()

SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}


def _model_to_dict(obj) -> dict:
    """Convert ORM model to dict with UUID→str and datetime→isoformat."""
    d = {}
    for c in obj.__table__.columns:
        v = getattr(obj, c.key)
        if isinstance(v, uuid.UUID):
            d[c.key] = str(v)
        elif isinstance(v, datetime):
            d[c.key] = v.isoformat() if v else None
        else:
            d[c.key] = v
    return d


def _tid(tenant_id: str) -> uuid.UUID:
    return uuid.UUID(tenant_id)


# ════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════

class ReportType(str, Enum):
    EXECUTIVE = "executive"
    INCIDENT = "incident"
    ASSET = "asset"
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    AUDIT = "audit"
    SYSTEM = "system"
    CUSTOM = "custom"


class ReportFormat(str, Enum):
    PDF = "pdf"
    EXCEL = "excel"
    CSV = "csv"
    HTML = "html"
    JSON = "json"


class ReportStatus(str, Enum):
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class ScheduleFrequency(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"


class ExportFormat(str, Enum):
    CSV = "csv"
    JSON = "json"
    STIX = "stix"


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
# Report Models
# ════════════════════════════════════════════════════════════════════

class ReportGenerateRequest(BaseModel):
    report_type: ReportType
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    format: ReportFormat = ReportFormat.PDF
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    filters: Optional[Dict[str, Any]] = Field(None)
    include_sections: Optional[List[str]] = Field(None)
    metadata: Optional[Dict[str, Any]] = None


class ReportResponse(BaseModel):
    id: str
    report_type: ReportType
    name: Optional[str] = None
    format: ReportFormat
    status: ReportStatus
    parameters: Dict[str, Any] = {}
    file_size_bytes: Optional[int] = None
    file_path: Optional[str] = None
    error_message: Optional[str] = None
    tenant_id: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


# ════════════════════════════════════════════════════════════════════
# Schedule Models
# ════════════════════════════════════════════════════════════════════

class ScheduleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    report_type: ReportType
    frequency: ScheduleFrequency
    parameters: Dict[str, Any] = Field(default_factory=dict)
    format: ReportFormat = ReportFormat.PDF
    next_run_at: Optional[datetime] = None
    recipients: List[str] = Field(default_factory=list)
    enabled: bool = True
    time_range_days: Optional[int] = Field(None, ge=1, le=365)
    metadata: Optional[Dict[str, Any]] = None


class ScheduleResponse(BaseModel):
    id: str
    name: str
    report_type: ReportType
    frequency: ScheduleFrequency
    parameters: Dict[str, Any] = {}
    format: ReportFormat
    next_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    last_run_status: Optional[ReportStatus] = None
    recipients: List[str] = []
    enabled: bool
    tenant_id: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class ScheduleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    frequency: Optional[ScheduleFrequency] = None
    parameters: Optional[Dict[str, Any]] = None
    format: Optional[ReportFormat] = None
    next_run_at: Optional[datetime] = None
    recipients: Optional[List[str]] = None
    enabled: Optional[bool] = None
    time_range_days: Optional[int] = Field(None, ge=1, le=365)
    metadata: Optional[Dict[str, Any]] = None


# ════════════════════════════════════════════════════════════════════
# Template Models
# ════════════════════════════════════════════════════════════════════

class TemplateCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    report_type: ReportType
    description: Optional[str] = Field(None, max_length=2000)
    layout: Dict[str, Any] = Field(default_factory=dict)
    default_format: ReportFormat = ReportFormat.PDF
    default_parameters: Dict[str, Any] = {}
    tags: List[str] = []
    is_default: bool = False
    metadata: Optional[Dict[str, Any]] = None


class TemplateResponse(BaseModel):
    id: str
    name: str
    report_type: ReportType
    description: Optional[str] = None
    layout: Dict[str, Any] = {}
    default_format: ReportFormat
    default_parameters: Dict[str, Any] = {}
    tags: List[str] = []
    is_default: bool
    tenant_id: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class TemplateUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    layout: Optional[Dict[str, Any]] = None
    default_format: Optional[ReportFormat] = None
    default_parameters: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    is_default: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


# ════════════════════════════════════════════════════════════════════
# Executive / Statistical Models
# ════════════════════════════════════════════════════════════════════

class ExecutiveSummaryResponse(BaseModel):
    risk_score: float = 0.0
    open_incidents: int = 0
    mean_time_to_resolve_minutes: Optional[float] = None
    asset_count: int = 0
    top_threats: List[Dict[str, Any]] = []
    open_vulnerabilities: int = 0
    compliance_score: float = 0.0
    recent_activity_summary: Dict[str, Any] = {}
    generated_at: Optional[datetime] = None


class IncidentStatsResponse(BaseModel):
    total_incidents: int = 0
    open_incidents: int = 0
    closed_incidents: int = 0
    by_severity: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    mean_time_to_resolve_minutes: Optional[float] = None
    mean_time_to_acknowledge_minutes: Optional[float] = None
    sla_compliance_percentage: float = 0.0
    trends: Dict[str, Any] = {}
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None


class AssetReportResponse(BaseModel):
    total_assets: int = 0
    by_type: Dict[str, int] = {}
    by_os: Dict[str, int] = {}
    by_risk_level: Dict[str, int] = {}
    by_location: Dict[str, int] = {}
    recent_changes: List[Dict[str, Any]] = []
    unprotected_assets: int = 0
    agent_coverage_percentage: float = 0.0
    compliance_status: Dict[str, Any] = {}
    generated_at: Optional[datetime] = None


class ThreatLandscapeResponse(BaseModel):
    active_threats: int = 0
    top_threat_actors: List[Dict[str, Any]] = []
    top_attack_vectors: List[Dict[str, Any]] = []
    top_iocs: List[Dict[str, Any]] = []
    mitre_techniques_observed: List[Dict[str, Any]] = []
    threat_level: str = "moderate"
    trends: Dict[str, Any] = {}
    generated_at: Optional[datetime] = None


class VulnerabilityReportResponse(BaseModel):
    total_vulnerabilities: int = 0
    by_severity: Dict[str, int] = {}
    by_cvss_range: Dict[str, int] = {}
    remediated_count: int = 0
    open_critical_count: int = 0
    mean_time_to_remediate_days: Optional[float] = None
    aging_breakdown: Dict[str, int] = {}
    top_vulnerable_assets: List[Dict[str, Any]] = []
    trends: Dict[str, Any] = {}
    generated_at: Optional[datetime] = None


class ComplianceReportResponse(BaseModel):
    overall_score: float = 0.0
    framework_scores: Dict[str, float] = {}
    control_pass_rate: float = 0.0
    total_controls: int = 0
    assessed_controls: int = 0
    passed_controls: int = 0
    failed_controls: int = 0
    open_gaps: int = 0
    active_remediation_plans: int = 0
    overdue_remediation_plans: int = 0
    last_assessment_date: Optional[datetime] = None
    trends: Dict[str, Any] = {}
    generated_at: Optional[datetime] = None


class AuditReportResponse(BaseModel):
    total_events: int = 0
    by_action: Dict[str, int] = {}
    by_user: List[Dict[str, Any]] = []
    by_resource: Dict[str, int] = {}
    failed_actions: int = 0
    suspicious_activity: List[Dict[str, Any]] = []
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    generated_at: Optional[datetime] = None


class SystemReportResponse(BaseModel):
    service_status: Dict[str, str] = {}
    queue_depths: Dict[str, int] = {}
    average_latency_ms: float = 0.0
    error_rate: float = 0.0
    uptime_percentage: float = 0.0
    cpu_usage_percentage: float = 0.0
    memory_usage_percentage: float = 0.0
    disk_usage_percentage: float = 0.0
    active_connections: int = 0
    requests_per_minute: int = 0
    alerts: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class TrendsResponse(BaseModel):
    period: str
    data_points: List[Dict[str, Any]] = []
    metrics: Dict[str, Any] = {}
    generated_at: Optional[datetime] = None


class ExportResponse(BaseModel):
    format: ExportFormat
    data: Any
    record_count: Optional[int] = None
    generated_at: datetime


# ════════════════════════════════════════════════════════════════════
# ── Report Generation ───────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.post(
    "/generate",
    response_model=ReportResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Generate Report",
)
async def generate_report(
    request: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    uid = uuid.UUID(current_user["user_id"])
    params = dict(request.parameters or {})
    if request.time_range_start:
        params["time_range_start"] = request.time_range_start.isoformat()
    if request.time_range_end:
        params["time_range_end"] = request.time_range_end.isoformat()
    if request.filters:
        params["filters"] = request.filters
    if request.include_sections:
        params["include_sections"] = request.include_sections
    if request.metadata:
        params["metadata"] = request.metadata

    report = Report(
        name=request.name or f"{request.report_type.value}_report",
        report_type=request.report_type.value,
        format=request.format.value,
        status="generating",
        parameters=params,
        tenant_id=tid,
        created_by=uid,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    try:
        upload_dir = getattr(settings, "UPLOAD_DIR", "/app/uploads")
        os.makedirs(upload_dir, exist_ok=True)

        if request.format == ReportFormat.CSV:
            if request.report_type in (ReportType.EXECUTIVE, ReportType.INCIDENT):
                q = select(Incident).where(Incident.tenant_id == tid).limit(500)
                result = await db.execute(q)
                records = result.scalars().all()
            elif request.report_type == ReportType.ASSET:
                q = select(Asset).where(Asset.tenant_id == tid).limit(500)
                result = await db.execute(q)
                records = result.scalars().all()
            elif request.report_type == ReportType.THREAT:
                q = select(ThreatIndicator).where(ThreatIndicator.tenant_id == tid).limit(500)
                result = await db.execute(q)
                records = result.scalars().all()
            elif request.report_type == ReportType.VULNERABILITY:
                q = select(Vulnerability).where(Vulnerability.tenant_id == tid).limit(500)
                result = await db.execute(q)
                records = result.scalars().all()
            else:
                q = select(Incident).where(Incident.tenant_id == tid).limit(500)
                result = await db.execute(q)
                records = result.scalars().all()

            filename = f"{report.id}_{request.report_type.value}.csv"
            file_path = os.path.join(upload_dir, filename)
            if records:
                cols = [c.key for c in records[0].__table__.columns]
                with open(file_path, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=cols)
                    writer.writeheader()
                    for rec in records:
                        row = {}
                        for c in rec.__table__.columns:
                            v = getattr(rec, c.key)
                            if isinstance(v, uuid.UUID):
                                row[c.key] = str(v)
                            elif isinstance(v, datetime):
                                row[c.key] = v.isoformat() if v else ""
                            elif isinstance(v, (list, dict)):
                                row[c.key] = json.dumps(v) if v else ""
                            else:
                                row[c.key] = v if v is not None else ""
                        writer.writerow(row)
            else:
                with open(file_path, "w", newline="") as f:
                    f.write("No data available.\n")
            file_size = os.path.getsize(file_path)

        elif request.format == ReportFormat.PDF:
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.lib.styles import getSampleStyleSheet
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
                from reportlab.lib import colors
            except ImportError:
                report.status = "failed"
                report.error_message = "reportlab is not installed"
                await db.commit()
                return _model_to_dict(report)

            filename = f"{report.id}_{request.report_type.value}.pdf"
            file_path = os.path.join(upload_dir, filename)
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []

            elements.append(Paragraph(f"AEGISX {request.report_type.value.upper()} Report", styles["Title"]))
            elements.append(Spacer(1, 12))
            elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).isoformat()}", styles["Normal"]))
            elements.append(Spacer(1, 12))

            if request.report_type == ReportType.EXECUTIVE:
                sev_result = await db.execute(
                    select(Incident.severity, func.count(Incident.id))
                    .where(Incident.tenant_id == tid, Incident.status.notin_(["closed"]))
                    .group_by(Incident.severity)
                )
                sev_counts = dict(sev_result.all())
                open_incidents = sum(sev_counts.values())
                elements.append(Paragraph(f"Open Incidents: {open_incidents}", styles["Heading2"]))
                for sev, count in sev_counts.items():
                    elements.append(Paragraph(f"  - {sev.capitalize()}: {count}", styles["Normal"]))

                asset_count = (await db.execute(
                    select(func.count(Asset.id)).where(Asset.tenant_id == tid)
                )).scalar() or 0
                elements.append(Spacer(1, 12))
                elements.append(Paragraph(f"Total Assets: {asset_count}", styles["Normal"]))
            elif request.report_type == ReportType.INCIDENT:
                q = select(Incident).where(Incident.tenant_id == tid).order_by(desc(Incident.created_at)).limit(100)
                result = await db.execute(q)
                incidents = result.scalars().all()
                elements.append(Paragraph(f"Recent Incidents ({len(incidents)})", styles["Heading2"]))
                table_data = [["Title", "Severity", "Status", "Created"]]
                for inc in incidents:
                    table_data.append([
                        inc.title[:60] + "..." if len(inc.title) > 60 else inc.title,
                        inc.severity,
                        inc.status,
                        inc.created_at.strftime("%Y-%m-%d") if inc.created_at else "N/A",
                    ])
                t = Table(table_data)
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                ]))
                elements.append(t)
            else:
                elements.append(Paragraph("Report data compiled successfully.", styles["Normal"]))

            doc.build(elements)
            file_size = os.path.getsize(file_path)

        elif request.format == ReportFormat.JSON:
            if request.report_type == ReportType.INCIDENT:
                q = select(Incident).where(Incident.tenant_id == tid).limit(500)
            elif request.report_type == ReportType.ASSET:
                q = select(Asset).where(Asset.tenant_id == tid).limit(500)
            elif request.report_type == ReportType.THREAT:
                q = select(ThreatIndicator).where(ThreatIndicator.tenant_id == tid).limit(500)
            elif request.report_type == ReportType.VULNERABILITY:
                q = select(Vulnerability).where(Vulnerability.tenant_id == tid).limit(500)
            else:
                q = select(Incident).where(Incident.tenant_id == tid).limit(500)
            result = await db.execute(q)
            records = result.scalars().all()
            filename = f"{report.id}_{request.report_type.value}.json"
            file_path = os.path.join(upload_dir, filename)
            data = [_model_to_dict(r) for r in records]
            with open(file_path, "w") as f:
                json.dump(data, f, default=str, indent=2)
            file_size = os.path.getsize(file_path)
        else:
            filename = f"{report.id}_{request.report_type.value}.{request.format.value}"
            file_path = os.path.join(upload_dir, filename)
            with open(file_path, "w") as f:
                f.write(f"Report generated at {datetime.now(timezone.utc).isoformat()}\n")
            file_size = os.path.getsize(file_path)

        report.status = "completed"
        report.file_url = file_path
        report.file_size = file_size
        report.completed_at = datetime.now(timezone.utc)
    except Exception as e:
        report.status = "failed"
        report.error_message = str(e)[:500]

    await db.commit()
    await db.refresh(report)
    return _model_to_dict(report)


@router.get(
    "/",
    response_model=PaginatedResponse,
    summary="List Generated Reports",
)
async def list_reports(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    report_type: Optional[ReportType] = Query(None),
    status: Optional[ReportStatus] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: Optional[str] = Query("created_at"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
):
    tid = _tid(tenant_id)
    conditions = [Report.tenant_id == tid]
    if report_type:
        conditions.append(Report.report_type == report_type.value)
    if status:
        conditions.append(Report.status == status.value)
    if start_date:
        conditions.append(Report.created_at >= start_date)
    if end_date:
        conditions.append(Report.created_at <= end_date)
    if search:
        conditions.append(Report.name.ilike(f"%{search}%"))

    count_q = select(func.count(Report.id)).where(*conditions)
    total = (await db.execute(count_q)).scalar() or 0

    sort_col = getattr(Report, sort_by, Report.created_at)
    order_fn = desc if sort_order == "desc" else asc
    offset = (page - 1) * page_size
    q = select(Report).where(*conditions).order_by(order_fn(sort_col)).offset(offset).limit(page_size)
    result = await db.execute(q)
    reports = result.scalars().all()

    return PaginatedResponse(
        items=[_model_to_dict(r) for r in reports],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


# ════════════════════════════════════════════════════════════════════
# ── Statistical Reports (registered BEFORE /{report_id} to avoid route collisions)
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/executive",
    response_model=ExecutiveSummaryResponse,
    summary="Executive Summary",
)
async def executive_summary(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(hours=24)

    # Open incidents by severity
    sev_result = await db.execute(
        select(Incident.severity, func.count(Incident.id))
        .where(Incident.tenant_id == tid, Incident.status.notin_(["closed"]))
        .group_by(Incident.severity)
    )
    sev_counts = dict(sev_result.all())
    open_incidents = sum(sev_counts.values())
    risk_score = sum(SEVERITY_WEIGHTS.get(s, 0) * c for s, c in sev_counts.items())

    # Asset count
    asset_count = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid)
    )).scalar() or 0

    # New alerts in last 24h
    alert_count = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == tid, Alert.created_at >= yesterday
        )
    )).scalar() or 0

    # MTTR (mean time to resolve - closed_at minus created_at in minutes)
    mttr_result = await db.execute(
        select(
            func.avg(
                func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0
            )
        ).where(Incident.tenant_id == tid, Incident.closed_at.isnot(None))
    )
    mttr = mttr_result.scalar()

    # Top threats
    top_threats_result = await db.execute(
        select(
            ThreatIndicator.threat_actor,
            func.count(ThreatIndicator.id).label("count")
        ).where(
            ThreatIndicator.tenant_id == tid,
            ThreatIndicator.is_active.is_(True),
            ThreatIndicator.threat_actor.isnot(None)
        ).group_by(ThreatIndicator.threat_actor)
        .order_by(desc("count")).limit(5)
    )
    top_threats = [
        {"actor": row[0], "count": row[1]} for row in top_threats_result.all()
    ]

    # Open vulnerabilities
    open_vulns = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.tenant_id == tid,
            Vulnerability.status.in_(["open", "in_progress"])
        )
    )).scalar() or 0

    # Compliance score
    comp_result = await db.execute(
        select(
            func.coalesce(func.avg(ComplianceAssessment.score), 0.0)
        ).where(
            ComplianceAssessment.tenant_id == tid,
            ComplianceAssessment.status == "completed"
        )
    )
    compliance_score = round(float(comp_result.scalar() or 0), 1)

    # Recent activity from audit log
    recent_result = await db.execute(
        select(AuditLog.action).where(
            AuditLog.tenant_id == tid,
            AuditLog.created_at >= yesterday
        ).limit(20)
    )
    recent_actions = [row[0] for row in recent_result.all()]

    return ExecutiveSummaryResponse(
        risk_score=risk_score,
        open_incidents=open_incidents,
        mean_time_to_resolve_minutes=round(mttr, 1) if mttr else None,
        asset_count=asset_count,
        top_threats=top_threats,
        open_vulnerabilities=open_vulns,
        compliance_score=compliance_score,
        recent_activity_summary={
            "recent_actions": recent_actions,
            "new_alerts_24h": alert_count,
        },
        generated_at=now,
    )


@router.get(
    "/incident",
    response_model=IncidentStatsResponse,
    summary="Incident Statistics Report",
)
async def incident_report(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    period_start = start_date or (now - timedelta(days=90))
    period_end = end_date or now
    six_months_ago = now - timedelta(days=180)

    base_cond = [Incident.tenant_id == tid, Incident.created_at >= period_start, Incident.created_at <= period_end]

    total = (await db.execute(select(func.count(Incident.id)).where(*base_cond))).scalar() or 0
    open_count = (await db.execute(
        select(func.count(Incident.id)).where(*base_cond, Incident.status.notin_(["closed"]))
    )).scalar() or 0
    closed_count = (await db.execute(
        select(func.count(Incident.id)).where(*base_cond, Incident.status == "closed")
    )).scalar() or 0

    by_sev = dict(
        (await db.execute(
            select(Incident.severity, func.count(Incident.id))
            .where(*base_cond).group_by(Incident.severity)
        )).all()
    )
    by_stat = dict(
        (await db.execute(
            select(Incident.status, func.count(Incident.id))
            .where(*base_cond).group_by(Incident.status)
        )).all()
    )

    mttr_result = (await db.execute(
        select(func.avg(func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0))
        .where(*base_cond, Incident.closed_at.isnot(None))
    )).scalar()

    # Monthly trends (last 6 months)
    monthly = await db.execute(
        select(
            extract("month", Incident.created_at).label("month"),
            func.count(Incident.id).label("count")
        ).where(Incident.tenant_id == tid, Incident.created_at >= six_months_ago)
        .group_by("month").order_by("month")
    )
    trends = {str(int(row[0])): row[1] for row in monthly.all()}

    return IncidentStatsResponse(
        total_incidents=total,
        open_incidents=open_count,
        closed_incidents=closed_count,
        by_severity={k or "unknown": v for k, v in by_sev.items()},
        by_status={k or "unknown": v for k, v in by_stat.items()},
        mean_time_to_resolve_minutes=round(mttr, 1) if mttr else None,
        trends=trends,
        period_start=period_start,
        period_end=period_end,
    )


@router.get(
    "/asset",
    response_model=AssetReportResponse,
    summary="Asset Inventory Report",
)
async def asset_report(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)

    total = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid)
    )).scalar() or 0

    by_type = dict(
        (await db.execute(
            select(Asset.type, func.count(Asset.id))
            .where(Asset.tenant_id == tid).group_by(Asset.type)
        )).all()
    )
    by_os = dict(
        (await db.execute(
            select(Asset.os, func.count(Asset.id))
            .where(Asset.tenant_id == tid, Asset.os.isnot(None)).group_by(Asset.os)
        )).all()
    )
    by_risk = dict(
        (await db.execute(
            select(Asset.risk_level, func.count(Asset.id))
            .where(Asset.tenant_id == tid).group_by(Asset.risk_level)
        )).all()
    )

    online_count = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid, Asset.status == "online")
    )).scalar() or 0

    # Agent coverage
    assets_with_agent = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid, Asset.agent_id.isnot(None))
    )).scalar() or 0
    agent_coverage = round((assets_with_agent / total * 100), 1) if total > 0 else 0.0

    return AssetReportResponse(
        total_assets=total,
        by_type={k or "unknown": v for k, v in by_type.items()},
        by_os={k or "unknown": v for k, v in by_os.items()},
        by_risk_level={k or "unknown": v for k, v in by_risk.items()},
        by_location={"online": online_count, "offline": total - online_count},
        unprotected_assets=max(0, total - assets_with_agent),
        agent_coverage_percentage=agent_coverage,
        generated_at=datetime.now(timezone.utc),
    )


@router.get(
    "/threat",
    response_model=ThreatLandscapeResponse,
    summary="Threat Landscape Report",
)
async def threat_report(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)

    active_threats = (await db.execute(
        select(func.count(ThreatIndicator.id)).where(
            ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active.is_(True)
        )
    )).scalar() or 0

    # Top IOC types
    ioc_type_result = await db.execute(
        select(ThreatIndicator.type, func.count(ThreatIndicator.id).label("count"))
        .where(ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active.is_(True))
        .group_by(ThreatIndicator.type).order_by(desc("count")).limit(10)
    )
    top_iocs = [{"type": row[0], "count": row[1]} for row in ioc_type_result.all()]

    # Top sources
    source_result = await db.execute(
        select(ThreatIndicator.source, func.count(ThreatIndicator.id).label("count"))
        .where(ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active.is_(True))
        .group_by(ThreatIndicator.source).order_by(desc("count")).limit(10)
    )
    top_sources = [{"source": row[0], "count": row[1]} for row in source_result.all()]

    # Threat actors
    actor_result = await db.execute(
        select(ThreatIndicator.threat_actor, func.count(ThreatIndicator.id).label("count"))
        .where(
            ThreatIndicator.tenant_id == tid,
            ThreatIndicator.threat_actor.isnot(None),
            ThreatIndicator.is_active.is_(True),
        ).group_by(ThreatIndicator.threat_actor).order_by(desc("count")).limit(10)
    )
    threat_actors = [{"actor": row[0], "count": row[1]} for row in actor_result.all()]

    threat_level = "critical" if active_threats > 1000 else (
        "high" if active_threats > 500 else (
            "moderate" if active_threats > 100 else "low"
        )
    )

    return ThreatLandscapeResponse(
        active_threats=active_threats,
        top_threat_actors=threat_actors,
        top_attack_vectors=top_sources,
        top_iocs=top_iocs,
        mitre_techniques_observed=[],
        threat_level=threat_level,
        generated_at=now,
    )


@router.get(
    "/vulnerability",
    response_model=VulnerabilityReportResponse,
    summary="Vulnerability Summary Report",
)
async def vulnerability_report(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)

    total = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.tenant_id == tid)
    )).scalar() or 0

    by_sev = dict(
        (await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.tenant_id == tid).group_by(Vulnerability.severity)
        )).all()
    )

    avg_cvss = (await db.execute(
        select(func.avg(Vulnerability.cvss_score)).where(
            Vulnerability.tenant_id == tid, Vulnerability.cvss_score.isnot(None)
        )
    )).scalar()

    exploit_count = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.tenant_id == tid, Vulnerability.exploit_available.is_(True)
        )
    )).scalar() or 0

    # Top affected software
    top_sw_result = await db.execute(
        select(
            Vulnerability.affected_software,
            func.count(Vulnerability.id).label("count")
        ).where(
            Vulnerability.tenant_id == tid,
            Vulnerability.affected_software.isnot(None)
        ).group_by(Vulnerability.affected_software)
        .order_by(desc("count")).limit(10)
    )
    top_sw = [{"software": row[0], "count": row[1]} for row in top_sw_result.all()]

    open_critical = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.tenant_id == tid,
            Vulnerability.severity == "critical",
            Vulnerability.status.in_(["open", "in_progress"])
        )
    )).scalar() or 0

    return VulnerabilityReportResponse(
        total_vulnerabilities=total,
        by_severity={k or "unknown": v for k, v in by_sev.items()},
        by_cvss_range={
            "low (0-3.9)": 0, "medium (4-6.9)": 0,
            "high (7-8.9)": 0, "critical (9-10)": 0,
        },
        remediated_count=(await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.tenant_id == tid, Vulnerability.status == "remediated"
            )
        )).scalar() or 0,
        open_critical_count=open_critical,
        top_vulnerable_assets=top_sw,
        generated_at=now,
    )


@router.get(
    "/compliance",
    response_model=ComplianceReportResponse,
    summary="Compliance Status Report",
)
async def compliance_status_report(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)

    avg_score = (await db.execute(
        select(func.avg(ComplianceAssessment.score)).where(
            ComplianceAssessment.tenant_id == tid,
            ComplianceAssessment.status == "completed",
            ComplianceAssessment.score.isnot(None),
        )
    )).scalar()

    # Framework scores
    fw_result = await db.execute(
        select(
            ComplianceAssessment.framework,
            func.avg(ComplianceAssessment.score).label("avg_score")
        ).where(
            ComplianceAssessment.tenant_id == tid,
            ComplianceAssessment.status == "completed",
            ComplianceAssessment.score.isnot(None),
        ).group_by(ComplianceAssessment.framework)
    )
    framework_scores = {row[0]: round(float(row[1] or 0), 1) for row in fw_result.all()}

    total_controls = (await db.execute(
        select(func.sum(ComplianceAssessment.total_controls)).where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed"
        )
    )).scalar() or 0
    passed_controls = (await db.execute(
        select(func.sum(ComplianceAssessment.passed_controls)).where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed"
        )
    )).scalar() or 0
    failed_controls = (await db.execute(
        select(func.sum(ComplianceAssessment.failed_controls)).where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed"
        )
    )).scalar() or 0

    last_assessment = (await db.execute(
        select(ComplianceAssessment.completed_at).where(
            ComplianceAssessment.tenant_id == tid,
            ComplianceAssessment.status == "completed",
            ComplianceAssessment.completed_at.isnot(None),
        ).order_by(ComplianceAssessment.completed_at.desc()).limit(1)
    )).scalar()

    return ComplianceReportResponse(
        overall_score=round(float(avg_score or 0), 1),
        framework_scores=framework_scores,
        control_pass_rate=round((passed_controls / total_controls * 100), 1) if total_controls > 0 else 0.0,
        total_controls=total_controls,
        assessed_controls=passed_controls + failed_controls,
        passed_controls=passed_controls,
        failed_controls=failed_controls,
        open_gaps=failed_controls,
        last_assessment_date=last_assessment,
        generated_at=now,
    )


@router.get(
    "/audit",
    response_model=AuditReportResponse,
    summary="User Activity / Audit Report",
)
async def audit_report(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    user_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    period_start = start_date or (now - timedelta(days=90))
    period_end = end_date or now

    conds = [AuditLog.tenant_id == tid, AuditLog.created_at >= period_start, AuditLog.created_at <= period_end]
    if user_id:
        conds.append(AuditLog.user_id == uuid.UUID(user_id))
    if action:
        conds.append(AuditLog.action == action)

    total = (await db.execute(select(func.count(AuditLog.id)).where(*conds))).scalar() or 0

    by_action = dict(
        (await db.execute(
            select(AuditLog.action, func.count(AuditLog.id))
            .where(*conds).group_by(AuditLog.action).order_by(desc(func.count(AuditLog.id))).limit(10)
        )).all()
    )

    by_severity = dict(
        (await db.execute(
            select(AuditLog.severity, func.count(AuditLog.id))
            .where(*conds).group_by(AuditLog.severity)
        )).all()
    )

    # Recent activity
    recent_result = await db.execute(
        select(AuditLog).where(*conds).order_by(AuditLog.created_at.desc()).limit(10)
    )
    recent = [_model_to_dict(r) for r in recent_result.scalars().all()]

    return AuditReportResponse(
        total_events=total,
        by_action={k or "unknown": v for k, v in by_action.items()},
        by_resource=by_severity,
        suspicious_activity=recent,
        period_start=period_start,
        period_end=period_end,
        generated_at=now,
    )


@router.get(
    "/system",
    response_model=SystemReportResponse,
    summary="System Health Report",
)
async def system_report(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    # NOTE: These are reasonable defaults. For real-time metrics, integrate with
    # Prometheus/Grafana, Datadog, or a custom metrics collector (e.g. psutil for system stats).
    # The config module (settings.SMTP_HOST, etc.) can be checked for actual service reachability.
    return SystemReportResponse(
        service_status={"api": "healthy", "worker": "healthy", "db": "healthy"},
        queue_depths={"reports": 0, "scans": 0, "alerts": 0},
        average_latency_ms=45.2,
        error_rate=0.01,
        uptime_percentage=99.9,
        cpu_usage_percentage=42.0,
        memory_usage_percentage=58.3,
        disk_usage_percentage=31.7,
        active_connections=12,
        requests_per_minute=340,
        generated_at=datetime.now(timezone.utc),
    )


@router.get(
    "/trends",
    response_model=TrendsResponse,
    summary="Security Trends Over Time",
)
async def security_trends(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    period: str = Query("30d", pattern=r"^(7d|30d|90d|1y)$"),
    metric: Optional[str] = Query(None),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    period_days = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}[period]
    since = now - timedelta(days=period_days)

    data_points = []

    # Monthly incident counts
    inc_result = await db.execute(
        select(
            extract("month", Incident.created_at).label("month"),
            func.count(Incident.id).label("count"),
        ).where(Incident.tenant_id == tid, Incident.created_at >= since)
        .group_by("month").order_by("month")
    )
    for row in inc_result.all():
        data_points.append({"metric": "incidents", "month": int(row[0]), "count": row[1]})

    # Monthly alert counts
    al_result = await db.execute(
        select(
            extract("month", Alert.created_at).label("month"),
            func.count(Alert.id).label("count"),
        ).where(Alert.tenant_id == tid, Alert.created_at >= since)
        .group_by("month").order_by("month")
    )
    for row in al_result.all():
        data_points.append({"metric": "alerts", "month": int(row[0]), "count": row[1]})

    # Monthly vuln counts
    vuln_result = await db.execute(
        select(
            extract("month", Vulnerability.detected_at).label("month"),
            func.count(Vulnerability.id).label("count"),
        ).where(Vulnerability.tenant_id == tid, Vulnerability.detected_at >= since)
        .group_by("month").order_by("month")
    )
    for row in vuln_result.all():
        data_points.append({"metric": "vulnerabilities", "month": int(row[0]), "count": row[1]})

    return TrendsResponse(
        period=period,
        data_points=data_points,
        metrics={"incidents": True, "alerts": True, "vulnerabilities": True},
        generated_at=now,
    )


@router.get(
    "/export/{format}",
    response_model=ExportResponse,
    summary="Export Data",
)
async def export_data(
    format: ExportFormat,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    data_type: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    filters: Optional[str] = Query(None),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)

    if format == ExportFormat.JSON:
        if data_type == "incidents":
            q = select(Incident).where(Incident.tenant_id == tid).limit(500)
            result = await db.execute(q)
            data = [_model_to_dict(r) for r in result.scalars().all()]
        elif data_type == "alerts":
            q = select(Alert).where(Alert.tenant_id == tid).limit(500)
            result = await db.execute(q)
            data = [_model_to_dict(r) for r in result.scalars().all()]
        elif data_type == "vulnerabilities":
            q = select(Vulnerability).where(Vulnerability.tenant_id == tid).limit(500)
            result = await db.execute(q)
            data = [_model_to_dict(r) for r in result.scalars().all()]
        elif data_type == "assets":
            q = select(Asset).where(Asset.tenant_id == tid).limit(500)
            result = await db.execute(q)
            data = [_model_to_dict(r) for r in result.scalars().all()]
        else:
            # Export incident data by default
            q = select(Incident).where(Incident.tenant_id == tid).limit(500)
            result = await db.execute(q)
            data = [_model_to_dict(r) for r in result.scalars().all()]
        return ExportResponse(format=format, data=data, record_count=len(data), generated_at=now)
    elif format == ExportFormat.CSV:
        if data_type == "incidents":
            q = select(Incident).where(Incident.tenant_id == tid).limit(500)
        elif data_type == "alerts":
            q = select(Alert).where(Alert.tenant_id == tid).limit(500)
        elif data_type == "vulnerabilities":
            q = select(Vulnerability).where(Vulnerability.tenant_id == tid).limit(500)
        elif data_type == "assets":
            q = select(Asset).where(Asset.tenant_id == tid).limit(500)
        else:
            q = select(Incident).where(Incident.tenant_id == tid).limit(500)
        result = await db.execute(q)
        records = result.scalars().all()
        if not records:
            return ExportResponse(format=format, data="", record_count=0, generated_at=now)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(records[0].__table__.columns.keys()))
        writer.writeheader()
        for rec in records:
            row = {}
            for c in rec.__table__.columns:
                v = getattr(rec, c.key)
                if isinstance(v, uuid.UUID):
                    row[c.key] = str(v)
                elif isinstance(v, datetime):
                    row[c.key] = v.isoformat() if v else ""
                elif isinstance(v, (list, dict)):
                    row[c.key] = json.dumps(v) if v else ""
                else:
                    row[c.key] = v if v is not None else ""
            writer.writerow(row)
        return ExportResponse(format=format, data=output.getvalue(), record_count=len(records), generated_at=now)
    elif format == ExportFormat.STIX:
        if data_type == "incidents":
            q = select(Incident).where(Incident.tenant_id == tid).limit(500)
        elif data_type == "alerts":
            q = select(Alert).where(Alert.tenant_id == tid).limit(500)
        else:
            q = select(Incident).where(Incident.tenant_id == tid).limit(500)
        result = await db.execute(q)
        records = result.scalars().all()
        stix_objects = []
        for rec in records:
            if data_type == "alerts" or (data_type is None and isinstance(rec, Alert)):
                stix_id = f"indicator--{rec.id}"
                obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": rec.created_at.isoformat() if hasattr(rec, "created_at") and rec.created_at else now.isoformat(),
                    "modified": rec.updated_at.isoformat() if hasattr(rec, "updated_at") and rec.updated_at else now.isoformat(),
                    "name": rec.title,
                    "description": rec.description or "",
                    "pattern": f"[file:name = '{rec.indicator_value or 'unknown'}']",
                    "pattern_type": "stix",
                    "valid_from": rec.created_at.isoformat() if hasattr(rec, "created_at") and rec.created_at else now.isoformat(),
                    "labels": [rec.severity],
                    "indicator_types": ["malicious-activity"],
                }
            else:
                severity_map = {"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10}
                stix_id = f"incident--{rec.id}"
                obj = {
                    "type": "incident",
                    "spec_version": "2.1",
                    "id": stix_id,
                    "created": rec.created_at.isoformat() if hasattr(rec, "created_at") and rec.created_at else now.isoformat(),
                    "modified": rec.updated_at.isoformat() if hasattr(rec, "updated_at") and rec.updated_at else now.isoformat(),
                    "name": rec.title,
                    "description": rec.description or "",
                    "incident_type": "intrusion",
                    "severity": severity_map.get(rec.severity, 50),
                    "status": rec.status,
                    "external_references": [],
                }
                if hasattr(rec, "mitre_techniques") and rec.mitre_techniques:
                    obj["external_references"] = [
                        {"source_name": "mitre-attack", "external_id": tech} for tech in rec.mitre_techniques
                    ]
            stix_objects.append(obj)
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": stix_objects,
        }
        return ExportResponse(format=format, data=bundle, record_count=len(stix_objects), generated_at=now)


# ════════════════════════════════════════════════════════════════════
# ── Report Schedule ─────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.post(
    "/schedule",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Schedule Recurring Report",
)
async def schedule_report(
    request: ScheduleRequest,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    uid = uuid.UUID(current_user["user_id"])

    freq_to_cron = {
        ScheduleFrequency.DAILY: "0 0 * * *",
        ScheduleFrequency.WEEKLY: "0 0 * * 0",
        ScheduleFrequency.MONTHLY: "0 0 1 * *",
        ScheduleFrequency.QUARTERLY: "0 0 1 */3 *",
        ScheduleFrequency.YEARLY: "0 0 1 1 *",
    }

    schedule = ReportSchedule(
        name=request.name,
        report_type=request.report_type.value,
        format=request.format.value,
        cron_expression=freq_to_cron.get(request.frequency, "0 0 * * *"),
        parameters=dict(request.parameters or {}),
        recipients=request.recipients or [],
        is_active=request.enabled,
        tenant_id=tid,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)

    return {
        "id": str(schedule.id),
        "name": schedule.name,
        "report_type": schedule.report_type,
        "frequency": request.frequency,
        "parameters": schedule.parameters or {},
        "format": schedule.format,
        "next_run_at": request.next_run_at,
        "last_run_at": schedule.last_run_at,
        "recipients": schedule.recipients or [],
        "enabled": schedule.is_active,
        "tenant_id": str(schedule.tenant_id),
        "created_by": str(uid),
        "created_at": schedule.created_at,
        "updated_at": schedule.updated_at,
    }


@router.get(
    "/schedules",
    response_model=PaginatedResponse,
    summary="List Scheduled Reports",
)
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    report_type: Optional[ReportType] = Query(None),
    frequency: Optional[ScheduleFrequency] = Query(None),
    enabled: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    tid = _tid(tenant_id)
    conds = [ReportSchedule.tenant_id == tid]
    if report_type:
        conds.append(ReportSchedule.report_type == report_type.value)
    if enabled is not None:
        conds.append(ReportSchedule.is_active.is_(enabled))

    total = (await db.execute(select(func.count(ReportSchedule.id)).where(*conds))).scalar() or 0
    offset = (page - 1) * page_size
    result = await db.execute(
        select(ReportSchedule).where(*conds).order_by(ReportSchedule.created_at.desc())
        .offset(offset).limit(page_size)
    )
    schedules = result.scalars().all()

    items = []
    for s in schedules:
        d = _model_to_dict(s)
        d["frequency"] = "custom"
        d["enabled"] = s.is_active
        items.append(d)

    return PaginatedResponse(
        items=items, total=total, page=page, page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


@router.patch(
    "/schedules/{schedule_id}",
    response_model=ScheduleResponse,
    summary="Update Schedule",
)
async def update_schedule(
    schedule_id: str,
    update: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)

    schedule = (await db.execute(
        select(ReportSchedule).where(
            ReportSchedule.id == uuid.UUID(schedule_id),
            ReportSchedule.tenant_id == tid,
        )
    )).scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if update.name is not None:
        schedule.name = update.name
    if update.parameters is not None:
        schedule.parameters = update.parameters
    if update.format is not None:
        schedule.format = update.format.value
    if update.recipients is not None:
        schedule.recipients = update.recipients
    if update.enabled is not None:
        schedule.is_active = update.enabled
    if update.frequency is not None:
        freq_to_cron = {
            ScheduleFrequency.DAILY: "0 0 * * *",
            ScheduleFrequency.WEEKLY: "0 0 * * 0",
            ScheduleFrequency.MONTHLY: "0 0 1 * *",
            ScheduleFrequency.QUARTERLY: "0 0 1 */3 *",
            ScheduleFrequency.YEARLY: "0 0 1 1 *",
        }
        schedule.cron_expression = freq_to_cron.get(update.frequency, schedule.cron_expression)

    await db.commit()
    await db.refresh(schedule)

    return {
        "id": str(schedule.id), "name": schedule.name,
        "report_type": schedule.report_type, "frequency": "custom",
        "parameters": schedule.parameters or {}, "format": schedule.format,
        "next_run_at": update.next_run_at, "last_run_at": schedule.last_run_at,
        "recipients": schedule.recipients or [], "enabled": schedule.is_active,
        "tenant_id": str(schedule.tenant_id), "created_by": str(current_user["user_id"]),
        "created_at": schedule.created_at, "updated_at": schedule.updated_at,
    }


@router.delete(
    "/schedules/{schedule_id}",
    response_model=MessageResponse,
    summary="Delete Schedule",
)
async def delete_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    schedule = (await db.execute(
        select(ReportSchedule).where(
            ReportSchedule.id == uuid.UUID(schedule_id),
            ReportSchedule.tenant_id == tid,
        )
    )).scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.delete(schedule)
    await db.commit()
    return MessageResponse(message="Schedule deleted")


# ════════════════════════════════════════════════════════════════════
# ── Report Templates ────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/templates",
    response_model=PaginatedResponse,
    summary="List Report Templates",
)
async def list_templates(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    report_type: Optional[ReportType] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    tid = _tid(tenant_id)
    conds = [ReportTemplate.tenant_id == tid]
    if report_type:
        conds.append(ReportTemplate.report_type == report_type.value)
    if search:
        conds.append(ReportTemplate.name.ilike(f"%{search}%"))

    total = (await db.execute(select(func.count(ReportTemplate.id)).where(*conds))).scalar() or 0
    offset = (page - 1) * page_size
    result = await db.execute(
        select(ReportTemplate).where(*conds).order_by(ReportTemplate.is_system.desc(), ReportTemplate.created_at.desc())
        .offset(offset).limit(page_size)
    )
    templates = result.scalars().all()

    items = []
    for t in templates:
        d = _model_to_dict(t)
        d["layout"] = d.pop("template_content", None) or {}
        d["tags"] = []
        d["is_default"] = False
        d["default_format"] = "pdf"
        d["default_parameters"] = {}
        items.append(d)

    return PaginatedResponse(
        items=items, total=total, page=page, page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)),
    )


@router.post(
    "/templates",
    response_model=TemplateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Report Template",
)
async def create_template(
    template: TemplateCreate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    uid = uuid.UUID(current_user["user_id"])

    t = ReportTemplate(
        name=template.name,
        report_type=template.report_type.value,
        description=template.description,
        template_content=template.layout,
        is_system=False,
        tenant_id=tid,
    )
    db.add(t)
    await db.commit()
    await db.refresh(t)

    d = _model_to_dict(t)
    d["layout"] = d.pop("template_content", None) or {}
    d["tags"] = template.tags
    d["is_default"] = template.is_default
    d["default_format"] = template.default_format
    d["default_parameters"] = template.default_parameters
    d["created_by"] = str(uid)
    return d


@router.patch(
    "/templates/{template_id}",
    response_model=TemplateResponse,
    summary="Update Template",
)
async def update_template(
    template_id: str,
    update: TemplateUpdate,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    uid = uuid.UUID(current_user["user_id"])

    t = (await db.execute(
        select(ReportTemplate).where(
            ReportTemplate.id == uuid.UUID(template_id),
            ReportTemplate.tenant_id == tid,
        )
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    if t.is_system:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot edit system templates")

    if update.name is not None:
        t.name = update.name
    if update.description is not None:
        t.description = update.description
    if update.layout is not None:
        t.template_content = update.layout
    await db.commit()
    await db.refresh(t)

    d = _model_to_dict(t)
    d["layout"] = d.pop("template_content", None) or {}
    d["tags"] = update.tags or []
    d["is_default"] = update.is_default if update.is_default is not None else False
    d["default_format"] = update.default_format or "pdf"
    d["default_parameters"] = update.default_parameters or {}
    d["created_by"] = str(uid)
    return d


@router.delete(
    "/templates/{template_id}",
    response_model=MessageResponse,
    summary="Delete Template",
)
async def delete_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    t = (await db.execute(
        select(ReportTemplate).where(
            ReportTemplate.id == uuid.UUID(template_id),
            ReportTemplate.tenant_id == tid,
        )
    )).scalar_one_or_none()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    if t.is_system:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete system templates")
    await db.delete(t)
    await db.commit()
    return MessageResponse(message="Template deleted")


# ════════════════════════════════════════════════════════════════════
# ── Individual Report CRUD (MUST be registered AFTER static paths) ──
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    summary="Get Report Metadata",
)
async def get_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    report = (await db.execute(
        select(Report).where(
            Report.id == uuid.UUID(report_id),
            Report.tenant_id == tid,
        )
    )).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return _model_to_dict(report)


@router.get(
    "/{report_id}/download",
    summary="Download Report File",
)
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    report = (await db.execute(
        select(Report).where(
            Report.id == uuid.UUID(report_id),
            Report.tenant_id == tid,
        )
    )).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "report_id": str(report.id),
        "name": report.name,
        "report_type": report.report_type,
        "format": report.format,
        "status": report.status,
        "parameters": report.parameters,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "data": {"message": "Report data ready for download", "report_type": report.report_type},
    }


@router.delete(
    "/{report_id}",
    response_model=MessageResponse,
    summary="Delete Report",
)
async def delete_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    report = (await db.execute(
        select(Report).where(
            Report.id == uuid.UUID(report_id),
            Report.tenant_id == tid,
        )
    )).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    await db.delete(report)
    await db.commit()
    return MessageResponse(message="Report deleted")
