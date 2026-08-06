"""
AEGISX - Search API Router
Global search, natural language search, resource-specific search, saved searches, suggestions, index stats
"""
import math
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, desc, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import (
    Asset, Incident, Alert, ThreatIndicator, User,
    Vulnerability, Playbook, Report, DetectionRule, AuditLog,
    IncidentEvidence, Agent,
)
from app.api.deps import (
    get_current_user,
    require_tenant,
    RequireSOCAnalyst,
)

router = APIRouter()

_saved_searches: Dict[str, Dict[str, Any]] = {}


# ════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════

class AssetType(str, Enum):
    WORKSTATION = "workstation"
    SERVER = "server"
    NETWORK_DEVICE = "network_device"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    MOBILE = "mobile"
    IOT = "iot"

class AssetOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    OTHER = "other"

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"

class AlertStatus(str, Enum):
    FIRING = "firing"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"

class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class UserRole(str, Enum):
    SUPER_ADMIN = "super_admin"
    TENANT_ADMIN = "tenant_admin"
    SOC_MANAGER = "soc_manager"
    SOC_ANALYST_L1 = "soc_analyst_l1"
    SOC_ANALYST_L2 = "soc_analyst_l2"
    SOC_ANALYST_L3 = "soc_analyst_l3"
    INCIDENT_RESPONDER = "incident_responder"
    THREAT_HUNTER = "threat_hunter"
    AUDITOR = "auditor"
    COMPLIANCE_OFFICER = "compliance_officer"

class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"

class VulnStatus(str, Enum):
    OPEN = "open"
    IN_REMEDIATION = "in_remediation"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"

class PlaybookStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"

class PlaybookTrigger(str, Enum):
    INCIDENT_CREATED = "incident_created"
    INCIDENT_SEVERITY_CHANGED = "incident_severity_changed"
    ALERT_FIRED = "alert_fired"
    IOC_DETECTED = "ioc_detected"
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    WEBHOOK = "webhook"

class ReportType(str, Enum):
    INCIDENT = "incident"
    COMPLIANCE = "compliance"
    THREAT_INTEL = "threat_intel"
    VULNERABILITY = "vulnerability"
    AUDIT = "audit"
    EXECUTIVE = "executive"

class EvidenceFileType(str, Enum):
    PDF = "pdf"
    IMAGE = "image"
    TEXT = "text"
    CSV = "csv"
    JSON = "json"
    ARCHIVE = "archive"
    OTHER = "other"


# ════════════════════════════════════════════════════════════════════
# Common Response Models
# ════════════════════════════════════════════════════════════════════

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None


# ════════════════════════════════════════════════════════════════════
# Search Result Models
# ════════════════════════════════════════════════════════════════════

class GlobalSearchResult(BaseModel):
    resource_type: str = Field(..., description="e.g. asset, incident, alert, ioc, user, report")
    resource_id: str
    title: str
    summary: str
    score: float = Field(..., ge=0.0, le=100.0)
    highlights: Dict[str, List[str]] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    url: Optional[str] = None

class NaturalSearchResult(BaseModel):
    interpretation: str = Field(..., description="How the natural language query was interpreted by AI")
    resource_type: str
    resource_id: str
    title: str
    summary: str
    relevance_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    explanation: Optional[str] = None
    url: Optional[str] = None

class AssetSearchResult(BaseModel):
    id: str
    name: str
    asset_type: AssetType
    os: Optional[AssetOS] = None
    status: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    tags: List[str]
    risk_score: Optional[float] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class IncidentSearchResult(BaseModel):
    id: str
    title: str
    severity: SeverityLevel
    status: IncidentStatus
    assignee_name: Optional[str] = None
    asset_name: Optional[str] = None
    tags: List[str]
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class AlertSearchResult(BaseModel):
    id: str
    name: str
    severity: SeverityLevel
    status: AlertStatus
    rule_name: Optional[str] = None
    source: Optional[str] = None
    triggered_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class IOCSearchResult(BaseModel):
    id: str
    type: IOCType
    value: str
    confidence: ConfidenceLevel
    status: str
    source: Optional[str] = None
    tags: List[str]
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class UserSearchResult(BaseModel):
    id: str
    username: str
    display_name: str
    role: UserRole
    department: Optional[str] = None
    status: UserStatus
    email: Optional[str] = None
    last_login: Optional[datetime] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class ProcessSearchResult(BaseModel):
    id: str
    process_name: str
    pid: int
    ppid: Optional[int] = None
    user: Optional[str] = None
    command_line: Optional[str] = None
    hash_sha256: Optional[str] = None
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    is_malicious: Optional[bool] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class LogSearchResult(BaseModel):
    id: str
    log_source: str
    level: LogLevel
    message: str
    timestamp: datetime
    host: Optional[str] = None
    service: Optional[str] = None
    raw_log: Optional[str] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class VulnerabilitySearchResult(BaseModel):
    id: str
    cve: Optional[str] = None
    title: str
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    status: VulnStatus
    affected_asset_id: Optional[str] = None
    affected_asset_name: Optional[str] = None
    discovered_at: Optional[datetime] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class PlaybookSearchResult(BaseModel):
    id: str
    name: str
    status: PlaybookStatus
    trigger_type: PlaybookTrigger
    description: Optional[str] = None
    step_count: int = 0
    last_executed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class ReportSearchResult(BaseModel):
    id: str
    title: str
    report_type: ReportType
    author: Optional[str] = None
    status: str
    tags: List[str]
    created_at: Optional[datetime] = None
    published_at: Optional[datetime] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)

class EvidenceSearchResult(BaseModel):
    id: str
    name: str
    file_type: EvidenceFileType
    file_name: Optional[str] = None
    file_size_bytes: Optional[int] = None
    incident_id: Optional[str] = None
    incident_title: Optional[str] = None
    uploaded_by: Optional[str] = None
    created_at: Optional[datetime] = None
    highlights: Dict[str, List[str]] = Field(default_factory=dict)


# ════════════════════════════════════════════════════════════════════
# Suggestion & Saved Search Models
# ════════════════════════════════════════════════════════════════════

class SearchSuggestion(BaseModel):
    text: str
    resource_type: Optional[str] = None
    category: str = Field(..., description="e.g. recent, common, label_match")
    score: float

class SavedSearchCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    resource_type: str
    query: str = Field(..., min_length=1)
    filters: Optional[Dict[str, Any]] = None
    is_shared: bool = False

class SavedSearchResponse(BaseModel):
    id: str
    tenant_id: str
    user_id: str
    name: str
    description: Optional[str] = None
    resource_type: str
    query: str
    filters: Optional[Dict[str, Any]] = None
    is_shared: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None
    use_count: int = 0

class IndexStats(BaseModel):
    resource_type: str
    document_count: int
    index_size_bytes: int
    last_indexed_at: Optional[datetime] = None
    index_latency_ms: Optional[float] = None
    health: str


# ════════════════════════════════════════════════════════════════════
# Paginated Search Response
# ════════════════════════════════════════════════════════════════════

class PaginatedSearchResults(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int
    took_ms: Optional[float] = None
    facet_counts: Optional[Dict[str, Dict[str, int]]] = None


# ════════════════════════════════════════════════════════════════════
# GLOBAL SEARCH
# ════════════════════════════════════════════════════════════════════

_GLOBAL_SEARCH_TABLES = [
    ("asset", Asset, "name"),
    ("incident", Incident, "title"),
    ("alert", Alert, "title"),
    ("ioc", ThreatIndicator, "value"),
    ("user", User, "full_name"),
    ("vulnerability", Vulnerability, "title"),
    ("playbook", Playbook, "name"),
    ("report", Report, "name"),
    ("detection_rule", DetectionRule, "name"),
]


@router.get("/global", response_model=PaginatedSearchResults)
async def global_search(
    q: str = Query(..., min_length=1, description="Search query string"),
    resource_types: Optional[List[str]] = Query(None, description="Filter by resource types"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    all_results: List[GlobalSearchResult] = []

    tables = _GLOBAL_SEARCH_TABLES
    if resource_types:
        tables = [(rt, model, field) for rt, model, field in _GLOBAL_SEARCH_TABLES if rt in resource_types]

    for resource_type, model, field in tables:
        if not hasattr(model, "tenant_id"):
            continue
        try:
            query_filter = getattr(model, field).ilike(f"%{q}%")
            stmt = select(model).where(
                model.tenant_id == tenant_uuid,
                query_filter,
            ).limit(20)
            result = await db.execute(stmt)
            rows = result.scalars().all()

            for row in rows:
                title_val = getattr(row, field, str(row.id)) or f"{resource_type} record"
                all_results.append(GlobalSearchResult(
                    resource_type=resource_type,
                    resource_id=str(row.id),
                    title=title_val,
                    summary=getattr(row, "description", None) or "",
                    score=85.0,
                    highlights={},
                    created_at=getattr(row, "created_at", None),
                    url=f"/{resource_type}s/{row.id}",
                ))
        except Exception:
            continue

    total = len(all_results)
    offset = (page - 1) * page_size
    items = all_results[offset:offset + page_size]
    total_pages = max(1, math.ceil(total / page_size))

    return PaginatedSearchResults(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/natural", response_model=List[NaturalSearchResult])
async def natural_language_search(
    q: str = Query(..., min_length=1, description="Natural language search query"),
    max_results: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    q_lower = q.lower().strip()
    results: List[NaturalSearchResult] = []

    keywords = []
    if "critical" in q_lower or "severe" in q_lower:
        keywords.append("critical")
    if "open" in q_lower:
        keywords.append("open")
    if "closed" in q_lower:
        keywords.append("closed")
    if "in progress" in q_lower or "in-progress" in q_lower:
        keywords.append("in_progress")
    if "high" in q_lower and "critical" not in q_lower:
        keywords.append("high")

    resource_terms = {
        "asset": (Asset, "name"),
        "incident": (Incident, "title"),
        "alert": (Alert, "title"),
        "user": (User, "full_name"),
        "ioc": (ThreatIndicator, "value"),
        "vulnerability": (Vulnerability, "title"),
        "playbook": (Playbook, "name"),
        "report": (Report, "name"),
        "rule": (DetectionRule, "name"),
    }

    matched_resource = None
    for term, (model, field) in resource_terms.items():
        if term in q_lower:
            matched_resource = term
            break

    models_to_search = resource_terms.items() if not matched_resource else [(matched_resource, resource_terms[matched_resource])]

    for rt, (model, search_field) in models_to_search:
        if not hasattr(model, "tenant_id"):
            continue
        try:
            conditions = [model.tenant_id == tenant_uuid]
            search_pattern = f"%{q}%"
            conditions.append(getattr(model, search_field).ilike(search_pattern))

            if "status" in [c.key for c in model.__table__.columns]:
                if "open" in keywords:
                    conditions.append(getattr(model, "status").in_(["open", "new", "in_progress", "investigating", "firing"]))
                elif "closed" in keywords:
                    conditions.append(getattr(model, "status").in_(["closed", "resolved"]))
            if "severity" in [c.key for c in model.__table__.columns]:
                if "critical" in keywords:
                    conditions.append(getattr(model, "severity").in_(["critical"]))

            stmt = select(model).where(and_(*conditions)).limit(max_results * 2)
            result = await db.execute(stmt)
            rows = result.scalars().all()

            for row in rows:
                title_val = getattr(row, search_field, str(row.id)) or f"{rt} record"
                results.append(NaturalSearchResult(
                    interpretation=f"Searching {rt}s matching '{q}'",
                    resource_type=rt,
                    resource_id=str(row.id),
                    title=title_val,
                    summary=getattr(row, "description", None) or "",
                    relevance_score=85.0,
                    confidence=0.8,
                    explanation=f"Matched by keyword search on {rt} records",
                    url=f"/{rt}s/{row.id}",
                ))
                if len(results) >= max_results:
                    break
        except Exception:
            continue
        if len(results) >= max_results:
            break

    return results[:max_results]


# ════════════════════════════════════════════════════════════════════
# ASSET SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/assets", response_model=PaginatedSearchResults)
async def search_assets(
    q: str = Query(..., min_length=1, description="Search query"),
    asset_type: Optional[AssetType] = Query(None),
    os: Optional[AssetOS] = Query(None),
    status: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [Asset.tenant_id == tenant_uuid]

    query_filter = or_(
        Asset.name.ilike(f"%{q}%"),
        Asset.hostname.ilike(f"%{q}%"),
    )
    conditions.append(query_filter)

    if asset_type:
        conditions.append(Asset.type == asset_type.value)
    if os:
        conditions.append(Asset.os == os.value)
    if status:
        conditions.append(Asset.status == status)
    if date_from:
        conditions.append(Asset.created_at >= date_from)
    if date_to:
        conditions.append(Asset.created_at <= date_to)

    count_stmt = select(func.count()).select_from(Asset).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = select(Asset).where(and_(*conditions)).order_by(desc(Asset.created_at)).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    assets = result.scalars().all()

    items = []
    for a in assets:
        os_enum = None
        if a.os:
            try:
                os_enum = AssetOS(a.os)
            except ValueError:
                pass
        items.append(AssetSearchResult(
            id=str(a.id),
            name=a.name,
            asset_type=AssetType(a.type) if a.type in [e.value for e in AssetType] else AssetType.WORKSTATION,
            os=os_enum,
            status=a.status,
            ip_address=a.ip_address,
            hostname=a.hostname,
            tags=a.tags or [],
            risk_score=None,
            last_seen=a.last_seen,
            created_at=a.created_at,
            highlights={},
        ))

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# INCIDENT SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/incidents", response_model=PaginatedSearchResults)
async def search_incidents(
    q: str = Query(..., min_length=1, description="Search query"),
    severity: Optional[SeverityLevel] = Query(None),
    status: Optional[IncidentStatus] = Query(None),
    assignee: Optional[str] = Query(None, description="Assignee user ID or name"),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [Incident.tenant_id == tenant_uuid]

    query_filter = or_(
        Incident.title.ilike(f"%{q}%"),
        Incident.description.ilike(f"%{q}%"),
    )
    conditions.append(query_filter)

    if severity:
        conditions.append(Incident.severity == severity.value)
    if status:
        conditions.append(Incident.status == status.value)
    if assignee:
        conditions.append(
            or_(
                Incident.assignee_name.ilike(f"%{assignee}%"),
                Incident.assignee_id == uuid.UUID(assignee) if _is_valid_uuid(assignee) else False,
            )
        )
    if date_from:
        conditions.append(Incident.created_at >= date_from)
    if date_to:
        conditions.append(Incident.created_at <= date_to)

    count_stmt = select(func.count()).select_from(Incident).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = select(Incident).where(and_(*conditions)).order_by(desc(Incident.created_at)).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    incidents = result.scalars().all()

    items = []
    for inc in incidents:
        items.append(IncidentSearchResult(
            id=str(inc.id),
            title=inc.title,
            severity=SeverityLevel(inc.severity) if inc.severity in [e.value for e in SeverityLevel] else SeverityLevel.MEDIUM,
            status=IncidentStatus(inc.status) if inc.status in [e.value for e in IncidentStatus] else IncidentStatus.OPEN,
            assignee_name=inc.assignee_name,
            asset_name=None,
            tags=inc.mitre_tactics or [],
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            highlights={},
        ))

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# ALERT SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/alerts", response_model=PaginatedSearchResults)
async def search_alerts(
    q: str = Query(..., min_length=1, description="Search query"),
    severity: Optional[SeverityLevel] = Query(None),
    status: Optional[AlertStatus] = Query(None),
    rule: Optional[str] = Query(None, description="Detection rule name or ID"),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [Alert.tenant_id == tenant_uuid]

    query_filter = or_(
        Alert.title.ilike(f"%{q}%"),
        Alert.description.ilike(f"%{q}%"),
    )
    conditions.append(query_filter)

    if severity:
        conditions.append(Alert.severity == severity.value)
    if status:
        conditions.append(Alert.status == status.value)
    if rule:
        conditions.append(
            or_(
                Alert.rule_name.ilike(f"%{rule}%"),
                Alert.rule_id == uuid.UUID(rule) if _is_valid_uuid(rule) else False,
            )
        )
    if date_from:
        conditions.append(Alert.created_at >= date_from)
    if date_to:
        conditions.append(Alert.created_at <= date_to)

    count_stmt = select(func.count()).select_from(Alert).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = select(Alert).where(and_(*conditions)).order_by(desc(Alert.created_at)).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    items = []
    for a in alerts:
        items.append(AlertSearchResult(
            id=str(a.id),
            name=a.title,
            severity=SeverityLevel(a.severity) if a.severity in [e.value for e in SeverityLevel] else SeverityLevel.MEDIUM,
            status=AlertStatus(a.status) if a.status in [e.value for e in AlertStatus] else AlertStatus.FIRING,
            rule_name=a.rule_name,
            source=a.source_ip,
            triggered_at=a.created_at,
            acknowledged_at=a.acknowledged_at,
            highlights={},
        ))

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# IOC SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/iocs", response_model=PaginatedSearchResults)
async def search_iocs(
    q: str = Query(..., min_length=1, description="Search query"),
    type: Optional[IOCType] = Query(None, description="IOC type filter"),
    confidence: Optional[ConfidenceLevel] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [ThreatIndicator.tenant_id == tenant_uuid]

    query_filter = or_(
        ThreatIndicator.value.ilike(f"%{q}%"),
        ThreatIndicator.description.ilike(f"%{q}%"),
    )
    conditions.append(query_filter)

    if type:
        conditions.append(ThreatIndicator.type == type.value)
    if confidence:
        conf_map = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 0.95}
        if confidence.value in conf_map:
            conditions.append(ThreatIndicator.confidence >= conf_map[confidence.value])

    count_stmt = select(func.count()).select_from(ThreatIndicator).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = select(ThreatIndicator).where(and_(*conditions)).order_by(desc(ThreatIndicator.created_at)).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    iocs = result.scalars().all()

    items = []
    for ioc in iocs:
        conf_level = ConfidenceLevel.MEDIUM
        if ioc.confidence >= 0.9:
            conf_level = ConfidenceLevel.CRITICAL
        elif ioc.confidence >= 0.7:
            conf_level = ConfidenceLevel.HIGH
        elif ioc.confidence >= 0.4:
            conf_level = ConfidenceLevel.MEDIUM
        else:
            conf_level = ConfidenceLevel.LOW

        items.append(IOCSearchResult(
            id=str(ioc.id),
            type=IOCType(ioc.type) if ioc.type in [e.value for e in IOCType] else IOCType.IP,
            value=ioc.value,
            confidence=conf_level,
            status="active" if ioc.is_active else "inactive",
            source=ioc.source,
            tags=ioc.tags or [],
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen,
            highlights={},
        ))

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# USER SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/users", response_model=PaginatedSearchResults)
async def search_users(
    q: str = Query(..., min_length=1, description="Search query"),
    role: Optional[UserRole] = Query(None),
    department: Optional[str] = Query(None),
    status: Optional[UserStatus] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [User.tenant_id == tenant_uuid]

    query_filter = or_(
        User.full_name.ilike(f"%{q}%"),
        User.email.ilike(f"%{q}%"),
        User.username.ilike(f"%{q}%"),
    )
    conditions.append(query_filter)

    if status:
        conditions.append(User.status == status.value)

    count_stmt = select(func.count()).select_from(User).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = select(User).where(and_(*conditions)).order_by(desc(User.created_at)).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    users = result.scalars().all()

    items = []
    for u in users:
        user_role = UserRole.SOC_ANALYST_L1
        if u.roles and len(u.roles) > 0:
            role_val = u.roles[0].get("name", "soc_analyst_l1") if isinstance(u.roles[0], dict) else str(u.roles[0])
            try:
                user_role = UserRole(role_val)
            except ValueError:
                pass

        if role and user_role != role:
            continue

        items.append(UserSearchResult(
            id=str(u.id),
            username=u.username,
            display_name=u.full_name or u.username,
            role=user_role,
            department=None,
            status=UserStatus(u.status) if u.status in [e.value for e in UserStatus] else UserStatus.ACTIVE,
            email=u.email,
            last_login=u.last_login_at,
            highlights={},
        ))

    if role:
        total = len(items)

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# PROCESS SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/processes", response_model=PaginatedSearchResults)
async def search_processes(
    q: str = Query(..., min_length=1, description="Search query"),
    asset_id: Optional[str] = Query(None),
    pid: Optional[int] = Query(None),
    user: Optional[str] = Query(None),
    hash: Optional[str] = Query(None, description="SHA256 or MD5 hash"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    conditions = [Asset.tenant_id == tid]

    if asset_id:
        conditions.append(Asset.id == uuid.UUID(asset_id))

    asset_query = select(Asset).where(and_(*conditions))
    asset_result = await db.execute(asset_query)
    assets = asset_result.scalars().all()

    conditions2 = [Agent.tenant_id == tid]
    agent_query = select(Agent).where(and_(*conditions2))
    agent_result = await db.execute(agent_query)
    agents = agent_result.scalars().all()

    items = []
    for agent in agents:
        if not agent.capabilities or "process_list" not in agent.capabilities:
            continue
        proc_data = agent.config.get("processes", []) if agent.config else []
        for proc in proc_data:
            name_match = q.lower() in (proc.get("name", "") or "").lower()
            cmd_match = q.lower() in (proc.get("command_line", "") or "").lower()
            if not name_match and not cmd_match:
                continue
            if pid is not None and proc.get("pid") != pid:
                continue
            if user and user.lower() not in (proc.get("user", "") or "").lower():
                continue
            if hash and hash.lower() not in ((proc.get("hash_sha256", "") or "")).lower():
                continue
            items.append(ProcessSearchResult(
                id=str(uuid.uuid4()),
                process_name=proc.get("name", "unknown"),
                pid=proc.get("pid", 0),
                ppid=proc.get("ppid"),
                user=proc.get("user"),
                command_line=proc.get("command_line"),
                hash_sha256=proc.get("hash_sha256"),
                asset_id=str(agent.asset_id) if agent.asset_id else None,
                asset_name=agent.hostname,
                start_time=None,
                end_time=None,
                is_malicious=proc.get("is_malicious"),
                highlights={},
            ))

    total = len(items)
    offset = (page - 1) * page_size
    paged_items = items[offset:offset + page_size]
    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=[i.model_dump() for i in paged_items],
        total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# LOG SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/logs", response_model=PaginatedSearchResults)
async def search_logs(
    q: str = Query(..., min_length=1, description="Full-text search on log entries"),
    log_source: Optional[str] = Query(None, description="Filter by log source name"),
    level: Optional[LogLevel] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    conditions = [AuditLog.tenant_id == tid]

    search_term = f"%{q}%"
    conditions.append(
        or_(
            AuditLog.action.ilike(search_term),
            AuditLog.resource_type.ilike(search_term),
            AuditLog.details.cast(String).ilike(search_term),
        )
    )

    if level:
        conditions.append(AuditLog.severity == level.value)
    if date_from:
        conditions.append(AuditLog.created_at >= date_from)
    if date_to:
        conditions.append(AuditLog.created_at <= date_to)

    count_stmt = select(func.count()).select_from(AuditLog).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = select(AuditLog).where(and_(*conditions)).order_by(desc(AuditLog.created_at)).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    logs = result.scalars().all()

    items = []
    for al in logs:
        detail_parts = []
        if al.details:
            for k, v in al.details.items():
                detail_parts.append(f"{k}={v}")
        message = f"{al.action} on {al.resource_type}" + (" " + " ".join(detail_parts) if detail_parts else "")

        log_level = LogLevel.INFO
        if al.severity == "critical":
            log_level = LogLevel.CRITICAL
        elif al.severity == "warning":
            log_level = LogLevel.WARNING
        elif al.severity == "error":
            log_level = LogLevel.ERROR

        items.append(LogSearchResult(
            id=str(al.id),
            log_source=al.resource_type,
            level=log_level,
            message=message,
            timestamp=al.created_at,
            host=al.ip_address,
            service="audit",
            raw_log=str(al.details) if al.details else message,
            highlights={},
        ))

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=[i.model_dump() for i in items],
        total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# VULNERABILITY SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/vulnerabilities", response_model=PaginatedSearchResults)
async def search_vulnerabilities(
    q: str = Query(..., min_length=1, description="Search query"),
    cve: Optional[str] = Query(None, description="Filter by CVE ID"),
    severity: Optional[SeverityLevel] = Query(None),
    asset: Optional[str] = Query(None, description="Filter by affected asset ID or name"),
    status: Optional[VulnStatus] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [Vulnerability.tenant_id == tenant_uuid]

    query_filter = or_(
        Vulnerability.title.ilike(f"%{q}%"),
        Vulnerability.cve_id.ilike(f"%{q}%"),
    )
    conditions.append(query_filter)

    if cve:
        conditions.append(Vulnerability.cve_id.ilike(f"%{cve}%"))
    if severity:
        conditions.append(Vulnerability.severity == severity.value)
    if status:
        conditions.append(Vulnerability.status == status.value)

    count_stmt = select(func.count()).select_from(Vulnerability).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = select(Vulnerability).where(and_(*conditions)).order_by(desc(Vulnerability.detected_at)).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    vulns = result.scalars().all()

    items = []
    for v in vulns:
        items.append(VulnerabilitySearchResult(
            id=str(v.id),
            cve=v.cve_id,
            title=v.title,
            severity=SeverityLevel(v.severity) if v.severity in [e.value for e in SeverityLevel] else SeverityLevel.MEDIUM,
            cvss_score=v.cvss_score,
            status=VulnStatus(v.status) if v.status in [e.value for e in VulnStatus] else VulnStatus.OPEN,
            affected_asset_id=str(v.affected_asset_id) if v.affected_asset_id else None,
            affected_asset_name=None,
            discovered_at=v.detected_at,
            highlights={},
        ))

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# PLAYBOOK SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/playbooks", response_model=PaginatedSearchResults)
async def search_playbooks(
    q: str = Query(..., min_length=1, description="Search query"),
    status: Optional[PlaybookStatus] = Query(None),
    trigger_type: Optional[PlaybookTrigger] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [Playbook.tenant_id == tenant_uuid]

    query_filter = or_(
        Playbook.name.ilike(f"%{q}%"),
        Playbook.description.ilike(f"%{q}%"),
    )
    conditions.append(query_filter)

    if status:
        conditions.append(Playbook.status == status.value)
    if trigger_type:
        conditions.append(Playbook.trigger_type == trigger_type.value)

    count_stmt = select(func.count()).select_from(Playbook).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = select(Playbook).where(and_(*conditions)).order_by(desc(Playbook.created_at)).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    playbooks = result.scalars().all()

    items = []
    for p in playbooks:
        step_count = len(p.steps) if p.steps else 0
        items.append(PlaybookSearchResult(
            id=str(p.id),
            name=p.name,
            status=PlaybookStatus(p.status) if p.status in [e.value for e in PlaybookStatus] else PlaybookStatus.DRAFT,
            trigger_type=PlaybookTrigger(p.trigger_type) if p.trigger_type in [e.value for e in PlaybookTrigger] else PlaybookTrigger.MANUAL,
            description=p.description,
            step_count=step_count,
            last_executed_at=p.last_executed_at,
            created_at=p.created_at,
            highlights={},
        ))

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# REPORT SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/reports", response_model=PaginatedSearchResults)
async def search_reports(
    q: str = Query(..., min_length=1, description="Search query"),
    report_type: Optional[ReportType] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    conditions = [Report.tenant_id == tenant_uuid]

    query_filter = or_(
        Report.name.ilike(f"%{q}%"),
    )
    conditions.append(query_filter)

    if report_type:
        conditions.append(Report.report_type == report_type.value)
    if date_from:
        conditions.append(Report.created_at >= date_from)
    if date_to:
        conditions.append(Report.created_at <= date_to)

    count_stmt = select(func.count()).select_from(Report).where(and_(*conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = select(Report).where(and_(*conditions)).order_by(desc(Report.created_at)).offset(offset).limit(page_size)
    result = await db.execute(stmt)
    reports = result.scalars().all()

    items = []
    for r in reports:
        items.append(ReportSearchResult(
            id=str(r.id),
            title=r.name,
            report_type=ReportType(r.report_type) if r.report_type in [e.value for e in ReportType] else ReportType.INCIDENT,
            author=str(r.created_by),
            status=r.status,
            tags=[],
            created_at=r.created_at,
            published_at=r.completed_at,
            highlights={},
        ))

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=items, total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# EVIDENCE SEARCH
# ════════════════════════════════════════════════════════════════════

@router.get("/evidence", response_model=PaginatedSearchResults)
async def search_evidence(
    q: str = Query(..., min_length=1, description="Search query"),
    incident_id: Optional[str] = Query(None),
    file_type: Optional[EvidenceFileType] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy.orm import joinedload
    tid = uuid.UUID(tenant_id)

    conditions = []
    if incident_id:
        conditions.append(IncidentEvidence.incident_id == uuid.UUID(incident_id))
    if file_type:
        conditions.append(IncidentEvidence.file_type == file_type.value)
    if date_from:
        conditions.append(IncidentEvidence.created_at >= date_from)
    if date_to:
        conditions.append(IncidentEvidence.created_at <= date_to)

    search_term = f"%{q}%"
    conditions.append(
        or_(
            IncidentEvidence.filename.ilike(search_term),
            IncidentEvidence.description.ilike(search_term),
        )
    )

    count_stmt = select(func.count()).select_from(IncidentEvidence).join(
        Incident, IncidentEvidence.incident_id == Incident.id
    ).where(and_(Incident.tenant_id == tid, *conditions))
    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    offset = (page - 1) * page_size
    stmt = (
        select(IncidentEvidence)
        .join(Incident, IncidentEvidence.incident_id == Incident.id)
        .options(joinedload(IncidentEvidence.incident))
        .where(and_(Incident.tenant_id == tid, *conditions))
        .order_by(desc(IncidentEvidence.created_at))
        .offset(offset)
        .limit(page_size)
    )
    result = await db.execute(stmt)
    evidence_items = result.unique().scalars().all()

    items = []
    for ev in evidence_items:
        ext = (ev.file_type or ev.filename.split(".")[-1] if "." in ev.filename else "other").lower()
        try:
            eft = EvidenceFileType(ext)
        except ValueError:
            eft = EvidenceFileType.OTHER

        items.append(EvidenceSearchResult(
            id=str(ev.id),
            name=ev.filename,
            file_type=eft,
            file_name=ev.filename,
            file_size_bytes=ev.file_size,
            incident_id=str(ev.incident_id),
            incident_title=ev.incident.title if ev.incident else None,
            uploaded_by=str(ev.uploaded_by),
            created_at=ev.created_at,
            highlights={},
        ))

    total_pages = max(1, math.ceil(total / page_size))
    return PaginatedSearchResults(
        items=[i.model_dump() for i in items],
        total=total, page=page, page_size=page_size, total_pages=total_pages,
    )


# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════

def _is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(val)
        return True
    except (ValueError, AttributeError):
        return False


_SUGGESTION_TABLES = [
    ("asset", Asset, "name"),
    ("incident", Incident, "title"),
    ("alert", Alert, "title"),
    ("ioc", ThreatIndicator, "value"),
    ("user", User, "full_name"),
    ("vulnerability", Vulnerability, "title"),
    ("playbook", Playbook, "name"),
    ("report", Report, "name"),
]


@router.get("/suggestions", response_model=List[SearchSuggestion])
async def get_search_suggestions(
    q: str = Query(..., min_length=2, description="Partial query for autocomplete"),
    resource_type: Optional[str] = Query(None, description="Limit suggestions to resource type"),
    max_suggestions: int = Query(10, ge=1, le=50),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    suggestions: List[SearchSuggestion] = []

    tables = _SUGGESTION_TABLES
    if resource_type:
        tables = [(rt, model, field) for rt, model, field in _SUGGESTION_TABLES if rt == resource_type]

    for rt, model, field in tables:
        if not hasattr(model, "tenant_id"):
            continue
        try:
            stmt = select(getattr(model, field)).where(
                model.tenant_id == tenant_uuid,
                getattr(model, field).ilike(f"%{q}%"),
            ).limit(5)
            result = await db.execute(stmt)
            titles = result.scalars().all()
            for title in titles:
                if title:
                    suggestions.append(SearchSuggestion(
                        text=str(title),
                        resource_type=rt,
                        category="label_match",
                        score=85.0,
                    ))
        except Exception:
            continue

    suggestions.sort(key=lambda s: s.score, reverse=True)
    return suggestions[:max_suggestions]


# ════════════════════════════════════════════════════════════════════
# SAVED SEARCHES
# ════════════════════════════════════════════════════════════════════

@router.get("/saved", response_model=List[SavedSearchResponse])
async def list_saved_searches(
    resource_type: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    result = []
    prefix = f"{tenant_id}:"
    for key, data in _saved_searches.items():
        if key.startswith(prefix):
            if resource_type and data.get("resource_type") != resource_type:
                continue
            result.append(SavedSearchResponse(**data))
    return result


@router.post("/saved", response_model=SavedSearchResponse, status_code=status.HTTP_201_CREATED)
async def save_search(
    body: SavedSearchCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    search_id = str(uuid.uuid4())
    now = datetime.now()
    data = {
        "id": search_id,
        "tenant_id": tenant_id,
        "user_id": current_user.get("user_id", ""),
        "name": body.name,
        "description": body.description,
        "resource_type": body.resource_type,
        "query": body.query,
        "filters": body.filters,
        "is_shared": body.is_shared,
        "created_at": now,
        "last_used_at": None,
        "use_count": 0,
    }
    _saved_searches[f"{tenant_id}:{search_id}"] = data
    return SavedSearchResponse(**data)


@router.delete("/saved/{search_id}", response_model=MessageResponse)
async def delete_saved_search(
    search_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    key = f"{tenant_id}:{search_id}"
    if key not in _saved_searches:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved search not found")
    data = _saved_searches.pop(key)
    return MessageResponse(message="Saved search deleted", detail=f"Search '{data.get('name')}' removed")


# ════════════════════════════════════════════════════════════════════
# INDEX STATISTICS
# ════════════════════════════════════════════════════════════════════

_INDEX_TABLES = [
    ("asset", Asset),
    ("incident", Incident),
    ("alert", Alert),
    ("ioc", ThreatIndicator),
    ("user", User),
    ("vulnerability", Vulnerability),
    ("playbook", Playbook),
    ("report", Report),
    ("detection_rule", DetectionRule),
    ("audit_log", AuditLog),
]


@router.get("/index-stats", response_model=List[IndexStats])
async def get_index_stats(
    resource_type: Optional[str] = Query(None, description="Filter by specific resource type"),
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    _: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tenant_uuid = uuid.UUID(tenant_id)
    stats = []

    tables = _INDEX_TABLES
    if resource_type:
        tables = [(rt, model) for rt, model in _INDEX_TABLES if rt == resource_type]

    for rt, model in tables:
        try:
            if not hasattr(model, "tenant_id"):
                continue
            count_stmt = select(func.count()).select_from(model).where(model.tenant_id == tenant_uuid)
            result = await db.execute(count_stmt)
            count = result.scalar() or 0
            stats.append(IndexStats(
                resource_type=rt,
                document_count=count,
                index_size_bytes=count * 1024,
                last_indexed_at=datetime.now(),
                index_latency_ms=0.5,
                health="green",
            ))
        except Exception:
            continue

    return stats
