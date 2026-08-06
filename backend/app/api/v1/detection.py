"""
AEGISX - Detection & Threat Intelligence API Router
Detection rules (YARA, Sigma, Suricata), alerts, IOCs, anomaly detection, UEBA, behavioral rules
"""
import json
import math
import uuid as uuid_mod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, update as sql_update, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    PaginationParams,
    get_current_user,
    require_tenant,
    RequireThreatHunter,
    RequireSOCManager,
    RequireSOCAnalyst,
)
from app.core.database import get_db
from app.models import DetectionRule, IOCRule, Alert, AuditLog

router = APIRouter()

# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════

def _uuid(v: Any) -> uuid_mod.UUID:
    if isinstance(v, uuid_mod.UUID):
        return v
    return uuid_mod.UUID(str(v))

def _build_rule_response(rule: DetectionRule) -> dict:
    rc = rule.rule_content or {}
    return {
        "id": str(rule.id),
        "name": rule.name,
        "description": rule.description,
        "rule_type": rule.rule_type,
        "severity": rule.severity,
        "status": rule.status,
        "mitre_attack": list(rule.mitre_tactics or []),
        "logic": rc if isinstance(rc, dict) else {"query": rule.query} if rule.query else {},
        "conditions": rc.get("conditions") if isinstance(rc, dict) else None,
        "tags": list(rule.tags or []),
        "references": rc.get("references", []) if isinstance(rc, dict) else [],
        "enabled": rule.status == "active",
        "priority": rule.risk_score,
        "schedule": rc.get("schedule") if isinstance(rc, dict) else None,
        "metadata": rc.get("metadata") if isinstance(rc, dict) else None,
        "tenant_id": str(rule.tenant_id),
        "created_by": str(rule.created_by) if rule.created_by else None,
        "updated_by": str(rule.created_by) if rule.created_by else None,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
        "last_triggered_at": rule.last_triggered,
        "trigger_count": rule.alert_count,
    }

def _build_alert_response(alert: Alert) -> dict:
    return {
        "id": str(alert.id),
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "rule_id": str(alert.rule_id) if alert.rule_id else None,
        "rule_name": alert.rule_name,
        "source": alert.source_ip,
        "category": alert.indicator_type,
        "assignee_id": str(alert.assigned_to) if alert.assigned_to else None,
        "assignee_name": None,
        "tenant_id": str(alert.tenant_id),
        "acknowledged_by": None,
        "acknowledged_at": alert.acknowledged_at,
        "dismissed_by": None,
        "dismissed_reason": None,
        "dismissed_at": None,
        "escalated_to_incident_id": str(alert.promoted_to_incident_id) if alert.promoted_to_incident_id else None,
        "escalated_at": None,
        "affected_assets": [str(alert.source_asset_id)] if alert.source_asset_id else [],
        "evidence": alert.raw_event,
        "raw_event": alert.raw_event,
        "tags": [],
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
        "resolved_at": alert.resolved_at,
    }

def _build_ioc_response(ioc: IOCRule) -> dict:
    return {
        "id": str(ioc.id),
        "ioc_type": ioc.ioc_type,
        "value": ioc.value,
        "description": ioc.description,
        "severity": ioc.severity,
        "tags": list(ioc.tags or []),
        "source": ioc.source,
        "tenant_id": str(ioc.tenant_id),
        "created_by": str(ioc.created_by) if ioc.created_by else None,
        "created_at": ioc.created_at,
        "expires_at": ioc.valid_until,
        "last_seen_at": None,
        "hit_count": 0,
        "enabled": ioc.is_active if ioc.is_active is not None else True,
        "metadata": None,
    }

async def _audit_log(
    db: AsyncSession,
    user: dict,
    action: str,
    resource_type: str,
    resource_id: Optional[uuid_mod.UUID] = None,
    details: Optional[dict] = None,
    status_val: str = "success",
):
    try:
        uid = _uuid(user["user_id"]) if user.get("user_id") else None
        tid = _uuid(user.get("tenant_id")) if user.get("tenant_id") else None
        log = AuditLog(
            tenant_id=tid,
            user_id=uid,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            status=status_val,
            severity="info",
        )
        db.add(log)
        await db.flush()
    except Exception:
        pass

def _paginated(items: list, total: int, page: int, page_size: int) -> dict:
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, math.ceil(total / page_size)) if page_size else 1,
    }

def _build_rule_content(rule_data: dict, *extra_keys) -> dict:
    rc = {}
    for k in extra_keys:
        if k in rule_data and rule_data[k] is not None:
            rc[k] = rule_data[k]
    return rc if rc else {}

# ════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════

class RuleType(str, Enum):
    SIGMA = "sigma"
    YARA = "yara"
    SURICATA = "suricata"
    CORRELATION = "correlation"
    THRESHOLD = "threshold"
    MACHINE_LEARNING = "machine_learning"
    BEHAVIORAL = "behavioral"

class RuleStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DRAFT = "draft"
    DEPRECATED = "deprecated"
    TESTING = "testing"

class RuleSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"

class AlertSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"

class AnomalyModelType(str, Enum):
    ISOLATION_FOREST = "isolation_forest"
    AUTOENCODER = "autoencoder"
    LOF = "local_outlier_factor"
    ONE_CLASS_SVM = "one_class_svm"

class AnomalyModelStatus(str, Enum):
    UNTRAINED = "untrained"
    TRAINING = "training"
    READY = "ready"
    FAILED = "failed"

class ExportFormat(str, Enum):
    SIGMA = "sigma"
    YARA = "yara"
    JSON = "json"

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
# Detection Rule Models
# ════════════════════════════════════════════════════════════════════

class RuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    rule_type: RuleType
    severity: RuleSeverity = RuleSeverity.MEDIUM
    mitre_attack: List[str] = Field(default_factory=list)
    logic: Dict[str, Any] = Field(default_factory=dict, description="Rule detection logic / query definition")
    conditions: Optional[Dict[str, Any]] = Field(None, description="Additional condition parameters")
    tags: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    enabled: bool = True
    priority: int = Field(0, ge=0, le=100)
    schedule: Optional[Dict[str, Any]] = Field(None, description="Cron schedule or interval config")
    metadata: Optional[Dict[str, Any]] = None

class RuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    rule_type: Optional[RuleType] = None
    severity: Optional[RuleSeverity] = None
    mitre_attack: Optional[List[str]] = None
    logic: Optional[Dict[str, Any]] = None
    conditions: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    references: Optional[List[str]] = None
    enabled: Optional[bool] = None
    priority: Optional[int] = Field(None, ge=0, le=100)
    status: Optional[RuleStatus] = None
    schedule: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

class RuleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    rule_type: RuleType
    severity: RuleSeverity
    status: RuleStatus
    mitre_attack: List[str] = []
    logic: Dict[str, Any] = {}
    conditions: Optional[Dict[str, Any]] = None
    tags: List[str] = []
    references: List[str] = []
    enabled: bool
    priority: int
    schedule: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    tenant_id: str
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_triggered_at: Optional[datetime] = None
    trigger_count: int = 0

    class Config:
        from_attributes = True

class RuleTestRequest(BaseModel):
    sample_data: Dict[str, Any] = Field(..., description="Sample event/log data to test against")
    simulate: bool = Field(False, description="If true, simulate without evaluating against DB")

class RuleTestResponse(BaseModel):
    matched: bool
    rule_id: str
    matches: List[Dict[str, Any]] = []
    execution_time_ms: float = 0.0
    details: Optional[Dict[str, Any]] = None

class RuleImportRequest(BaseModel):
    source: str = Field(..., description="Raw Sigma/YARA/Suricata rule text or batch content")
    format: RuleType = Field(..., description="Format of the imported rule(s)")
    overwrite_existing: bool = False
    tags: List[str] = []
    metadata: Optional[Dict[str, Any]] = None

class RuleImportResponse(BaseModel):
    imported: int
    skipped: int
    failed: int
    errors: List[Dict[str, Any]] = []
    rule_ids: List[str] = []

class RuleExportRequest(BaseModel):
    rule_ids: Optional[List[str]] = Field(None, description="Specific rule IDs to export; omit for all")
    format: ExportFormat = ExportFormat.JSON

class RuleExportResponse(BaseModel):
    format: ExportFormat
    count: int
    content: Any


# ════════════════════════════════════════════════════════════════════
# Sigma Rule Models
# ════════════════════════════════════════════════════════════════════

class SigmaRuleResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    status: Optional[str] = None
    author: Optional[str] = None
    level: Optional[str] = None
    tags: List[str] = []
    false_positives: List[str] = []
    detection: Dict[str, Any] = {}
    logsource: Optional[Dict[str, Any]] = None
    references: List[str] = []
    raw_yaml: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class SigmaConvertRequest(BaseModel):
    sigma_rule: str = Field(..., description="Sigma rule in YAML format")
    target: str = Field("kibana", description="Target query language (kibana, splunk, elastic, sentinel, etc.)")
    parameters: Optional[Dict[str, Any]] = None

class SigmaConvertResponse(BaseModel):
    original: str
    target: str
    query: str
    conditions: List[str] = []


# ════════════════════════════════════════════════════════════════════
# YARA Rule Models
# ════════════════════════════════════════════════════════════════════

class YARARuleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    rule_text: str
    tags: List[str] = []
    severity: RuleSeverity = RuleSeverity.MEDIUM
    enabled: bool = True
    compile_status: Optional[str] = None
    compile_error: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class YARAScanRequest(BaseModel):
    target: str = Field(..., description="File path or process ID to scan")
    target_type: str = Field("file", description="'file' or 'process'")
    rule_ids: Optional[List[str]] = Field(None, description="Specific rule IDs; omit to use all active YARA rules")
    timeout_seconds: int = Field(300, ge=1, le=3600)

class YARAScanResponse(BaseModel):
    target: str
    target_type: str
    scan_duration_seconds: float = 0.0
    rules_evaluated: int = 0
    matches: List[Dict[str, Any]] = []
    status: str = "completed"


# ════════════════════════════════════════════════════════════════════
# Alert Models
# ════════════════════════════════════════════════════════════════════

class AlertResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    severity: AlertSeverity
    status: AlertStatus
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    source: Optional[str] = None
    category: Optional[str] = None
    assignee_id: Optional[str] = None
    assignee_name: Optional[str] = None
    tenant_id: str
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    dismissed_by: Optional[str] = None
    dismissed_reason: Optional[str] = None
    dismissed_at: Optional[datetime] = None
    escalated_to_incident_id: Optional[str] = None
    escalated_at: Optional[datetime] = None
    affected_assets: List[str] = []
    evidence: Optional[Dict[str, Any]] = None
    raw_event: Optional[Dict[str, Any]] = None
    tags: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    severity: Optional[AlertSeverity] = None
    assignee_id: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    affected_assets: Optional[List[str]] = None

class AlertDismissRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)
    suppress_similar: bool = False
    suppress_duration_hours: Optional[int] = Field(None, ge=1, le=8760)

class AlertEscalateRequest(BaseModel):
    incident_priority: Optional[str] = "medium"
    incident_title_override: Optional[str] = None
    assignee_id: Optional[str] = None
    notes: Optional[str] = None

class AlertEscalateResponse(BaseModel):
    alert_id: str
    incident_id: str
    message: str

class BulkAlertOperation(BaseModel):
    alert_ids: List[str] = Field(..., min_length=1, max_length=1000)
    action: str = Field(..., pattern=r"^(acknowledge|dismiss|escalate|update_severity|assign)$")
    parameters: Optional[Dict[str, Any]] = None

class BulkAlertResponse(BaseModel):
    affected: int
    failed: List[str] = []
    errors: List[Dict[str, Any]] = []

class AlertStatsResponse(BaseModel):
    total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    new_last_24h: int = 0
    escalated_last_24h: int = 0
    mean_time_to_acknowledge_minutes: Optional[float] = None
    mean_time_to_resolve_minutes: Optional[float] = None
    top_triggered_rules: List[Dict[str, Any]] = []


# ════════════════════════════════════════════════════════════════════
# IOC Models
# ════════════════════════════════════════════════════════════════════

class IocCreate(BaseModel):
    ioc_type: IOCType
    value: str = Field(..., min_length=1, max_length=4096)
    description: Optional[str] = Field(None, max_length=2000)
    severity: RuleSeverity = RuleSeverity.MEDIUM
    tags: List[str] = []
    source: Optional[str] = None
    expires_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None

class IocResponse(BaseModel):
    id: str
    ioc_type: IOCType
    value: str
    description: Optional[str] = None
    severity: RuleSeverity
    tags: List[str] = []
    source: Optional[str] = None
    tenant_id: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    hit_count: int = 0
    enabled: bool = True
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

class IocBulkImportRequest(BaseModel):
    iocs: List[Dict[str, Any]] = Field(..., min_length=1, max_length=10000)
    tags: List[str] = []

class IocBulkImportResponse(BaseModel):
    imported: int
    skipped: int
    failed: int
    errors: List[Dict[str, Any]] = []


# ════════════════════════════════════════════════════════════════════
# Anomaly Detection Models
# ════════════════════════════════════════════════════════════════════

class AnomalyModelResponse(BaseModel):
    id: str
    name: str
    model_type: AnomalyModelType
    status: AnomalyModelStatus
    description: Optional[str] = None
    features: List[str] = []
    hyperparameters: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, Any]] = None
    training_data_size: Optional[int] = None
    tenant_id: str
    created_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    trained_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class AnomalyModelTrainRequest(BaseModel):
    dataset_id: Optional[str] = Field(None, description="Dataset identifier for training data")
    start_time: Optional[datetime] = Field(None, description="Training data window start")
    end_time: Optional[datetime] = Field(None, description="Training data window end")
    hyperparameters: Optional[Dict[str, Any]] = None

class AnomalyModelStatusResponse(BaseModel):
    model_id: str
    status: AnomalyModelStatus
    progress_percentage: float = 0.0
    current_step: Optional[str] = None
    started_at: Optional[datetime] = None
    estimated_completion_at: Optional[datetime] = None
    error_message: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None


# ════════════════════════════════════════════════════════════════════
# Behavioral Rule Models
# ════════════════════════════════════════════════════════════════════

class BehavioralRuleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    pattern: Dict[str, Any] = {}
    severity: RuleSeverity = RuleSeverity.MEDIUM
    enabled: bool = True
    tags: List[str] = []
    mitre_attack: List[str] = []
    threshold: Optional[float] = None
    window_seconds: int = 3600
    tenant_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ════════════════════════════════════════════════════════════════════
# UEBA Models
# ════════════════════════════════════════════════════════════════════

class UEBAProfileResponse(BaseModel):
    user_id: str
    display_name: Optional[str] = None
    department: Optional[str] = None
    baseline_score: Optional[float] = None
    baseline_established_at: Optional[datetime] = None
    risk_score: float = 0.0
    typical_logon_hours: Optional[Dict[str, Any]] = None
    typical_locations: List[str] = []
    typical_devices: List[str] = []
    typical_commands: List[str] = []
    typical_accessed_resources: List[str] = []
    peer_group: Optional[str] = None
    anomaly_count_30d: int = 0
    last_activity_at: Optional[datetime] = None
    last_evaluated_at: Optional[datetime] = None

class UEBABaselineResponse(BaseModel):
    user_id: str
    display_name: Optional[str] = None
    department: Optional[str] = None
    baseline_period_days: int = 30
    baseline_established_at: Optional[datetime] = None
    metrics: Dict[str, Any] = {}
    vector: Optional[List[float]] = None
    risk_factors: List[Dict[str, Any]] = []

class UEBAAnomalyResponse(BaseModel):
    id: str
    user_id: str
    anomaly_type: str
    severity: AlertSeverity
    description: Optional[str] = None
    score: float = 0.0
    deviation: Optional[float] = None
    evidence: Optional[Dict[str, Any]] = None
    detected_at: Optional[datetime] = None
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    tenant_id: str

    class Config:
        from_attributes = True


# ════════════════════════════════════════════════════════════════════
# ── Detection Rules CRUD ───────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.post(
    "/rules",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Detection Rule",
    description="Create a new detection rule (Sigma, YARA, Suricata, Correlation, etc.)",
)
async def create_rule(
    rule: RuleCreate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    existing = await db.execute(
        select(DetectionRule).where(
            and_(DetectionRule.tenant_id == tid, DetectionRule.name == rule.name)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule with name '{rule.name}' already exists for this tenant",
        )

    rule_content = dict(rule.logic)
    if rule.conditions is not None:
        rule_content["conditions"] = rule.conditions
    if rule.references:
        rule_content["references"] = rule.references
    if rule.schedule is not None:
        rule_content["schedule"] = dict(rule.schedule) if hasattr(rule.schedule, "items") else rule.schedule
    if rule.metadata is not None:
        rule_content["metadata"] = rule.metadata

    query_str = rule_content.get("query", None)

    db_rule = DetectionRule(
        tenant_id=tid,
        name=rule.name,
        description=rule.description,
        rule_type=rule.rule_type.value,
        severity=rule.severity.value,
        status="active" if rule.enabled else "disabled",
        rule_content=rule_content,
        query=query_str,
        mitre_tactics=rule.mitre_attack,
        tags=rule.tags,
        risk_score=rule.priority,
        created_by=_uuid(current_user["user_id"]) if current_user.get("user_id") else None,
    )
    db.add(db_rule)
    await db.flush()
    await db.refresh(db_rule)

    await _audit_log(db, current_user, "rule.created", "detection_rule", db_rule.id,
                     {"name": rule.name, "rule_type": rule.rule_type.value})
    return _build_rule_response(db_rule)


@router.get(
    "/rules",
    response_model=PaginatedResponse,
    summary="List Detection Rules",
    description="List all detection rules with filtering, search, and pagination.",
)
async def list_rules(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    rule_type: Optional[RuleType] = Query(None, description="Filter by rule type"),
    status_val: Optional[RuleStatus] = Query(None, description="Filter by rule status", alias="status"),
    severity: Optional[RuleSeverity] = Query(None, description="Filter by severity"),
    search: Optional[str] = Query(None, description="Search in name, description, tags"),
    tags: Optional[List[str]] = Query(None, description="Filter by tags"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled state"),
    sort_by: Optional[str] = Query("created_at", description="Field to sort by"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    tid = _uuid(tenant_id)
    conditions = [DetectionRule.tenant_id == tid]

    if rule_type:
        conditions.append(DetectionRule.rule_type == rule_type.value)
    if status_val:
        conditions.append(DetectionRule.status == status_val.value)
    if severity:
        conditions.append(DetectionRule.severity == severity.value)
    if enabled is not None:
        conditions.append(DetectionRule.status == ("active" if enabled else "disabled"))
    if search:
        search_term = f"%{search}%"
        conditions.append(
            or_(
                DetectionRule.name.ilike(search_term),
                DetectionRule.description.ilike(search_term),
            )
        )
    if tags:
        conditions.append(DetectionRule.tags.overlap(tags))

    count_q = select(func.count()).select_from(DetectionRule).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    sort_col = getattr(DetectionRule, sort_by, DetectionRule.created_at)
    order_fn = desc if sort_order == "desc" else asc

    q = select(DetectionRule).where(and_(*conditions)).order_by(order_fn(sort_col)).offset(
        (page - 1) * page_size
    ).limit(page_size)
    result = await db.execute(q)
    rules = result.scalars().all()

    return _paginated(
        [_build_rule_response(r) for r in rules],
        total, page, page_size,
    )


@router.get(
    "/rules/import",
    response_model=dict,
    summary="Get Import Status",
    description="Check the status of a bulk rule import operation.",
    deprecated=True,
)
async def rule_import_status(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
):
    return {"message": "Use POST /rules/import to import rules"}


@router.post(
    "/rules/import",
    response_model=RuleImportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Import Rules",
    description="Import detection rules in Sigma, YARA, or Suricata format.",
)
async def import_rules(
    request: RuleImportRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    uid = _uuid(current_user["user_id"]) if current_user.get("user_id") else None
    imported = 0
    skipped = 0
    failed = 0
    errors: list = []
    rule_ids: list = []

    try:
        parsed = json.loads(request.source)
    except json.JSONDecodeError:
        try:
            import yaml
            parsed = yaml.safe_load(request.source)
        except Exception:
            return RuleImportResponse(imported=0, skipped=0, failed=1,
                                      errors=[{"error": "Unable to parse input"}], rule_ids=[])

    rules_list = parsed if isinstance(parsed, list) else [parsed]

    for item in rules_list:
        if not isinstance(item, dict):
            failed += 1
            errors.append({"error": "Invalid rule entry", "entry": str(item)})
            continue

        rule_name = item.get("title") or item.get("name") or f"imported-rule-{uuid_mod.uuid4().hex[:8]}"

        existing = await db.execute(
            select(DetectionRule).where(
                and_(DetectionRule.tenant_id == tid, DetectionRule.name == rule_name)
            )
        )
        if existing.scalar_one_or_none():
            if not request.overwrite_existing:
                skipped += 1
                continue
            else:
                existing_rule = existing.scalar_one_or_none()
                existing_rule.rule_content = item
                existing_rule.severity = item.get("severity", "medium")
                existing_rule.tags = list(set((existing_rule.tags or []) + request.tags))
                existing_rule.updated_at = datetime.now(timezone.utc)
                imported += 1
                rule_ids.append(str(existing_rule.id))
                continue

        db_rule = DetectionRule(
            tenant_id=tid,
            name=rule_name,
            description=item.get("description"),
            rule_type=request.format.value,
            severity=item.get("severity", item.get("level", "medium")),
            rule_content=item,
            mitre_tactics=item.get("mitre_attack") or item.get("tags", []),
            tags=list(set((item.get("tags") or []) + request.tags)),
            created_by=uid,
        )
        db.add(db_rule)
        await db.flush()
        rule_ids.append(str(db_rule.id))
        imported += 1

    await _audit_log(db, current_user, "rules.imported", "detection_rule", None,
                     {"imported": imported, "skipped": skipped, "failed": failed})
    return RuleImportResponse(imported=imported, skipped=skipped, failed=failed,
                              errors=errors, rule_ids=rule_ids)


@router.get(
    "/rules/export",
    response_model=RuleExportResponse,
    summary="Export Rules",
    description="Export detection rules in Sigma, YARA, or JSON format.",
)
async def export_rules(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
    rule_ids: Optional[List[str]] = Query(None, description="Specific rule IDs to export"),
    format: ExportFormat = Query(ExportFormat.JSON, description="Export format"),
):
    tid = _uuid(tenant_id)
    conditions = [DetectionRule.tenant_id == tid]
    if rule_ids:
        uuids = [_uuid(rid) for rid in rule_ids]
        conditions.append(DetectionRule.id.in_(uuids))

    result = await db.execute(select(DetectionRule).where(and_(*conditions)))
    rules = result.scalars().all()

    content = [_build_rule_response(r) for r in rules]
    return RuleExportResponse(format=format, count=len(content), content=content)


@router.get(
    "/rules/ioc",
    response_model=PaginatedResponse,
    summary="List IOC Rules",
    description="List all Indicator of Compromise (IOC) rules.",
)
async def list_ioc_rules(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
    ioc_type: Optional[IOCType] = Query(None, description="Filter by IOC type"),
    severity: Optional[RuleSeverity] = Query(None, description="Filter by severity"),
    search: Optional[str] = Query(None, description="Search in value, description"),
    tags: Optional[List[str]] = Query(None),
    active: Optional[bool] = Query(None, description="Filter by active state"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: Optional[str] = Query("created_at"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
):
    tid = _uuid(tenant_id)
    conditions = [IOCRule.tenant_id == tid]

    if ioc_type:
        conditions.append(IOCRule.ioc_type == ioc_type.value)
    if severity:
        conditions.append(IOCRule.severity == severity.value)
    if active is not None:
        conditions.append(IOCRule.is_active == active)
    if search:
        search_term = f"%{search}%"
        conditions.append(
            or_(IOCRule.value.ilike(search_term), IOCRule.description.ilike(search_term))
        )
    if tags:
        conditions.append(IOCRule.tags.overlap(tags))

    count_q = select(func.count()).select_from(IOCRule).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    sort_col = getattr(IOCRule, sort_by, IOCRule.created_at)
    order_fn = desc if sort_order == "desc" else asc

    q = select(IOCRule).where(and_(*conditions)).order_by(order_fn(sort_col)).offset(
        (page - 1) * page_size
    ).limit(page_size)
    result = await db.execute(q)
    iocs = result.scalars().all()

    return _paginated(
        [_build_ioc_response(i) for i in iocs],
        total, page, page_size,
    )


@router.post(
    "/rules/ioc",
    response_model=IocResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add IOC Rule",
    description="Add a single Indicator of Compromise rule.",
)
async def add_ioc_rule(
    ioc: IocCreate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    existing = await db.execute(
        select(IOCRule).where(
            and_(
                IOCRule.tenant_id == tid,
                IOCRule.value == ioc.value,
                IOCRule.ioc_type == ioc.ioc_type.value,
            )
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"IOC with value '{ioc.value}' and type '{ioc.ioc_type.value}' already exists",
        )

    db_ioc = IOCRule(
        tenant_id=tid,
        ioc_type=ioc.ioc_type.value,
        value=ioc.value,
        description=ioc.description,
        severity=ioc.severity.value,
        tags=ioc.tags,
        source=ioc.source,
        valid_until=ioc.expires_at,
        created_by=_uuid(current_user["user_id"]) if current_user.get("user_id") else None,
    )
    db.add(db_ioc)
    await db.flush()
    await db.refresh(db_ioc)

    await _audit_log(db, current_user, "ioc.created", "ioc_rule", db_ioc.id,
                     {"value": ioc.value, "ioc_type": ioc.ioc_type.value})
    return _build_ioc_response(db_ioc)


@router.post(
    "/rules/ioc/bulk",
    response_model=IocBulkImportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bulk Import IOCs",
    description="Import multiple IOCs at once.",
)
async def bulk_import_iocs(
    request: IocBulkImportRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    uid = _uuid(current_user["user_id"]) if current_user.get("user_id") else None
    imported = 0
    skipped = 0
    failed = 0
    errors: list = []

    for entry in request.iocs:
        ioc_type = entry.get("ioc_type") or entry.get("type", "")
        value = entry.get("value", "")
        if not value or not ioc_type:
            failed += 1
            errors.append({"error": "Missing value or ioc_type", "entry": entry})
            continue

        existing = await db.execute(
            select(IOCRule).where(
                and_(IOCRule.tenant_id == tid, IOCRule.value == value, IOCRule.ioc_type == ioc_type)
            )
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue

        db_ioc = IOCRule(
            tenant_id=tid,
            ioc_type=ioc_type,
            value=value,
            description=entry.get("description"),
            severity=entry.get("severity", "high"),
            source=entry.get("source"),
            tags=list(set((entry.get("tags") or []) + request.tags)),
            created_by=uid,
        )
        db.add(db_ioc)
        imported += 1

    await db.flush()
    await _audit_log(db, current_user, "iocs.bulk_imported", "ioc_rule", None,
                     {"imported": imported, "skipped": skipped, "failed": failed})
    return IocBulkImportResponse(imported=imported, skipped=skipped, failed=failed, errors=errors)


@router.get(
    "/rules/{rule_id}",
    response_model=RuleResponse,
    summary="Get Rule Detail",
    description="Retrieve a single detection rule by ID.",
)
async def get_rule(
    rule_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    rid = _uuid(rule_id)
    result = await db.execute(
        select(DetectionRule).where(
            and_(DetectionRule.id == rid, DetectionRule.tenant_id == tid)
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return _build_rule_response(rule)


@router.patch(
    "/rules/{rule_id}",
    response_model=RuleResponse,
    summary="Update Detection Rule",
    description="Update an existing detection rule partially.",
)
async def update_rule(
    rule_id: str,
    rule_update: RuleUpdate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    rid = _uuid(rule_id)
    result = await db.execute(
        select(DetectionRule).where(
            and_(DetectionRule.id == rid, DetectionRule.tenant_id == tid)
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    update_data = rule_update.model_dump(exclude_unset=True)

    if "name" in update_data:
        rule.name = update_data["name"]
    if "description" in update_data:
        rule.description = update_data["description"]
    if "severity" in update_data and update_data["severity"]:
        rule.severity = update_data["severity"].value
    if "rule_type" in update_data and update_data["rule_type"]:
        rule.rule_type = update_data["rule_type"].value
    if "mitre_attack" in update_data:
        rule.mitre_tactics = update_data["mitre_attack"]
    if "tags" in update_data:
        rule.tags = update_data["tags"]
    if "enabled" in update_data:
        rule.status = "active" if update_data["enabled"] else "disabled"
    if "status" in update_data and update_data["status"]:
        rule.status = update_data["status"].value
    if "priority" in update_data:
        rule.risk_score = update_data["priority"]

    rc = dict(rule.rule_content) if rule.rule_content else {}
    if "logic" in update_data:
        rc.update(update_data["logic"])
    if "conditions" in update_data:
        rc["conditions"] = update_data["conditions"]
    if "references" in update_data:
        rc["references"] = update_data["references"]
    if "schedule" in update_data:
        rc["schedule"] = update_data["schedule"] if update_data["schedule"] else None
    if "metadata" in update_data:
        rc["metadata"] = update_data["metadata"]
    rule.rule_content = rc
    if "logic" in update_data and isinstance(update_data["logic"], dict):
        rule.query = update_data["logic"].get("query", rule.query)

    rule.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(rule)

    await _audit_log(db, current_user, "rule.updated", "detection_rule", rule.id,
                     {"updated_fields": list(update_data.keys())})
    return _build_rule_response(rule)


@router.delete(
    "/rules/{rule_id}",
    response_model=MessageResponse,
    summary="Delete Detection Rule",
    description="Delete a detection rule permanently.",
)
async def delete_rule(
    rule_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    rid = _uuid(rule_id)
    result = await db.execute(
        select(DetectionRule).where(
            and_(DetectionRule.id == rid, DetectionRule.tenant_id == tid)
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    await db.delete(rule)
    await db.flush()

    await _audit_log(db, current_user, "rule.deleted", "detection_rule", rid,
                     {"name": rule.name})
    return MessageResponse(message="Rule deleted successfully", detail=f"Rule '{rule.name}' removed")


@router.delete(
    "/rules/ioc/{ioc_id}",
    response_model=MessageResponse,
    summary="Remove IOC",
    description="Delete an IOC rule by ID.",
)
async def remove_ioc(
    ioc_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    iid = _uuid(ioc_id)
    result = await db.execute(
        select(IOCRule).where(
            and_(IOCRule.id == iid, IOCRule.tenant_id == tid)
        )
    )
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    await db.delete(ioc)
    await db.flush()

    await _audit_log(db, current_user, "ioc.deleted", "ioc_rule", iid,
                     {"value": ioc.value})
    return MessageResponse(message="IOC deleted successfully", detail=f"IOC '{ioc.value}' removed")


@router.post(
    "/rules/{rule_id}/enable",
    response_model=RuleResponse,
    summary="Enable Rule",
    description="Enable a detection rule.",
)
async def enable_rule(
    rule_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    rid = _uuid(rule_id)
    result = await db.execute(
        select(DetectionRule).where(
            and_(DetectionRule.id == rid, DetectionRule.tenant_id == tid)
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    rule.status = "active"
    rule.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(rule)

    await _audit_log(db, current_user, "rule.enabled", "detection_rule", rule.id)
    return _build_rule_response(rule)


@router.post(
    "/rules/{rule_id}/disable",
    response_model=RuleResponse,
    summary="Disable Rule",
    description="Disable a detection rule.",
)
async def disable_rule(
    rule_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    rid = _uuid(rule_id)
    result = await db.execute(
        select(DetectionRule).where(
            and_(DetectionRule.id == rid, DetectionRule.tenant_id == tid)
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    rule.status = "disabled"
    rule.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(rule)

    await _audit_log(db, current_user, "rule.disabled", "detection_rule", rule.id)
    return _build_rule_response(rule)


@router.post(
    "/rules/{rule_id}/test",
    response_model=RuleTestResponse,
    summary="Test Rule",
    description="Test a detection rule against provided sample data.",
)
async def test_rule(
    rule_id: str,
    request: RuleTestRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    import time as _time
    start = _time.time()
    tid = _uuid(tenant_id)
    rid = _uuid(rule_id)
    result = await db.execute(
        select(DetectionRule).where(
            and_(DetectionRule.id == rid, DetectionRule.tenant_id == tid)
        )
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    matches: List[Dict[str, Any]] = []
    matched = False
    details: Dict[str, Any] = {"rule_type": rule.rule_type}
    sample = request.sample_data

    if rule.rule_type == "sigma":
        rc = rule.rule_content or {}
        detection = rc.get("detection", {})
        if detection and isinstance(detection, dict):
            condition = detection.get("condition", "")
            selection_entries = {k: v for k, v in detection.items() if k.startswith("selection")}
            field_matches = []
            for sel_name, sel_fields in selection_entries.items():
                if isinstance(sel_fields, dict):
                    sel_matched = True
                    for field_key, field_val in sel_fields.items():
                        sample_val = sample.get(field_key)
                        if sample_val is None:
                            sel_matched = False
                            break
                        if isinstance(field_val, list):
                            if sample_val not in field_val:
                                sel_matched = False
                                break
                    if sel_matched:
                        field_matches.append({"selection": sel_name, "matched_fields": list(sel_fields.keys())})
            if field_matches:
                matched = True
                matches = field_matches
                details["condition_matched"] = condition

    elif rule.rule_type == "suricata":
        query = rule.query or ""
        details["query"] = query
        for key in ("src_ip", "dest_ip", "src_port", "dest_port", "proto", "http_uri", "dns_query"):
            if key in sample and key in query:
                matched = True
                matches.append({"field": key, "value": sample[key], "in_query": True})
                break

    elif rule.rule_type in ("correlation", "threshold", "machine_learning", "behavioral"):
        query = rule.query or ""
        if query:
            for field_name in sample:
                if field_name.lower() in query.lower():
                    matched = True
                    matches.append({"field": field_name, "value": sample.get(field_name)})

    ioc_check_performed = False
    if not matched and (rule.rule_type == "sigma" or not rule.query):
        ioc_result = await db.execute(
            select(IOCRule).where(IOCRule.tenant_id == tid, IOCRule.is_active == True)
        )
        iocs = ioc_result.scalars().all()
        ioc_matches = []
        sample_str = json.dumps(sample).lower()
        for ioc in iocs:
            if ioc.value and ioc.value.lower() in sample_str:
                ioc_matches.append({"ioc_type": ioc.ioc_type, "value": ioc.value, "description": ioc.description})
        if ioc_matches:
            matched = True
            matches = ioc_matches
            ioc_check_performed = True

    details["ioc_check_performed"] = ioc_check_performed
    elapsed = (_time.time() - start) * 1000

    await _audit_log(db, current_user, "rule.tested", "detection_rule", rule.id,
                     {"rule_type": rule.rule_type, "matched": matched, "sample_keys": list(sample.keys())[:10]})
    return RuleTestResponse(
        matched=matched,
        rule_id=str(rule.id),
        matches=matches,
        execution_time_ms=round(elapsed, 2),
        details=details,
    )


# ════════════════════════════════════════════════════════════════════
# ── Sigma Rules ────────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/sigma/rules",
    response_model=PaginatedResponse,
    summary="List Sigma Rules",
    description="List all Sigma-formatted detection rules.",
)
async def list_sigma_rules(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
    search: Optional[str] = Query(None),
    level: Optional[str] = Query(None, description="Filter by Sigma rule level"),
    tags: Optional[List[str]] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    tid = _uuid(tenant_id)
    conditions = [DetectionRule.tenant_id == tid, DetectionRule.rule_type == "sigma"]

    if search:
        search_term = f"%{search}%"
        conditions.append(
            or_(DetectionRule.name.ilike(search_term), DetectionRule.description.ilike(search_term))
        )
    if tags:
        conditions.append(DetectionRule.tags.overlap(tags))

    count_q = select(func.count()).select_from(DetectionRule).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    q = select(DetectionRule).where(and_(*conditions)).order_by(desc(DetectionRule.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size)
    result = await db.execute(q)
    rules = result.scalars().all()

    items = []
    for r in rules:
        rc = r.rule_content or {}
        items.append({
            "id": str(r.id),
            "title": r.name,
            "description": r.description,
            "status": r.status,
            "author": None,
            "level": rc.get("level") or rc.get("severity"),
            "tags": list(r.tags or []),
            "false_positives": rc.get("falsepositives") or rc.get("false_positives", []),
            "detection": rc.get("detection", {}),
            "logsource": rc.get("logsource"),
            "references": rc.get("references", []),
            "raw_yaml": None,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        })
    return _paginated(items, total, page, page_size)


@router.post(
    "/sigma/convert",
    response_model=SigmaConvertResponse,
    summary="Convert Sigma Rule",
    description="Convert a Sigma rule to a target query language (Splunk, Elastic, Sentinel, etc.).",
)
async def convert_sigma_rule(
    request: SigmaConvertRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
):
    sigma_rule = request.sigma_rule
    target = request.target
    parsed = None
    conditions: List[str] = []

    try:
        import yaml
        parsed = yaml.safe_load(sigma_rule)
    except Exception:
        try:
            parsed = json.loads(sigma_rule)
        except Exception:
            return SigmaConvertResponse(
                original=sigma_rule,
                target=target,
                query=f"# Unable to parse Sigma rule for target: {target}",
                conditions=["parse-error"],
            )

    if not isinstance(parsed, dict):
        return SigmaConvertResponse(
            original=sigma_rule,
            target=target,
            query="# Invalid Sigma rule format",
            conditions=["invalid-format"],
        )

    title = parsed.get("title", "unnamed_rule")
    logsource = parsed.get("logsource", {})
    detection = parsed.get("detection", {})

    product = logsource.get("product", "windows")
    service = logsource.get("service", "")
    category = logsource.get("category", "")

    condition_expr = detection.get("condition", "")
    conditions.append(f"sigma-title:{title}")
    conditions.append(f"logsource-product:{product}")

    query_parts = []
    if target == "kibana":
        query_parts.append(f"event.module: \"{product}\"")
        if category:
            query_parts.append(f"event.category: \"{category}\"")

        selection_entries = {k: v for k, v in detection.items() if k not in ("condition",) and isinstance(v, dict)}
        for sel_name, sel_fields in selection_entries.items():
            for field_name, field_value in sel_fields.items():
                if isinstance(field_value, list):
                    val_list = " OR ".join(f'"{v}"' for v in field_value)
                    query_parts.append(f"({field_name}: ({val_list}))")
                else:
                    query_parts.append(f"{field_name}: \"{field_value}\"")

    elif target == "splunk":
        query_parts.append(f"index=* source=*")
        if product:
            query_parts.append(f"sourcetype={product}*")
        selection_entries = {k: v for k, v in detection.items() if k not in ("condition",) and isinstance(v, dict)}
        for sel_name, sel_fields in selection_entries.items():
            for field_name, field_value in sel_fields.items():
                if isinstance(field_value, list):
                    val_or = " OR ".join(f'{field_name}="{v}"' for v in field_value)
                    query_parts.append(f"({val_or})")
                else:
                    query_parts.append(f'{field_name}="{field_value}"')

    elif target == "elastic":
        query_parts.append(f"event.provider: \"{product}\"")
        if category:
            query_parts.append(f"event.category: \"{category}\"")
        selection_entries = {k: v for k, v in detection.items() if k not in ("condition",) and isinstance(v, dict)}
        for sel_name, sel_fields in selection_entries.items():
            for field_name, field_value in sel_fields.items():
                ecs_field = field_name.replace(".", "_") if "." in field_name else field_name
                if isinstance(field_value, list):
                    val_list = " OR ".join(f'{ecs_field}:"{v}"' for v in field_value)
                    query_parts.append(f"({val_list})")
                else:
                    query_parts.append(f'{ecs_field}:"{field_value}"')

    elif target == "sentinel":
        query_parts.append(f"let EventLog = CommonSecurityLog | EventLog")
        selection_entries = {k: v for k, v in detection.items() if k not in ("condition",) and isinstance(v, dict)}
        for sel_name, sel_fields in selection_entries.items():
            for field_name, field_value in sel_fields.items():
                if isinstance(field_value, list):
                    val_or = " or ".join(f'{field_name} == "{v}"' for v in field_value)
                    query_parts.append(f"| where {val_or}")
                else:
                    query_parts.append(f'| where {field_name} == "{field_value}"')

    else:
        selection_entries = {k: v for k, v in detection.items() if k not in ("condition",) and isinstance(v, dict)}
        for sel_name, sel_fields in selection_entries.items():
            for field_name, field_value in sel_fields.items():
                if isinstance(field_value, list):
                    query_parts.append(f"{field_name} IN ({', '.join(repr(v) for v in field_value)})")
                else:
                    query_parts.append(f"{field_name} == {repr(field_value)}")
        query_parts.insert(0, f"# {target} query for {title}")

    query = " AND ".join(query_parts) if query_parts else f"# No selection fields found in Sigma rule: {title}"
    if condition_expr:
        conditions.append(f"condition:{condition_expr}")

    for k in detection:
        if isinstance(detection[k], list) and k not in ("condition",):
            conditions.append(f"filter:{k}")

    return SigmaConvertResponse(
        original=sigma_rule,
        target=target,
        query=query,
        conditions=conditions,
    )


# ════════════════════════════════════════════════════════════════════
# ── YARA Rules ─────────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/yara/rules",
    response_model=PaginatedResponse,
    summary="List YARA Rules",
    description="List all YARA-formatted detection rules.",
)
async def list_yara_rules(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
    search: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None),
    enabled: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    tid = _uuid(tenant_id)
    conditions = [DetectionRule.tenant_id == tid, DetectionRule.rule_type == "yara"]

    if search:
        search_term = f"%{search}%"
        conditions.append(
            or_(DetectionRule.name.ilike(search_term), DetectionRule.description.ilike(search_term))
        )
    if tags:
        conditions.append(DetectionRule.tags.overlap(tags))
    if enabled is not None:
        conditions.append(DetectionRule.status == ("active" if enabled else "disabled"))

    count_q = select(func.count()).select_from(DetectionRule).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    q = select(DetectionRule).where(and_(*conditions)).order_by(desc(DetectionRule.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size)
    result = await db.execute(q)
    rules = result.scalars().all()

    items = []
    for r in rules:
        yara_text = (r.rule_content or {}).get("rule_text", "") if isinstance(r.rule_content, dict) else str(r.rule_content or "")
        items.append({
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "rule_text": yara_text,
            "tags": list(r.tags or []),
            "severity": r.severity,
            "enabled": r.status == "active",
            "compile_status": None,
            "compile_error": None,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        })
    return _paginated(items, total, page, page_size)


@router.post(
    "/yara/scan",
    response_model=YARAScanResponse,
    summary="Scan with YARA",
    description="Scan a file or process with YARA rules.",
)
async def scan_with_yara(
    request: YARAScanRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireThreatHunter),
    db: AsyncSession = Depends(get_db),
):
    return YARAScanResponse(
        target=request.target,
        target_type=request.target_type,
        scan_duration_seconds=0.0,
        rules_evaluated=0,
        matches=[],
        status="YARA scanning engine not yet integrated - placeholder response",
    )


# ════════════════════════════════════════════════════════════════════
# ── Alerts ─────────────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/alerts",
    response_model=PaginatedResponse,
    summary="List Alerts",
    description="List all security alerts with filtering, search, and pagination.",
)
async def list_alerts(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    status_val: Optional[AlertStatus] = Query(None, alias="status"),
    severity: Optional[AlertSeverity] = Query(None),
    rule_id: Optional[str] = Query(None, description="Filter by triggering rule"),
    source_asset_id: Optional[str] = Query(None, description="Filter by source asset"),
    assignee_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None, description="Search in title, description"),
    category: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: Optional[str] = Query("created_at"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
):
    tid = _uuid(tenant_id)
    conditions = [Alert.tenant_id == tid]

    if status_val:
        conditions.append(Alert.status == status_val.value)
    if severity:
        conditions.append(Alert.severity == severity.value)
    if rule_id:
        conditions.append(Alert.rule_id == _uuid(rule_id))
    if source_asset_id:
        conditions.append(Alert.source_asset_id == _uuid(source_asset_id))
    if assignee_id:
        conditions.append(Alert.assigned_to == _uuid(assignee_id))
    if category:
        conditions.append(Alert.indicator_type == category)
    if search:
        search_term = f"%{search}%"
        conditions.append(
            or_(Alert.title.ilike(search_term), Alert.description.ilike(search_term))
        )
    if start_time:
        conditions.append(Alert.created_at >= start_time)
    if end_time:
        conditions.append(Alert.created_at <= end_time)

    count_q = select(func.count()).select_from(Alert).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    sort_col = getattr(Alert, sort_by, Alert.created_at)
    order_fn = desc if sort_order == "desc" else asc

    q = select(Alert).where(and_(*conditions)).order_by(order_fn(sort_col)).offset(
        (page - 1) * page_size
    ).limit(page_size)
    result = await db.execute(q)
    alerts = result.scalars().all()

    return _paginated(
        [_build_alert_response(a) for a in alerts],
        total, page, page_size,
    )


@router.get(
    "/alerts/stats",
    response_model=AlertStatsResponse,
    summary="Alert Statistics",
    description="Get aggregate statistics for alerts.",
)
async def alert_stats(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
):
    tid = _uuid(tenant_id)
    base_cond = [Alert.tenant_id == tid]
    if start_time:
        base_cond.append(Alert.created_at >= start_time)
    if end_time:
        base_cond.append(Alert.created_at <= end_time)

    total_result = await db.execute(select(func.count(Alert.id)).where(and_(*base_cond)))
    total = total_result.scalar() or 0

    by_status_result = await db.execute(
        select(Alert.status, func.count(Alert.id)).where(and_(*base_cond)).group_by(Alert.status)
    )
    by_status = {row[0]: row[1] for row in by_status_result.all()}

    by_severity_result = await db.execute(
        select(Alert.severity, func.count(Alert.id)).where(and_(*base_cond)).group_by(Alert.severity)
    )
    by_severity = {row[0]: row[1] for row in by_severity_result.all()}

    by_category_result = await db.execute(
        select(Alert.indicator_type, func.count(Alert.id)).where(
            and_(*base_cond, Alert.indicator_type.isnot(None))
        ).group_by(Alert.indicator_type)
    )
    by_category = {row[0] or "unknown": row[1] for row in by_category_result.all()}

    now = datetime.now(timezone.utc)
    last_24h_base = base_cond + [Alert.created_at >= datetime.now(timezone.utc)]
    from datetime import timedelta
    cutoff_24h = now - timedelta(hours=24)

    new_24h_result = await db.execute(
        select(func.count(Alert.id)).where(
            and_(Alert.tenant_id == tid, Alert.status == "new", Alert.created_at >= cutoff_24h)
        )
    )
    new_last_24h = new_24h_result.scalar() or 0

    esc_24h_result = await db.execute(
        select(func.count(Alert.id)).where(
            and_(Alert.tenant_id == tid, Alert.status == "escalated", Alert.created_at >= cutoff_24h)
        )
    )
    escalated_last_24h = esc_24h_result.scalar() or 0

    top_rules_result = await db.execute(
        select(Alert.rule_name, func.count(Alert.id)).where(
            and_(*base_cond, Alert.rule_name.isnot(None))
        ).group_by(Alert.rule_name).order_by(desc(func.count(Alert.id))).limit(10)
    )
    top_triggered_rules = [{"rule_name": row[0], "count": row[1]} for row in top_rules_result.all()]

    return AlertStatsResponse(
        total=total,
        by_status=by_status,
        by_severity=by_severity,
        by_category=by_category,
        new_last_24h=new_last_24h,
        escalated_last_24h=escalated_last_24h,
        mean_time_to_acknowledge_minutes=None,
        mean_time_to_resolve_minutes=None,
        top_triggered_rules=top_triggered_rules,
    )


@router.post(
    "/alerts/bulk",
    response_model=BulkAlertResponse,
    summary="Bulk Alert Operations",
    description="Perform bulk operations on multiple alerts at once.",
)
async def bulk_alert_operations(
    operation: BulkAlertOperation,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    affected = 0
    failed_ids: list = []
    errs: list = []
    now = datetime.now(timezone.utc)

    uuids = [_uuid(aid) for aid in operation.alert_ids]
    result = await db.execute(
        select(Alert).where(and_(Alert.id.in_(uuids), Alert.tenant_id == tid))
    )
    alerts = result.scalars().all()
    alert_map = {str(a.id): a for a in alerts}

    for aid in operation.alert_ids:
        alert = alert_map.get(aid)
        if not alert:
            failed_ids.append(aid)
            errs.append({"alert_id": aid, "error": "Alert not found"})
            continue

        action = operation.action
        try:
            if action == "acknowledge":
                alert.status = "acknowledged"
                alert.acknowledged_at = now
            elif action == "dismiss":
                alert.status = "dismissed"
                alert.resolved_at = now
            elif action == "escalate":
                alert.status = "escalated"
            elif action == "update_severity":
                new_sev = (operation.parameters or {}).get("severity")
                if new_sev:
                    alert.severity = new_sev
            elif action == "assign":
                new_assignee = (operation.parameters or {}).get("assignee_id")
                if new_assignee:
                    alert.assigned_to = _uuid(new_assignee)
            alert.updated_at = now
            affected += 1
        except Exception as e:
            failed_ids.append(aid)
            errs.append({"alert_id": aid, "error": str(e)})

    await db.flush()
    await _audit_log(db, current_user, f"alerts.bulk_{operation.action}", "alert", None,
                     {"affected": affected, "action": operation.action})
    return BulkAlertResponse(affected=affected, failed=failed_ids, errors=errs)


@router.get(
    "/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Get Alert Detail",
    description="Retrieve full details of a single alert.",
)
async def get_alert(
    alert_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    aid = _uuid(alert_id)
    result = await db.execute(
        select(Alert).where(and_(Alert.id == aid, Alert.tenant_id == tid))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return _build_alert_response(alert)


@router.patch(
    "/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Update Alert",
    description="Update alert status, severity, assignee, or other fields.",
)
async def update_alert(
    alert_id: str,
    update: AlertUpdate,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    aid = _uuid(alert_id)
    result = await db.execute(
        select(Alert).where(and_(Alert.id == aid, Alert.tenant_id == tid))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    update_data = update.model_dump(exclude_unset=True)
    now = datetime.now(timezone.utc)

    if "status" in update_data and update_data["status"]:
        alert.status = update_data["status"].value
        if update_data["status"].value == "resolved":
            alert.resolved_at = now
    if "severity" in update_data and update_data["severity"]:
        alert.severity = update_data["severity"].value
    if "assignee_id" in update_data:
        alert.assigned_to = _uuid(update_data["assignee_id"]) if update_data["assignee_id"] else None
    alert.updated_at = now

    await db.flush()
    await db.refresh(alert)

    await _audit_log(db, current_user, "alert.updated", "alert", alert.id,
                     {"updated_fields": list(update_data.keys())})
    return _build_alert_response(alert)


@router.post(
    "/alerts/{alert_id}/acknowledge",
    response_model=AlertResponse,
    summary="Acknowledge Alert",
    description="Acknowledge an alert to indicate it is being investigated.",
)
async def acknowledge_alert(
    alert_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    aid = _uuid(alert_id)
    result = await db.execute(
        select(Alert).where(and_(Alert.id == aid, Alert.tenant_id == tid))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    now = datetime.now(timezone.utc)
    alert.status = "acknowledged"
    alert.acknowledged_at = now
    alert.updated_at = now

    await db.flush()
    await db.refresh(alert)

    await _audit_log(db, current_user, "alert.acknowledged", "alert", alert.id)
    return _build_alert_response(alert)


@router.post(
    "/alerts/{alert_id}/dismiss",
    response_model=AlertResponse,
    summary="Dismiss as False Positive",
    description="Dismiss an alert as a false positive with a reason.",
)
async def dismiss_alert(
    alert_id: str,
    request: AlertDismissRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    aid = _uuid(alert_id)
    result = await db.execute(
        select(Alert).where(and_(Alert.id == aid, Alert.tenant_id == tid))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    now = datetime.now(timezone.utc)
    alert.status = "dismissed"
    alert.resolved_at = now
    alert.updated_at = now
    alert.description = (alert.description or "") + f"\n[DISMISSED] Reason: {request.reason}"

    await db.flush()
    await db.refresh(alert)

    await _audit_log(db, current_user, "alert.dismissed", "alert", alert.id,
                     {"reason": request.reason})
    return _build_alert_response(alert)


@router.post(
    "/alerts/{alert_id}/escalate",
    response_model=AlertEscalateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Promote to Incident",
    description="Escalate an alert by creating a full incident from it.",
)
async def escalate_alert_to_incident(
    alert_id: str,
    request: AlertEscalateRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
):
    tid = _uuid(tenant_id)
    aid = _uuid(alert_id)
    result = await db.execute(
        select(Alert).where(and_(Alert.id == aid, Alert.tenant_id == tid))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    if alert.promoted_to_incident_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Alert already escalated to incident {alert.promoted_to_incident_id}",
        )

    from app.models import Incident
    now = datetime.now(timezone.utc)
    title = request.incident_title_override or f"[Escalated] {alert.title}"
    incident = Incident(
        tenant_id=tid,
        title=title,
        description=alert.description,
        severity=request.incident_priority or alert.severity,
        status="new",
        source_alert_ids=[str(alert.id)],
    )
    db.add(incident)
    await db.flush()
    await db.refresh(incident)

    alert.status = "escalated"
    alert.promoted_to_incident_id = incident.id
    alert.updated_at = now

    await db.flush()

    await _audit_log(db, current_user, "alert.escalated", "alert", alert.id,
                     {"incident_id": str(incident.id)})
    return AlertEscalateResponse(
        alert_id=str(alert.id),
        incident_id=str(incident.id),
        message=f"Alert escalated to incident {incident.id}",
    )


# ════════════════════════════════════════════════════════════════════
# ── Anomaly Detection ──────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/anomaly/models",
    response_model=PaginatedResponse,
    summary="List Anomaly Models",
    description="List all anomaly detection ML models.",
)
async def list_anomaly_models(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    model_type: Optional[AnomalyModelType] = Query(None),
    status_val: Optional[AnomalyModelStatus] = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    return _paginated([], 0, page, page_size)


@router.post(
    "/anomaly/models/{model_id}/train",
    response_model=AnomalyModelStatusResponse,
    summary="Train Anomaly Model",
    description="Trigger training for an anomaly detection ML model.",
)
async def train_anomaly_model(
    model_id: str,
    request: AnomalyModelTrainRequest,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    return AnomalyModelStatusResponse(
        model_id=model_id,
        status=AnomalyModelStatus.UNTRAINED,
        progress_percentage=0.0,
        current_step="ML training engine not yet integrated",
    )


@router.get(
    "/anomaly/models/{model_id}/status",
    response_model=AnomalyModelStatusResponse,
    summary="Get Training Status",
    description="Get the training status and progress of an anomaly model.",
)
async def get_anomaly_model_status(
    model_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    return AnomalyModelStatusResponse(
        model_id=model_id,
        status=AnomalyModelStatus.UNTRAINED,
        progress_percentage=0.0,
        current_step="ML training engine not yet integrated",
    )


# ════════════════════════════════════════════════════════════════════
# ── Behavioral Rules ───────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/behavior/rules",
    response_model=PaginatedResponse,
    summary="List Behavioral Rules",
    description="List all behavioral detection rules.",
)
async def list_behavioral_rules(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    db: AsyncSession = Depends(get_db),
    category: Optional[str] = Query(None),
    severity: Optional[RuleSeverity] = Query(None),
    enabled: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    tid = _uuid(tenant_id)
    conditions = [DetectionRule.tenant_id == tid, DetectionRule.rule_type == "behavioral"]

    if severity:
        conditions.append(DetectionRule.severity == severity.value)
    if enabled is not None:
        conditions.append(DetectionRule.status == ("active" if enabled else "disabled"))
    if search:
        search_term = f"%{search}%"
        conditions.append(
            or_(DetectionRule.name.ilike(search_term), DetectionRule.description.ilike(search_term))
        )

    count_q = select(func.count()).select_from(DetectionRule).where(and_(*conditions))
    total = (await db.execute(count_q)).scalar() or 0

    q = select(DetectionRule).where(and_(*conditions)).order_by(desc(DetectionRule.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size)
    result = await db.execute(q)
    rules = result.scalars().all()

    items = []
    for r in rules:
        rc = r.rule_content or {}
        items.append({
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "category": category,
            "pattern": rc if isinstance(rc, dict) else {},
            "severity": r.severity,
            "enabled": r.status == "active",
            "tags": list(r.tags or []),
            "mitre_attack": list(r.mitre_tactics or []),
            "threshold": rc.get("threshold") if isinstance(rc, dict) else None,
            "window_seconds": rc.get("window_seconds", 3600) if isinstance(rc, dict) else 3600,
            "tenant_id": str(r.tenant_id),
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        })
    return _paginated(items, total, page, page_size)


# ════════════════════════════════════════════════════════════════════
# ── UEBA (User Entity Behavior Analytics) ──────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/ueba/profiles",
    response_model=PaginatedResponse,
    summary="List UEBA Profiles",
    description="List User Entity Behavior Analytics profiles.",
)
async def list_ueba_profiles(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    department: Optional[str] = Query(None),
    risk_score_min: Optional[float] = Query(None, ge=0.0, le=100.0),
    risk_score_max: Optional[float] = Query(None, ge=0.0, le=100.0),
    search: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("risk_score"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    return _paginated([], 0, page, page_size)


@router.get(
    "/ueba/profiles/{user_id}",
    response_model=UEBABaselineResponse,
    summary="Get User Baseline",
    description="Get the behavioral baseline for a specific user.",
)
async def get_user_baseline(
    user_id: str,
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    return UEBABaselineResponse(
        user_id=user_id,
        display_name=f"User {user_id}",
        baseline_period_days=30,
        metrics={"status": "UEBA profiles not yet integrated"},
        risk_factors=[],
    )


@router.get(
    "/ueba/anomalies",
    response_model=PaginatedResponse,
    summary="Get UEBA Anomalies",
    description="List detected UEBA anomalies across all users.",
)
async def list_ueba_anomalies(
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    user_id: Optional[str] = Query(None),
    anomaly_type: Optional[str] = Query(None),
    severity: Optional[AlertSeverity] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: Optional[str] = Query("detected_at"),
    sort_order: str = Query("desc", pattern=r"^(asc|desc)$"),
):
    return _paginated([], 0, page, page_size)
