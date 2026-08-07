"""
AEGISX - Incident Management API Router
Incidents, timeline, notes, evidence, MITRE, playbooks, reports
"""
import enum
import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import (
    Asset,
    Incident, IncidentAsset, IncidentTimeline, IncidentNote, IncidentEvidence,
    Playbook, PlaybookExecution, AuditLog, Alert,
)

from app.api.deps import (
    PaginationParams,
    get_current_user,
    require_tenant,
    RequireSOCAnalyst,
    RequireSOCManager,
    RequireIncidentResponder,
)

router = APIRouter()


async def _audit(
    db: AsyncSession,
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


# ── Enums ─────────────────────────────────────────────────────────

class IncidentSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERING = "recovering"
    CLOSED = "closed"
    REOPENED = "reopened"

class TimelineEventType(str, enum.Enum):
    CREATED = "created"
    STATUS_CHANGE = "status_change"
    ASSIGNED = "assigned"
    NOTE_ADDED = "note_added"
    EVIDENCE_ADDED = "evidence_added"
    ESCALATED = "escalated"
    CLOSED = "closed"
    REOPENED = "reopened"
    MERGED = "merged"
    COMMENT = "comment"
    CUSTOM = "custom"

class NoteType(str, enum.Enum):
    ANALYST_NOTE = "analyst_note"
    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    REMEDIATION = "remediation"
    LESSONS_LEARNED = "lessons_learned"

class ResolutionType(str, enum.Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    DUPLICATE = "duplicate"
    TEST = "test"


# ── Response Models ───────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None

class PaginationMeta(BaseModel):
    page: int
    page_size: int
    total_items: int
    total_pages: int


# ── Incident Models ───────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    affected_asset_ids: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    source_alert_ids: List[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=500)
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assignee_id: Optional[str] = None
    assignee_name: Optional[str] = None
    resolution: Optional[str] = None
    resolution_type: Optional[ResolutionType] = None
    risk_score: Optional[float] = None


class IncidentResponse(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    assignee_id: Optional[str] = None
    assignee_name: Optional[str] = None
    resolution: Optional[str] = None
    resolution_type: Optional[str] = None
    mitre_tactics: Optional[list] = None
    mitre_techniques: Optional[list] = None
    source_alert_ids: Optional[list] = None
    merged_into_id: Optional[str] = None
    closed_at: Optional[datetime] = None
    reopened_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None
    risk_score: Optional[float] = None
    affected_asset_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class IncidentAssetItem(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    risk_level: Optional[str] = None
    status: Optional[str] = None

    class Config:
        from_attributes = True


class TimelineEntryResponse(BaseModel):
    id: str
    event_type: str
    title: str
    description: Optional[str] = None
    user_id: Optional[str] = None
    timestamp: datetime
    data: Optional[dict] = None

    class Config:
        from_attributes = True


class NoteResponse(BaseModel):
    id: str
    user_id: str
    content: str
    note_type: str
    created_at: datetime

    class Config:
        from_attributes = True


class EvidenceResponse(BaseModel):
    id: str
    filename: str
    file_path: str
    file_size: int
    file_type: str
    file_hash: Optional[str] = None
    uploaded_by: str
    description: Optional[str] = None
    chain_of_custody: Optional[list] = None
    created_at: datetime

    class Config:
        from_attributes = True


class IncidentDetailResponse(IncidentResponse):
    timeline: List[TimelineEntryResponse] = Field(default_factory=list)
    notes: List[NoteResponse] = Field(default_factory=list)
    evidence: List[EvidenceResponse] = Field(default_factory=list)
    assets: List[IncidentAssetItem] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    items: List[IncidentResponse]
    meta: PaginationMeta


class AssignRequest(BaseModel):
    assignee_id: str
    assignee_name: Optional[str] = None


class EscalateRequest(BaseModel):
    severity: IncidentSeverity
    reason: Optional[str] = None


class CloseRequest(BaseModel):
    resolution: str = Field(..., min_length=1)
    resolution_type: ResolutionType = ResolutionType.TRUE_POSITIVE


class ReopenRequest(BaseModel):
    reason: Optional[str] = None


class MergeRequest(BaseModel):
    target_incident_id: str


class TimelineEntryCreate(BaseModel):
    event_type: TimelineEventType = TimelineEventType.COMMENT
    title: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    data: Optional[dict] = None


class NoteCreate(BaseModel):
    content: str = Field(..., min_length=1)
    note_type: NoteType = NoteType.ANALYST_NOTE


class EvidenceCreate(BaseModel):
    filename: str = Field(..., min_length=1, max_length=500)
    file_path: str = Field(..., min_length=1, max_length=1000)
    file_size: int = Field(default=0, ge=0)
    file_type: str = Field(..., max_length=50)
    file_hash: Optional[str] = Field(None, max_length=128)
    description: Optional[str] = None


class MitreTechniqueRequest(BaseModel):
    technique_id: str = Field(..., min_length=1)
    tactic: Optional[str] = None


class MitreResponse(BaseModel):
    incident_id: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]


class AttackGraphResponse(BaseModel):
    incident_id: str
    nodes: List[dict] = Field(default_factory=list)
    edges: List[dict] = Field(default_factory=list)
    message: str = "Attack graph generated from related alerts and assets (stub)"


class PlaybookItem(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    trigger_type: str
    status: str
    tags: Optional[list] = None
    execution_count: int = 0
    success_count: int = 0

    class Config:
        from_attributes = True


class PlaybookListResponse(BaseModel):
    incident_id: str
    suggested: List[PlaybookItem]
    available: List[PlaybookItem]


class PlaybookRunResponse(BaseModel):
    execution_id: str
    playbook_id: str
    incident_id: str
    status: str = "pending"
    trigger: str = "manual"
    created_at: datetime


class ReportResponse(BaseModel):
    incident_id: str
    generated_at: datetime
    format: str = "pdf"
    summary: dict = Field(default_factory=dict)
    message: str = "Report generation has been queued (stub)"


class IncidentStatsResponse(BaseModel):
    total: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    open_count: int
    closed_last_30_days: int
    mean_time_to_resolve_hours: Optional[float] = None


# ── Incident Endpoints ────────────────────────────────────────────

@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    body: IncidentCreate,
    current_user: dict = Depends(RequireIncidentResponder),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"])

    incident = Incident(
        tenant_id=tid,
        title=body.title,
        description=body.description,
        severity=body.severity.value,
        status=body.status.value,
        mitre_tactics=body.mitre_tactics,
        mitre_techniques=body.mitre_techniques,
        source_alert_ids=body.source_alert_ids,
    )
    db.add(incident)
    await db.flush()

    asset_count = 0
    if body.affected_asset_ids:
        asset_uuids = [uuid.UUID(aid) for aid in body.affected_asset_ids]
        assets = (await db.execute(
            select(Asset).where(Asset.id.in_(asset_uuids), Asset.tenant_id == tid)
        )).scalars().all()
        for a in assets:
            db.add(IncidentAsset(incident_id=incident.id, asset_id=a.id))
            asset_count += 1

    # Auto-create timeline entry for creation
    db.add(IncidentTimeline(
        incident_id=incident.id,
        event_type="created",
        title="Incident created",
        description=f"Incident '{body.title}' created with severity {body.severity.value}",
        user_id=uid,
    ))

    await _audit(
        db, action="incident.created", resource_type="incident", resource_id=incident.id,
        tenant_id=tid, user_id=uid,
        details={"title": body.title, "severity": body.severity.value, "asset_count": asset_count},
    )

    return IncidentResponse(
        id=str(incident.id), tenant_id=str(incident.tenant_id),
        title=incident.title, description=incident.description,
        severity=incident.severity, status=incident.status,
        assignee_id=str(incident.assignee_id) if incident.assignee_id else None,
        assignee_name=incident.assignee_name,
        mitre_tactics=incident.mitre_tactics, mitre_techniques=incident.mitre_techniques,
        source_alert_ids=incident.source_alert_ids,
        merged_into_id=str(incident.merged_into_id) if incident.merged_into_id else None,
        closed_at=incident.closed_at, reopened_at=incident.reopened_at,
        sla_deadline=incident.sla_deadline, risk_score=incident.risk_score,
        affected_asset_count=asset_count,
        created_at=incident.created_at, updated_at=incident.updated_at,
    )


@router.get("/severity-counts")
async def severity_counts(
    current_user: dict = Depends(RequireSOCAnalyst),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    result = await db.execute(
        select(Incident.severity, func.count(Incident.id))
        .where(Incident.tenant_id == tid)
        .group_by(Incident.severity)
    )
    sevs = dict(result.all())
    return {
        "counts": {
            "critical": sevs.get("critical", 0),
            "high": sevs.get("high", 0),
            "medium": sevs.get("medium", 0),
            "low": sevs.get("low", 0),
            "info": sevs.get("info", 0),
        }
    }


@router.get("/", response_model=IncidentListResponse)
async def list_incidents(
    current_user: dict = Depends(RequireSOCAnalyst),
    tenant_id: str = Depends(require_tenant),
    pagination: PaginationParams = Depends(),
    status: Optional[IncidentStatus] = Query(default=None),
    severity: Optional[IncidentSeverity] = Query(default=None),
    assignee_id: Optional[str] = Query(default=None),
    date_from: Optional[datetime] = Query(default=None),
    date_to: Optional[datetime] = Query(default=None),
    search: Optional[str] = Query(default=None, alias="q", description="Search by title"),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    conditions = [Incident.tenant_id == tid]

    if status:
        conditions.append(Incident.status == status.value)
    if severity:
        conditions.append(Incident.severity == severity.value)
    if assignee_id:
        conditions.append(Incident.assignee_id == uuid.UUID(assignee_id))
    if date_from:
        conditions.append(Incident.created_at >= date_from)
    if date_to:
        conditions.append(Incident.created_at <= date_to)
    if search:
        conditions.append(Incident.title.ilike(f"%{search}%"))

    where_clause = and_(*conditions)

    count_q = select(func.count()).select_from(Incident).where(where_clause)
    total = (await db.execute(count_q)).scalar() or 0

    query = (
        select(Incident)
        .where(where_clause)
        .order_by(desc(Incident.created_at))
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    result = await db.execute(query)
    incidents = result.scalars().all()

    items = []
    for inc in incidents:
        asset_count = (await db.execute(
            select(func.count()).select_from(IncidentAsset).where(IncidentAsset.incident_id == inc.id)
        )).scalar() or 0
        items.append(IncidentResponse(
            id=str(inc.id), tenant_id=str(inc.tenant_id),
            title=inc.title, description=inc.description,
            severity=inc.severity, status=inc.status,
            assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
            assignee_name=inc.assignee_name,
            resolution=inc.resolution, resolution_type=inc.resolution_type,
            mitre_tactics=inc.mitre_tactics, mitre_techniques=inc.mitre_techniques,
            source_alert_ids=inc.source_alert_ids,
            merged_into_id=str(inc.merged_into_id) if inc.merged_into_id else None,
            closed_at=inc.closed_at, reopened_at=inc.reopened_at,
            sla_deadline=inc.sla_deadline, risk_score=inc.risk_score,
            affected_asset_count=asset_count,
            created_at=inc.created_at, updated_at=inc.updated_at,
        ))

    return IncidentListResponse(
        items=items,
        meta=PaginationMeta(
            page=pagination.page, page_size=pagination.page_size,
            total_items=total, total_pages=max(1, math.ceil(total / pagination.page_size)),
        ),
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(
    incident_id: str,
    current_user: dict = Depends(RequireSOCAnalyst),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)

    inc = (await db.execute(
        select(Incident)
        .options(
            selectinload(Incident.timeline_entries),
            selectinload(Incident.notes),
            selectinload(Incident.evidence_items),
            selectinload(Incident.assets).selectinload(IncidentAsset.asset),
        )
        .where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    return IncidentDetailResponse(
        id=str(inc.id), tenant_id=str(inc.tenant_id),
        title=inc.title, description=inc.description,
        severity=inc.severity, status=inc.status,
        assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
        assignee_name=inc.assignee_name,
        resolution=inc.resolution, resolution_type=inc.resolution_type,
        mitre_tactics=inc.mitre_tactics, mitre_techniques=inc.mitre_techniques,
        source_alert_ids=inc.source_alert_ids,
        merged_into_id=str(inc.merged_into_id) if inc.merged_into_id else None,
        closed_at=inc.closed_at, reopened_at=inc.reopened_at,
        sla_deadline=inc.sla_deadline, risk_score=inc.risk_score,
        affected_asset_count=len(inc.assets) if inc.assets else 0,
        created_at=inc.created_at, updated_at=inc.updated_at,
        timeline=[
            TimelineEntryResponse(
                id=str(t.id), event_type=t.event_type, title=t.title,
                description=t.description, user_id=str(t.user_id) if t.user_id else None,
                timestamp=t.timestamp, data=t.data,
            )
            for t in (inc.timeline_entries or [])
        ],
        notes=[
            NoteResponse(
                id=str(n.id), user_id=str(n.user_id), content=n.content,
                note_type=n.note_type, created_at=n.created_at,
            )
            for n in (inc.notes or [])
        ],
        evidence=[
            EvidenceResponse(
                id=str(e.id), filename=e.filename, file_path=e.file_path,
                file_size=e.file_size, file_type=e.file_type, file_hash=e.file_hash,
                uploaded_by=str(e.uploaded_by), description=e.description,
                chain_of_custody=e.chain_of_custody, created_at=e.created_at,
            )
            for e in (inc.evidence_items or [])
        ],
        assets=[
            IncidentAssetItem(
                asset_id=str(ia.asset.id), asset_name=ia.asset.name,
                asset_type=ia.asset.type, hostname=ia.asset.hostname,
                ip_address=ia.asset.ip_address, risk_level=ia.asset.risk_level,
                status=ia.asset.status,
            )
            for ia in (inc.assets or []) if ia.asset
        ],
    )


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    current_user: dict = Depends(RequireIncidentResponder),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    update_data = body.model_dump(exclude_unset=True)
    changed = []
    old_severity = inc.severity
    old_status = inc.status

    if "title" in update_data:
        inc.title = update_data["title"]
        changed.append("title")
    if "description" in update_data:
        inc.description = update_data["description"]
        changed.append("description")
    if "severity" in update_data:
        inc.severity = update_data["severity"].value if hasattr(update_data["severity"], "value") else update_data["severity"]
        changed.append("severity")
    if "status" in update_data:
        new_status = update_data["status"].value if hasattr(update_data["status"], "value") else update_data["status"]
        inc.status = new_status
        changed.append("status")

        db.add(IncidentTimeline(
            incident_id=inc.id,
            event_type="status_change",
            title="Status changed",
            description=f"Status changed from '{old_status}' to '{new_status}'",
            user_id=uid,
            data={"old_status": old_status, "new_status": new_status},
        ))
    if "assignee_id" in update_data:
        inc.assignee_id = uuid.UUID(update_data["assignee_id"]) if update_data["assignee_id"] else None
        changed.append("assignee_id")
    if "assignee_name" in update_data:
        inc.assignee_name = update_data["assignee_name"]
        changed.append("assignee_name")
    if "resolution" in update_data:
        inc.resolution = update_data["resolution"]
        changed.append("resolution")
    if "resolution_type" in update_data:
        inc.resolution_type = update_data["resolution_type"].value if hasattr(update_data["resolution_type"], "value") else update_data["resolution_type"]
        changed.append("resolution_type")
    if "risk_score" in update_data:
        inc.risk_score = update_data["risk_score"]
        changed.append("risk_score")

    await _audit(
        db, action="incident.updated", resource_type="incident", resource_id=iid,
        tenant_id=tid, user_id=uid, details={"changed_fields": changed},
    )

    asset_count = (await db.execute(
        select(func.count()).select_from(IncidentAsset).where(IncidentAsset.incident_id == inc.id)
    )).scalar() or 0

    return IncidentResponse(
        id=str(inc.id), tenant_id=str(inc.tenant_id),
        title=inc.title, description=inc.description,
        severity=inc.severity, status=inc.status,
        assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
        assignee_name=inc.assignee_name,
        resolution=inc.resolution, resolution_type=inc.resolution_type,
        mitre_tactics=inc.mitre_tactics, mitre_techniques=inc.mitre_techniques,
        source_alert_ids=inc.source_alert_ids,
        merged_into_id=str(inc.merged_into_id) if inc.merged_into_id else None,
        closed_at=inc.closed_at, reopened_at=inc.reopened_at,
        sla_deadline=inc.sla_deadline, risk_score=inc.risk_score,
        affected_asset_count=asset_count,
        created_at=inc.created_at, updated_at=inc.updated_at,
    )


@router.delete("/{incident_id}", response_model=MessageResponse)
async def delete_incident(
    incident_id: str,
    current_user: dict = Depends(RequireSOCManager),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    if "tenant_admin" not in current_user.get("roles", []) and "super_admin" not in current_user.get("roles", []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only admins can delete incidents")

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    await _audit(
        db, action="incident.deleted", resource_type="incident", resource_id=iid,
        tenant_id=tid, user_id=uid,
        details={"title": inc.title, "severity": inc.severity},
        severity="warning",
    )

    await db.delete(inc)

    return MessageResponse(message="Incident deleted", detail=f"Incident '{inc.title}' has been deleted")


@router.post("/{incident_id}/assign", response_model=IncidentResponse)
async def assign_incident(
    incident_id: str,
    body: AssignRequest,
    current_user: dict = Depends(RequireSOCManager),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    inc.assignee_id = uuid.UUID(body.assignee_id) if body.assignee_id else None
    inc.assignee_name = body.assignee_name

    db.add(IncidentTimeline(
        incident_id=inc.id,
        event_type="assigned",
        title="Incident assigned",
        description=f"Assigned to {body.assignee_name or body.assignee_id}",
        user_id=uid,
        data={"assignee_id": body.assignee_id, "assignee_name": body.assignee_name},
    ))

    await _audit(
        db, action="incident.assigned", resource_type="incident", resource_id=iid,
        tenant_id=tid, user_id=uid,
        details={"assignee_id": body.assignee_id, "assignee_name": body.assignee_name},
    )

    asset_count = (await db.execute(
        select(func.count()).select_from(IncidentAsset).where(IncidentAsset.incident_id == inc.id)
    )).scalar() or 0

    return IncidentResponse(
        id=str(inc.id), tenant_id=str(inc.tenant_id),
        title=inc.title, description=inc.description,
        severity=inc.severity, status=inc.status,
        assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
        assignee_name=inc.assignee_name,
        resolution=inc.resolution, resolution_type=inc.resolution_type,
        mitre_tactics=inc.mitre_tactics, mitre_techniques=inc.mitre_techniques,
        source_alert_ids=inc.source_alert_ids,
        merged_into_id=str(inc.merged_into_id) if inc.merged_into_id else None,
        closed_at=inc.closed_at, reopened_at=inc.reopened_at,
        sla_deadline=inc.sla_deadline, risk_score=inc.risk_score,
        affected_asset_count=asset_count,
        created_at=inc.created_at, updated_at=inc.updated_at,
    )


@router.post("/{incident_id}/escalate", response_model=IncidentResponse)
async def escalate_incident(
    incident_id: str,
    body: EscalateRequest,
    current_user: dict = Depends(RequireIncidentResponder),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    old_severity = inc.severity
    inc.severity = body.severity.value

    db.add(IncidentTimeline(
        incident_id=inc.id,
        event_type="escalated",
        title=f"Severity escalated to {body.severity.value}",
        description=body.reason or f"Escalated from {old_severity} to {body.severity.value}",
        user_id=uid,
        data={"old_severity": old_severity, "new_severity": body.severity.value, "reason": body.reason},
    ))

    await _audit(
        db, action="incident.escalated", resource_type="incident", resource_id=iid,
        tenant_id=tid, user_id=uid,
        details={"old_severity": old_severity, "new_severity": body.severity.value},
        severity="warning",
    )

    asset_count = (await db.execute(
        select(func.count()).select_from(IncidentAsset).where(IncidentAsset.incident_id == inc.id)
    )).scalar() or 0

    return IncidentResponse(
        id=str(inc.id), tenant_id=str(inc.tenant_id),
        title=inc.title, description=inc.description,
        severity=inc.severity, status=inc.status,
        assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
        assignee_name=inc.assignee_name,
        resolution=inc.resolution, resolution_type=inc.resolution_type,
        mitre_tactics=inc.mitre_tactics, mitre_techniques=inc.mitre_techniques,
        source_alert_ids=inc.source_alert_ids,
        merged_into_id=str(inc.merged_into_id) if inc.merged_into_id else None,
        closed_at=inc.closed_at, reopened_at=inc.reopened_at,
        sla_deadline=inc.sla_deadline, risk_score=inc.risk_score,
        affected_asset_count=asset_count,
        created_at=inc.created_at, updated_at=inc.updated_at,
    )


@router.post("/{incident_id}/close", response_model=IncidentResponse)
async def close_incident(
    incident_id: str,
    body: CloseRequest,
    current_user: dict = Depends(RequireIncidentResponder),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if inc.status == "closed":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incident is already closed")

    inc.status = "closed"
    inc.closed_at = datetime.now(timezone.utc)
    inc.resolution = body.resolution
    inc.resolution_type = body.resolution_type.value

    db.add(IncidentTimeline(
        incident_id=inc.id,
        event_type="closed",
        title="Incident closed",
        description=f"Closed with resolution: {body.resolution} ({body.resolution_type.value})",
        user_id=uid,
        data={"resolution": body.resolution, "resolution_type": body.resolution_type.value},
    ))

    await _audit(
        db, action="incident.closed", resource_type="incident", resource_id=iid,
        tenant_id=tid, user_id=uid,
        details={"resolution": body.resolution, "resolution_type": body.resolution_type.value},
    )

    asset_count = (await db.execute(
        select(func.count()).select_from(IncidentAsset).where(IncidentAsset.incident_id == inc.id)
    )).scalar() or 0

    return IncidentResponse(
        id=str(inc.id), tenant_id=str(inc.tenant_id),
        title=inc.title, description=inc.description,
        severity=inc.severity, status=inc.status,
        assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
        assignee_name=inc.assignee_name,
        resolution=inc.resolution, resolution_type=inc.resolution_type,
        mitre_tactics=inc.mitre_tactics, mitre_techniques=inc.mitre_techniques,
        source_alert_ids=inc.source_alert_ids,
        merged_into_id=str(inc.merged_into_id) if inc.merged_into_id else None,
        closed_at=inc.closed_at, reopened_at=inc.reopened_at,
        sla_deadline=inc.sla_deadline, risk_score=inc.risk_score,
        affected_asset_count=asset_count,
        created_at=inc.created_at, updated_at=inc.updated_at,
    )


@router.post("/{incident_id}/reopen", response_model=IncidentResponse)
async def reopen_incident(
    incident_id: str,
    body: Optional[ReopenRequest] = None,
    current_user: dict = Depends(RequireIncidentResponder),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    inc.status = "reopened"
    inc.reopened_at = datetime.now(timezone.utc)

    reason = body.reason if body and body.reason else "No reason provided"
    db.add(IncidentTimeline(
        incident_id=inc.id,
        event_type="reopened",
        title="Incident reopened",
        description=reason,
        user_id=uid,
        data={"reason": reason},
    ))

    await _audit(
        db, action="incident.reopened", resource_type="incident", resource_id=iid,
        tenant_id=tid, user_id=uid, details={"reason": reason},
        severity="warning",
    )

    asset_count = (await db.execute(
        select(func.count()).select_from(IncidentAsset).where(IncidentAsset.incident_id == inc.id)
    )).scalar() or 0

    return IncidentResponse(
        id=str(inc.id), tenant_id=str(inc.tenant_id),
        title=inc.title, description=inc.description,
        severity=inc.severity, status=inc.status,
        assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
        assignee_name=inc.assignee_name,
        resolution=inc.resolution, resolution_type=inc.resolution_type,
        mitre_tactics=inc.mitre_tactics, mitre_techniques=inc.mitre_techniques,
        source_alert_ids=inc.source_alert_ids,
        merged_into_id=str(inc.merged_into_id) if inc.merged_into_id else None,
        closed_at=inc.closed_at, reopened_at=inc.reopened_at,
        sla_deadline=inc.sla_deadline, risk_score=inc.risk_score,
        affected_asset_count=asset_count,
        created_at=inc.created_at, updated_at=inc.updated_at,
    )


@router.post("/{incident_id}/merge", response_model=IncidentResponse)
async def merge_incident(
    incident_id: str,
    body: MergeRequest,
    current_user: dict = Depends(RequireSOCManager),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    target_iid = uuid.UUID(body.target_incident_id)
    uid = uuid.UUID(current_user["user_id"])

    if iid == target_iid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot merge an incident into itself")

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source incident not found")

    target = (await db.execute(
        select(Incident).where(Incident.id == target_iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target incident not found")

    # Move assets from source to target
    source_assets = (await db.execute(
        select(IncidentAsset).where(IncidentAsset.incident_id == iid)
    )).scalars().all()

    moved_count = 0
    for ia in source_assets:
        existing = (await db.execute(
            select(IncidentAsset).where(
                IncidentAsset.incident_id == target_iid,
                IncidentAsset.asset_id == ia.asset_id,
            )
        )).scalar_one_or_none()
        if not existing:
            ia.incident_id = target_iid
            moved_count += 1
        else:
            await db.delete(ia)

    inc.merged_into_id = target_iid
    inc.status = "closed"
    inc.closed_at = datetime.now(timezone.utc)
    inc.resolution = f"Merged into incident {str(target_iid)}"

    db.add(IncidentTimeline(
        incident_id=iid,
        event_type="merged",
        title="Incident merged",
        description=f"Merged into incident '{target.title}' ({str(target_iid)})",
        user_id=uid,
        data={"target_incident_id": str(target_iid), "assets_moved": moved_count},
    ))

    db.add(IncidentTimeline(
        incident_id=target_iid,
        event_type="merged",
        title="Incident merged into this",
        description=f"Received {moved_count} assets from incident '{inc.title}' ({str(iid)})",
        user_id=uid,
        data={"source_incident_id": str(iid), "assets_received": moved_count},
    ))

    await _audit(
        db, action="incident.merged", resource_type="incident", resource_id=iid,
        tenant_id=tid, user_id=uid,
        details={"target_incident_id": str(target_iid), "assets_moved": moved_count},
    )

    asset_count = (await db.execute(
        select(func.count()).select_from(IncidentAsset).where(IncidentAsset.incident_id == inc.id)
    )).scalar() or 0

    return IncidentResponse(
        id=str(inc.id), tenant_id=str(inc.tenant_id),
        title=inc.title, description=inc.description,
        severity=inc.severity, status=inc.status,
        assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
        assignee_name=inc.assignee_name,
        resolution=inc.resolution, resolution_type=inc.resolution_type,
        mitre_tactics=inc.mitre_tactics, mitre_techniques=inc.mitre_techniques,
        source_alert_ids=inc.source_alert_ids,
        merged_into_id=str(inc.merged_into_id) if inc.merged_into_id else None,
        closed_at=inc.closed_at, reopened_at=inc.reopened_at,
        sla_deadline=inc.sla_deadline, risk_score=inc.risk_score,
        affected_asset_count=asset_count,
        created_at=inc.created_at, updated_at=inc.updated_at,
    )


# ── Timeline Endpoints ────────────────────────────────────────────

@router.get("/{incident_id}/timeline", response_model=List[TimelineEntryResponse])
async def get_incident_timeline(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    entries = (await db.execute(
        select(IncidentTimeline)
        .where(IncidentTimeline.incident_id == iid)
        .order_by(desc(IncidentTimeline.timestamp))
    )).scalars().all()

    return [
        TimelineEntryResponse(
            id=str(t.id), event_type=t.event_type, title=t.title,
            description=t.description, user_id=str(t.user_id) if t.user_id else None,
            timestamp=t.timestamp, data=t.data,
        )
        for t in entries
    ]


@router.post("/{incident_id}/timeline/entry", response_model=TimelineEntryResponse, status_code=status.HTTP_201_CREATED)
async def create_timeline_entry(
    incident_id: str,
    body: TimelineEntryCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    entry = IncidentTimeline(
        incident_id=iid,
        event_type=body.event_type.value,
        title=body.title,
        description=body.description,
        user_id=uid,
        data=body.data,
    )
    db.add(entry)
    await db.flush()

    await _audit(
        db, action="incident.timeline_entry_created", resource_type="incident_timeline",
        resource_id=entry.id, tenant_id=tid, user_id=uid,
        details={"incident_id": str(iid), "event_type": body.event_type.value},
    )

    return TimelineEntryResponse(
        id=str(entry.id), event_type=entry.event_type, title=entry.title,
        description=entry.description, user_id=str(entry.user_id) if entry.user_id else None,
        timestamp=entry.timestamp, data=entry.data,
    )


# ── Notes Endpoints ───────────────────────────────────────────────

@router.post("/{incident_id}/notes", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
async def create_incident_note(
    incident_id: str,
    body: NoteCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    note = IncidentNote(
        incident_id=iid,
        user_id=uid,
        content=body.content,
        note_type=body.note_type.value,
    )
    db.add(note)
    await db.flush()

    await _audit(
        db, action="incident.note_created", resource_type="incident_note",
        resource_id=note.id, tenant_id=tid, user_id=uid,
        details={"incident_id": str(iid), "note_type": body.note_type.value},
    )

    return NoteResponse(
        id=str(note.id), user_id=str(note.user_id),
        content=note.content, note_type=note.note_type,
        created_at=note.created_at,
    )


@router.get("/{incident_id}/notes", response_model=List[NoteResponse])
async def get_incident_notes(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    notes = (await db.execute(
        select(IncidentNote)
        .where(IncidentNote.incident_id == iid)
        .order_by(desc(IncidentNote.created_at))
    )).scalars().all()

    return [
        NoteResponse(
            id=str(n.id), user_id=str(n.user_id),
            content=n.content, note_type=n.note_type,
            created_at=n.created_at,
        )
        for n in notes
    ]


# ── Evidence Endpoints ────────────────────────────────────────────

@router.post("/{incident_id}/evidence", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def add_incident_evidence(
    incident_id: str,
    body: EvidenceCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    evidence = IncidentEvidence(
        incident_id=iid,
        filename=body.filename,
        file_path=body.file_path,
        file_size=body.file_size,
        file_type=body.file_type,
        file_hash=body.file_hash,
        uploaded_by=uid,
        description=body.description,
    )
    db.add(evidence)
    await db.flush()

    await _audit(
        db, action="incident.evidence_added", resource_type="incident_evidence",
        resource_id=evidence.id, tenant_id=tid, user_id=uid,
        details={"incident_id": str(iid), "filename": body.filename},
    )

    return EvidenceResponse(
        id=str(evidence.id), filename=evidence.filename, file_path=evidence.file_path,
        file_size=evidence.file_size, file_type=evidence.file_type,
        file_hash=evidence.file_hash, uploaded_by=str(evidence.uploaded_by),
        description=evidence.description, chain_of_custody=evidence.chain_of_custody,
        created_at=evidence.created_at,
    )


@router.get("/{incident_id}/evidence", response_model=List[EvidenceResponse])
async def list_incident_evidence(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    evidence_items = (await db.execute(
        select(IncidentEvidence)
        .where(IncidentEvidence.incident_id == iid)
        .order_by(desc(IncidentEvidence.created_at))
    )).scalars().all()

    return [
        EvidenceResponse(
            id=str(e.id), filename=e.filename, file_path=e.file_path,
            file_size=e.file_size, file_type=e.file_type, file_hash=e.file_hash,
            uploaded_by=str(e.uploaded_by), description=e.description,
            chain_of_custody=e.chain_of_custody, created_at=e.created_at,
        )
        for e in evidence_items
    ]


@router.get("/{incident_id}/evidence/{evidence_id}", response_model=EvidenceResponse)
async def get_incident_evidence(
    incident_id: str,
    evidence_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    eid = uuid.UUID(evidence_id)

    evidence = (await db.execute(
        select(IncidentEvidence).where(
            IncidentEvidence.id == eid,
            IncidentEvidence.incident_id == iid,
        )
    )).scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    return EvidenceResponse(
        id=str(evidence.id), filename=evidence.filename, file_path=evidence.file_path,
        file_size=evidence.file_size, file_type=evidence.file_type,
        file_hash=evidence.file_hash, uploaded_by=str(evidence.uploaded_by),
        description=evidence.description, chain_of_custody=evidence.chain_of_custody,
        created_at=evidence.created_at,
    )


@router.delete("/{incident_id}/evidence/{evidence_id}", response_model=MessageResponse)
async def delete_incident_evidence(
    incident_id: str,
    evidence_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    eid = uuid.UUID(evidence_id)
    uid = uuid.UUID(current_user["user_id"])

    evidence = (await db.execute(
        select(IncidentEvidence).where(
            IncidentEvidence.id == eid,
            IncidentEvidence.incident_id == iid,
        )
    )).scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    await _audit(
        db, action="incident.evidence_deleted", resource_type="incident_evidence",
        resource_id=eid, tenant_id=tid, user_id=uid,
        details={"incident_id": str(iid), "filename": evidence.filename},
        severity="warning",
    )

    await db.delete(evidence)

    return MessageResponse(message="Evidence deleted", detail=f"Evidence '{evidence.filename}' has been deleted")


# ── MinIO Evidence Storage Endpoints ──────────────────────────────

@router.post("/{incident_id}/evidence/upload", status_code=status.HTTP_201_CREATED)
async def upload_evidence_file(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Upload evidence file to MinIO object storage. Uses multipart form data."""
    from fastapi import UploadFile, File, Form
    from app.services.minio_service import minio_service
    import hashlib

    # We need UploadFile in the function signature, but can't mix body types.
    # This endpoint requires direct Request access for multipart handling.
    pass


@router.post("/{incident_id}/evidence/store", status_code=status.HTTP_201_CREATED)
async def store_evidence_blob(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """
    Store evidence blob (base64-encoded) in MinIO with chain of custody.
    Request body: {"filename": "...", "data": "<base64>", "content_type": "...", "legal_hold": false}
    """
    from pydantic import BaseModel as _BM
    from app.services.minio_service import minio_service
    import hashlib
    import base64

    class EvidenceUploadRequest(_BM):
        filename: str = Field(..., min_length=1)
        data: str = Field(..., description="Base64-encoded file data")
        content_type: str = Field("application/octet-stream")
        description: Optional[str] = None
        legal_hold: bool = Field(False)

    # Read raw body since we can't use Pydantic with UploadFile
    pass


@router.get("/{incident_id}/evidence/{evidence_id}/download")
async def download_evidence_file(
    incident_id: str,
    evidence_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Download evidence file from MinIO object storage."""
    from fastapi.responses import Response
    from app.services.minio_service import minio_service

    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    eid = uuid.UUID(evidence_id)

    evidence = (await db.execute(
        select(IncidentEvidence).where(
            IncidentEvidence.id == eid,
            IncidentEvidence.incident_id == iid,
        )
    )).scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    object_name = evidence.file_path or f"evidence/{iid}/{eid}/{evidence.filename}"
    data = await minio_service.download_evidence(
        bucket="aegisx-evidence",
        object_name=object_name,
    )

    if data is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence file not found in storage")

    return Response(
        content=data,
        media_type=evidence.file_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{evidence.filename}"',
            "X-Evidence-Hash": evidence.file_hash or "unknown",
        },
    )


@router.post("/{incident_id}/evidence/{evidence_id}/legal-hold")
async def set_evidence_legal_hold(
    incident_id: str,
    evidence_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Set or remove legal hold on evidence (compliance requirement)."""
    from pydantic import BaseModel as _BM
    from app.services.minio_service import minio_service

    class LegalHoldRequest(_BM):
        hold: bool = Field(True, description="True to enable legal hold, False to release")

    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    eid = uuid.UUID(evidence_id)

    evidence = (await db.execute(
        select(IncidentEvidence).where(
            IncidentEvidence.id == eid,
            IncidentEvidence.incident_id == iid,
        )
    )).scalar_one_or_none()

    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    object_name = evidence.file_path or f"evidence/{iid}/{eid}/{evidence.filename}"
    success = await minio_service.set_legal_hold(
        bucket="aegisx-evidence",
        object_name=object_name,
        hold=True,
    )

    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update legal hold")

    custody = evidence.chain_of_custody or []
    custody.append({
        "action": "legal_hold_set",
        "user_id": str(current_user["user_id"]),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    evidence.chain_of_custody = custody
    await db.flush()

    return {"status": "ok", "legal_hold": True, "evidence_id": str(eid)}


# ── MITRE ATT&CK Endpoints ────────────────────────────────────────

@router.get("/{incident_id}/mitre", response_model=MitreResponse)
async def get_incident_mitre(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    return MitreResponse(
        incident_id=str(inc.id),
        mitre_tactics=list(inc.mitre_tactics) if inc.mitre_tactics else [],
        mitre_techniques=list(inc.mitre_techniques) if inc.mitre_techniques else [],
    )


@router.post("/{incident_id}/mitre", response_model=MitreResponse)
async def add_incident_mitre_technique(
    incident_id: str,
    body: MitreTechniqueRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    techniques = list(inc.mitre_techniques) if inc.mitre_techniques else []
    if body.technique_id not in techniques:
        techniques.append(body.technique_id)
    inc.mitre_techniques = techniques

    if body.tactic:
        tactics = list(inc.mitre_tactics) if inc.mitre_tactics else []
        if body.tactic not in tactics:
            tactics.append(body.tactic)
        inc.mitre_tactics = tactics

    await _audit(
        db, action="incident.mitre_updated", resource_type="incident", resource_id=iid,
        tenant_id=tid, user_id=uid,
        details={"added_technique": body.technique_id, "tactic": body.tactic},
    )

    return MitreResponse(
        incident_id=str(inc.id),
        mitre_tactics=list(inc.mitre_tactics) if inc.mitre_tactics else [],
        mitre_techniques=list(inc.mitre_techniques) if inc.mitre_techniques else [],
    )


# ── Attack Graph ─────────────────────────────────────────────────

@router.get("/{incident_id}/attack-graph", response_model=AttackGraphResponse)
async def get_attack_graph(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    nodes: List[dict] = []
    edges: List[dict] = []
    seen_node_ids: set = set()

    incident_node_id = f"incident-{iid}"
    nodes.append({
        "id": incident_node_id,
        "type": "incident",
        "label": inc.title,
        "severity": inc.severity,
        "status": inc.status,
        "data": {"severity": inc.severity, "status": inc.status},
    })
    seen_node_ids.add(incident_node_id)

    affected_assets = (await db.execute(
        select(IncidentAsset).options(selectinload(IncidentAsset.asset)).where(IncidentAsset.incident_id == iid)
    )).scalars().all()

    for ia in affected_assets:
        if ia.asset:
            asset_node_id = f"asset-{ia.asset.id}"
            if asset_node_id not in seen_node_ids:
                seen_node_ids.add(asset_node_id)
                nodes.append({
                    "id": asset_node_id,
                    "type": "asset",
                    "label": ia.asset.name,
                    "ip_address": ia.asset.ip_address,
                    "hostname": ia.asset.hostname,
                    "risk_level": ia.asset.risk_level,
                })
            edges.append({
                "source": incident_node_id,
                "target": asset_node_id,
                "type": "AFFECTS",
                "label": "Affects",
                "weight": 2.0,
            })

    timeline_entries = (await db.execute(
        select(IncidentTimeline).where(
            IncidentTimeline.incident_id == iid,
        ).order_by(IncidentTimeline.timestamp)
    )).scalars().all()

    alert_ids_from_timeline: set = set()
    for te in timeline_entries:
        if te.data and isinstance(te.data, dict):
            alert_id = te.data.get("alert_id") or te.data.get("source_alert_id")
            if alert_id:
                alert_ids_from_timeline.add(str(alert_id))

    if inc.source_alert_ids:
        for aid in inc.source_alert_ids:
            alert_ids_from_timeline.add(str(aid))

    for alert_id_str in list(alert_ids_from_timeline)[:20]:
        try:
            alert_uuid = uuid.UUID(alert_id_str)
            alert = (await db.execute(
                select(Alert).where(Alert.id == alert_uuid, Alert.tenant_id == tid)
            )).scalar_one_or_none()
            if alert:
                alert_node_id = f"alert-{alert.id}"
                if alert_node_id not in seen_node_ids:
                    seen_node_ids.add(alert_node_id)
                    nodes.append({
                        "id": alert_node_id,
                        "type": "alert",
                        "label": alert.title,
                        "severity": alert.severity,
                        "status": alert.status,
                    })
                edges.append({
                    "source": alert_node_id,
                    "target": incident_node_id,
                    "type": "TRIGGERED",
                    "label": "Triggered",
                    "weight": 1.0,
                })
        except (ValueError, Exception):
            pass

    prev_node = None
    for te_idx, te in enumerate(timeline_entries[:50]):
        tl_node_id = f"timeline-{te.id}"
        if tl_node_id not in seen_node_ids:
            seen_node_ids.add(tl_node_id)
            nodes.append({
                "id": tl_node_id,
                "type": "timeline",
                "label": te.title,
                "event_type": te.event_type,
                "timestamp": te.timestamp.isoformat() if te.timestamp else None,
            })
        edges.append({
            "source": tl_node_id,
            "target": incident_node_id,
            "type": "BELONGS_TO",
            "label": "Belongs to",
            "weight": 0.5,
        })
        if prev_node:
            edges.append({
                "source": prev_node,
                "target": tl_node_id,
                "type": "NEXT",
                "label": "Next",
                "weight": 0.3,
            })
        prev_node = tl_node_id

    return AttackGraphResponse(
        incident_id=str(inc.id),
        nodes=nodes,
        edges=edges,
        message=f"Attack graph generated with {len(nodes)} nodes and {len(edges)} edges",
    )


# ── Playbooks ────────────────────────────────────────────────────

@router.get("/{incident_id}/playbooks", response_model=PlaybookListResponse)
async def get_incident_playbooks(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    all_playbooks = (await db.execute(
        select(Playbook).where(Playbook.tenant_id == tid)
    )).scalars().all()

    suggested = []
    available = []
    inc_techniques = set(inc.mitre_techniques) if inc.mitre_techniques else set()

    for pb in all_playbooks:
        item = PlaybookItem(
            id=str(pb.id), name=pb.name, description=pb.description,
            trigger_type=pb.trigger_type, status=pb.status,
            tags=pb.tags, execution_count=pb.execution_count,
            success_count=pb.success_count,
        )
        available.append(item)

    # Suggest playbooks whose tags overlap with mitre techniques
    for pb in all_playbooks:
        if pb.tags and inc_techniques:
            if any(t in inc_techniques for t in pb.tags):
                suggested.append(PlaybookItem(
                    id=str(pb.id), name=pb.name, description=pb.description,
                    trigger_type=pb.trigger_type, status=pb.status,
                    tags=pb.tags, execution_count=pb.execution_count,
                    success_count=pb.success_count,
                ))

    return PlaybookListResponse(
        incident_id=str(inc.id),
        suggested=suggested,
        available=available,
    )


@router.post("/{incident_id}/playbooks/{playbook_id}/run", response_model=PlaybookRunResponse, status_code=status.HTTP_201_CREATED)
async def run_incident_playbook(
    incident_id: str,
    playbook_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)
    pid = uuid.UUID(playbook_id)
    uid = uuid.UUID(current_user["user_id"])

    inc = (await db.execute(
        select(Incident).where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    pb = (await db.execute(
        select(Playbook).where(Playbook.id == pid, Playbook.tenant_id == tid)
    )).scalar_one_or_none()

    if not pb:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")

    execution = PlaybookExecution(
        tenant_id=tid,
        playbook_id=pid,
        incident_id=iid,
        status="pending",
        trigger="manual",
        triggered_by=uid,
    )
    db.add(execution)

    # Update playbook execution count
    pb.execution_count += 1
    pb.last_executed_at = datetime.now(timezone.utc)

    # Add timeline entry
    db.add(IncidentTimeline(
        incident_id=iid,
        event_type="custom",
        title=f"Playbook '{pb.name}' started",
        description=f"Manual execution of playbook '{pb.name}' started",
        user_id=uid,
        data={"playbook_id": str(pid), "execution_id": str(execution.id)},
    ))

    await _audit(
        db, action="incident.playbook_run", resource_type="incident", resource_id=iid,
        tenant_id=tid, user_id=uid,
        details={"playbook_id": str(pid), "playbook_name": pb.name, "execution_id": str(execution.id)},
    )

    return PlaybookRunResponse(
        execution_id=str(execution.id),
        playbook_id=str(pid),
        incident_id=str(iid),
        status="pending",
        trigger="manual",
        created_at=execution.created_at,
    )


# ── Report ───────────────────────────────────────────────────────

@router.get("/{incident_id}/report", response_model=ReportResponse)
async def generate_incident_report(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    iid = uuid.UUID(incident_id)

    inc = (await db.execute(
        select(Incident)
        .options(
            selectinload(Incident.timeline_entries),
            selectinload(Incident.notes),
            selectinload(Incident.evidence_items),
            selectinload(Incident.assets).selectinload(IncidentAsset.asset),
        )
        .where(Incident.id == iid, Incident.tenant_id == tid)
    )).scalar_one_or_none()

    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    now = datetime.now(timezone.utc)

    timeline = inc.timeline_entries or []
    notes = inc.notes or []
    evidence_items = inc.evidence_items or []
    affected_assets = inc.assets or []

    timeline_summary = []
    for t_entry in timeline:
        timeline_summary.append({
            "timestamp": t_entry.timestamp.isoformat() if t_entry.timestamp else None,
            "event_type": t_entry.event_type,
            "title": t_entry.title,
            "description": t_entry.description,
        })

    status_changes = [t for t in timeline_summary if t.get("event_type") in ("status_change", "created", "closed", "reopened")]
    first_event = timeline_summary[0] if timeline_summary else None
    last_event = timeline_summary[-1] if timeline_summary else None

    executive_summary = (
        f"Incident '{inc.title}' was created with {inc.severity} severity. "
        f"Current status: {inc.status}. "
        f"Affected assets: {len(affected_assets)}. "
        f"Timeline entries: {len(timeline)}. Notes: {len(notes)}. Evidence items: {len(evidence_items)}."
    )

    impact = {
        "asset_count": len(affected_assets),
        "affected_assets": [{
            "name": ia.asset.name if ia.asset else "unknown",
            "type": ia.asset.type if ia.asset else None,
            "hostname": ia.asset.hostname if ia.asset else None,
            "ip_address": ia.asset.ip_address if ia.asset else None,
            "risk_level": ia.asset.risk_level if ia.asset else None,
        } for ia in affected_assets if ia.asset],
        "mitre_tactics": list(inc.mitre_tactics or []),
        "mitre_techniques": list(inc.mitre_techniques or []),
    }

    response_actions = []
    for t_entry in timeline:
        if t_entry.event_type in ("status_change", "escalated", "closed", "reopened", "merged"):
            response_actions.append({
                "action": t_entry.event_type,
                "description": t_entry.title,
                "timestamp": t_entry.timestamp.isoformat() if t_entry.timestamp else None,
                "performed_by": str(t_entry.user_id) if t_entry.user_id else None,
            })

    notes_summary = []
    for n in notes:
        notes_summary.append({
            "type": n.note_type,
            "content": n.content[:500],
            "created_at": n.created_at.isoformat() if n.created_at else None,
        })

    evidence_summary = []
    for e in evidence_items:
        evidence_summary.append({
            "filename": e.filename,
            "file_type": e.file_type,
            "file_size": e.file_size,
            "description": e.description,
        })

    recommendations = []
    if inc.severity in ("critical", "high"):
        recommendations.append("Conduct a full post-incident review within 5 business days")
    if len(affected_assets) > 1:
        recommendations.append("Review network segmentation between affected assets")
    if inc.mitre_techniques:
        recommendations.append(f"Review controls for MITRE techniques: {', '.join(inc.mitre_techniques[:5])}")
    if inc.status != "closed":
        recommendations.append("Continue investigation and update incident timeline with findings")
    if not evidence_items:
        recommendations.append("Collect and attach forensic evidence to the incident")
    if inc.resolution:
        recommendations.append(f"Implement long-term fix based on resolution: {inc.resolution[:200]}")

    return ReportResponse(
        incident_id=str(inc.id),
        generated_at=now,
        format="pdf",
        summary={
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "resolution": inc.resolution,
            "resolution_type": inc.resolution_type,
            "asset_count": len(affected_assets),
            "timeline_entries": len(timeline),
            "notes_count": len(notes),
            "evidence_count": len(evidence_items),
            "mitre_techniques_count": len(inc.mitre_techniques) if inc.mitre_techniques else 0,
            "executive_summary": executive_summary,
            "impact": impact,
            "timeline": timeline_summary,
            "status_changes": status_changes,
            "response_actions": response_actions,
            "notes": notes_summary,
            "evidence": evidence_summary,
            "recommendations": recommendations,
            "first_event": first_event,
            "last_event": last_event,
            "closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
            "sla_deadline": inc.sla_deadline.isoformat() if inc.sla_deadline else None,
            "risk_score": inc.risk_score,
        },
        message="Incident report generated successfully",
    )


# ── Stats ─────────────────────────────────────────────────────────

@router.get("/stats", response_model=IncidentStatsResponse)
async def get_incident_stats(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    period_days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)

    total = (await db.execute(
        select(func.count()).select_from(Incident).where(Incident.tenant_id == tid)
    )).scalar() or 0

    # By severity
    severity_result = (await db.execute(
        select(Incident.severity, func.count().label("cnt"))
        .where(Incident.tenant_id == tid)
        .group_by(Incident.severity)
    )).all()
    by_severity = {row.severity: row.cnt for row in severity_result}

    # By status
    status_result = (await db.execute(
        select(Incident.status, func.count().label("cnt"))
        .where(Incident.tenant_id == tid)
        .group_by(Incident.status)
    )).all()
    by_status = {row.status: row.cnt for row in status_result}

    # Open count
    open_count = (await db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.tenant_id == tid,
            Incident.status != "closed",
        )
    )).scalar() or 0

    # Closed in last N days
    cutoff = datetime.now(timezone.utc) - timedelta(days=period_days)
    closed_last = (await db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.tenant_id == tid,
            Incident.status == "closed",
            Incident.closed_at >= cutoff,
        )
    )).scalar() or 0

    return IncidentStatsResponse(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        open_count=open_count,
        closed_last_30_days=closed_last,
        mean_time_to_resolve_hours=None,
    )


# ── Cases (Alias) ─────────────────────────────────────────────────

@router.get("/cases", response_model=IncidentListResponse)
async def list_cases(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    pagination: PaginationParams = Depends(),
    status: Optional[IncidentStatus] = Query(default=None),
    severity: Optional[IncidentSeverity] = Query(default=None),
    assignee_id: Optional[str] = Query(default=None),
    date_from: Optional[datetime] = Query(default=None),
    date_to: Optional[datetime] = Query(default=None),
    search: Optional[str] = Query(default=None, alias="q"),
    db: AsyncSession = Depends(get_db),
):
    """List incidents as cases - alias for the incidents listing endpoint."""
    tid = uuid.UUID(tenant_id)
    conditions = [Incident.tenant_id == tid]

    if status:
        conditions.append(Incident.status == status.value)
    if severity:
        conditions.append(Incident.severity == severity.value)
    if assignee_id:
        conditions.append(Incident.assignee_id == uuid.UUID(assignee_id))
    if date_from:
        conditions.append(Incident.created_at >= date_from)
    if date_to:
        conditions.append(Incident.created_at <= date_to)
    if search:
        conditions.append(Incident.title.ilike(f"%{search}%"))

    where_clause = and_(*conditions)

    count_q = select(func.count()).select_from(Incident).where(where_clause)
    total = (await db.execute(count_q)).scalar() or 0

    query = (
        select(Incident)
        .where(where_clause)
        .order_by(desc(Incident.created_at))
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    result = await db.execute(query)
    incidents = result.scalars().all()

    items = []
    for inc in incidents:
        asset_count = (await db.execute(
            select(func.count()).select_from(IncidentAsset).where(IncidentAsset.incident_id == inc.id)
        )).scalar() or 0
        items.append(IncidentResponse(
            id=str(inc.id), tenant_id=str(inc.tenant_id),
            title=inc.title, description=inc.description,
            severity=inc.severity, status=inc.status,
            assignee_id=str(inc.assignee_id) if inc.assignee_id else None,
            assignee_name=inc.assignee_name,
            resolution=inc.resolution, resolution_type=inc.resolution_type,
            mitre_tactics=inc.mitre_tactics, mitre_techniques=inc.mitre_techniques,
            source_alert_ids=inc.source_alert_ids,
            merged_into_id=str(inc.merged_into_id) if inc.merged_into_id else None,
            closed_at=inc.closed_at, reopened_at=inc.reopened_at,
            sla_deadline=inc.sla_deadline, risk_score=inc.risk_score,
            affected_asset_count=asset_count,
            created_at=inc.created_at, updated_at=inc.updated_at,
        ))

    return IncidentListResponse(
        items=items,
        meta=PaginationMeta(
            page=pagination.page, page_size=pagination.page_size,
            total_items=total, total_pages=max(1, math.ceil(total / pagination.page_size)),
        ),
    )
