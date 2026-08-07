"""
AEGISX - Asset Management API Router
Assets, agents, groups, discovery, monitoring
"""
import enum
import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import Asset, AssetGroup, Agent, Vulnerability, Alert, Incident, IncidentAsset, AuditLog, Tenant

from app.api.deps import (
    PaginationParams,
    get_current_user,
    require_tenant,
    RequireSOCAnalyst,
    RequireSOCManager,
)

router = APIRouter()

_discovery_scans: Dict[str, Dict[str, Any]] = {}


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

class AssetType(str, enum.Enum):
    ENDPOINT = "endpoint"
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    IOT = "iot"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"
    DATABASE = "database"
    APPLICATION = "application"
    VIRTUAL = "virtual"
    MOBILE = "mobile"
    OTHER = "other"

class AssetStatus(str, enum.Enum):
    UNKNOWN = "unknown"
    ONLINE = "online"
    OFFLINE = "offline"
    MONITORING = "monitoring"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"

class AssetRiskLevel(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AgentStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    UPDATING = "updating"
    UNINSTALLED = "uninstalled"


# ── Response Models ───────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str
    detail: Optional[str] = None

class PaginationMeta(BaseModel):
    page: int
    page_size: int
    total_items: int
    total_pages: int


# ── Asset Models ──────────────────────────────────────────────────

class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    mac_address: Optional[str] = Field(None, max_length=17)
    type: AssetType = AssetType.ENDPOINT
    os: Optional[str] = Field(None, max_length=50)
    os_version: Optional[str] = Field(None, max_length=100)
    status: AssetStatus = AssetStatus.UNKNOWN
    risk_level: AssetRiskLevel = AssetRiskLevel.INFO
    tags: List[str] = Field(default_factory=list)
    group_id: Optional[str] = None
    hardware_info: Optional[dict] = None
    software_info: Optional[dict] = None
    network_info: Optional[dict] = None
    cloud_info: Optional[dict] = None
    metadata: Optional[dict] = Field(None, alias="metadata_")


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    type: Optional[AssetType] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    status: Optional[AssetStatus] = None
    risk_level: Optional[AssetRiskLevel] = None
    group_id: Optional[str] = None
    hardware_info: Optional[dict] = None
    software_info: Optional[dict] = None
    network_info: Optional[dict] = None
    cloud_info: Optional[dict] = None
    metadata: Optional[dict] = Field(None, alias="metadata_")
    agent_id: Optional[str] = None


class AssetResponse(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    name: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    type: str
    os: Optional[str] = None
    os_version: Optional[str] = None
    status: str
    risk_level: str
    tags: Optional[list] = None
    group_id: Optional[str] = None
    agent_id: Optional[str] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AssetDetailResponse(AssetResponse):
    hardware_info: Optional[dict] = None
    software_info: Optional[dict] = None
    network_info: Optional[dict] = None
    cloud_info: Optional[dict] = None
    group_name: Optional[str] = None


class AssetListResponse(BaseModel):
    items: List[AssetResponse]
    meta: PaginationMeta


# ── Agent Models ──────────────────────────────────────────────────

class AgentResponse(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    name: str
    agent_key: str
    version: Optional[str] = None
    platform: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    status: str
    last_heartbeat: Optional[datetime] = None
    capabilities: Optional[list] = None
    asset_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AgentCommandRequest(BaseModel):
    command: str = Field(..., min_length=1)
    parameters: Optional[dict] = None
    timeout: int = Field(default=60, ge=1, le=600)


class AgentCommandResponse(BaseModel):
    command_id: str
    agent_id: str
    command: str
    status: str = "queued"
    queued_at: datetime


class AgentListResponse(BaseModel):
    items: List[AgentResponse]
    meta: PaginationMeta


# ── Group Models ──────────────────────────────────────────────────

class AssetGroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    parent_group_id: Optional[str] = None


class AssetGroupUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    parent_group_id: Optional[str] = None


class AssetGroupResponse(BaseModel):
    id: str
    tenant_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    parent_group_id: Optional[str] = None
    asset_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AssetGroupListResponse(BaseModel):
    items: List[AssetGroupResponse]


class TagsRequest(BaseModel):
    tags: List[str] = Field(..., min_length=1)


class GroupAssetsRequest(BaseModel):
    asset_ids: List[str] = Field(..., min_length=1)


# ── Discovery Models ──────────────────────────────────────────────

class DiscoveryScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# ── Alert / Vulnerability / Incident List Models ─────────────────

class AlertItem(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    rule_name: Optional[str] = None
    confidence: float
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class VulnerabilityItem(BaseModel):
    id: str
    cve_id: Optional[str] = None
    title: str
    severity: str
    status: str
    cvss_score: Optional[float] = None
    detected_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class IncidentItem(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PaginatedAlerts(BaseModel):
    items: List[AlertItem]
    meta: PaginationMeta


class PaginatedVulnerabilities(BaseModel):
    items: List[VulnerabilityItem]
    meta: PaginationMeta


class PaginatedIncidents(BaseModel):
    items: List[IncidentItem]
    meta: PaginationMeta


# ── Asset Endpoints ───────────────────────────────────────────────

@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    body: AssetCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"])

    # Quota enforcement
    tenant = (await db.execute(select(Tenant).where(Tenant.id == tid))).scalar_one_or_none()
    if tenant:
        asset_count = (await db.execute(
            select(func.count(Asset.id)).where(Asset.tenant_id == tid)
        )).scalar() or 0
        if asset_count >= tenant.quota_assets:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Asset quota exceeded ({tenant.quota_assets}). Contact your administrator to upgrade.",
            )

    existing = (await db.execute(
        select(Asset).where(
            Asset.tenant_id == tid,
            Asset.name == body.name,
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Asset with this name already exists in tenant")

    if body.group_id:
        group = (await db.execute(
            select(AssetGroup).where(
                AssetGroup.id == uuid.UUID(body.group_id),
                AssetGroup.tenant_id == tid,
            )
        )).scalar_one_or_none()
        if not group:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset group not found")

    data = body.model_dump(exclude={"group_id", "metadata_"}, exclude_none=True)
    if "metadata_" in body.model_dump(exclude_none=True):
        data["metadata_"] = body.model_dump(exclude_none=True).get("metadata_")

    asset = Asset(
        tenant_id=tid,
        group_id=uuid.UUID(body.group_id) if body.group_id else None,
        **{k: v for k, v in data.items() if k not in ("metadata", "metadata_")},
    )
    if body.metadata or (hasattr(body, 'meta_data') and getattr(body, 'meta_data', None)):
        meta_val = body.metadata if body.metadata else getattr(body, 'meta_data', None)
        asset.meta_data = meta_val
    db.add(asset)
    await db.flush()

    await _audit(
        db, action="asset.created", resource_type="asset", resource_id=asset.id,
        tenant_id=tid, user_id=uid, details={"name": body.name, "type": body.type},
    )

    return AssetResponse(
        id=str(asset.id), tenant_id=str(asset.tenant_id), name=asset.name,
        hostname=asset.hostname, ip_address=asset.ip_address, mac_address=asset.mac_address,
        type=asset.type, os=asset.os, os_version=asset.os_version,
        status=asset.status, risk_level=asset.risk_level, tags=asset.tags,
        group_id=str(asset.group_id) if asset.group_id else None,
        agent_id=asset.agent_id, last_seen=asset.last_seen,
        created_at=asset.created_at, updated_at=asset.updated_at,
    )


@router.get("/", response_model=AssetListResponse)
async def list_assets(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    pagination: PaginationParams = Depends(),
    type: Optional[AssetType] = Query(default=None),
    status: Optional[AssetStatus] = Query(default=None),
    os: Optional[str] = Query(default=None),
    risk_level: Optional[AssetRiskLevel] = Query(default=None),
    tags: Optional[str] = Query(default=None, description="Comma-separated tags to filter by (any match)"),
    search: Optional[str] = Query(default=None, alias="q", description="Search by name or hostname"),
    group_id: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    conditions = [Asset.tenant_id == tid]

    if type:
        conditions.append(Asset.type == type.value)
    if status:
        conditions.append(Asset.status == status.value)
    if os:
        conditions.append(Asset.os == os)
    if risk_level:
        conditions.append(Asset.risk_level == risk_level.value)
    if search:
        conditions.append(or_(Asset.name.ilike(f"%{search}%"), Asset.hostname.ilike(f"%{search}%")))
    if group_id:
        conditions.append(Asset.group_id == uuid.UUID(group_id))
    if tags:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        if tag_list:
            conditions.append(Asset.tags.overlap(tag_list))

    where_clause = and_(*conditions)

    count_q = select(func.count()).select_from(Asset).where(where_clause)
    total = (await db.execute(count_q)).scalar() or 0

    query = (
        select(Asset)
        .where(where_clause)
        .order_by(desc(Asset.created_at))
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    result = await db.execute(query)
    assets = result.scalars().all()

    items = [
        AssetResponse(
            id=str(a.id), tenant_id=str(a.tenant_id), name=a.name,
            hostname=a.hostname, ip_address=a.ip_address, mac_address=a.mac_address,
            type=a.type, os=a.os, os_version=a.os_version,
            status=a.status, risk_level=a.risk_level, tags=a.tags,
            group_id=str(a.group_id) if a.group_id else None,
            agent_id=a.agent_id, last_seen=a.last_seen,
            created_at=a.created_at, updated_at=a.updated_at,
        )
        for a in assets
    ]

    return AssetListResponse(
        items=items,
        meta=PaginationMeta(
            page=pagination.page, page_size=pagination.page_size,
            total_items=total, total_pages=max(1, math.ceil(total / pagination.page_size)),
        ),
    )


@router.get("/{asset_id}", response_model=AssetDetailResponse)
async def get_asset(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)

    a = (await db.execute(
        select(Asset)
        .options(selectinload(Asset.group))
        .where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return AssetDetailResponse(
        id=str(a.id), tenant_id=str(a.tenant_id), name=a.name,
        hostname=a.hostname, ip_address=a.ip_address, mac_address=a.mac_address,
        type=a.type, os=a.os, os_version=a.os_version,
        status=a.status, risk_level=a.risk_level, tags=a.tags,
        group_id=str(a.group_id) if a.group_id else None,
        group_name=a.group.name if a.group else None,
        agent_id=a.agent_id, last_seen=a.last_seen,
        hardware_info=a.hardware_info, software_info=a.software_info,
        network_info=a.network_info, cloud_info=a.cloud_info,
        created_at=a.created_at, updated_at=a.updated_at,
    )


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: str,
    body: AssetUpdate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)
    uid = uuid.UUID(current_user["user_id"])

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    update_data = body.model_dump(exclude_unset=True)
    changed = []

    simple_fields = [
        "name", "hostname", "ip_address", "mac_address", "os", "os_version",
        "agent_id", "hardware_info", "software_info", "network_info", "cloud_info",
    ]
    for field in simple_fields:
        if field in update_data:
            setattr(a, field, update_data[field])
            changed.append(field)

    if "type" in update_data:
        a.type = update_data["type"].value if hasattr(update_data["type"], "value") else update_data["type"]
        changed.append("type")
    if "status" in update_data:
        a.status = update_data["status"].value if hasattr(update_data["status"], "value") else update_data["status"]
        changed.append("status")
    if "risk_level" in update_data:
        a.risk_level = update_data["risk_level"].value if hasattr(update_data["risk_level"], "value") else update_data["risk_level"]
        changed.append("risk_level")

    if "group_id" in update_data:
        if update_data["group_id"]:
            group = (await db.execute(
                select(AssetGroup).where(
                    AssetGroup.id == uuid.UUID(update_data["group_id"]),
                    AssetGroup.tenant_id == tid,
                )
            )).scalar_one_or_none()
            if not group:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset group not found")
            a.group_id = uuid.UUID(update_data["group_id"])
        else:
            a.group_id = None
        changed.append("group_id")

    if "metadata_" in update_data:
        a.meta_data = update_data["metadata_"]
        changed.append("metadata")

    await _audit(
        db, action="asset.updated", resource_type="asset", resource_id=aid,
        tenant_id=tid, user_id=uid, details={"changed_fields": changed},
    )

    return AssetResponse(
        id=str(a.id), tenant_id=str(a.tenant_id), name=a.name,
        hostname=a.hostname, ip_address=a.ip_address, mac_address=a.mac_address,
        type=a.type, os=a.os, os_version=a.os_version,
        status=a.status, risk_level=a.risk_level, tags=a.tags,
        group_id=str(a.group_id) if a.group_id else None,
        agent_id=a.agent_id, last_seen=a.last_seen,
        created_at=a.created_at, updated_at=a.updated_at,
    )


@router.delete("/{asset_id}", response_model=MessageResponse)
async def delete_asset(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)
    uid = uuid.UUID(current_user["user_id"])

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    a.status = "decommissioned"

    # Dissociate from group
    a.group_id = None

    await _audit(
        db, action="asset.deleted", resource_type="asset", resource_id=aid,
        tenant_id=tid, user_id=uid, details={"name": a.name},
        severity="warning",
    )

    return MessageResponse(message="Asset decommissioned", detail=f"Asset '{a.name}' has been decommissioned")


# ── Discovery Endpoints ───────────────────────────────────────────

@router.post("/discover/scan", response_model=DiscoveryScanResponse, status_code=status.HTTP_201_CREATED)
async def create_discovery_scan(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"])
    scan_id = uuid.uuid4()

    _discovery_scans[str(scan_id)] = {
        "scan_id": str(scan_id),
        "tenant_id": tenant_id,
        "status": "running",
        "created_by": uid,
        "created_at": datetime.now(timezone.utc),
        "discovered_hosts": [],
        "progress": 0,
    }

    await _audit(
        db, action="discovery.scan_created", resource_type="discovery_scan", resource_id=scan_id,
        tenant_id=tid, user_id=uid, details={"status": "running"},
    )

    return DiscoveryScanResponse(
        scan_id=str(scan_id),
        status="running",
        message="Discovery scan has been started",
    )


@router.get("/discover/scan/{scan_id}", response_model=DiscoveryScanResponse)
async def get_discovery_scan_status(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    scan = _discovery_scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery scan not found")
    if scan.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this scan")

    discovered = scan.get("discovered_hosts", [])
    host_summary = f"Discovered {len(discovered)} hosts" if discovered else "No hosts discovered yet"

    return DiscoveryScanResponse(
        scan_id=scan_id,
        status=scan.get("status", "unknown"),
        message=f"Scan status: {scan.get('status', 'unknown')}. {host_summary}.",
    )


# ── Asset Info Endpoints ──────────────────────────────────────────

@router.get("/{asset_id}/hardware")
async def get_asset_hardware(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return {"asset_id": str(a.id), "hardware_info": a.hardware_info or {}}


@router.get("/{asset_id}/software")
async def get_asset_software(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return {"asset_id": str(a.id), "software_info": a.software_info or {}}


@router.get("/{asset_id}/network")
async def get_asset_network(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return {"asset_id": str(a.id), "network_info": a.network_info or {}}


@router.get("/{asset_id}/processes")
async def get_asset_processes(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return {
        "asset_id": str(a.id),
        "processes": [],
        "message": "Process list retrieved via agent; no cached data available",
    }


# ── Monitoring Endpoints ──────────────────────────────────────────

@router.post("/{asset_id}/monitor/start", response_model=MessageResponse)
async def start_monitoring(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)
    uid = uuid.UUID(current_user["user_id"])

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    a.status = "monitoring"
    await _audit(
        db, action="asset.monitoring_started", resource_type="asset", resource_id=aid,
        tenant_id=tid, user_id=uid, details={"previous_status": a.status},
    )

    return MessageResponse(message="Monitoring started", detail=f"Asset '{a.name}' is now being monitored")


@router.post("/{asset_id}/monitor/stop", response_model=MessageResponse)
async def stop_monitoring(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)
    uid = uuid.UUID(current_user["user_id"])

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    previous_status = a.status
    a.status = "online"
    await _audit(
        db, action="asset.monitoring_stopped", resource_type="asset", resource_id=aid,
        tenant_id=tid, user_id=uid, details={"previous_status": previous_status},
    )

    return MessageResponse(message="Monitoring stopped", detail=f"Asset '{a.name}' monitoring has been stopped")


# ── Asset Relationships ───────────────────────────────────────────

@router.get("/{asset_id}/vulnerabilities", response_model=PaginatedVulnerabilities)
async def get_asset_vulnerabilities(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    count_q = select(func.count()).select_from(Vulnerability).where(
        Vulnerability.affected_asset_id == aid, Vulnerability.tenant_id == tid
    )
    total = (await db.execute(count_q)).scalar() or 0

    query = (
        select(Vulnerability)
        .where(Vulnerability.affected_asset_id == aid, Vulnerability.tenant_id == tid)
        .order_by(desc(Vulnerability.detected_at))
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    result = await db.execute(query)
    vulns = result.scalars().all()

    items = [
        VulnerabilityItem(
            id=str(v.id), cve_id=v.cve_id, title=v.title,
            severity=v.severity, status=v.status,
            cvss_score=v.cvss_score, detected_at=v.detected_at,
        )
        for v in vulns
    ]

    return PaginatedVulnerabilities(
        items=items,
        meta=PaginationMeta(
            page=pagination.page, page_size=pagination.page_size,
            total_items=total, total_pages=max(1, math.ceil(total / pagination.page_size)),
        ),
    )


@router.get("/{asset_id}/alerts", response_model=PaginatedAlerts)
async def get_asset_alerts(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    count_q = select(func.count()).select_from(Alert).where(Alert.source_asset_id == aid)
    total = (await db.execute(count_q)).scalar() or 0

    query = (
        select(Alert)
        .where(Alert.source_asset_id == aid)
        .order_by(desc(Alert.created_at))
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    result = await db.execute(query)
    alerts = result.scalars().all()

    items = [
        AlertItem(
            id=str(al.id), title=al.title, severity=al.severity,
            status=al.status, rule_name=al.rule_name,
            confidence=al.confidence, created_at=al.created_at,
        )
        for al in alerts
    ]

    return PaginatedAlerts(
        items=items,
        meta=PaginationMeta(
            page=pagination.page, page_size=pagination.page_size,
            total_items=total, total_pages=max(1, math.ceil(total / pagination.page_size)),
        ),
    )


@router.get("/{asset_id}/incidents", response_model=PaginatedIncidents)
async def get_asset_incidents(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    count_q = (
        select(func.count())
        .select_from(Incident)
        .join(IncidentAsset, IncidentAsset.incident_id == Incident.id)
        .where(IncidentAsset.asset_id == aid, Incident.tenant_id == tid)
    )
    total = (await db.execute(count_q)).scalar() or 0

    query = (
        select(Incident)
        .join(IncidentAsset, IncidentAsset.incident_id == Incident.id)
        .where(IncidentAsset.asset_id == aid, Incident.tenant_id == tid)
        .order_by(desc(Incident.created_at))
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    result = await db.execute(query)
    incidents = result.scalars().all()

    items = [
        IncidentItem(
            id=str(inc.id), title=inc.title, severity=inc.severity,
            status=inc.status, created_at=inc.created_at,
        )
        for inc in incidents
    ]

    return PaginatedIncidents(
        items=items,
        meta=PaginationMeta(
            page=pagination.page, page_size=pagination.page_size,
            total_items=total, total_pages=max(1, math.ceil(total / pagination.page_size)),
        ),
    )


# ── Tag Endpoints ─────────────────────────────────────────────────

@router.post("/{asset_id}/tags", response_model=AssetResponse)
async def add_asset_tags(
    asset_id: str,
    body: TagsRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)
    uid = uuid.UUID(current_user["user_id"])

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    current_tags = list(a.tags) if a.tags else []
    new_tags = [t for t in body.tags if t not in current_tags]
    current_tags.extend(new_tags)
    a.tags = current_tags

    await _audit(
        db, action="asset.tags_added", resource_type="asset", resource_id=aid,
        tenant_id=tid, user_id=uid, details={"added_tags": new_tags},
    )

    return AssetResponse(
        id=str(a.id), tenant_id=str(a.tenant_id), name=a.name,
        hostname=a.hostname, ip_address=a.ip_address, mac_address=a.mac_address,
        type=a.type, os=a.os, os_version=a.os_version,
        status=a.status, risk_level=a.risk_level, tags=a.tags,
        group_id=str(a.group_id) if a.group_id else None,
        agent_id=a.agent_id, last_seen=a.last_seen,
        created_at=a.created_at, updated_at=a.updated_at,
    )


@router.delete("/{asset_id}/tags", response_model=AssetResponse)
async def remove_asset_tags(
    asset_id: str,
    body: TagsRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    aid = uuid.UUID(asset_id)
    uid = uuid.UUID(current_user["user_id"])

    a = (await db.execute(
        select(Asset).where(Asset.id == aid, Asset.tenant_id == tid)
    )).scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    current_tags = list(a.tags) if a.tags else []
    removed = [t for t in body.tags if t in current_tags]
    a.tags = [t for t in current_tags if t not in body.tags]

    await _audit(
        db, action="asset.tags_removed", resource_type="asset", resource_id=aid,
        tenant_id=tid, user_id=uid, details={"removed_tags": removed},
    )

    return AssetResponse(
        id=str(a.id), tenant_id=str(a.tenant_id), name=a.name,
        hostname=a.hostname, ip_address=a.ip_address, mac_address=a.mac_address,
        type=a.type, os=a.os, os_version=a.os_version,
        status=a.status, risk_level=a.risk_level, tags=a.tags,
        group_id=str(a.group_id) if a.group_id else None,
        agent_id=a.agent_id, last_seen=a.last_seen,
        created_at=a.created_at, updated_at=a.updated_at,
    )


# ── Agent Endpoints ───────────────────────────────────────────────

@router.get("/agents", response_model=AgentListResponse)
async def list_agents(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    pagination: PaginationParams = Depends(),
    status_filter: Optional[AgentStatus] = Query(default=None, alias="status"),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    conditions = [Agent.tenant_id == tid]

    if status_filter:
        conditions.append(Agent.status == status_filter.value)

    where_clause = and_(*conditions)

    count_q = select(func.count()).select_from(Agent).where(where_clause)
    total = (await db.execute(count_q)).scalar() or 0

    query = (
        select(Agent)
        .where(where_clause)
        .order_by(desc(Agent.last_heartbeat))
        .offset(pagination.offset)
        .limit(pagination.page_size)
    )
    result = await db.execute(query)
    agents = result.scalars().all()

    items = [
        AgentResponse(
            id=str(ag.id), tenant_id=str(ag.tenant_id), name=ag.name,
            agent_key=ag.agent_key, version=ag.version, platform=ag.platform,
            hostname=ag.hostname, ip_address=ag.ip_address,
            status=ag.status, last_heartbeat=ag.last_heartbeat,
            capabilities=ag.capabilities, asset_id=str(ag.asset_id) if ag.asset_id else None,
            created_at=ag.created_at, updated_at=ag.updated_at,
        )
        for ag in agents
    ]

    return AgentListResponse(
        items=items,
        meta=PaginationMeta(
            page=pagination.page, page_size=pagination.page_size,
            total_items=total, total_pages=max(1, math.ceil(total / pagination.page_size)),
        ),
    )


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    agid = uuid.UUID(agent_id)

    ag = (await db.execute(
        select(Agent).where(Agent.id == agid, Agent.tenant_id == tid)
    )).scalar_one_or_none()

    if not ag:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    return AgentResponse(
        id=str(ag.id), tenant_id=str(ag.tenant_id), name=ag.name,
        agent_key=ag.agent_key, version=ag.version, platform=ag.platform,
        hostname=ag.hostname, ip_address=ag.ip_address,
        status=ag.status, last_heartbeat=ag.last_heartbeat,
        capabilities=ag.capabilities, asset_id=str(ag.asset_id) if ag.asset_id else None,
        created_at=ag.created_at, updated_at=ag.updated_at,
    )


@router.post("/agents/{agent_id}/command", response_model=AgentCommandResponse, status_code=status.HTTP_201_CREATED)
async def send_agent_command(
    agent_id: str,
    body: AgentCommandRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    agid = uuid.UUID(agent_id)
    uid = uuid.UUID(current_user["user_id"])

    ag = (await db.execute(
        select(Agent).where(Agent.id == agid, Agent.tenant_id == tid)
    )).scalar_one_or_none()

    if not ag:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    command_id = uuid.uuid4()

    await _audit(
        db, action="agent.command_queued", resource_type="agent", resource_id=agid,
        tenant_id=tid, user_id=uid,
        details={"command_id": str(command_id), "command": body.command, "parameters": body.parameters},
    )

    return AgentCommandResponse(
        command_id=str(command_id),
        agent_id=str(ag.id),
        command=body.command,
        status="queued",
        queued_at=datetime.now(timezone.utc),
    )


# ── Group Endpoints ───────────────────────────────────────────────

@router.get("/groups", response_model=AssetGroupListResponse)
async def list_groups(
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)

    groups = (await db.execute(
        select(AssetGroup).where(AssetGroup.tenant_id == tid).order_by(AssetGroup.name)
    )).scalars().all()

    items = []
    for g in groups:
        asset_count = (await db.execute(
            select(func.count()).select_from(Asset).where(Asset.group_id == g.id, Asset.tenant_id == tid)
        )).scalar() or 0
        items.append(AssetGroupResponse(
            id=str(g.id), tenant_id=str(g.tenant_id), name=g.name,
            description=g.description,
            parent_group_id=str(g.parent_group_id) if g.parent_group_id else None,
            asset_count=asset_count,
            created_at=g.created_at, updated_at=g.updated_at,
        ))

    return AssetGroupListResponse(items=items)


@router.post("/groups", response_model=AssetGroupResponse, status_code=status.HTTP_201_CREATED)
async def create_group(
    body: AssetGroupCreate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    uid = uuid.UUID(current_user["user_id"])

    if body.parent_group_id:
        parent = (await db.execute(
            select(AssetGroup).where(AssetGroup.id == uuid.UUID(body.parent_group_id), AssetGroup.tenant_id == tid)
        )).scalar_one_or_none()
        if not parent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent group not found")

    group = AssetGroup(
        tenant_id=tid,
        name=body.name,
        description=body.description,
        parent_group_id=uuid.UUID(body.parent_group_id) if body.parent_group_id else None,
    )
    db.add(group)
    await db.flush()

    await _audit(
        db, action="group.created", resource_type="asset_group", resource_id=group.id,
        tenant_id=tid, user_id=uid, details={"name": body.name},
    )

    return AssetGroupResponse(
        id=str(group.id), tenant_id=str(group.tenant_id), name=group.name,
        description=group.description,
        parent_group_id=str(group.parent_group_id) if group.parent_group_id else None,
        asset_count=0, created_at=group.created_at, updated_at=group.updated_at,
    )


@router.patch("/groups/{group_id}", response_model=AssetGroupResponse)
async def update_group(
    group_id: str,
    body: AssetGroupUpdate,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    gid = uuid.UUID(group_id)
    uid = uuid.UUID(current_user["user_id"])

    g = (await db.execute(
        select(AssetGroup).where(AssetGroup.id == gid, AssetGroup.tenant_id == tid)
    )).scalar_one_or_none()

    if not g:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset group not found")

    update_data = body.model_dump(exclude_unset=True)
    changed = []

    if "name" in update_data:
        g.name = update_data["name"]
        changed.append("name")
    if "description" in update_data:
        g.description = update_data["description"]
        changed.append("description")
    if "parent_group_id" in update_data:
        new_parent = uuid.UUID(update_data["parent_group_id"]) if update_data["parent_group_id"] else None
        if new_parent and new_parent == gid:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Group cannot be its own parent")
        if new_parent:
            parent = (await db.execute(
                select(AssetGroup).where(AssetGroup.id == new_parent, AssetGroup.tenant_id == tid)
            )).scalar_one_or_none()
            if not parent:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent group not found")
        g.parent_group_id = new_parent
        changed.append("parent_group_id")

    await _audit(
        db, action="group.updated", resource_type="asset_group", resource_id=gid,
        tenant_id=tid, user_id=uid, details={"changed_fields": changed},
    )

    asset_count = (await db.execute(
        select(func.count()).select_from(Asset).where(Asset.group_id == gid, Asset.tenant_id == tid)
    )).scalar() or 0

    return AssetGroupResponse(
        id=str(g.id), tenant_id=str(g.tenant_id), name=g.name,
        description=g.description,
        parent_group_id=str(g.parent_group_id) if g.parent_group_id else None,
        asset_count=asset_count, created_at=g.created_at, updated_at=g.updated_at,
    )


@router.delete("/groups/{group_id}", response_model=MessageResponse)
async def delete_group(
    group_id: str,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    gid = uuid.UUID(group_id)
    uid = uuid.UUID(current_user["user_id"])

    g = (await db.execute(
        select(AssetGroup).where(AssetGroup.id == gid, AssetGroup.tenant_id == tid)
    )).scalar_one_or_none()

    if not g:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset group not found")

    asset_count = (await db.execute(
        select(func.count()).select_from(Asset).where(Asset.group_id == gid, Asset.tenant_id == tid)
    )).scalar() or 0
    if asset_count > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot delete group with {asset_count} assets. Remove assets from group first.",
        )

    child_count = (await db.execute(
        select(func.count()).select_from(AssetGroup).where(
            AssetGroup.parent_group_id == gid, AssetGroup.tenant_id == tid
        )
    )).scalar() or 0
    if child_count > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot delete group with {child_count} child groups. Delete or reassign children first.",
        )

    await db.delete(g)

    await _audit(
        db, action="group.deleted", resource_type="asset_group", resource_id=gid,
        tenant_id=tid, user_id=uid, details={"name": g.name}, severity="warning",
    )

    return MessageResponse(message="Group deleted", detail=f"Asset group '{g.name}' has been deleted")


@router.post("/groups/{group_id}/assets", response_model=AssetGroupResponse)
async def add_assets_to_group(
    group_id: str,
    body: GroupAssetsRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    gid = uuid.UUID(group_id)
    uid = uuid.UUID(current_user["user_id"])

    g = (await db.execute(
        select(AssetGroup).where(AssetGroup.id == gid, AssetGroup.tenant_id == tid)
    )).scalar_one_or_none()

    if not g:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset group not found")

    asset_uuids = [uuid.UUID(aid) for aid in body.asset_ids]
    assets = (await db.execute(
        select(Asset).where(Asset.id.in_(asset_uuids), Asset.tenant_id == tid)
    )).scalars().all()

    count = 0
    for a in assets:
        a.group_id = gid
        count += 1

    await _audit(
        db, action="group.assets_added", resource_type="asset_group", resource_id=gid,
        tenant_id=tid, user_id=uid,
        details={"added_asset_count": count, "asset_ids": [str(a.id) for a in assets]},
    )

    asset_count = (await db.execute(
        select(func.count()).select_from(Asset).where(Asset.group_id == gid, Asset.tenant_id == tid)
    )).scalar() or 0

    return AssetGroupResponse(
        id=str(g.id), tenant_id=str(g.tenant_id), name=g.name,
        description=g.description,
        parent_group_id=str(g.parent_group_id) if g.parent_group_id else None,
        asset_count=asset_count, created_at=g.created_at, updated_at=g.updated_at,
    )


@router.delete("/groups/{group_id}/assets", response_model=AssetGroupResponse)
async def remove_assets_from_group(
    group_id: str,
    body: GroupAssetsRequest,
    current_user: dict = Depends(get_current_user),
    tenant_id: str = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    tid = uuid.UUID(tenant_id)
    gid = uuid.UUID(group_id)
    uid = uuid.UUID(current_user["user_id"])

    g = (await db.execute(
        select(AssetGroup).where(AssetGroup.id == gid, AssetGroup.tenant_id == tid)
    )).scalar_one_or_none()

    if not g:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset group not found")

    asset_uuids = [uuid.UUID(aid) for aid in body.asset_ids]
    assets = (await db.execute(
        select(Asset).where(Asset.id.in_(asset_uuids), Asset.tenant_id == tid, Asset.group_id == gid)
    )).scalars().all()

    count = 0
    for a in assets:
        a.group_id = None
        count += 1

    await _audit(
        db, action="group.assets_removed", resource_type="asset_group", resource_id=gid,
        tenant_id=tid, user_id=uid,
        details={"removed_asset_count": count, "asset_ids": [str(a.id) for a in assets]},
    )

    asset_count = (await db.execute(
        select(func.count()).select_from(Asset).where(Asset.group_id == gid, Asset.tenant_id == tid)
    )).scalar() or 0

    return AssetGroupResponse(
        id=str(g.id), tenant_id=str(g.tenant_id), name=g.name,
        description=g.description,
        parent_group_id=str(g.parent_group_id) if g.parent_group_id else None,
        asset_count=asset_count, created_at=g.created_at, updated_at=g.updated_at,
    )
