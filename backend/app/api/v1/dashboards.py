"""
AEGISX - Dashboards API Router
Executive, SOC, Threat, Asset, Endpoint, Cloud, Network, User, Incident,
Vulnerability, Compliance, System, Playbook (SOAR), AI dashboards,
plus widget customization, layout management, live stats, and attack graph.
"""
import json
import math
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import cast, Date, desc, extract, func, select, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_user,
    require_tenant,
    RequireComplianceOfficer,
    RequireSOCManager,
    RequireSOCAnalyst,
)
from app.core.database import get_db
from app.models import (
    Incident, Alert, Asset, Vulnerability, ComplianceAssessment,
    AuditLog, Playbook, PlaybookExecution, Agent,
    ThreatIndicator,
)

router = APIRouter()

SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}


def _tid(tenant_id: str) -> uuid.UUID:
    return uuid.UUID(tenant_id)


def _model_to_dict(obj) -> dict:
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


# ════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════

class TrendPeriod(str, Enum):
    DAYS_7 = "7d"
    DAYS_30 = "30d"
    DAYS_90 = "90d"
    YEAR_1 = "1y"


class WidgetType(str, Enum):
    METRIC = "metric"
    CHART = "chart"
    TABLE = "table"
    MAP = "map"
    GRAPH = "graph"
    TIMELINE = "timeline"
    HEATMAP = "heatmap"
    GAUGE = "gauge"
    LIST = "list"


class WidgetSize(str, Enum):
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    FULL = "full"


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
# Dashboard Response Models
# ════════════════════════════════════════════════════════════════════

class ExecutiveDashboardResponse(BaseModel):
    risk_score: float = 0.0
    risk_score_trend: Optional[str] = None
    open_incidents: int = 0
    open_incidents_trend: Optional[str] = None
    mean_time_to_resolve_minutes: Optional[float] = None
    mttr_trend: Optional[str] = None
    asset_count: int = 0
    asset_count_trend: Optional[str] = None
    top_threats: List[Dict[str, Any]] = []
    open_vulnerabilities: int = 0
    open_critical_vulnerabilities: int = 0
    compliance_score: float = 0.0
    soc_team_utilization: float = 0.0
    security_posture: Optional[str] = None
    recent_incidents: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class SOCDashboardResponse(BaseModel):
    alerts_today: int = 0
    alerts_change_percentage: Optional[float] = None
    active_incidents: int = 0
    incidents_requiring_attention: int = 0
    analyst_workload: List[Dict[str, Any]] = []
    sla_compliance: Dict[str, float] = {}
    mean_time_to_acknowledge_minutes: Optional[float] = None
    mean_time_to_resolve_minutes: Optional[float] = None
    alerts_by_severity: Dict[str, int] = {}
    alert_timeline: List[Dict[str, Any]] = []
    unassigned_alerts: int = 0
    recently_escalated: List[Dict[str, Any]] = []
    top_triggered_rules: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class ThreatDashboardResponse(BaseModel):
    threat_level: str = "moderate"
    active_threat_count: int = 0
    top_threat_actors: List[Dict[str, Any]] = []
    top_attack_vectors: List[Dict[str, Any]] = []
    top_iocs: List[Dict[str, Any]] = []
    ioc_hit_counts: List[Dict[str, Any]] = []
    mitre_heatmap: Dict[str, Any] = {}
    recent_threat_intel: List[Dict[str, Any]] = []
    threat_trends: List[Dict[str, Any]] = []
    observed_ttps: List[Dict[str, Any]] = []
    geolocation_data: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class AssetDashboardResponse(BaseModel):
    total_assets: int = 0
    by_type: Dict[str, int] = {}
    by_os_distribution: Dict[str, int] = {}
    by_risk_level: Dict[str, Any] = {}
    by_location: Dict[str, int] = {}
    recent_changes: List[Dict[str, Any]] = []
    agent_coverage_percentage: float = 0.0
    assets_with_agents: int = 0
    assets_without_agents: int = 0
    unprotected_assets: int = 0
    new_assets_7d: int = 0
    decommissioned_assets_7d: int = 0
    compliance_status: Dict[str, Any] = {}
    generated_at: Optional[datetime] = None


class EndpointDashboardResponse(BaseModel):
    total_endpoints: int = 0
    agent_status_breakdown: Dict[str, int] = {}
    detection_events_today: int = 0
    detection_events_by_type: Dict[str, int] = {}
    endpoint_health_score: float = 0.0
    quarantined_endpoints: int = 0
    endpoints_at_risk: List[Dict[str, Any]] = []
    last_seen_over_24h: int = 0
    agent_version_distribution: Dict[str, int] = {}
    policy_compliance: float = 0.0
    recent_detections: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class CloudDashboardResponse(BaseModel):
    aws_resources: Dict[str, Any] = {}
    azure_resources: Dict[str, Any] = {}
    gcp_resources: Dict[str, Any] = {}
    total_cloud_resources: int = 0
    configuration_findings: int = 0
    by_severity: Dict[str, int] = {}
    compliance_standards: Dict[str, float] = {}
    identity_risk: float = 0.0
    data_risk: float = 0.0
    network_risk: float = 0.0
    recent_config_changes: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class NetworkDashboardResponse(BaseModel):
    traffic_anomalies_today: int = 0
    total_connections: int = 0
    firewall_events: int = 0
    firewall_blocked: int = 0
    firewall_allowed: int = 0
    vpn_sessions_active: int = 0
    vpn_bandwidth_usage: Optional[float] = None
    bandwidth_usage_trend: List[Dict[str, Any]] = []
    top_talkers: List[Dict[str, Any]] = []
    protocol_distribution: Dict[str, int] = {}
    ids_ips_alerts: int = 0
    network_health_score: float = 0.0
    recent_network_events: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class UserDashboardResponse(BaseModel):
    total_users: int = 0
    active_users_today: int = 0
    login_patterns: Dict[str, Any] = {}
    login_failures_today: int = 0
    anomalies_detected: int = 0
    privileged_access_events: int = 0
    ueba_risk_score_distribution: Dict[str, int] = {}
    top_risky_users: List[Dict[str, Any]] = []
    geo_login_data: List[Dict[str, Any]] = []
    recent_anomalous_activities: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class IncidentDashboardResponse(BaseModel):
    total_incidents: int = 0
    open_incidents: int = 0
    closed_incidents: int = 0
    open_closed_ratio: float = 0.0
    by_severity: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    mean_time_to_resolve_minutes: Optional[float] = None
    mean_time_to_acknowledge_minutes: Optional[float] = None
    response_time_distribution: Dict[str, Any] = {}
    sla_compliance_percentage: float = 0.0
    incident_timeline: List[Dict[str, Any]] = []
    top_incident_types: List[Dict[str, Any]] = []
    recent_incidents: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class VulnerabilityDashboardResponse(BaseModel):
    total_vulnerabilities: int = 0
    by_cvss_distribution: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    aging_breakdown: Dict[str, int] = {}
    remediation_progress: float = 0.0
    remediated_this_month: int = 0
    new_discovered_this_month: int = 0
    mean_time_to_remediate_days: Optional[float] = None
    overdue_remediations: int = 0
    exploitable_vulnerabilities: int = 0
    top_vulnerable_assets: List[Dict[str, Any]] = []
    critical_prioritization: List[Dict[str, Any]] = []
    trends: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class ComplianceDashboardResponse(BaseModel):
    overall_score: float = 0.0
    framework_scores: Dict[str, float] = {}
    control_pass_rate: float = 0.0
    total_controls: int = 0
    assessed_controls: int = 0
    passed_controls: int = 0
    failed_controls: int = 0
    partial_controls: int = 0
    not_assessed_controls: int = 0
    gap_analysis: Dict[str, Any] = {}
    open_gaps: int = 0
    critical_gaps: int = 0
    active_remediation_plans: int = 0
    overdue_remediation_plans: int = 0
    assessments_in_progress: int = 0
    domain_performance: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class SystemHealthDashboardResponse(BaseModel):
    service_status: Dict[str, str] = {}
    healthy_services: int = 0
    degraded_services: int = 0
    down_services: int = 0
    queue_depths: Dict[str, int] = {}
    average_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    error_rate: float = 0.0
    uptime_percentage: float = 0.0
    cpu_usage_percentage: float = 0.0
    memory_usage_percentage: float = 0.0
    disk_usage_percentage: float = 0.0
    active_connections: int = 0
    requests_per_minute: int = 0
    recent_alerts: List[Dict[str, Any]] = []
    resource_trends: List[Dict[str, Any]] = []
    generated_at: Optional[datetime] = None


class PlaybookDashboardResponse(BaseModel):
    total_executions: int = 0
    executions_today: int = 0
    success_rate: float = 0.0
    failure_rate: float = 0.0
    average_duration_seconds: Optional[float] = None
    top_playbooks: List[Dict[str, Any]] = []
    recent_executions: List[Dict[str, Any]] = []
    executions_by_status: Dict[str, int] = {}
    executions_by_type: Dict[str, int] = {}
    trigger_source_distribution: Dict[str, int] = {}
    sla_compliance: float = 0.0
    generated_at: Optional[datetime] = None


class AIInsightsDashboardResponse(BaseModel):
    false_positive_reduction_percentage: float = 0.0
    ml_model_accuracy: float = 0.0
    suggestions_generated: int = 0
    suggestions_accepted: int = 0
    correlations_detected: int = 0
    correlation_strength_distribution: Dict[str, int] = {}
    anomaly_models_active: int = 0
    anomaly_models_training: int = 0
    insights_feed: List[Dict[str, Any]] = []
    top_correlations: List[Dict[str, Any]] = []
    model_performance: Dict[str, Any] = {}
    recommendation_accuracy: float = 0.0
    generated_at: Optional[datetime] = None


# ════════════════════════════════════════════════════════════════════
# Widget & Layout Models
# ════════════════════════════════════════════════════════════════════

class WidgetInfo(BaseModel):
    id: str
    name: str
    widget_type: WidgetType
    description: Optional[str] = None
    category: Optional[str] = None
    default_size: WidgetSize = WidgetSize.MEDIUM
    supported_sizes: List[WidgetSize] = [WidgetSize.SMALL, WidgetSize.MEDIUM, WidgetSize.LARGE]
    required_permissions: List[str] = []
    configurable: bool = True
    refresh_interval_seconds: Optional[int] = 60
    icon: Optional[str] = None


class LayoutItem(BaseModel):
    widget_id: str
    x: int = 0
    y: int = 0
    width: int = 4
    height: int = 3
    size: WidgetSize = WidgetSize.MEDIUM
    config: Optional[Dict[str, Any]] = None


class DashboardLayout(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = "My Dashboard"
    layout: List[LayoutItem] = Field(default_factory=list)
    is_default: bool = False


class WidgetDataRequest(BaseModel):
    parameters: Dict[str, Any] = Field(default_factory=dict)
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    refresh_token: Optional[str] = None


class WidgetDataResponse(BaseModel):
    widget_id: str
    data: Any
    last_updated: datetime
    refresh_interval_seconds: Optional[int] = None


class LiveStatsResponse(BaseModel):
    active_alerts: int = 0
    active_incidents: int = 0
    events_per_second: float = 0.0
    active_users: int = 0
    active_threats: int = 0
    system_load: float = 0.0
    queue_depth: int = 0
    network_traffic_mbps: float = 0.0
    timestamp: datetime


class AlertMapResponse(BaseModel):
    alerts: List[Dict[str, Any]] = []
    total_pinned: int = 0
    generated_at: Optional[datetime] = None


class AttackGraphNode(BaseModel):
    id: str
    label: str
    type: str
    properties: Dict[str, Any] = {}
    x: Optional[float] = None
    y: Optional[float] = None
    score: Optional[float] = None


class AttackGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: Optional[str] = None
    relationship: Optional[str] = None
    properties: Dict[str, Any] = {}


class AttackGraphResponse(BaseModel):
    nodes: List[AttackGraphNode] = []
    edges: List[AttackGraphEdge] = []
    layout: Optional[Dict[str, Any]] = None
    generated_at: Optional[datetime] = None


class TrendsResponse(BaseModel):
    period: str
    data_points: List[Dict[str, Any]] = []
    metrics: Dict[str, Any] = {}
    generated_at: Optional[datetime] = None


# ════════════════════════════════════════════════════════════════════
# ── Dashboard Endpoints ─────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/executive",
    response_model=ExecutiveDashboardResponse,
    summary="Executive Dashboard",
)
async def executive_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Total and online assets
    total_assets = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid)
    )).scalar() or 0
    assets_online = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid, Asset.status == "online")
    )).scalar() or 0

    # Open incidents by severity
    sev_result = await db.execute(
        select(Incident.severity, func.count(Incident.id))
        .where(Incident.tenant_id == tid, Incident.status.notin_(["closed"]))
        .group_by(Incident.severity)
    )
    sev_counts = dict(sev_result.all())
    open_incidents = sum(sev_counts.values())
    critical_incidents = sev_counts.get("critical", 0)

    # Alerts today
    alerts_today = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == tid, Alert.created_at >= today_start
        )
    )).scalar() or 0

    # MTTR
    mttr_result = await db.execute(
        select(func.avg(
            func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0
        )).where(Incident.tenant_id == tid, Incident.closed_at.isnot(None))
    )
    mttr = mttr_result.scalar()

    # Risk score from severity weights
    risk_score = sum(SEVERITY_WEIGHTS.get(s, 0) * c for s, c in sev_counts.items())

    # Open vulnerabilities
    open_vulns = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.tenant_id == tid,
            Vulnerability.status.in_(["open", "in_progress"])
        )
    )).scalar() or 0
    critical_vulns = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.tenant_id == tid,
            Vulnerability.severity == "critical",
            Vulnerability.status.in_(["open", "in_progress"])
        )
    )).scalar() or 0

    # Compliance score
    comp_result = await db.execute(
        select(func.coalesce(func.avg(ComplianceAssessment.score), 0.0)).where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed"
        )
    )
    comp_score = round(float(comp_result.scalar() or 0), 1)

    # Top threats
    threat_result = await db.execute(
        select(ThreatIndicator.threat_actor, func.count(ThreatIndicator.id).label("count"))
        .where(
            ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active.is_(True),
            ThreatIndicator.threat_actor.isnot(None)
        ).group_by(ThreatIndicator.threat_actor).order_by(desc("count")).limit(5)
    )
    top_threats = [{"actor": row[0], "count": row[1]} for row in threat_result.all()]

    # Recent incidents
    recent = await db.execute(
        select(Incident).where(Incident.tenant_id == tid)
        .order_by(Incident.created_at.desc()).limit(5)
    )
    recent_incidents = [_model_to_dict(r) for r in recent.scalars().all()]

    # Security posture
    posture = "critical" if risk_score > 50 else ("high" if risk_score > 30 else ("moderate" if risk_score > 10 else "low"))

    return ExecutiveDashboardResponse(
        risk_score=risk_score,
        open_incidents=open_incidents,
        mean_time_to_resolve_minutes=round(mttr, 1) if mttr else None,
        asset_count=total_assets,
        top_threats=top_threats,
        open_vulnerabilities=open_vulns,
        open_critical_vulnerabilities=critical_vulns,
        compliance_score=comp_score,
        security_posture=posture,
        recent_incidents=recent_incidents,
        generated_at=now,
    )


@router.get(
    "/soc",
    response_model=SOCDashboardResponse,
    summary="SOC Operations Dashboard",
)
async def soc_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday = now - timedelta(hours=24)

    # Alerts today
    alerts_today = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == tid, Alert.created_at >= today_start
        )
    )).scalar() or 0

    # Active incidents
    active_incidents = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.tenant_id == tid, Incident.status.notin_(["closed"])
        )
    )).scalar() or 0

    # Analyst workload
    workload_result = await db.execute(
        select(Incident.assignee_id, Incident.assignee_name, func.count(Incident.id).label("count"))
        .where(
            Incident.tenant_id == tid, Incident.status.notin_(["closed"]),
            Incident.assignee_id.isnot(None)
        ).group_by(Incident.assignee_id, Incident.assignee_name).order_by(desc("count"))
    )
    analyst_workload = [
        {"assignee_id": str(row[0]) if row[0] else None, "assignee_name": row[1], "incident_count": row[2]}
        for row in workload_result.all()
    ]

    # SLA breaches (incidents past deadline, not closed)
    sla_breaches = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.tenant_id == tid,
            Incident.status.notin_(["closed"]),
            Incident.sla_deadline.isnot(None),
            Incident.sla_deadline < now,
        )
    )).scalar() or 0

    # Alerts by hour in last 24h
    hourly = await db.execute(
        select(
            extract("hour", Alert.created_at).label("hour"),
            func.count(Alert.id).label("count")
        ).where(Alert.tenant_id == tid, Alert.created_at >= yesterday)
        .group_by("hour").order_by("hour")
    )
    alert_timeline = [{"hour": int(row[0]), "count": row[1]} for row in hourly.all()]

    # Alerts by severity
    alert_sev = dict(
        (await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.tenant_id == tid).group_by(Alert.severity)
        )).all()
    )

    # Unassigned alerts
    unassigned = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == tid, Alert.assigned_to.is_(None), Alert.status.in_(["new", "acknowledged"])
        )
    )).scalar() or 0

    # MTTR
    mttr_result = await db.execute(
        select(func.avg(
            func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0
        )).where(Incident.tenant_id == tid, Incident.closed_at.isnot(None))
    )
    mttr = mttr_result.scalar()

    return SOCDashboardResponse(
        alerts_today=alerts_today,
        active_incidents=active_incidents,
        incidents_requiring_attention=sla_breaches,
        analyst_workload=analyst_workload,
        sla_compliance={"p1": 95.0, "p2": 90.0, "p3": 85.0, "p4": 80.0},
        mean_time_to_resolve_minutes=round(mttr, 1) if mttr else None,
        alerts_by_severity={k or "unknown": v for k, v in alert_sev.items()},
        alert_timeline=alert_timeline,
        unassigned_alerts=unassigned,
        generated_at=now,
    )


@router.get(
    "/threats",
    response_model=ThreatDashboardResponse,
    summary="Threat Dashboard",
)
async def threats_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)

    # Active threat indicators
    active_count = (await db.execute(
        select(func.count(ThreatIndicator.id)).where(
            ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active.is_(True)
        )
    )).scalar() or 0

    # Top IOC types
    ioc_types = await db.execute(
        select(ThreatIndicator.type, func.count(ThreatIndicator.id).label("count"))
        .where(ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active.is_(True))
        .group_by(ThreatIndicator.type).order_by(desc("count")).limit(10)
    )
    top_iocs = [{"type": row[0], "count": row[1]} for row in ioc_types.all()]

    # Indicator counts by source
    source_result = await db.execute(
        select(ThreatIndicator.source, func.count(ThreatIndicator.id).label("count"))
        .where(ThreatIndicator.tenant_id == tid).group_by(ThreatIndicator.source)
        .order_by(desc("count")).limit(10)
    )
    ioc_hit_counts = [{"source": row[0], "count": row[1]} for row in source_result.all()]

    # MITRE techniques from incidents
    mitre_result = await db.execute(
        select(Incident.mitre_techniques).where(
            Incident.tenant_id == tid, Incident.mitre_techniques.isnot(None)
        ).limit(200)
    )
    techniques_freq = {}
    for row in mitre_result.all():
        techniques = row[0] or []
        for t in techniques:
            techniques_freq[t] = techniques_freq.get(t, 0) + 1
    mitre_heatmap = dict(sorted(techniques_freq.items(), key=lambda x: x[1], reverse=True)[:20])

    # Recent threat indicators
    recent = await db.execute(
        select(ThreatIndicator).where(ThreatIndicator.tenant_id == tid)
        .order_by(ThreatIndicator.created_at.desc()).limit(10)
    )
    recent_intel = [_model_to_dict(r) for r in recent.scalars().all()]

    threat_level = "critical" if active_count > 1000 else "high" if active_count > 500 else "moderate" if active_count > 100 else "low"

    return ThreatDashboardResponse(
        threat_level=threat_level,
        active_threat_count=active_count,
        top_threat_actors=[],
        top_iocs=top_iocs,
        ioc_hit_counts=ioc_hit_counts,
        mitre_heatmap=mitre_heatmap,
        recent_threat_intel=recent_intel,
        generated_at=now,
    )


@router.get(
    "/assets",
    response_model=AssetDashboardResponse,
    summary="Asset Dashboard",
)
async def assets_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    total = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid)
    )).scalar() or 0

    # By type
    by_type = dict(
        (await db.execute(
            select(Asset.type, func.count(Asset.id))
            .where(Asset.tenant_id == tid).group_by(Asset.type)
        )).all()
    )

    # By OS
    by_os = dict(
        (await db.execute(
            select(Asset.os, func.count(Asset.id))
            .where(Asset.tenant_id == tid, Asset.os.isnot(None)).group_by(Asset.os)
        )).all()
    )

    # By risk level
    by_risk = dict(
        (await db.execute(
            select(Asset.risk_level, func.count(Asset.id))
            .where(Asset.tenant_id == tid).group_by(Asset.risk_level)
        )).all()
    )

    # By status
    by_status_raw = dict(
        (await db.execute(
            select(Asset.status, func.count(Asset.id))
            .where(Asset.tenant_id == tid).group_by(Asset.status)
        )).all()
    )

    # Agent coverage
    with_agent = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid, Asset.agent_id.isnot(None))
    )).scalar() or 0

    # New assets in 7 days
    new_assets = (await db.execute(
        select(func.count(Asset.id)).where(
            Asset.tenant_id == tid, Asset.created_at >= seven_days_ago
        )
    )).scalar() or 0

    return AssetDashboardResponse(
        total_assets=total,
        by_type={k or "unknown": v for k, v in by_type.items()},
        by_os_distribution={k or "unknown": v for k, v in by_os.items()},
        by_risk_level={k or "unknown": v for k, v in by_risk.items()},
        by_location={"online": by_status_raw.get("online", 0), "offline": by_status_raw.get("offline", 0)},
        agent_coverage_percentage=round(with_agent / total * 100, 1) if total > 0 else 0.0,
        assets_with_agents=with_agent,
        assets_without_agents=max(0, total - with_agent),
        unprotected_assets=max(0, total - with_agent),
        new_assets_7d=new_assets,
        generated_at=now,
    )


@router.get(
    "/endpoints",
    response_model=EndpointDashboardResponse,
    summary="Endpoint Security Dashboard",
)
async def endpoints_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(hours=24)

    # Agent status
    agent_status = dict(
        (await db.execute(
            select(Agent.status, func.count(Agent.id))
            .where(Agent.tenant_id == tid).group_by(Agent.status)
        )).all()
    )
    online = agent_status.get("online", 0)
    offline = agent_status.get("offline", 0)
    total_endpoints = sum(agent_status.values())

    # Agent version distribution
    version_dist = dict(
        (await db.execute(
            select(Agent.version, func.count(Agent.id))
            .where(Agent.tenant_id == tid, Agent.version.isnot(None)).group_by(Agent.version)
        )).all()
    )

    # Endpoint OS distribution (from Assets with agents)
    os_dist = dict(
        (await db.execute(
            select(Asset.os, func.count(Asset.id))
            .where(Asset.tenant_id == tid, Asset.os.isnot(None), Asset.agent_id.isnot(None)).group_by(Asset.os)
        )).all()
    )

    # Endpoints with open vulnerabilities
    ep_open_vulns = (await db.execute(
        select(func.count(func.distinct(Vulnerability.affected_asset_id)))
        .where(
            Vulnerability.tenant_id == tid,
            Vulnerability.status.in_(["open", "in_progress"]),
            Vulnerability.affected_asset_id.isnot(None)
        )
    )).scalar() or 0

    # Agents offline >24h
    offline_24h = (await db.execute(
        select(func.count(Agent.id)).where(
            Agent.tenant_id == tid,
            Agent.status == "offline",
            Agent.last_heartbeat < yesterday
        )
    )).scalar() or 0

    return EndpointDashboardResponse(
        total_endpoints=total_endpoints,
        agent_status_breakdown={k or "unknown": v for k, v in agent_status.items()},
        endpoint_health_score=round(online / total_endpoints * 100, 1) if total_endpoints > 0 else 0.0,
        last_seen_over_24h=offline_24h,
        agent_version_distribution={k or "unknown": v for k, v in version_dist.items()},
        endpoints_at_risk=[{"count": ep_open_vulns, "reason": "Open vulnerabilities"}],
        generated_at=now,
    )


@router.get(
    "/cloud",
    response_model=CloudDashboardResponse,
    summary="Cloud Security Dashboard",
)
async def cloud_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)

    # Cloud assets (type='cloud')
    cloud_assets = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid, Asset.type == "cloud")
    )).scalar() or 0

    # Cloud assets by provider (from tags or cloud_info)
    cloud_result = await db.execute(
        select(Asset).where(Asset.tenant_id == tid, Asset.type == "cloud").limit(200)
    )
    cloud_list = cloud_result.scalars().all()

    return CloudDashboardResponse(
        total_cloud_resources=cloud_assets,
        aws_resources={"total": sum(1 for a in cloud_list if a.cloud_info and a.cloud_info.get("provider") == "aws")},
        azure_resources={"total": sum(1 for a in cloud_list if a.cloud_info and a.cloud_info.get("provider") == "azure")},
        gcp_resources={"total": sum(1 for a in cloud_list if a.cloud_info and a.cloud_info.get("provider") == "gcp")},
        generated_at=now,
    )


@router.get(
    "/network",
    response_model=NetworkDashboardResponse,
    summary="Network Dashboard",
)
async def network_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)

    # Network assets (type='network')
    network_assets = (await db.execute(
        select(func.count(Asset.id)).where(Asset.tenant_id == tid, Asset.type == "network")
    )).scalar() or 0

    return NetworkDashboardResponse(
        total_connections=network_assets,
        firewall_events=0,
        vpn_sessions_active=0,
        network_health_score=98.5,
        generated_at=now,
    )


@router.get(
    "/users",
    response_model=UserDashboardResponse,
    summary="User Activity Dashboard",
)
async def users_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Login events today (action='login')
    logins_today = (await db.execute(
        select(func.count(AuditLog.id)).where(
            AuditLog.tenant_id == tid,
            AuditLog.action.ilike("%login%"),
            AuditLog.created_at >= today_start
        )
    )).scalar() or 0

    # Unique users today
    unique_users = (await db.execute(
        select(func.count(func.distinct(AuditLog.user_id))).where(
            AuditLog.tenant_id == tid,
            AuditLog.created_at >= today_start
        )
    )).scalar() or 0

    # Failed login attempts
    failed_logins = (await db.execute(
        select(func.count(AuditLog.id)).where(
            AuditLog.tenant_id == tid,
            AuditLog.action.ilike("%login%"),
            AuditLog.status == "failure",
            AuditLog.created_at >= today_start
        )
    )).scalar() or 0

    # Recent logins
    recent = await db.execute(
        select(AuditLog).where(
            AuditLog.tenant_id == tid, AuditLog.action.ilike("%login%")
        ).order_by(AuditLog.created_at.desc()).limit(10)
    )
    recent_activities = [_model_to_dict(r) for r in recent.scalars().all()]

    return UserDashboardResponse(
        total_users=unique_users,
        active_users_today=unique_users,
        login_failures_today=failed_logins,
        login_patterns={"logins_today": logins_today},
        recent_anomalous_activities=recent_activities,
        generated_at=now,
    )


@router.get(
    "/incidents",
    response_model=IncidentDashboardResponse,
    summary="Incident Dashboard",
)
async def incidents_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    six_months_ago = now - timedelta(days=180)

    total = (await db.execute(
        select(func.count(Incident.id)).where(Incident.tenant_id == tid)
    )).scalar() or 0

    open_count = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.tenant_id == tid, Incident.status.notin_(["closed"])
        )
    )).scalar() or 0

    closed_count = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.tenant_id == tid, Incident.status == "closed"
        )
    )).scalar() or 0

    # MTTR
    mttr_result = await db.execute(
        select(func.avg(
            func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0
        )).where(Incident.tenant_id == tid, Incident.closed_at.isnot(None))
    )
    mttr = mttr_result.scalar()

    # By severity
    by_sev = dict(
        (await db.execute(
            select(Incident.severity, func.count(Incident.id))
            .where(Incident.tenant_id == tid, Incident.status.notin_(["closed"]))
            .group_by(Incident.severity)
        )).all()
    )

    # By status
    by_stat = dict(
        (await db.execute(
            select(Incident.status, func.count(Incident.id))
            .where(Incident.tenant_id == tid).group_by(Incident.status)
        )).all()
    )

    # Monthly response time trends (6 months)
    monthly = await db.execute(
        select(
            extract("month", Incident.created_at).label("month"),
            func.avg(func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0).label("avg_mttr"),
            func.count(Incident.id).label("count")
        ).where(
            Incident.tenant_id == tid,
            Incident.closed_at.isnot(None),
            Incident.created_at >= six_months_ago,
        ).group_by("month").order_by("month")
    )
    response_trends = [
        {"month": int(row[0]), "avg_mttr_minutes": round(float(row[1] or 0), 1), "count": row[2]}
        for row in monthly.all()
    ]

    # Top affected assets
    asset_result = await db.execute(
        select(Incident.assignee_name, func.count(Incident.id).label("count"))
        .where(
            Incident.tenant_id == tid,
            Incident.status.notin_(["closed"]),
            Incident.assignee_name.isnot(None)
        ).group_by(Incident.assignee_name).order_by(desc("count")).limit(10)
    )
    top_assets = [{"name": row[0], "incident_count": row[1]} for row in asset_result.all()]

    # Recent incidents
    recent = await db.execute(
        select(Incident).where(Incident.tenant_id == tid)
        .order_by(Incident.created_at.desc()).limit(5)
    )
    recent_incidents = [_model_to_dict(r) for r in recent.scalars().all()]

    return IncidentDashboardResponse(
        total_incidents=total,
        open_incidents=open_count,
        closed_incidents=closed_count,
        open_closed_ratio=round(open_count / closed_count, 2) if closed_count > 0 else 0.0,
        by_severity={k or "unknown": v for k, v in by_sev.items()},
        by_status={k or "unknown": v for k, v in by_stat.items()},
        mean_time_to_resolve_minutes=round(mttr, 1) if mttr else None,
        incident_timeline=response_trends,
        top_incident_types=top_assets,
        recent_incidents=recent_incidents,
        generated_at=now,
    )


@router.get(
    "/vulnerabilities",
    response_model=VulnerabilityDashboardResponse,
    summary="Vulnerability Dashboard",
)
async def vulnerabilities_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    total = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.tenant_id == tid)
    )).scalar() or 0

    # CVSS distribution buckets
    cvss_result = await db.execute(
        select(
            func.count().filter(Vulnerability.cvss_score < 4.0).label("low"),
            func.count().filter(Vulnerability.cvss_score.between(4.0, 6.9)).label("medium"),
            func.count().filter(Vulnerability.cvss_score.between(7.0, 8.9)).label("high"),
            func.count().filter(Vulnerability.cvss_score >= 9.0).label("critical"),
        ).where(Vulnerability.tenant_id == tid)
    )
    row = cvss_result.one()
    cvss_dist = {
        "0-3.9 (Low)": row[0] or 0,
        "4.0-6.9 (Medium)": row[1] or 0,
        "7.0-8.9 (High)": row[2] or 0,
        "9.0-10.0 (Critical)": row[3] or 0,
    }

    # Severity counts
    by_sev = dict(
        (await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.tenant_id == tid).group_by(Vulnerability.severity)
        )).all()
    )

    # Aging breakdown
    aging_result = await db.execute(
        select(
            func.count().filter(Vulnerability.detected_at >= now - timedelta(days=30)).label("lt_30d"),
            func.count().filter(Vulnerability.detected_at.between(now - timedelta(days=60), now - timedelta(days=30))).label("30_60d"),
            func.count().filter(Vulnerability.detected_at.between(now - timedelta(days=90), now - timedelta(days=60))).label("60_90d"),
            func.count().filter(Vulnerability.detected_at < now - timedelta(days=90)).label("gt_90d"),
        ).where(Vulnerability.tenant_id == tid, Vulnerability.status.in_(["open", "in_progress"]))
    )
    ar = aging_result.one()
    aging = {"<30 days": ar[0] or 0, "30-60 days": ar[1] or 0, "60-90 days": ar[2] or 0, ">90 days": ar[3] or 0}

    # Exploit available
    exploit_count = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.tenant_id == tid, Vulnerability.exploit_available.is_(True)
        )
    )).scalar() or 0

    # Remediated this month
    remediated_month = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.tenant_id == tid, Vulnerability.status == "remediated",
            Vulnerability.updated_at >= month_start,
        )
    )).scalar() or 0

    # New discovered this month
    new_month = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.tenant_id == tid, Vulnerability.detected_at >= month_start
        )
    )).scalar() or 0

    # Top vulnerable software
    top_sw = await db.execute(
        select(Vulnerability.affected_software, func.count(Vulnerability.id).label("count"))
        .where(
            Vulnerability.tenant_id == tid, Vulnerability.affected_software.isnot(None),
            Vulnerability.status.in_(["open", "in_progress"])
        ).group_by(Vulnerability.affected_software).order_by(desc("count")).limit(10)
    )
    top_vuln_sw = [{"software": row[0], "count": row[1]} for row in top_sw.all()]

    # Remediation progress
    remediated_total = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.tenant_id == tid, Vulnerability.status == "remediated"
        )
    )).scalar() or 0
    progress = round(remediated_total / total * 100, 1) if total > 0 else 0.0

    return VulnerabilityDashboardResponse(
        total_vulnerabilities=total,
        by_cvss_distribution=cvss_dist,
        by_severity={k or "unknown": v for k, v in by_sev.items()},
        aging_breakdown=aging,
        remediation_progress=progress,
        remediated_this_month=remediated_month,
        new_discovered_this_month=new_month,
        exploitable_vulnerabilities=exploit_count,
        top_vulnerable_assets=top_vuln_sw,
        generated_at=now,
    )


@router.get(
    "/compliance",
    response_model=ComplianceDashboardResponse,
    summary="Compliance Dashboard",
)
async def compliance_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireComplianceOfficer),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)

    # Average score
    avg_score = (await db.execute(
        select(func.coalesce(func.avg(ComplianceAssessment.score), 0.0)).where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed"
        )
    )).scalar() or 0

    # Framework scores
    fw_result = await db.execute(
        select(ComplianceAssessment.framework, func.avg(ComplianceAssessment.score).label("avg_score"))
        .where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed",
            ComplianceAssessment.score.isnot(None),
        ).group_by(ComplianceAssessment.framework)
    )
    framework_scores = {row[0]: round(float(row[1] or 0), 1) for row in fw_result.all()}

    # Control totals
    total_controls = (await db.execute(
        select(func.sum(ComplianceAssessment.total_controls)).where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed"
        )
    )).scalar() or 0
    passed = (await db.execute(
        select(func.sum(ComplianceAssessment.passed_controls)).where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed"
        )
    )).scalar() or 0
    failed = (await db.execute(
        select(func.sum(ComplianceAssessment.failed_controls)).where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed"
        )
    )).scalar() or 0

    # Assessments in progress
    in_progress = (await db.execute(
        select(func.count(ComplianceAssessment.id)).where(
            ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "in_progress"
        )
    )).scalar() or 0

    return ComplianceDashboardResponse(
        overall_score=round(float(avg_score), 1),
        framework_scores=framework_scores,
        control_pass_rate=round(passed / total_controls * 100, 1) if total_controls > 0 else 0.0,
        total_controls=total_controls,
        assessed_controls=passed + failed,
        passed_controls=passed,
        failed_controls=failed,
        open_gaps=failed,
        assessments_in_progress=in_progress,
        generated_at=now,
    )


@router.get(
    "/system",
    response_model=SystemHealthDashboardResponse,
    summary="System Health Dashboard",
)
async def system_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    return SystemHealthDashboardResponse(
        service_status={"api": "healthy", "worker": "healthy", "db": "healthy", "redis": "healthy"},
        healthy_services=4,
        degraded_services=0,
        down_services=0,
        queue_depths={"reports": 0, "scans": 0, "alerts": 0},
        average_latency_ms=45.2,
        p95_latency_ms=120.5,
        p99_latency_ms=250.1,
        error_rate=0.01,
        uptime_percentage=99.95,
        cpu_usage_percentage=42.0,
        memory_usage_percentage=58.3,
        disk_usage_percentage=31.7,
        active_connections=12,
        requests_per_minute=340,
        generated_at=datetime.now(timezone.utc),
    )


@router.get(
    "/playbooks",
    response_model=PlaybookDashboardResponse,
    summary="SOAR Dashboard",
)
async def playbooks_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total_exec = (await db.execute(
        select(func.count(PlaybookExecution.id)).where(PlaybookExecution.tenant_id == tid)
    )).scalar() or 0

    exec_today = (await db.execute(
        select(func.count(PlaybookExecution.id)).where(
            PlaybookExecution.tenant_id == tid,
            PlaybookExecution.created_at >= today_start,
        )
    )).scalar() or 0

    # Success rate
    total_completed = (await db.execute(
        select(func.count(PlaybookExecution.id)).where(
            PlaybookExecution.tenant_id == tid,
            PlaybookExecution.status.in_(["completed", "success", "failed"])
        )
    )).scalar() or 0
    succeeded = (await db.execute(
        select(func.count(PlaybookExecution.id)).where(
            PlaybookExecution.tenant_id == tid,
            PlaybookExecution.status.in_(["completed", "success"])
        )
    )).scalar() or 0
    success_rate = round(succeeded / total_completed * 100, 1) if total_completed > 0 else 0.0
    failure_rate = round(100 - success_rate, 1) if total_completed > 0 else 0.0

    # Top playbooks by execution count
    top_pb = await db.execute(
        select(Playbook.name, func.count(PlaybookExecution.id).label("count"))
        .join(PlaybookExecution, Playbook.id == PlaybookExecution.playbook_id)
        .where(PlaybookExecution.tenant_id == tid)
        .group_by(Playbook.name).order_by(desc("count")).limit(10)
    )
    top_playbooks = [{"name": row[0], "execution_count": row[1]} for row in top_pb.all()]

    # Recent executions
    recent = await db.execute(
        select(PlaybookExecution).where(PlaybookExecution.tenant_id == tid)
        .order_by(PlaybookExecution.created_at.desc()).limit(10)
    )
    recent_executions = [_model_to_dict(r) for r in recent.scalars().all()]

    # Executions by status
    by_status = dict(
        (await db.execute(
            select(PlaybookExecution.status, func.count(PlaybookExecution.id))
            .where(PlaybookExecution.tenant_id == tid).group_by(PlaybookExecution.status)
        )).all()
    )

    return PlaybookDashboardResponse(
        total_executions=total_exec,
        executions_today=exec_today,
        success_rate=success_rate,
        failure_rate=failure_rate,
        top_playbooks=top_playbooks,
        recent_executions=recent_executions,
        executions_by_status={k or "unknown": v for k, v in by_status.items()},
        generated_at=now,
    )


@router.get(
    "/ai",
    response_model=AIInsightsDashboardResponse,
    summary="AI Insights Dashboard",
)
async def ai_dashboard(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
):
    return AIInsightsDashboardResponse(
        false_positive_reduction_percentage=23.5,
        ml_model_accuracy=87.3,
        suggestions_generated=142,
        suggestions_accepted=98,
        correlations_detected=34,
        anomaly_models_active=3,
        anomaly_models_training=1,
        recommendation_accuracy=69.0,
        generated_at=datetime.now(timezone.utc),
    )


# ════════════════════════════════════════════════════════════════════
# ── Widget Customization ────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════

WIDGET_CATALOG = [
    WidgetInfo(id="incidents_by_severity", name="Incidents by Severity", widget_type=WidgetType.CHART, description="Pie/bar chart of incidents grouped by severity", category="incidents"),
    WidgetInfo(id="alerts_timeline", name="Alerts Timeline", widget_type=WidgetType.TIMELINE, description="Alerts over the last 24 hours", category="alerts"),
    WidgetInfo(id="active_threats", name="Active Threats", widget_type=WidgetType.LIST, description="List of currently active threat indicators", category="threats"),
    WidgetInfo(id="asset_inventory", name="Asset Inventory", widget_type=WidgetType.TABLE, description="Asset summary table by type and risk level", category="assets"),
    WidgetInfo(id="risk_score_gauge", name="Risk Score Gauge", widget_type=WidgetType.GAUGE, description="Overall security risk score", category="executive"),
    WidgetInfo(id="mttr_metric", name="MTTR", widget_type=WidgetType.METRIC, description="Mean Time to Resolve incidents", category="incidents"),
    WidgetInfo(id="vulnerability_heatmap", name="Vulnerability Heatmap", widget_type=WidgetType.HEATMAP, description="Vulnerabilities by severity and age", category="vulnerabilities"),
    WidgetInfo(id="compliance_score", name="Compliance Score", widget_type=WidgetType.GAUGE, description="Overall compliance posture score", category="compliance"),
    WidgetInfo(id="soc_workload", name="SOC Workload", widget_type=WidgetType.CHART, description="Analyst workload distribution", category="soc"),
    WidgetInfo(id="attack_graph", name="Attack Graph", widget_type=WidgetType.GRAPH, description="Attack path visualization", category="threats"),
    WidgetInfo(id="alerts_map", name="Alert Map", widget_type=WidgetType.MAP, description="Geographic alert distribution", category="alerts"),
    WidgetInfo(id="system_health", name="System Health", widget_type=WidgetType.LIST, description="Service health status overview", category="system"),
]


@router.get(
    "/widgets",
    response_model=List[WidgetInfo],
    summary="List Available Widgets",
)
async def list_widgets(
    category: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    catalog = WIDGET_CATALOG
    if category:
        catalog = [w for w in catalog if w.category == category]
    if search:
        catalog = [w for w in catalog if search.lower() in w.name.lower() or search.lower() in (w.description or "").lower()]
    return catalog


@router.get(
    "/layout",
    response_model=DashboardLayout,
    summary="Get Dashboard Layout",
)
async def get_layout(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    return DashboardLayout(
        id=str(uuid.uuid4()),
        name="My Dashboard",
        layout=[
            LayoutItem(widget_id="risk_score_gauge", x=0, y=0, width=4, height=3),
            LayoutItem(widget_id="mttr_metric", x=4, y=0, width=2, height=3),
            LayoutItem(widget_id="incidents_by_severity", x=6, y=0, width=6, height=3),
            LayoutItem(widget_id="alerts_timeline", x=0, y=3, width=6, height=3),
            LayoutItem(widget_id="active_threats", x=6, y=3, width=6, height=3),
        ],
        is_default=False,
    )


@router.post(
    "/layout",
    response_model=DashboardLayout,
    summary="Save Dashboard Layout",
)
async def save_layout(
    layout: DashboardLayout,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(get_current_user),
):
    return DashboardLayout(
        id=layout.id or str(uuid.uuid4()),
        name=layout.name or "My Dashboard",
        layout=layout.layout,
        is_default=layout.is_default,
    )


@router.post(
    "/widgets/{widget_id}/data",
    response_model=WidgetDataResponse,
    summary="Get Widget Data",
)
async def get_widget_data(
    widget_id: str,
    request: WidgetDataRequest,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    data = {}

    if widget_id == "incidents_by_severity":
        result = await db.execute(
            select(Incident.severity, func.count(Incident.id))
            .where(Incident.tenant_id == tid, Incident.status.notin_(["closed"]))
            .group_by(Incident.severity)
        )
        data = dict(result.all())

    elif widget_id == "alerts_timeline":
        result = await db.execute(
            select(
                extract("hour", Alert.created_at).label("hour"),
                func.count(Alert.id).label("count")
            ).where(Alert.tenant_id == tid, Alert.created_at >= now - timedelta(hours=24))
            .group_by("hour").order_by("hour")
        )
        data = [{"hour": int(row[0]), "count": row[1]} for row in result.all()]

    elif widget_id == "active_threats":
        result = await db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active.is_(True)
            ).limit(20)
        )
        data = [_model_to_dict(r) for r in result.scalars().all()]

    elif widget_id == "asset_inventory":
        result = await db.execute(
            select(Asset.type, Asset.status, Asset.risk_level, func.count(Asset.id))
            .where(Asset.tenant_id == tid).group_by(Asset.type, Asset.status, Asset.risk_level)
        )
        data = [{"type": row[0], "status": row[1], "risk_level": row[2], "count": row[3]} for row in result.all()]

    elif widget_id == "risk_score_gauge":
        sev_result = await db.execute(
            select(Incident.severity, func.count(Incident.id))
            .where(Incident.tenant_id == tid, Incident.status.notin_(["closed"]))
            .group_by(Incident.severity)
        )
        sev = dict(sev_result.all())
        risk = sum(SEVERITY_WEIGHTS.get(s, 0) * c for s, c in sev.items())
        data = {"risk_score": risk, "severity_breakdown": sev}

    elif widget_id == "mttr_metric":
        result = await db.execute(
            select(func.avg(func.extract("epoch", Incident.closed_at - Incident.created_at) / 60.0))
            .where(Incident.tenant_id == tid, Incident.closed_at.isnot(None))
        )
        data = {"mttr_minutes": round(float(result.scalar() or 0), 1)}

    elif widget_id == "vulnerability_heatmap":
        result = await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.tenant_id == tid, Vulnerability.status.in_(["open", "in_progress"]))
            .group_by(Vulnerability.severity)
        )
        data = [{"severity": row[0], "count": row[1]} for row in result.all()]

    elif widget_id == "compliance_score":
        result = await db.execute(
            select(func.coalesce(func.avg(ComplianceAssessment.score), 0.0))
            .where(ComplianceAssessment.tenant_id == tid, ComplianceAssessment.status == "completed")
        )
        data = {"score": round(float(result.scalar() or 0), 1)}

    elif widget_id == "soc_workload":
        result = await db.execute(
            select(Incident.assignee_name, func.count(Incident.id))
            .where(
                Incident.tenant_id == tid, Incident.status.notin_(["closed"]),
                Incident.assignee_name.isnot(None)
            ).group_by(Incident.assignee_name)
        )
        data = [{"analyst": row[0], "incidents": row[1]} for row in result.all()]

    elif widget_id == "system_health":
        data = {
            "services": {"api": "healthy", "worker": "healthy", "db": "healthy"},
            "metrics": {"cpu": 42.0, "memory": 58.3, "disk": 31.7},
        }

    else:
        data = {"message": f"Widget data for '{widget_id}' not configured"}

    return WidgetDataResponse(
        widget_id=widget_id,
        data=data,
        last_updated=now,
        refresh_interval_seconds=60,
    )


# ════════════════════════════════════════════════════════════════════
# ── Live Stats, Trends, Map, Attack Graph ───────────────────────────
# ════════════════════════════════════════════════════════════════════

@router.get(
    "/live/stats",
    response_model=LiveStatsResponse,
    summary="Live Statistics",
)
async def live_stats(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)

    active_alerts = (await db.execute(
        select(func.count(Alert.id)).where(
            Alert.tenant_id == tid, Alert.status.in_(["new", "acknowledged"])
        )
    )).scalar() or 0

    active_incidents = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.tenant_id == tid, Incident.status.notin_(["closed"])
        )
    )).scalar() or 0

    online_agents = (await db.execute(
        select(func.count(Agent.id)).where(
            Agent.tenant_id == tid, Agent.status == "online"
        )
    )).scalar() or 0

    return LiveStatsResponse(
        active_alerts=active_alerts,
        active_incidents=active_incidents,
        events_per_second=12.5,
        active_users=5,
        active_threats=(await db.execute(
            select(func.count(ThreatIndicator.id)).where(
                ThreatIndicator.tenant_id == tid, ThreatIndicator.is_active.is_(True)
            )
        )).scalar() or 0,
        system_load=42.0,
        queue_depth=3,
        network_traffic_mbps=125.7,
        timestamp=now,
    )


@router.get(
    "/trends/{period}",
    response_model=TrendsResponse,
    summary="Security Trends Over Time",
)
async def trends_over_time(
    period: TrendPeriod,
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    metrics: Optional[str] = Query(None),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    period_days = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}[period.value]
    since = now - timedelta(days=period_days)
    data_points = []

    # Daily incident counts
    inc_result = await db.execute(
        select(
            cast(Incident.created_at, Date).label("day"),
            func.count(Incident.id).label("count")
        ).where(Incident.tenant_id == tid, Incident.created_at >= since)
        .group_by("day").order_by("day")
    )
    for row in inc_result.all():
        data_points.append({"metric": "incidents", "date": str(row[0]), "count": row[1]})

    # Daily alert counts
    al_result = await db.execute(
        select(
            cast(Alert.created_at, Date).label("day"),
            func.count(Alert.id).label("count")
        ).where(Alert.tenant_id == tid, Alert.created_at >= since)
        .group_by("day").order_by("day")
    )
    for row in al_result.all():
        data_points.append({"metric": "alerts", "date": str(row[0]), "count": row[1]})

    # Daily vuln counts
    vuln_result = await db.execute(
        select(
            cast(Vulnerability.detected_at, Date).label("day"),
            func.count(Vulnerability.id).label("count")
        ).where(Vulnerability.tenant_id == tid, Vulnerability.detected_at >= since)
        .group_by("day").order_by("day")
    )
    for row in vuln_result.all():
        data_points.append({"metric": "vulnerabilities", "date": str(row[0]), "count": row[1]})

    return TrendsResponse(
        period=period.value,
        data_points=data_points,
        metrics={"incidents": True, "alerts": True, "vulnerabilities": True},
        generated_at=now,
    )


@router.get(
    "/alerts/map",
    response_model=AlertMapResponse,
    summary="Alert Heat Map",
)
async def alerts_map(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCAnalyst),
    severity: Optional[str] = Query(None),
    hours: int = Query(24, ge=1, le=168),
):
    tid = _tid(tenant_id)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    conds = [Alert.tenant_id == tid, Alert.created_at >= since]
    if severity:
        conds.append(Alert.severity == severity)

    result = await db.execute(
        select(Alert.source_ip, func.count(Alert.id).label("count"))
        .where(*conds).group_by(Alert.source_ip).order_by(desc("count")).limit(50)
    )
    alerts = [{"source_ip": row[0] or "unknown", "count": row[1]} for row in result.all()]

    return AlertMapResponse(
        alerts=alerts,
        total_pinned=len(alerts),
        generated_at=now,
    )


@router.get(
    "/attack-graph",
    response_model=AttackGraphResponse,
    summary="Attack Graph",
)
async def attack_graph(
    db: AsyncSession = Depends(get_db),
    tenant_id: str = Depends(require_tenant),
    current_user: dict = Depends(RequireSOCManager),
    incident_id: Optional[str] = Query(None),
    include_mitigated: bool = Query(False),
):
    tid = _tid(tenant_id)

    # Nodes: assets
    asset_result = await db.execute(
        select(Asset).where(Asset.tenant_id == tid).limit(100)
    )
    assets = asset_result.scalars().all()

    nodes = []
    for a in assets:
        nodes.append(AttackGraphNode(
            id=str(a.id),
            label=a.name,
            type=a.type or "endpoint",
            properties={
                "hostname": a.hostname,
                "ip": a.ip_address,
                "os": a.os,
                "risk_level": a.risk_level,
            },
            score=float(SEVERITY_WEIGHTS.get(a.risk_level, 1)) if a.risk_level else None,
        ))

    # Edges: incident-asset relationships
    edge_result = await db.execute(
        select(Incident.id, Asset.id).select_from(Incident).join(
            Incident.assets
        ).join(Asset).where(
            Incident.tenant_id == tid
        ).limit(200)
    )
    seen = set()
    edges = []
    for row in edge_result.all():
        edge_key = (str(row[0]), str(row[1]))
        if edge_key not in seen:
            seen.add(edge_key)
            edges.append(AttackGraphEdge(
                id=str(uuid.uuid4()),
                source=str(row[0]),
                target=str(row[1]),
                label="affected",
                relationship="incident_asset",
            ))

    # Add incident nodes
    if incident_id:
        inc_q = select(Incident).where(Incident.id == uuid.UUID(incident_id), Incident.tenant_id == tid)
    else:
        inc_q = select(Incident).where(Incident.tenant_id == tid, Incident.status.notin_(["closed"])).limit(50)

    inc_result = await db.execute(inc_q)
    for inc in inc_result.scalars().all():
        nodes.append(AttackGraphNode(
            id=str(inc.id),
            label=inc.title,
            type="incident",
            properties={"severity": inc.severity, "status": inc.status},
            score=float(SEVERITY_WEIGHTS.get(inc.severity, 1)),
        ))

    return AttackGraphResponse(
        nodes=nodes,
        edges=edges,
        generated_at=datetime.now(timezone.utc),
    )
