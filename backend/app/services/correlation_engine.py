"""
AEGISX - Event Correlation Engine
Groups related alerts into potential incidents using
similarity scoring across multiple dimensions.
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_factory
from app.models import Alert, Incident, IncidentAsset, Asset

logger = logging.getLogger(__name__)

CORRELATION_WINDOW_HOURS = 24
HIGH_CORRELATION_THRESHOLD = 0.7
MEDIUM_CORRELATION_THRESHOLD = 0.5
AUTO_INCIDENT_THRESHOLD = 2.5

WEIGHTS = {
    "same_source_ip": 1.0,
    "same_host": 0.8,
    "same_mitre_technique": 0.6,
    "same_rule": 0.3,
    "temporal_proximity": 0.5,
}


def _score_correlation(alert: Alert, other: Alert) -> float:
    """Compute a correlation score between two alerts. Higher = more related."""
    score = 0.0

    if alert.source_ip and other.source_ip and alert.source_ip == other.source_ip:
        score += WEIGHTS["same_source_ip"]

    alert_host = None
    other_host = None
    if alert.raw_event and isinstance(alert.raw_event, dict):
        alert_host = alert.raw_event.get("host") or alert.raw_event.get("hostname")
    if other.raw_event and isinstance(other.raw_event, dict):
        other_host = other.raw_event.get("host") or other.raw_event.get("hostname")
    if alert_host and other_host and alert_host == other_host:
        score += WEIGHTS["same_host"]

    if (alert.rule_id and other.rule_id and alert.rule_id == other.rule_id):
        score += WEIGHTS["same_rule"]

    if alert.created_at and other.created_at:
        delta = abs((alert.created_at - other.created_at).total_seconds())
        hours = delta / 3600
        if hours <= 24:
            score += WEIGHTS["temporal_proximity"] * (1 - hours / 24)

    return round(score, 2)


async def _find_related_alerts(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    alert: Alert,
    window_hours: int = CORRELATION_WINDOW_HOURS,
) -> List[Alert]:
    """Find alerts within the time window that share indicators with the given alert."""
    if not alert.created_at:
        return []

    window_start = alert.created_at - timedelta(hours=window_hours)
    window_end = alert.created_at + timedelta(hours=1)

    base_cond = [
        Alert.tenant_id == tenant_id,
        Alert.id != alert.id,
        Alert.status.in_(["new", "acknowledged", "in_progress"]),
        Alert.created_at >= window_start,
        Alert.created_at <= window_end,
    ]

    related: Set[str] = set()

    if alert.source_ip:
        result = await db.execute(
            select(Alert).where(and_(Alert.source_ip == alert.source_ip, *base_cond))
        )
        for a in result.scalars().all():
            related.add(a)

    if alert.destination_ip:
        result = await db.execute(
            select(Alert).where(and_(Alert.destination_ip == alert.destination_ip, *base_cond))
        )
        for a in result.scalars().all():
            related.add(a)

    if alert.rule_id:
        result = await db.execute(
            select(Alert).where(and_(Alert.rule_id == alert.rule_id, *base_cond))
        )
        for a in result.scalars().all():
            related.add(a)

    if alert.source_asset_id:
        result = await db.execute(
            select(Alert).where(and_(Alert.source_asset_id == alert.source_asset_id, *base_cond))
        )
        for a in result.scalars().all():
            related.add(a)

    return list(related)


def _find_correlation_groups(alerts: List[Alert]) -> List[List[str]]:
    """Group alert IDs into correlation clusters based on pairwise scores."""
    if not alerts:
        return []

    alert_ids = [str(a.id) for a in alerts]
    alert_map = {str(a.id): a for a in alerts}

    graph: Dict[str, Set[str]] = {aid: set() for aid in alert_ids}
    for i, a1 in enumerate(alerts):
        for j in range(i + 1, len(alerts)):
            a2 = alerts[j]
            score = _score_correlation(a1, a2)
            if score >= MEDIUM_CORRELATION_THRESHOLD:
                graph[str(a1.id)].add(str(a2.id))
                graph[str(a2.id)].add(str(a1.id))

    visited: Set[str] = set()
    groups: List[List[str]] = []

    def dfs(node: str, current_group: List[str]):
        visited.add(node)
        current_group.append(node)
        for neighbor in graph[node]:
            if neighbor not in visited:
                dfs(neighbor, current_group)

    for aid in alert_ids:
        if aid not in visited:
            group: List[str] = []
            dfs(aid, group)
            if len(group) >= 2:
                groups.append(group)

    return groups


async def _auto_create_incident(
    db: AsyncSession, tenant_id: uuid.UUID, alerts: List[Alert]
) -> Optional[Incident]:
    """Create an incident from a group of correlated alerts."""
    if not alerts:
        return None

    pairwise = 0.0
    count = 0
    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            pairwise += _score_correlation(alerts[i], alerts[j])
            count += 1

    avg_score = pairwise / max(count, 1)
    if avg_score < HIGH_CORRELATION_THRESHOLD:
        logger.debug(
            "Average correlation %.2f below threshold %.2f, skipping auto-incident",
            avg_score, HIGH_CORRELATION_THRESHOLD,
        )
        return None

    sevs = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    top_severity = max(alerts, key=lambda a: sevs.get(a.severity, 1))
    title = f"Correlated Incident: {top_severity.rule_name or 'Multiple Rules'} ({len(alerts)} alerts)"

    description_parts = [
        f"Automatically generated from {len(alerts)} correlated alerts.",
        "",
        "Correlated Alerts:",
    ]
    for a in alerts[:10]:
        description_parts.append(f"- [{a.severity}] {a.title} (ID: {a.id})")
    if len(alerts) > 10:
        description_parts.append(f"  ... and {len(alerts) - 10} more")

    description = "\n".join(description_parts)

    techniques: Set[str] = set()
    source_ips: Set[str] = set()
    for a in alerts:
        if a.source_ip:
            source_ips.add(a.source_ip)

    now = datetime.now(timezone.utc)
    incident = Incident(
        tenant_id=tenant_id,
        title=title,
        description=description,
        severity=top_severity.severity,
        status="new",
        source_alert_ids=[str(a.id) for a in alerts],
        mitre_techniques=list(techniques) if techniques else None,
        risk_score=round(avg_score * 100, 1),
    )
    db.add(incident)
    await db.flush()
    await db.refresh(incident)

    for alert in alerts:
        alert.promoted_to_incident_id = incident.id
        if alert.status == "new":
            alert.status = "escalated"

    logger.info(
        "Auto-created incident %s from %d correlated alerts (avg score: %.2f)",
        incident.id, len(alerts), avg_score,
    )
    return incident


class CorrelationEngine:
    """Correlates alerts and auto-creates incidents when thresholds are met."""

    def __init__(self, tenant_id: str, db: AsyncSession):
        self.tenant_id = uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id
        self.db = db

    async def correlate_events(self, alert: Alert) -> List[Incident]:
        """Correlate a new alert with existing alerts and return any auto-created incidents."""
        related = await _find_related_alerts(
            self.db, self.tenant_id, alert,
        )

        if not related:
            logger.debug("No related alerts found for alert %s", alert.id)
            return []

        logger.info(
            "Found %d related alerts for new alert %s", len(related), alert.id,
        )

        all_candidates = [alert] + related
        groups = _find_correlation_groups(all_candidates)

        if not groups:
            return []

        new_incidents: List[Incident] = []
        for group_ids in groups:
            group_alerts = [a for a in all_candidates if str(a.id) in group_ids]
            if not group_alerts:
                continue

            already_incident = any(a.promoted_to_incident_id is not None for a in group_alerts)
            if already_incident:
                logger.debug("Group %s already has an incident, skipping", group_ids)
                continue

            incident = await _auto_create_incident(self.db, self.tenant_id, group_alerts)
            if incident:
                new_incidents.append(incident)

        return new_incidents

    async def run_correlation_job(self) -> Dict[str, Any]:
        """Background job: correlate all ungrouped alerts across the tenant."""
        result = await self.db.execute(
            select(Alert).where(
                and_(
                    Alert.tenant_id == self.tenant_id,
                    Alert.status.in_(["new", "acknowledged"]),
                    Alert.promoted_to_incident_id.is_(None),
                    Alert.created_at >= datetime.now(timezone.utc) - timedelta(hours=CORRELATION_WINDOW_HOURS),
                )
            ).order_by(Alert.created_at.asc())
        )
        alerts = result.scalars().all()

        if not alerts:
            logger.info("No ungrouped alerts to correlate for tenant %s", self.tenant_id)
            return {"alerts_processed": 0, "groups_found": 0, "incidents_created": 0}

        groups = _find_correlation_groups(list(alerts))
        incidents_created = 0

        for group_ids in groups:
            group_alerts = [a for a in alerts if str(a.id) in group_ids]
            if not group_alerts:
                continue
            incident = await _auto_create_incident(self.db, self.tenant_id, group_alerts)
            if incident:
                incidents_created += 1

        await self.db.commit()

        logger.info(
            "Correlation job: %d alerts -> %d groups -> %d incidents",
            len(alerts), len(groups), incidents_created,
        )
        return {
            "alerts_processed": len(alerts),
            "groups_found": len(groups),
            "incidents_created": incidents_created,
        }
