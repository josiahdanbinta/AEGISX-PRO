"""
AEGISX - Alert Generation Pipeline
Creates Alert records from Sigma matches with deduplication,
severity mapping, MITRE enrichment, and asset context.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import DetectionRule, Alert, Asset, Incident

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

RISK_SCORE_TO_SEVERITY = [
    (80, "critical"),
    (60, "high"),
    (40, "medium"),
    (20, "low"),
]


def _map_severity(rule: DetectionRule) -> str:
    sigma_level = "medium"
    if rule.rule_content and isinstance(rule.rule_content, dict):
        sigma_level = rule.rule_content.get("level", "medium")
    mapped = SEVERITY_MAP.get(sigma_level.lower(), sigma_level.lower())
    if mapped in SEVERITY_MAP.values():
        return mapped

    risk = rule.risk_score or 50
    for threshold, sev in RISK_SCORE_TO_SEVERITY:
        if risk >= threshold:
            return sev
    return "low"


def _extract_event_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract common security event fields from a raw event dict."""
    extracted = {
        "source_ip": None,
        "destination_ip": None,
        "hostname": None,
        "username": None,
        "process_name": None,
        "event_id": event.get("id") or event.get("event_id"),
    }

    ip_fields = [
        "source_ip", "src_ip", "SourceIp", "src", "client_ip",
    ]
    for f in ip_fields:
        if event.get(f):
            extracted["source_ip"] = str(event[f])
            break

    dst_fields = [
        "destination_ip", "dest_ip", "dst_ip", "DestinationIp", "dst",
    ]
    for f in dst_fields:
        if event.get(f):
            extracted["destination_ip"] = str(event[f])
            break

    host_fields = [
        "host", "hostname", "Hostname", "ComputerName", "computer_name",
        "agent.hostname", "beat.hostname",
    ]
    for f in host_fields:
        if event.get(f):
            extracted["hostname"] = str(event[f])
            break

    user_fields = [
        "username", "user", "UserName", "user.name", "SubjectUserName",
    ]
    for f in user_fields:
        if event.get(f):
            extracted["username"] = str(event[f])
            break

    proc_fields = [
        "process_name", "process.name", "Image", "NewProcessName",
    ]
    for f in proc_fields:
        if event.get(f):
            extracted["process_name"] = str(event[f])
            break

    return extracted


async def _find_asset(
    db: AsyncSession, tenant_id: uuid.UUID, hostname: Optional[str], source_ip: Optional[str]
) -> Optional[Asset]:
    """Find an asset matching hostname or IP address."""
    if not hostname and not source_ip:
        return None

    conditions = [Asset.tenant_id == tenant_id, Asset.is_deleted == False]
    if hostname:
        result = await db.execute(
            select(Asset).where(and_(Asset.hostname == hostname, *conditions))
        )
        asset = result.scalar_one_or_none()
        if asset:
            return asset
    if source_ip:
        result = await db.execute(
            select(Asset).where(and_(Asset.ip_address == source_ip, *conditions))
        )
        asset = result.scalar_one_or_none()
        if asset:
            return asset
    return None


async def _check_duplicate(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    rule_id: uuid.UUID,
    title: str,
    source_ip: Optional[str],
    hostname: Optional[str],
) -> bool:
    """Check if an open alert already exists for this rule+entity combination."""
    conditions = [
        Alert.tenant_id == tenant_id,
        Alert.rule_id == rule_id,
        Alert.status.in_(["new", "acknowledged", "in_progress"]),
    ]
    if source_ip:
        result = await db.execute(
            select(Alert).where(and_(Alert.source_ip == source_ip, *conditions))
        )
        if result.scalar_one_or_none():
            return True
    if hostname:
        result = await db.execute(
            select(Alert).where(and_(
                Alert.source_asset_id.isnot(None),
                *conditions,
            ))
        )
        dup = result.scalar_one_or_none()
        if dup:
            return True
    return False


class AlertPipeline:
    """Pipeline for creating and enriching alerts from detection matches."""

    def __init__(self, tenant_id: str, db: AsyncSession):
        self.tenant_id = uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id
        self.db = db

    async def generate_alert(
        self, rule: DetectionRule, matches: List[dict]
    ) -> List[Alert]:
        """Generate Alert records from a list of matched events."""
        if not matches:
            return []

        created_alerts: List[Alert] = []
        now = datetime.now(timezone.utc)
        severity = _map_severity(rule)
        dedup_count = 0

        for event in matches:
            fields = _extract_event_fields(event)
            source_ip = fields["source_ip"]
            dest_ip = fields["destination_ip"]
            hostname = fields["hostname"]

            is_duplicate = await _check_duplicate(
                self.db, self.tenant_id, rule.id,
                rule.name, source_ip, hostname,
            )
            if is_duplicate:
                dedup_count += 1
                continue

            asset = await _find_asset(
                self.db, self.tenant_id, hostname, source_ip,
            )

            title = self._build_alert_title(rule, fields, event)
            description = self._build_alert_description(rule, fields, event)

            alert = Alert(
                tenant_id=self.tenant_id,
                title=title,
                description=description,
                severity=severity,
                status="new",
                rule_id=rule.id,
                rule_name=rule.name,
                source_asset_id=asset.id if asset else None,
                source_ip=source_ip,
                destination_ip=dest_ip,
                indicator_type="sigma_match",
                indicator_value=hostname or source_ip,
                confidence=self._compute_confidence(rule),
                raw_event=event,
                created_at=now,
                updated_at=now,
            )
            self.db.add(alert)
            await self.db.flush()
            created_alerts.append(alert)

        logger.info(
            "AlertPipeline generated %d alerts for rule '%s' (deduped: %d)",
            len(created_alerts), rule.name, dedup_count,
        )
        return created_alerts

    def _build_alert_title(
        self, rule: DetectionRule, fields: Dict[str, Any], event: Dict[str, Any]
    ) -> str:
        sigma_title = rule.name
        if fields["hostname"]:
            return f"{sigma_title} on {fields['hostname']}"
        if fields["source_ip"]:
            return f"{sigma_title} from {fields['source_ip']}"
        if fields["username"]:
            return f"{sigma_title} by {fields['username']}"
        if fields["process_name"]:
            return f"{sigma_title}: {fields['process_name']}"
        return sigma_title

    def _build_alert_description(
        self, rule: DetectionRule, fields: Dict[str, Any], event: Dict[str, Any]
    ) -> str:
        parts = [f"Sigma rule '{rule.name}' matched."]

        mitre = rule.mitre_techniques or []
        if mitre:
            parts.append(f"MITRE: {', '.join(mitre[:5])}")

        if fields["source_ip"]:
            parts.append(f"Source IP: {fields['source_ip']}")
        if fields["destination_ip"]:
            parts.append(f"Destination IP: {fields['destination_ip']}")
        if fields["username"]:
            parts.append(f"User: {fields['username']}")
        if fields["process_name"]:
            parts.append(f"Process: {fields['process_name']}")

        event_type = event.get("event_type") or event.get("event.action") or event.get("EventID")
        if event_type:
            parts.append(f"Event: {event_type}")

        return "\n".join(parts)

    def _compute_confidence(self, rule: DetectionRule) -> float:
        base = 0.5
        risk = rule.risk_score or 50
        base += (risk / 100) * 0.3
        if rule.false_positive_rate is not None:
            base -= min(rule.false_positive_rate * 0.5, 0.4)
        return round(max(0.1, min(1.0, base)), 2)

    async def enrich_with_mitre(self, alert: Alert, rule: DetectionRule) -> None:
        if not rule.mitre_techniques and not rule.mitre_tactics:
            return
        techniques = list(rule.mitre_techniques or [])
        existing_desc = alert.description or ""
        if not any("MITRE:" in line for line in existing_desc.split("\n") if techniques):
            mitre_line = f"MITRE Techniques: {', '.join(techniques[:10])}"
            alert.description = (existing_desc.strip() + "\n" + mitre_line).strip()

    async def correlate_with_incidents(self, alert: Alert) -> List[Incident]:
        """Find existing incidents that may be related to this alert."""
        conditions = [
            Incident.tenant_id == self.tenant_id,
            Incident.status.notin_(["closed", "resolved"]),
        ]
        if alert.source_ip:
            from sqlalchemy import or_
            result = await self.db.execute(
                select(Incident).where(
                    and_(
                        *conditions,
                        or_(
                            Incident.title.ilike(f"%{alert.source_ip}%"),
                            Incident.description.ilike(f"%{alert.source_ip}%"),
                        ),
                    )
                )
            )
            incidents = result.scalars().all()
            if incidents:
                return list(incidents)
        return []
