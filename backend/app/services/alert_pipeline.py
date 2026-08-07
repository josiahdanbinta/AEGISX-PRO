"""
AEGISX - Alert Generation Pipeline
Creates Alert records from Sigma matches with deduplication,
severity mapping, MITRE enrichment, and asset context.
"""
import logging
import time
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

        from app.services.dedup_service import dedup_service
        from app.services.metrics_instrument import record_alert_created
        import time as _time

        created_alerts: List[Alert] = []
        now = datetime.now(timezone.utc)
        severity = _map_severity(rule)
        dedup_count = 0

        tenant_str = str(self.tenant_id)

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

            bloom_dup = await dedup_service.is_alert_duplicate(
                tenant_str, str(rule.id), source_ip, hostname,
            )
            if bloom_dup:
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
            record_alert_created(str(self.tenant_id), severity, rule.name)
            created_alerts.append(alert)

        logger.info(
            "AlertPipeline generated %d alerts for rule '%s' (deduped: %d)",
            len(created_alerts), rule.name, dedup_count,
        )

        if created_alerts:
            await self._run_ueba_scoring(created_alerts)
            await self._publish_to_eventbus(created_alerts)

        return created_alerts

    async def _run_ueba_scoring(self, alerts: List[Alert]) -> None:
        """Run UEBA scoring on generated alerts. Publish anomalies above threshold."""
        try:
            from app.services.ueba_scorer import ueba_scorer
            from app.services.event_bus import event_bus

            tenant_str = str(self.tenant_id)
            threshold = settings.UEBA_ANOMALY_THRESHOLD

            for alert in alerts:
                event = alert.raw_event or {}
                if not event:
                    continue

                enriched = {
                    "event_id": str(alert.id),
                    "tenant_id": tenant_str,
                    "severity": alert.severity,
                    "source_ip": alert.source_ip,
                    "hostname": getattr(alert, "source_asset_id", None),
                    "enrichment": {},
                    "tags": [],
                }
                if isinstance(event, dict):
                    enriched.update(event)

                try:
                    ueba_result = await ueba_scorer.score_event(tenant_str, enriched)
                    anomaly_score = ueba_result.get("anomaly_score", 0)

                    if anomaly_score >= threshold:
                        alert.confidence = max(
                            alert.confidence or 0.5,
                            ueba_result.get("confidence", 0.5),
                        )
                        alert.ueba_score = anomaly_score

                        await event_bus.anomaly_detected(tenant_str, {
                            "alert_id": str(alert.id),
                            "title": alert.title,
                            "severity": "critical" if anomaly_score >= settings.UEBA_CRITICAL_THRESHOLD else "high",
                            "anomaly_score": round(anomaly_score, 4),
                            "entity_scores": ueba_result.get("entity_scores", {}),
                            "mitre_techniques": ueba_result.get("mitre_techniques", []),
                            "details": ueba_result.get("details", {}),
                        })
                        logger.info(
                            "UEBA anomaly detected: alert=%s score=%.4f entities=%s",
                            str(alert.id), anomaly_score,
                            list(ueba_result.get("entity_scores", {}).keys()),
                        )
                except Exception as e:
                    logger.debug("UEBA scoring skipped for alert %s: %s", str(alert.id), e)
        except Exception as e:
            logger.warning("UEBA scoring pipeline error: %s", e)

    async def _publish_to_eventbus(self, alerts: List[Alert]) -> None:
        """Publish generated alerts to EventBus for real-time WebSocket push."""
        try:
            from app.services.event_bus import event_bus
            tenant_str = str(self.tenant_id)

            for alert in alerts:
                await event_bus.alert_created(tenant_str, {
                    "id": str(alert.id),
                    "title": alert.title,
                    "severity": alert.severity,
                    "status": alert.status,
                    "rule_name": alert.rule_name,
                    "source_ip": alert.source_ip or "",
                    "destination_ip": alert.destination_ip or "",
                    "description": alert.description or "",
                    "confidence": alert.confidence or 0.5,
                    "ueba_score": getattr(alert, "ueba_score", None),
                    "triggered_at": alert.created_at.isoformat() if alert.created_at else None,
                })
        except Exception:
            pass

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
